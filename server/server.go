// Package server implements a DiceMix Light server for CoinShuffle++.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/trace"
	"sort"
	"sync"
	"time"

	"decred.org/cspp/v2/chacha20prng"
	"decred.org/cspp/v2/coinjoin"
	"decred.org/cspp/v2/dcnet"
	"decred.org/cspp/v2/messages"
	"decred.org/cspp/v2/solver"
	"decred.org/cspp/v2/x25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/sync/errgroup"
)

const (
	pairTimeout = 24 * time.Hour
	prTimeout   = 5 * time.Second

	sendTimeout = 20 * time.Second
	recvTimeout = 10 * time.Second
)

type deadlines struct {
	recvKE  time.Time
	sendKEs time.Time
	recvCT  time.Time
	sendCTs time.Time
	recvSR  time.Time
	sendRM  time.Time
	recvDC  time.Time
	sendCM  time.Time
	recvCM  time.Time
	sendCM2 time.Time
}

func (d *deadlines) reset(begin time.Time) {
	t := begin
	add := func(duration time.Duration) time.Time {
		t = t.Add(duration)
		return t
	}
	d.recvKE = add(recvTimeout)
	d.sendKEs = add(sendTimeout)
	d.recvCT = add(recvTimeout)
	d.sendCTs = add(sendTimeout)
	d.recvSR = add(recvTimeout)
	d.sendRM = add(sendTimeout)
	d.recvDC = add(recvTimeout)
	d.sendCM = add(sendTimeout)
	d.recvCM = add(recvTimeout)
	d.sendCM2 = add(sendTimeout)
}

// Mixer is any binary-representable data which can add mixed messages and be
// confirmed with signatures.
type Mixer interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	// Mix adds a mixed message.
	Mix(m []byte)

	// Confirm extracts signatures from confirm from a specific peer and
	// includes them in the Mixer.
	Confirm(confirm interface{}, pid int) error
}

// Joiner is any data which can be joined with binary unmixed data of similar type.
// The pid describes the submitting peer ID for blame assignment.
// Joiner must be implemented by the Mixer when the server is used for CoinJoins.
type Joiner interface {
	Join(unmixed []byte, pid int) error
	ValidateUnmixed(unmixed []byte, mcount int) error
}

// LimitedJoiner is a Joiner that is limited by the total size of the mix.  If
// the unmixed data can not be added to the Joiner without exceeding these
// limits, the peer submitting this unmixed data must be excluded from a run,
// even though they have not acted maliciously.
type LimitedJoiner interface {
	Joiner
	CheckLimited(unmixed []byte, totalMixes int) error
}

// Shuffler shuffles all values (including non-anonymous) of a mix.
// If a Mixer implements Shuffler, all values are shuffled before confirming.
// It is not necessary to implement Shuffler to provide mixed message anonymity.
type Shuffler interface {
	Shuffle()
}

// PublishMixer is a Mixer which is capable of using the server to publish the
// data.  If Mixer implements PublishMixer, the mix will be published (and blame
// may be assigned for bad submitted data if the publish fails).
type PublishMixer interface {
	PublishMix(ctx context.Context) error
}

// Server implements pairing of clients performing compatible mixes, and
// coordinates a DiceMix Light session between paired clients.
type Server struct {
	svrState   uint32 // 0=stopped, 1=running, 2=finished
	svrStateMu sync.Mutex

	sidPRNG    *chacha20prng.Reader // Generates sids, used because it never errors
	msize      int
	newm       NewMixer
	epoch      time.Duration
	minPeers   int
	pairings   map[string][]*client
	pairingsMu sync.Mutex

	report *json.Encoder
}

type runState struct {
	keCount   uint32
	ctCount   uint32
	srCount   uint32
	dcCount   uint32
	confCount uint32
	rsCount   uint32

	allKEs   chan struct{}
	allCTs   chan struct{}
	allSRs   chan struct{}
	allDCs   chan struct{}
	allConfs chan struct{}
	allRSs   chan struct{}

	blaming   chan struct{}
	rerunning chan struct{}
}

type session struct {
	runs []runState

	deadlines deadlines

	sid    []byte
	msgses *messages.Session
	br     *messages.BR
	msize  int
	minp   int
	newm   func() (Mixer, error)
	mix    Mixer

	run      int
	mtot     int
	clients  []*client
	excluded []*client
	vk       []ed25519.PublicKey
	mcounts  []int
	roots    []*big.Int

	pids map[string]int
	mu   sync.Mutex

	report *json.Encoder

	denom int64
}

type client struct {
	conn          net.Conn
	readDeadline  time.Time
	writeDeadline time.Time
	dec           *gob.Decoder // decodes from conn
	enc           *gob.Encoder // encodes to conn
	sesc          chan *session
	pr            *messages.PR
	ke            *messages.KE
	ct            *messages.CT
	sr            *messages.SR
	dc            *messages.DC
	cm            *messages.CM
	rs            *messages.RS
	mix           Mixer
	out           chan interface{}
	blamed        chan struct{}
	done          chan struct{}
	cancel        func()
}

// NewMixer returns a Mixer to join data with described features.
// The result should contain no initial messages.
// If the BinaryMixer is also a Joiner, it will be joined with the unmixed
// data from a pairing request message.
type NewMixer func(desc []byte) (Mixer, error)

// New creates a Server that will perform DiceMix Light with messages of length msize.
// When newm creates a CoinJoin transaction, this implements CoinShuffle++.
//
// If the Mixer returned by newm implements the Joiner and Shuffler interfaces,
// these will be called to join and shuffle non-anonymous portions of a mix.
func New(msize int, newm NewMixer, epoch time.Duration) (*Server, error) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, err
	}
	s := &Server{
		sidPRNG:  chacha20prng.New(seed, 0),
		msize:    msize,
		newm:     newm,
		epoch:    epoch,
		minPeers: 3,
		pairings: make(map[string][]*client),
	}
	return s, nil
}

func (s *Server) SetReportEncoder(enc *json.Encoder) {
	s.report = enc
}

func (s *Server) SetMinPeers(min int) {
	s.minPeers = min
}

// Run executes the server, listening on lis for new client connections.
func (s *Server) Run(ctx context.Context, lis net.Listener) error {
	s.svrStateMu.Lock()
	if s.svrState == 2 {
		s.svrStateMu.Unlock()
		return errors.New("server cannot be reused")
	}
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		if s.svrState == 0 {
			s.svrState = 1
			s.svrStateMu.Unlock()
			return s.pairSessions(ctx)
		}
		s.svrStateMu.Unlock()
		return nil
	})
	g.Go(func() error {
		var wg sync.WaitGroup
		for {
			conn, err := lis.Accept()
			if err != nil {
				wg.Wait()
				return err
			}
			log.Printf("serving %s", conn.RemoteAddr())
			ctx, task := trace.NewTask(ctx, "serveConn")
			wg.Add(1)
			go func() {
				var err error
				defer func() {
					if r := recover(); r != nil {
						log.Printf("recovered: %v", r)
						debug.PrintStack()
					}
					conn.Close()
					// TODO: remove peer pairing if necessary
					if err == nil {
						log.Printf("closed %v", conn.RemoteAddr())
					} else {
						log.Printf("closed %v: %v", conn.RemoteAddr(), err)
					}
					task.End()
					wg.Done()
				}()
				trace.Logf(ctx, "", "serving %v", conn.RemoteAddr())
				err = s.serveConn(ctx, conn)
				trace.Logf(ctx, "", "closed %v: %v", conn.RemoteAddr(), err)
			}()
		}
	})
	return g.Wait()
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) error {
	// Read pairing request
	dec := gob.NewDecoder(conn)
	enc := gob.NewEncoder(conn)
	pr := new(messages.PR)
	if err := conn.SetReadDeadline(time.Now().Add(prTimeout)); err != nil {
		return err
	}
	err := dec.Decode(pr)
	if err != nil {
		return fmt.Errorf("read PR: %v", err)
	}
	if len(pr.Identity) != ed25519.PublicKeySize || !pr.VerifySignature(pr.Identity) {
		return errors.New("invalid identity")
	}
	if pr.MessageCount < 0 {
		return errors.New("negative message count")
	}
	_, denom, _, _, _, _ := coinjoin.DecodeDesc(pr.PairCommitment)
	log.Printf("recv(%v) PR Identity:%x PairCommitment:%x MessageCount:%d Unmixed:%x Denom:%v",
		conn.RemoteAddr(), pr.Identity, pr.PairCommitment, pr.MessageCount, pr.Unmixed,
		denom)
	mix, err := s.newm(pr.PairCommitment)
	if err != nil {
		return fmt.Errorf("unable to begin mix: %v", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := &client{
		conn:   conn,
		dec:    dec,
		enc:    enc,
		sesc:   make(chan *session, 1),
		pr:     pr,
		mix:    mix,
		out:    make(chan interface{}, 1),
		blamed: make(chan struct{}),
		done:   make(chan struct{}),
		cancel: cancel,
	}
	go func() {
		<-ctx.Done()
		close(c.done)
	}()
	if j, ok := mix.(Joiner); ok {
		err = j.ValidateUnmixed(pr.Unmixed, pr.MessageCount)
		if err != nil {
			c.setWriteDeadline(time.Now().Add(time.Second))
			c.send(invalidUnmixed)
			return err
		}
	} else if pr.Unmixed != nil {
		return errors.New("cannot join unmixed data")
	}

	// Wait to be paired.
	// Begin reading a KE to detect disconnect before pairing completes.
	var PRRemoved bool
	defer func() {
		if !PRRemoved {
			s.removePR(pr.PairCommitment, c)
		}
	}()

	s.pairingsMu.Lock()
	s.pairings[string(pr.PairCommitment)] = append(s.pairings[string(pr.PairCommitment)], c)
	s.pairingsMu.Unlock()
	if err := conn.SetReadDeadline(time.Now().Add(pairTimeout)); err != nil {
		return err
	}
	var ses *session
	ke := new(messages.KE)
	readErr := make(chan error, 1)
	go c.readCh(ke, pr.Identity, readErr)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-readErr:
		if err == nil {
			return fmt.Errorf("%v: read message before run started",
				c.conn.RemoteAddr())
		}
		return err
	case ses = <-c.sesc:
		// write deadline set by session
		err := c.send(ses.br)
		if err != nil {
			return err
		}
	}

	// Wait for initial KE to be read.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-readErr:
		s.removePR(pr.PairCommitment, c)
		PRRemoved = true
		if err != nil {
			return err
		}
	}

	for run := 0; ; run++ {
		err := func() error {
			defer trace.StartRegion(ctx, "run").End()
			trace.Logf(ctx, "", "sid=%x run=%d client=%v", ses.sid, run, c.conn.RemoteAddr())
			return c.run(ctx, run, ses, ke)
		}()
		ke = nil
		if err == nil {
			return nil
		}
		if errors.Is(err, errRerun) {
			log.Printf("client %v: rerunning session %x", c.conn.RemoteAddr(), ses.sid)
			continue
		}
		return err
	}
}

func (s *Server) removePR(commitment []byte, c *client) {
	defer s.pairingsMu.Unlock()
	s.pairingsMu.Lock()
	clients := s.pairings[string(commitment)]
	for i := range clients {
		if clients[i] == c {
			clients[i] = clients[len(clients)-1]
			s.pairings[string(commitment)] = clients[:len(clients)-1]
			c.cancel()
			log.Printf("removed %v from pairing queue", c.conn.RemoteAddr())
			break
		}
	}
}

func (s *Server) pairSessions(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	ticker := time.NewTicker(s.epoch)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			log.Print("epoch tick")
		}

		var pairs []*session
		s.pairingsMu.Lock()
		for commitment, clients := range s.pairings {
			if len(clients) < s.minPeers {
				continue
			}

			// Make a copy for the session
			clients = append(clients[:0:0], clients...)

			pairCommitment := []byte(commitment)
			newm := func() (Mixer, error) {
				return s.newm(pairCommitment)
			}
			mix, err := newm()
			if err != nil {
				log.Printf("failed to create mix object: %v", err)
				continue
			}

			// When the mix type implements LimitedJoiner, create
			// another copy to detect limits before pairing all
			// compatible peers.  Leave out any peers that would
			// cause the limits to be exceeded.
			var lj LimitedJoiner
			var excludedClients []*client
			switch mix.(type) {
			case LimitedJoiner:
				mix, _ := newm()
				lj = mix.(LimitedJoiner)
			}

			delete(s.pairings, commitment)

			sid := s.sidPRNG.Next(32)

			sort.Slice(clients, func(i, j int) bool {
				id1 := clients[i].pr.Identity[:]
				id2 := clients[j].pr.Identity[:]
				return bytes.Compare(id1, id2) < 0
			})
			vk := make([]ed25519.PublicKey, 0, len(clients))
			mcounts := make([]int, 0, len(clients))
			pids := make(map[string]int)
			totalMessages := 0
			var i int
			for _, c := range clients {
				pr := c.pr
				if lj != nil {
					err := lj.CheckLimited(pr.Unmixed,
						totalMessages+pr.MessageCount)
					if err != nil {
						log.Printf("skipping inclusion of %v "+
							"in session %x: %v",
							c.raddr(), sid, err)
						excludedClients = append(excludedClients, c)
						continue
					}
					lj.Join(pr.Unmixed, i)
				}

				clients[i] = c
				vk = append(vk, pr.Identity)
				mcounts = append(mcounts, pr.MessageCount)
				totalMessages += pr.MessageCount
				pids[string(vk[i])] = i
				i++
			}
			clients = clients[:i]
			if len(clients) < s.minPeers {
				s.pairings[commitment] = append(clients, excludedClients...)
				continue
			}
			if len(excludedClients) != 0 {
				s.pairings[commitment] = excludedClients
			}
			_, denom, _, _, _, _ := coinjoin.DecodeDesc(pairCommitment)
			ses := &session{
				sid:     sid,
				msgses:  messages.NewSession(sid, 0, nil, vk),
				br:      messages.BeginRun(vk, mcounts, sid),
				msize:   s.msize,
				minp:    s.minPeers,
				newm:    newm,
				mix:     mix,
				mtot:    totalMessages,
				clients: clients,
				vk:      vk,
				mcounts: mcounts,
				pids:    pids,
				report:  s.report,
				denom:   denom,
			}
			ses.runs = append(ses.runs, runState{
				allKEs:    make(chan struct{}),
				allCTs:    make(chan struct{}),
				allSRs:    make(chan struct{}),
				allDCs:    make(chan struct{}),
				allConfs:  make(chan struct{}),
				allRSs:    make(chan struct{}),
				blaming:   make(chan struct{}),
				rerunning: make(chan struct{}),
			})
			pairs = append(pairs, ses)
		}
		s.pairingsMu.Unlock()

		for _, ses := range pairs {
			ses.start(ctx, &wg)
		}
	}
}

func (s *session) log(format string, args ...interface{}) {
	a := append(make([]interface{}, 0, len(args)+3), s.sid, s.run, s.denom)
	a = append(a, args...)
	log.Printf("sid=%x run=%d denom=%d "+format, a...)
}

func (s *session) start(ctx context.Context, wg *sync.WaitGroup) {
	for _, c := range s.clients {
		s.log("including peer %x in session", c.pr.Identity)
		// Sending the session to the client signals the client to sent
		// the BR message and read the KE.  Set this timeout here.
		// Since clients base their send/recv deadlines after they
		// receive the BR, use the same deadline as for reading the KE
		// so that the deadlines match up better.
		c.setWriteDeadline(s.deadlines.recvKE)
		c.setReadDeadline(s.deadlines.recvKE)
		c.sesc <- s
	}
	run := func(i int) error {
		defer trace.StartRegion(ctx, "run").End()
		err := s.doRun(ctx)
		s.log("run ended: %v", err)
		return err
	}
	wg.Add(1)
	defer func() {
		if r := recover(); r != nil {
			s.log("recovered: %v", r)
			debug.PrintStack()
		}
		for _, c := range s.clients {
			c.cancel()
		}
		wg.Done()
	}()

	// Set first deadline schedule.  Deadlines for reruns are reset
	// again before sending BR messages in (*session).exclude.
	startTime := time.Now()
	s.deadlines.reset(startTime)

	for i := 0; ; i++ {
		err := run(i)

		var b blamer
		if errors.As(err, &b) {
			err = s.exclude(b.Blame())
			if err != nil {
				s.log("cannot continue after exclusion: %v", err)
				return
			}
			continue
		}
		if err != nil {
			s.abortSession(err)
		}
		return
	}
}

func uniq(blamed []int) []int {
	sort.Ints(blamed)
	n := len(blamed)
	blamed = blamed[:1]
	last := blamed[0]
	for _, pid := range blamed[1:n] {
		if pid != last {
			blamed = append(blamed, pid)
			last = pid
		}
	}
	return blamed
}

// exclude removes blamed peers from the session so the next run can proceed.
// BRs are written to each remaining client's out channel to be sent by the handler.
func (s *session) exclude(blamed []int) error {
	if len(blamed) == 0 {
		// Should never happen, but gracefully abort the mix session
		// instead of panicing if this bug occurs.
		return errors.New("exclude called with no blamed peers")
	}

	// Remove duplicates
	blamed = uniq(blamed)

	defer s.mu.Unlock()
	s.mu.Lock()

	close(s.runs[s.run].rerunning)
	s.run++

	s.log("excluding %v", blamed)
	for _, pid := range blamed {
		s.log("excluding %v", s.clients[pid].raddr())
		close(s.clients[pid].blamed)
		s.excluded = append(s.excluded, s.clients[pid])
		s.clients[pid].cancel()
		s.clients[pid].conn.Close()
		s.mtot -= s.clients[pid].pr.MessageCount
		s.clients[pid] = nil
	}
	clients := s.clients[:0]
	for _, c := range s.clients {
		if c != nil {
			clients = append(clients, c)
		}
	}
	sort.Slice(clients, func(i, j int) bool {
		id1 := clients[i].pr.Identity[:]
		id2 := clients[j].pr.Identity[:]
		return bytes.Compare(id1, id2) < 0
	})
	s.clients = clients
	if len(s.clients) < s.minp {
		return fmt.Errorf("too few peers (%v < %v) to continue session",
			len(s.clients), s.minp)
	}
	s.vk = s.vk[:len(s.clients)]
	s.mcounts = s.mcounts[:len(s.clients)]
	s.pids = make(map[string]int)
	for i, c := range s.clients {
		mix, err := s.newm()
		if err != nil {
			return err
		}
		s.vk[i] = c.pr.Identity
		s.mcounts[i] = c.pr.MessageCount
		s.pids[string(c.pr.Identity)] = i
		c.ke = nil
		c.sr = nil
		c.dc = nil
		c.mix = mix
	}

	mix, err := s.newm()
	if err != nil {
		return err
	}

	s.runs = append(s.runs, runState{
		allKEs:    make(chan struct{}),
		allCTs:    make(chan struct{}),
		allSRs:    make(chan struct{}),
		allDCs:    make(chan struct{}),
		allConfs:  make(chan struct{}),
		allRSs:    make(chan struct{}),
		blaming:   make(chan struct{}),
		rerunning: make(chan struct{}),
	})
	s.roots = nil
	s.msgses = messages.NewSession(s.sid, s.run, nil, s.vk)
	s.br = messages.BeginRun(s.vk, s.mcounts, s.sid)
	s.mix = mix

	s.deadlines.reset(time.Now())
	for _, c := range s.clients {
		c.setWriteDeadline(s.deadlines.recvKE)
		c.setReadDeadline(s.deadlines.recvKE)
		select {
		case c.out <- s.br:
		case <-c.done:
		case <-time.After(time.Until(s.deadlines.recvKE)):
			s.log("BR timeout after peer exclusion: %#v", c)
		}
	}
	return nil
}

func (s *session) reportCompletedMix() {
	defer s.mu.Unlock()
	s.mu.Lock()

	if s.report == nil {
		return
	}
	type report struct {
		Time          time.Time
		Mixes         int
		PeerCount     int
		ExcludedPeers int
		Mix           interface{} `json:",omitempty"`
	}
	r := &report{
		Time:          time.Now(),
		Mixes:         s.mtot,
		PeerCount:     len(s.clients),
		ExcludedPeers: len(s.excluded),
	}
	type mixReporter interface {
		Report() interface{}
	}
	if m, ok := s.mix.(mixReporter); ok {
		r.Mix = m.Report()
	}
	if err := s.report.Encode(r); err != nil {
		s.log("cannot write mix report: %v", err)
	}
}

func (s *session) abortSession(err error) {
	defer s.mu.Unlock()
	s.mu.Lock()

	s.log("aborting due to failed blame assignment: %v", err)

	deadline := time.Now().Add(500 * time.Millisecond)
	for _, c := range s.clients {
		c.setWriteDeadline(deadline)
		c.send(abortedSession)
	}
}

func (s *session) doRun(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			return
		}
		s.reportCompletedMix()
	}()

	var blamed blamePIDs
	st := &s.runs[s.run]

	// Wait for all KE messages, or KE timeout.
	timer := time.NewTimer(time.Until(s.deadlines.recvKE))
	timerFired := false
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-st.allKEs:
		s.log("finished all KE reads")
	case <-timer.C:
		timerFired = true
		s.log("KE timeout")
	}

	// Broadcast received KEs to each unexcluded peer.
	s.mu.Lock()
	kes := &messages.KEs{
		KEs: make([]*messages.KE, 0, len(s.clients)),
	}
	for i, c := range s.clients {
		if c.ke == nil {
			blamed = append(blamed, i)
			continue
		}
		kes.KEs = append(kes.KEs, c.ke)
		if joiner, ok := s.mix.(Joiner); ok {
			err := joiner.Join(c.pr.Unmixed, i)
			if err != nil {
				s.log("blaming %v for unmixed join error: %v", c.raddr(), err)
				blamed = append(blamed, i)
			}
		} else if len(c.pr.Unmixed) != 0 {
			s.mu.Unlock()
			return fmt.Errorf("%T cannot join unmixed data", s.mix)
		}
	}
	if len(blamed) != 0 {
		s.mu.Unlock()
		return blamed
	}
	for _, c := range s.clients {
		c.setWriteDeadline(s.deadlines.sendKEs)
		c.setReadDeadline(s.deadlines.recvCT)
		select {
		case c.out <- kes:
		case <-c.done:
		}
	}
	s.mu.Unlock()

	// Wait for all CT messages, or CT timeout.
	if !timerFired && !timer.Stop() {
		<-timer.C
	}
	timerFired = false
	timer.Reset(time.Until(s.deadlines.recvCT))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-st.allCTs:
		s.log("finished all CT reads")
	case <-timer.C:
		timerFired = true
		s.log("CT timeout")
	}

	// Broadcast received ciphertexts to each unexcluded peer.
	s.mu.Lock()
	for i, c := range s.clients {
		if c.ct == nil {
			blamed = append(blamed, i)
			continue
		}
		if len(c.ct.Ciphertexts) != len(s.clients) {
			blamed = append(blamed, i)
			continue
		}
		for j := range s.clients {
			if i == j {
				continue
			}
			if s.clients[i].ct.Ciphertexts[j] == nil {
				blamed = append(blamed, i)
				continue
			}
		}
	}
	if len(blamed) != 0 {
		s.mu.Unlock()
		return blamed
	}
	// Encapsulated key ciphertexts are very large.  To save bandwidth,
	// rather than broadcasting all ciphertexts to every peer, only those
	// ciphertexts that can be decapsulated by a peer are sent to the peer.
	cts := make([]*messages.CTs, len(s.clients))
	for i := range s.clients {
		cts[i] = new(messages.CTs)
		cts[i].Ciphertexts = make([]*messages.Sntrup4591761Ciphertext, len(s.clients))
		for j := range s.clients {
			cts[i].Ciphertexts[j] = s.clients[j].ct.Ciphertexts[i]
		}
	}
	for i, c := range s.clients {
		c.setWriteDeadline(s.deadlines.sendCTs)
		c.setReadDeadline(s.deadlines.recvSR)
		select {
		case c.out <- cts[i]:
		case <-c.done:
		}
	}
	s.mu.Unlock()

	// Wait for all SR messages, or SR timeout.
	if !timerFired && !timer.Stop() {
		<-timer.C
	}
	timerFired = false
	timer.Reset(time.Until(s.deadlines.recvSR))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-st.allSRs:
		s.log("finished all SR reads")
	case <-timer.C:
		timerFired = true
		s.log("SR timeout")
	}

	// Solve roots.
	s.mu.Lock()
	blaming := st.blaming
	vs := make([][]*big.Int, 0, len(s.clients))
	for i, c := range s.clients {
		if c.sr == nil {
			blamed = append(blamed, i)
			continue
		}
		vs = append(vs, c.sr.DCMix...)
	}
	if len(blamed) != 0 {
		s.mu.Unlock()
		return blamed
	}
	powerSums := dcnet.AddVectors(vs...)
	coeffs := dcnet.Coefficients(powerSums)
	t := time.Now()
	roots, err := solver.Roots(coeffs, dcnet.F)
	if err != nil {
		s.log("failed to solve roots: %v", err)
		for _, c := range s.clients {
			c.setWriteDeadline(s.deadlines.sendRM)
			c.setReadDeadline(s.deadlines.recvDC)
		}
		close(blaming)
		s.mu.Unlock()
		return s.blame(ctx, nil)
	}
	s.log("solved roots in %v", time.Since(t))
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Cmp(roots[j]) == -1
	})
	s.log("roots: %x", roots)
	rm := messages.RecoveredMessages(roots, s.msgses)
	for _, c := range s.clients {
		c.setWriteDeadline(s.deadlines.sendRM)
		c.setReadDeadline(s.deadlines.recvDC)
		select {
		case c.out <- rm:
		case <-c.done:
		}
	}
	s.mu.Unlock()
	s.roots = roots

	// Wait for all DC messages, or DC timeout.
	if !timerFired && !timer.Stop() {
		<-timer.C
	}
	timerFired = false
	timer.Reset(time.Until(s.deadlines.recvDC))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-st.allDCs:
		s.log("finished all DC reads")
	case <-timer.C:
		timerFired = true
		s.log("DC timeout")
	}

	s.mu.Lock()
	var reportedFailure []int
	dcVecs := make([]*dcnet.Vec, 0, s.mtot)
	for i, c := range s.clients {
		if c.dc == nil {
			blamed = append(blamed, i)
			continue
		}
		if c.dc.RevealSecrets {
			reportedFailure = append(reportedFailure, i)
		}
		dcVecs = append(dcVecs, c.dc.DCNet...)
	}
	if len(reportedFailure) > 0 {
		for _, c := range s.clients {
			c.setWriteDeadline(s.deadlines.sendCM)
			c.setReadDeadline(s.deadlines.recvCM)
		}
	}
	s.mu.Unlock()
	if len(blamed) != 0 {
		return blamed
	}
	if len(reportedFailure) > 0 {
		close(blaming)
		return s.blame(ctx, reportedFailure)
	}
	res := dcnet.XorVectors(dcVecs)
	s.log("recovered message set %v", res)

	for i := 0; i < res.N; i++ {
		s.mix.Mix(res.M(i))
	}
	if shuffler, ok := s.mix.(Shuffler); ok {
		shuffler.Shuffle()
	}
	finishedMix, err := s.mix.MarshalBinary()
	if err != nil {
		return err
	}
	s.log("unsigned mix: %x", finishedMix)

	// Broadcast mix to each unexcluded peer.
	cm := messages.ConfirmMix(nil, s.mix)
	s.mu.Lock()
	for _, c := range s.clients {
		c.setWriteDeadline(s.deadlines.sendCM)
		c.setReadDeadline(s.deadlines.recvCM)
		select {
		case c.out <- cm:
		case <-c.done:
		}
	}
	s.mu.Unlock()

	// Wait for all confirmations, or confirmation timeout.
	if !timerFired && !timer.Stop() {
		<-timer.C
	}
	timerFired = false
	timer.Reset(time.Until(s.deadlines.recvCM))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-st.allConfs:
		s.log("finished all CM reads")
	case <-timer.C:
		timerFired = true
		s.log("CM timeout")
	}

	if !timerFired && !timer.Stop() {
		<-timer.C
	}

	s.mu.Lock()
	for i, c := range s.clients {
		if c.cm == nil {
			blamed = append(blamed, i)
			continue
		}
		if c.cm.RevealSecrets {
			reportedFailure = append(reportedFailure, i)
		}
	}
	if len(blamed) != 0 {
		s.mu.Unlock()
		return blamed
	}
	if len(reportedFailure) > 0 {
		for _, c := range s.clients {
			c.setWriteDeadline(s.deadlines.sendCM2)
			c.setReadDeadline(s.deadlines.sendCM2.Add(recvTimeout))
		}
		close(blaming)
		s.mu.Unlock()
		return s.blame(ctx, reportedFailure)
	}
	for i, c := range s.clients {
		err = s.mix.Confirm(c.mix, i)
		if err != nil {
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Unlock()

	if p, ok := s.mix.(PublishMixer); ok {
		err := p.PublishMix(ctx)
		if err != nil {
			return err
		}
	}

	signedMix, err := s.mix.MarshalBinary()
	if err != nil {
		return err
	}
	s.log("signed mix: %x", signedMix)

	// Broadcast signed mix to each peer.
	cm = messages.ConfirmMix(nil, s.mix)
	s.mu.Lock()
	for _, c := range s.clients {
		c.setWriteDeadline(s.deadlines.sendCM2)
		select {
		case c.out <- cm:
		case <-c.done:
		}
	}
	s.mu.Unlock()

	return nil
}

var revealSecrets interface{} = &struct{ RevealSecrets bool }{true}
var errBlamed = errors.New("blamed")

type serverErrorCode struct {
	Err messages.ServerError
}

var abortedSession = &serverErrorCode{messages.ErrAbortedSession}
var invalidUnmixed = &serverErrorCode{messages.ErrInvalidUnmixed}

func (c *client) run(ctx context.Context, run int, s *session, ke *messages.KE) error {
	log.Printf("Performing run %d with %v", run, c.raddr())

	const (
		erroredKE = 1 + iota
		erroredCT
		erroredSR
		erroredDC
		erroredCM
	)
	erroredMessage := func(message int) {
		s.mu.Lock()
		defer s.mu.Unlock()

		st := &s.runs[run]

		var count *uint32
		var ch chan struct{}
		switch message {
		case erroredKE:
			count = &st.keCount
			ch = st.allKEs
		case erroredCT:
			count = &st.ctCount
			ch = st.allCTs
		case erroredSR:
			count = &st.srCount
			ch = st.allSRs
		case erroredDC:
			count = &st.dcCount
			ch = st.allDCs
		case erroredCM:
			count = &st.confCount
			ch = st.allConfs
		}

		*count++
		if *count == uint32(len(s.clients)) {
			close(ch)
		}
	}

	if ke != nil && run != 0 {
		panic("ke parameter must be nil on reruns")
	}
	if ke == nil {
		ke = new(messages.KE)
		// read deadline set by session
		err := c.read(ke, c.pr.Identity)
		if err != nil {
			erroredMessage(erroredKE)
			return fmt.Errorf("read KE: %v", err)
		}
	}
	if len(ke.ECDH) == 0 {
		erroredMessage(erroredKE)
		return fmt.Errorf("invalid KE: missing ECDH")
	}
	if len(ke.Commitment) != 32 {
		erroredMessage(erroredKE)
		return fmt.Errorf("invalid KE: commitment not 32 bytes")
	}

	log.Printf("recv(%v) KE Run:%d Commitment:%x", c.raddr(), ke.Run, ke.Commitment)

	s.mu.Lock()
	st := &s.runs[run]
	c.ke = ke
	st.keCount++
	if st.keCount == uint32(len(s.clients)) {
		close(st.allKEs)
	}
	blaming := st.blaming
	rerunning := st.rerunning
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-blaming:
		err := c.send(revealSecrets)
		if err != nil {
			return err
		}
		return c.blame(ctx, s, run)
	case kes := <-c.out:
		// write deadline set by session
		err := c.send(kes)
		if err != nil {
			return err
		}
		select {
		case <-rerunning:
			return errRerun
		default:
		}
	}

	ct := new(messages.CT)
	// read deadline set by session
	err := c.read(ct, c.pr.Identity)
	if err != nil {
		erroredMessage(erroredCT)
		return fmt.Errorf("read CT: %v", err)
	}

	s.mu.Lock()
	c.ct = ct
	st.ctCount++
	if st.ctCount == uint32(len(s.clients)) {
		close(st.allCTs)
	}
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-blaming:
		err := c.send(revealSecrets)
		if err != nil {
			return err
		}
		return c.blame(ctx, s, run)
	case cts := <-c.out:
		// write deadline set by session
		err := c.send(cts)
		if err != nil {
			return err
		}
		select {
		case <-rerunning:
			return errRerun
		default:
		}
	}

	sr := new(messages.SR)
	// read deadline set by session
	err = c.read(sr, c.pr.Identity)
	if err != nil {
		erroredMessage(erroredSR)
		return fmt.Errorf("read SR: %v", err)
	}

	log.Printf("recv(%v) SR Run:%d DCMix:%x", c.raddr(), sr.Run, sr.DCMix)

	if len(sr.DCMix) != c.pr.MessageCount {
		erroredMessage(erroredSR)
		return fmt.Errorf("invalid SR")
	}

	s.mu.Lock()
	mtotal := s.mtot
	for i := range sr.DCMix {
		if len(sr.DCMix[i]) != mtotal {
			s.mu.Unlock()
			erroredMessage(erroredSR)
			return fmt.Errorf("invalid SR")
		}
	}
	c.sr = sr
	st.srCount++
	if st.srCount == uint32(len(s.clients)) {
		close(st.allSRs)
	}
	blaming = st.blaming
	rerunning = st.rerunning
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-blaming:
		err := c.send(revealSecrets)
		if err != nil {
			return err
		}
		return c.blame(ctx, s, run)
	case mix := <-c.out:
		// write deadline set by session
		err = c.send(mix)
		if err != nil {
			return err
		}
		select {
		case <-rerunning:
			return errRerun
		default:
		}
	}

	dc := new(messages.DC)
	// read deadline set by session
	err = c.read(dc, c.pr.Identity)
	if err != nil {
		erroredMessage(erroredDC)
		return fmt.Errorf("read DC: %v", err)
	}

	log.Printf("recv(%v) DC Run:%d DCNet:%v", c.raddr(), dc.Run, dc.DCNet)

	if len(dc.DCNet) != c.pr.MessageCount {
		erroredMessage(erroredDC)
		return fmt.Errorf("invalid DC")
	}
	for _, vec := range dc.DCNet {
		if !vec.IsDim(mtotal, s.msize) {
			erroredMessage(erroredDC)
			return fmt.Errorf("bad dc-net dimensions")
		}
	}

	s.mu.Lock()
	c.dc = dc
	st.dcCount++
	if st.dcCount == uint32(len(s.clients)) {
		close(st.allDCs)
	}
	mix := c.mix
	blaming = st.blaming
	rerunning = st.rerunning
	s.mu.Unlock()

	if dc.RevealSecrets {
		return c.blame(ctx, s, run)
	}

	// Send unconfirmed mix
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-blaming:
		err := c.send(revealSecrets)
		if err != nil {
			return err
		}
		return c.blame(ctx, s, run)
	case mix := <-c.out:
		// write deadline set by session
		err = c.send(mix)
		if err != nil {
			return err
		}
		select {
		case <-rerunning:
			return errRerun
		default:
		}
	}

	cm := &messages.CM{Mix: mix}
	// read deadline set by session
	err = c.read(cm, c.pr.Identity)
	if err != nil {
		erroredMessage(erroredCM)
		return err
	}

	log.Printf("recv(%v) CM RevealSecrets:%v", c.raddr(), cm.RevealSecrets)

	s.mu.Lock()
	c.cm = cm
	c.mix = mix
	st.confCount++
	if st.confCount == uint32(len(s.clients)) {
		close(st.allConfs)
	}
	blaming = st.blaming
	rerunning = st.rerunning
	s.mu.Unlock()

	if cm.RevealSecrets {
		return c.blame(ctx, s, run)
	}

	// Send signed mix
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-blaming:
		err := c.send(revealSecrets)
		if err != nil {
			return err
		}
		return c.blame(ctx, s, run)
	case out := <-c.out:
		// write deadline set by session
		err = c.send(out)
		if err != nil {
			return err
		}
		select {
		case <-rerunning:
			return errRerun
		default:
		}
	}

	return nil
}

type blame struct {
	prng *chacha20prng.Reader

	// Key exchange keys (derived from prng)
	kx *dcnet.KX

	// Exponential slot reservation mix
	srMsg []*big.Int // random numbers to be exponential dc-net mixed
	srKP  [][][]byte // shared keys for exp dc-net

	// XOR DC-net
	dcMsg [][]byte
	dcKP  [][]*dcnet.Vec
}

// blamer describes IDs of blamed peers in a failed run.
type blamer interface {
	Blame() []int
}

type blamePIDs []int

func (pids blamePIDs) Error() string { return "blame assigned" }
func (pids blamePIDs) Blame() []int  { return []int(pids) }

func (s *session) blame(ctx context.Context, reported []int) (err error) {
	var blamed blamePIDs
	defer func() {
		if len(blamed) > 0 {
			s.log("blamed peers %v", []int(blamed))
		}
	}()

	if len(reported) > 0 {
		// If blame cannot be assigned on a failed mix, blame the peers
		// who reported failure.
		defer func() {
			if err != nil || len(reported) == 0 {
				return
			}
			// Filter out duplicates
			reportedm := make(map[int]struct{})
			blamed = blamePIDs(reported[:0])
			for _, pid := range reported {
				if _, ok := reportedm[pid]; ok {
					continue
				}
				reportedm[pid] = struct{}{}
				s.log("blaming %v for false failure accusation",
					s.clients[pid].raddr())
				blamed = append(blamed, pid)
			}
			err = blamed
		}()
	}

	// Wait for all secrets, or timeout.
	st := &s.runs[s.run]
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-st.allRSs:
		log.Print("received all RS messages")
	case <-time.After(5000 * time.Millisecond):
		s.mu.Lock()
		for i, c := range s.clients {
			if c.rs == nil {
				s.log("blaming %v for RS timeout", c.raddr())
				blamed = append(blamed, i)
			}
		}
		s.mu.Unlock()
		return blamed
	}

	defer s.mu.Unlock()
	s.mu.Lock()

	b := make([]blame, len(s.clients))
	var start int
	starts := make([]int, 0, len(s.clients))
	ecdh := make([]*x25519.Public, 0, len(s.clients))
	pqPublics := make([]*dcnet.PQPublicKey, 0, len(s.clients))
KELoop:
	for i, c := range s.clients {
		if c.ke == nil {
			s.log("blaming %v for missing messages", c.raddr())
			blamed = append(blamed, i)
			continue
		}

		// Blame when revealed secrets do not match prior commitment to the secrets.
		if cm := c.rs.Commit(s.msgses); !bytes.Equal(cm, c.ke.Commitment) {
			s.log("blaming %v for false commitment", c.raddr())
			blamed = append(blamed, i)
			continue
		}

		// Blame peers whose seed is not the correct length (will panic chacha20prng).
		if len(c.rs.Seed) != chacha20prng.SeedSize {
			s.log("blaming %v for bad seed size in RS message", c.raddr())
			blamed = append(blamed, i)
			continue KELoop
		}

		// Blame peers with SR messages outside of the field.
		for _, m := range c.rs.SR {
			if !dcnet.InField(m) {
				s.log("blaming %v for SR message outside field", c.raddr())
				blamed = append(blamed, i)
				continue KELoop
			}
		}

		ecdh = append(ecdh, c.ke.ECDH)
		pqPublics = append(pqPublics, c.ke.PQPK)
		mcount := c.pr.MessageCount
		starts = append(starts, start)
		start += mcount
		prng := chacha20prng.New(c.rs.Seed, uint32(s.run))
		b[i].prng = prng
		b[i].kx, err = dcnet.NewKX(prng)
		if err != nil {
			s.log("blaming %v for bad KX", c.raddr())
			blamed = append(blamed, i)
			continue KELoop
		}

		// Blame when public keys do not match those derived from the PRNG.
		switch {
		case !bytes.Equal(c.ke.ECDH[:], b[i].kx.X25519.Public[:]):
			fallthrough
		case !bytes.Equal(c.ke.PQPK[:], b[i].kx.PQPublic[:]):
			s.log("blaming %v for KE public keys not derived from their PRNG",
				c.raddr())
			blamed = append(blamed, i)
			continue KELoop
		}

		if len(c.rs.SR) != mcount || len(c.rs.M) != mcount {
			s.log("blaming %v for bad message count", c.raddr())
			blamed = append(blamed, i)
			continue
		}
		b[i].srMsg = c.rs.SR
		b[i].dcMsg = c.rs.M
	}
	if len(blamed) > 0 {
		return blamed
	}

	// Blame peers who share SR messages.
	shared := make(map[string][]int)
	for i := range s.clients {
		for _, m := range b[i].srMsg {
			key := string(m.Bytes())
			shared[key] = append(shared[key], i)
		}
	}
	for _, pids := range shared {
		if len(pids) > 1 {
			for i := range pids {
				s.log("blaming %v for shared SR message", s.clients[i].raddr())
			}
			blamed = append(blamed, pids...)
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

	cts := make([][]*messages.Sntrup4591761Ciphertext, len(s.clients))
	for i, c := range s.clients {
		if c.ct == nil {
			s.log("blaming %v for missing messages", c.raddr())
			blamed = append(blamed, i)
			continue
		}
		cts[i] = make([]*messages.Sntrup4591761Ciphertext, len(s.clients))
		for j := range s.clients {
			cts[i][j] = s.clients[j].ct.Ciphertexts[i]
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

SRLoop:
	for i, c := range s.clients {
		// Recover shared secrets
		kx := b[i].kx
		b[i].srKP, b[i].dcKP, err = dcnet.SharedKeys(kx, ecdh, cts[i], s.sid, s.msize,
			s.run, i, s.mcounts)

		for j, m := range b[i].srMsg {
			// Recover SR pads and mix with committed messages
			pads := dcnet.SRMixPads(b[i].srKP[j], starts[i]+j)
			srMix := dcnet.SRMix(m, pads)

			// Blame when committed mix does not match provided.
			for k := range srMix {
				if srMix[k].Cmp(c.sr.DCMix[j][k]) != 0 {
					s.log("blaming %v for bad SR mix", c.raddr())
					blamed = append(blamed, i)
					continue SRLoop
				}
			}
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

	rootSlots := make(map[string]int)
	for i, m := range s.roots {
		rootSlots[string(m.Bytes())] = i
	}
DCLoop:
	for i, c := range s.clients {
		// With the slot reservation successful, no peers should have
		// notified failure to find their slots in the next (DC)
		// message, and there must be mcount DC-net vectors.
		mcount := c.pr.MessageCount
		if len(c.dc.DCNet) != mcount {
			s.log("blaming %v for missing DC mix vectors", c.raddr())
			blamed = append(blamed, i)
			continue
		}

		for j, m := range b[i].dcMsg {
			srMsg := b[i].srMsg[j]
			slot, ok := rootSlots[string(srMsg.Bytes())]
			if !ok {
				// Should never get here after a valid SR mix
				return fmt.Errorf("blame failed: no slot for message %v", m)
			}

			// Recover DC pads and mix with committed messages
			pads := dcnet.DCMixPads(b[i].dcKP[j], s.msize, starts[i]+j)
			dcMix := dcnet.DCMix(pads, m, slot)

			// Blame when committed mix does not match provided.
			for k := 0; k < dcMix.N; k++ {
				if !dcMix.Equals(c.dc.DCNet[j]) {
					s.log("blaming %v for bad DC mix", c.raddr())
					blamed = append(blamed, i)
					continue DCLoop
				}
			}
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

	// Blame peers whose unmixed data became invalid since the initial pair
	// request.
	if j, ok := s.mix.(Joiner); ok {
		// Validation occurs in parallel as it may involve high latency.
		var mu sync.Mutex // protect concurrent appends to blamed
		var wg sync.WaitGroup
		wg.Add(len(s.clients))
		for i := range s.clients {
			i := i
			pr := s.clients[i].pr
			go func() {
				err := j.ValidateUnmixed(pr.Unmixed, pr.MessageCount)
				if err != nil {
					mu.Lock()
					blamed = append(blamed, i)
					mu.Unlock()
				}
				wg.Done()
			}()
		}
		wg.Wait()
	}
	if len(blamed) > 0 {
		return blamed
	}

	return nil
}

var errRerun = errors.New("rerun")

func (c *client) blame(ctx context.Context, s *session, run int) error {
	rs := new(messages.RS)
	err := c.read(rs, c.pr.Identity)
	if err != nil {
		return err
	}

	s.mu.Lock()
	st := &s.runs[run]
	c.rs = rs
	st.rsCount++
	if st.rsCount == uint32(len(s.clients)) {
		close(st.allRSs)
	}
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case msg := <-c.out:
		err := c.send(msg)
		if err != nil {
			return err
		}
	case <-c.blamed:
		return errBlamed
	}
	return errRerun
}

// raddr returns the remote address of the client.
func (c *client) raddr() net.Addr {
	return c.conn.RemoteAddr()
}

var errInvalidSig = errors.New("invalid signature")

// setReadDeadline sets the read deadline that will be used by the next call to c.read.
func (c *client) setReadDeadline(deadline time.Time) {
	c.readDeadline = deadline
}

// setWriteDeadline sets the write deadline that will be used by the next call to c.send.
func (c *client) setWriteDeadline(deadline time.Time) {
	c.writeDeadline = deadline
}

// readCh reads a value from the gob decoder, without timeout, writing the error
// result to ch.
func (c *client) readCh(out interface{}, pub ed25519.PublicKey, ch chan error) {
	if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
		ch <- err
		return
	}
	if err := c.dec.Decode(out); err != nil {
		ch <- err
		return
	}
	switch out := out.(type) {
	case messages.Signed:
		if !out.VerifySignature(pub) {
			ch <- errInvalidSig
			return
		}
	}

	ch <- nil
}

// read reads a value from the decoder with a relative timeout.
func (c *client) read(out interface{}, pub ed25519.PublicKey) (err error) {
	defer func() {
		if err != nil {
			_, file, line, _ := runtime.Caller(2)
			file = filepath.Base(file)
			log.Printf("read %T at caller %v:%v failed: %v", out, file, line, err)
		}
	}()
	log.Printf("awaiting(%v) %T", c.raddr(), out)
	if err = c.conn.SetReadDeadline(c.readDeadline); err != nil {
		return err
	}
	err = c.dec.Decode(out)
	if err != nil {
		return err
	}
	switch out := out.(type) {
	case messages.Signed:
		if !out.VerifySignature(pub) {
			return errInvalidSig
		}
	}
	return nil
}

// send writes msg to the gob stream with a relative timeout.
func (c *client) send(msg interface{}) (err error) {
	if err = c.conn.SetWriteDeadline(c.writeDeadline); err != nil {
		return err
	}
	log.Printf("send(%v) %T", c.raddr(), msg)
	err = c.enc.Encode(msg)
	if err != nil {
		return fmt.Errorf("send(%v) %T: %w", c.raddr(), msg, err)
	}
	return nil
}
