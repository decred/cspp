// Package server implements a DiceMix Light server for CoinShuffle++.
package server

import (
	"bytes"
	"compress/flate"
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

	"decred.org/cspp/chacha20prng"
	"decred.org/cspp/dcnet"
	"decred.org/cspp/messages"
	"decred.org/cspp/solver"
	"decred.org/cspp/x25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/sync/errgroup"
)

const (
	pairTimeout = 24 * time.Hour
	sendTimeout = time.Second
	recvTimeout = 5 * time.Second
	minPeers    = 3
)

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
	ValidateUnmixed(unmixed []byte) error
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
	pairings   map[string][]*client
	pairingsMu sync.Mutex

	report *json.Encoder
}

type runState struct {
	keCount   uint32
	srCount   uint32
	dcCount   uint32
	confCount uint32
	rsCount   uint32

	run      int
	mtot     int
	clients  []*client
	excluded []*client
	vk       []ed25519.PublicKey
	mcounts  []int
	roots    []*big.Int

	allKEs   chan struct{}
	allSRs   chan struct{}
	allDCs   chan struct{}
	allConfs chan struct{}
	allRSs   chan struct{}

	blaming   chan struct{}
	rerunning chan struct{}
}

type session struct {
	runState

	sid    []byte
	msgses *messages.Session
	br     *messages.BR
	msize  int
	newm   func() (Mixer, error)
	mix    Mixer

	pids map[string]int
	mu   sync.Mutex

	report *json.Encoder
}

type client struct {
	conn   net.Conn
	zw     *flate.Writer
	dec    *gob.Decoder // decodes from conn
	enc    *gob.Encoder // encodes to conn
	sesc   chan *session
	pr     *messages.PR
	ke     *messages.KE
	sr     *messages.SR
	dc     *messages.DC
	cm     *messages.CM
	rs     *messages.RS
	mix    Mixer
	out    chan interface{}
	blamed chan struct{}
	done   chan struct{}
	cancel func()
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
		pairings: make(map[string][]*client),
	}
	return s, nil
}

func (s *Server) SetReportEncoder(enc *json.Encoder) {
	s.report = enc
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
	zr := flate.NewReader(conn)
	zw, _ := flate.NewWriter(conn, flate.DefaultCompression)
	dec := gob.NewDecoder(zr)
	enc := gob.NewEncoder(zw)
	pr := new(messages.PR)
	if err := conn.SetReadDeadline(time.Now().Add(recvTimeout)); err != nil {
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
	log.Printf("recv(%v) PR Identity:%x PairCommitment:%x MessageCount:%d Unmixed:%x",
		conn.RemoteAddr(), pr.Identity, pr.PairCommitment, pr.MessageCount, pr.Unmixed)
	mix, err := s.newm(pr.PairCommitment)
	if err != nil {
		return fmt.Errorf("unable to begin mix: %v", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := &client{
		conn:   conn,
		zw:     zw,
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
		err = j.ValidateUnmixed(pr.Unmixed)
		if err != nil {
			c.sendDeadline(invalidUnmixed, sendTimeout)
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
	go c.read(ke, readErr)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-readErr:
		if err == nil {
			return fmt.Errorf("%v: read message before run started", c.conn.RemoteAddr())
		}
		return err
	case ses = <-c.sesc:
		err := c.sendDeadline(ses.br, sendTimeout)
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
		if err == errRerun {
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
			if len(clients) < minPeers {
				continue
			}

			pairCommitment := []byte(commitment)
			newm := func() (Mixer, error) {
				return s.newm(pairCommitment)
			}
			mix, err := newm()
			if err != nil {
				log.Printf("failed to create mix object: %v", err)
				continue
			}

			delete(s.pairings, commitment)

			sort.Slice(clients, func(i, j int) bool {
				id1 := clients[i].pr.Identity[:]
				id2 := clients[j].pr.Identity[:]
				return bytes.Compare(id1, id2) < 0
			})
			vk := make([]ed25519.PublicKey, len(clients))
			mcounts := make([]int, len(clients))
			pids := make(map[string]int)
			totalMessages := 0
			for i := range clients {
				vk[i] = clients[i].pr.Identity
				pids[string(vk[i])] = i
				mcounts[i] = clients[i].pr.MessageCount
				totalMessages += clients[i].pr.MessageCount
			}
			sid := s.sidPRNG.Next(32)
			ses := &session{
				runState: runState{
					allKEs:    make(chan struct{}),
					allSRs:    make(chan struct{}),
					allDCs:    make(chan struct{}),
					allConfs:  make(chan struct{}),
					allRSs:    make(chan struct{}),
					mtot:      totalMessages,
					clients:   clients,
					vk:        vk,
					mcounts:   mcounts,
					blaming:   make(chan struct{}),
					rerunning: make(chan struct{}),
				},
				sid:    sid,
				msgses: messages.NewSession(sid, 0, vk),
				br:     messages.BeginRun(vk, mcounts, sid),
				msize:  s.msize,
				newm:   newm,
				mix:    mix,
				pids:   pids,
				report: s.report,
			}
			pairs = append(pairs, ses)
		}
		s.pairingsMu.Unlock()

		for _, ses := range pairs {
			ses.start(ctx, &wg)
		}
	}
}

func (s *session) start(ctx context.Context, wg *sync.WaitGroup) {
	for _, c := range s.clients {
		log.Printf("peer %x paired with session %x", c.pr.Identity, s.sid)
		c.sesc <- s
	}
	run := func(i int) error {
		defer trace.StartRegion(ctx, "run").End()
		err := s.doRun(ctx)
		log.Printf("session %x run %d ended: %v", s.sid, i, err)
		return err
	}
	wg.Add(1)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered: %v", r)
			debug.PrintStack()
		}
		for _, c := range s.clients {
			c.cancel()
		}
		wg.Done()
	}()
	for i := 0; ; i++ {
		err := run(i)
		if b, ok := err.(blamer); ok {
			err = s.exclude(b.Blame())
			if err != nil {
				log.Printf("cannot continue after exclusion: %v", err)
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

// exclude removes blamed peers from the session so the next run can proceed.
// BRs are written to each remaining client's out channel to be sent by the handler.
func (s *session) exclude(blamed []int) error {
	defer s.mu.Unlock()
	s.mu.Lock()

	close(s.rerunning)
	s.run++

	log.Printf("excluding %v", blamed)
	for _, pid := range blamed {
		log.Printf("excluding %v\n", s.clients[pid].raddr())
		close(s.clients[pid].blamed)
		s.excluded = append(s.excluded, s.clients[pid])
		s.clients[pid].cancel()
		s.mtot -= s.clients[pid].pr.MessageCount
		s.clients[pid] = nil
	}
	clients := s.clients[:0]
	for _, c := range s.clients {
		if c != nil {
			clients = append(clients, c)
		}
	}
	s.clients = clients
	if len(s.clients) < minPeers {
		return fmt.Errorf("too few peers (%v) to continue session", len(s.clients))
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

	s.keCount = 0
	s.srCount = 0
	s.dcCount = 0
	s.confCount = 0
	s.rsCount = 0
	s.allKEs = make(chan struct{})
	s.allSRs = make(chan struct{})
	s.allDCs = make(chan struct{})
	s.allConfs = make(chan struct{})
	s.allRSs = make(chan struct{})
	s.roots = nil
	s.msgses = messages.NewSession(s.sid, s.run, s.vk)
	s.br = messages.BeginRun(s.vk, s.mcounts, s.sid)
	s.mix = mix
	s.blaming = make(chan struct{})
	s.rerunning = make(chan struct{})

	for _, c := range s.clients {
		select {
		case c.out <- s.br:
		case <-c.done:
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
		log.Printf("cannot write mix report: %v", err)
	}
}

func (s *session) abortSession(err error) {
	defer s.mu.Unlock()
	s.mu.Lock()

	log.Printf("aborting session %x with failed blame assignment: %v", s.sid, err)

	for _, c := range s.clients {
		c.sendDeadline(abortedSession, 500*time.Millisecond)
	}
}

func (s *session) doRun(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			return
		}
		s.reportCompletedMix()
	}()

	var timedOut blamePIDs

	// Wait for all KE messages, or KE timeout.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.allKEs:
		log.Print("received all KE messages")
	case <-time.After(recvTimeout):
		log.Print("KE timeout")
	}

	// Broadcast received KEs to each unexcluded peer.
	s.mu.Lock()
	kes := &messages.KEs{
		KEs: make([]*messages.KE, 0, len(s.clients)),
	}
	for i, c := range s.clients {
		if c.ke == nil {
			timedOut = append(timedOut, i)
			continue
		}
		kes.KEs = append(kes.KEs, c.ke)
		if joiner, ok := s.mix.(Joiner); ok {
			err := joiner.Join(c.pr.Unmixed, i)
			if err != nil {
				s.mu.Unlock()
				return err
			}
		} else if len(c.pr.Unmixed) != 0 {
			s.mu.Unlock()
			return fmt.Errorf("%T cannot join unmixed data", s.mix)
		}
	}
	if len(timedOut) != 0 {
		s.mu.Unlock()
		return timedOut
	}
	for _, c := range s.clients {
		select {
		case c.out <- kes:
		case <-c.done:
		}
	}
	s.mu.Unlock()

	// Wait for all SR messages, or SR timeout.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.allSRs:
		log.Print("received all SR messages")
	case <-time.After(recvTimeout):
		log.Print("SR timeout")
	}

	// Solve roots.
	s.mu.Lock()
	blaming := s.blaming
	vs := make([][]*big.Int, 0, len(s.clients))
	for i, c := range s.clients {
		if c.sr == nil {
			timedOut = append(timedOut, i)
			continue
		}
		vs = append(vs, c.sr.DCMix...)
	}
	if len(timedOut) != 0 {
		s.mu.Unlock()
		return timedOut
	}
	powerSums := dcnet.AddVectors(vs...)
	coeffs := dcnet.Coefficients(powerSums)
	t := time.Now()
	roots, err := solver.Roots(coeffs, dcnet.F)
	if err != nil {
		close(blaming)
		s.mu.Unlock()
		return s.blame(ctx, nil)
	}
	log.Printf("solved roots in %v", time.Since(t))
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Cmp(roots[j]) == -1
	})
	log.Printf("roots: %x", roots)
	rm := messages.RecoveredMessages(roots, s.msgses)
	for _, c := range s.clients {
		select {
		case c.out <- rm:
		case <-c.done:
		}
	}
	s.mu.Unlock()
	s.roots = roots

	// Wait for all DC messages, or DC timeout.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.allDCs:
		log.Print("received all DC messages")
	case <-time.After(recvTimeout):
		log.Print("DC timeout")
	}

	s.mu.Lock()
	var reportedFailure []int
	dcVecs := make([]*dcnet.Vec, 0, s.mtot)
	for i, c := range s.clients {
		if c.dc == nil {
			timedOut = append(timedOut, i)
			continue
		}
		if c.dc.RevealSecrets {
			reportedFailure = append(reportedFailure, i)
		}
		dcVecs = append(dcVecs, c.dc.DCNet...)
	}
	s.mu.Unlock()
	if len(timedOut) != 0 {
		return timedOut
	}
	if len(reportedFailure) > 0 {
		close(blaming)
		return s.blame(ctx, reportedFailure)
	}
	res := dcnet.XorVectors(dcVecs)
	log.Printf("recovered message set %v", res)

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
	log.Printf("unsigned mix: %x\n", finishedMix)

	// Broadcast mix to each unexcluded peer.
	cm := messages.ConfirmMix(s.mix)
	s.mu.Lock()
	for _, c := range s.clients {
		select {
		case c.out <- cm:
		case <-c.done:
		}
	}
	s.mu.Unlock()

	// Wait for all confirmations, or confirmation timeout.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.allConfs:
		log.Print("received all CM messages")
	case <-time.After(recvTimeout):
		log.Print("CM timeout")
	}

	s.mu.Lock()
	for i, c := range s.clients {
		if c.cm == nil {
			timedOut = append(timedOut, i)
			continue
		}
		if c.cm.RevealSecrets {
			reportedFailure = append(reportedFailure, i)
		}
	}
	if len(timedOut) != 0 {
		s.mu.Unlock()
		return timedOut
	}
	if len(reportedFailure) > 0 {
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
	log.Printf("signed mix: %x\n", signedMix)

	// Broadcast signed mix to each peer.
	cm = messages.ConfirmMix(s.mix)
	s.mu.Lock()
	for _, c := range s.clients {
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

	if ke != nil && run != 0 {
		panic("ke parameter must be nil on reruns")
	}
	if ke == nil {
		ke = new(messages.KE)
		err := c.readDeadline(ke, recvTimeout)
		if err != nil {
			return fmt.Errorf("read KE: %v", err)
		}
	}
	if len(ke.ECDH) == 0 {
		return fmt.Errorf("invalid KE: missing ECDH")
	}
	if len(ke.Commitment) != 32 {
		return fmt.Errorf("invalid KE: commitment not 32 bytes")
	}

	log.Printf("recv(%v) KE Run:%d Commitment:%x", c.raddr(), ke.Run, ke.Commitment)

	s.mu.Lock()
	c.ke = ke
	s.keCount++
	if s.keCount == uint32(len(s.clients)) {
		close(s.allKEs)
	}
	blaming := s.blaming
	rerunning := s.rerunning
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-blaming:
		err := c.sendDeadline(revealSecrets, sendTimeout)
		if err != nil {
			return err
		}
		return c.blame(ctx, s)
	case kes := <-c.out:
		err := c.sendDeadline(kes, sendTimeout)
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
	err := c.readDeadline(sr, recvTimeout)
	if err != nil {
		return fmt.Errorf("read SR: %v", err)
	}

	log.Printf("recv(%v) SR Run:%d DCMix:%x", c.raddr(), sr.Run, sr.DCMix)

	if len(sr.DCMix) != c.pr.MessageCount {
		return fmt.Errorf("invalid SR")
	}

	s.mu.Lock()
	mtotal := s.mtot
	for i := range sr.DCMix {
		if len(sr.DCMix[i]) != mtotal {
			s.mu.Unlock()
			return fmt.Errorf("invalid SR")
		}
	}
	c.sr = sr
	s.srCount++
	if s.srCount == uint32(len(s.clients)) {
		close(s.allSRs)
	}
	blaming = s.blaming
	rerunning = s.rerunning
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-blaming:
		err := c.sendDeadline(revealSecrets, sendTimeout)
		if err != nil {
			return err
		}
		return c.blame(ctx, s)
	case mix := <-c.out:
		err = c.sendDeadline(mix, sendTimeout)
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
	err = c.readDeadline(dc, recvTimeout)
	if err != nil {
		return fmt.Errorf("read DC: %v", err)
	}

	log.Printf("recv(%v) DC Run:%d DCNet:%v", c.raddr(), dc.Run, dc.DCNet)

	if len(dc.DCNet) != c.pr.MessageCount {
		return fmt.Errorf("invalid DC")
	}
	for _, vec := range dc.DCNet {
		if !vec.IsDim(mtotal, s.msize) {
			return fmt.Errorf("bad dc-net dimensions")
		}
	}

	s.mu.Lock()
	c.dc = dc
	s.dcCount++
	if s.dcCount == uint32(len(s.clients)) {
		close(s.allDCs)
	}
	mix := c.mix
	blaming = s.blaming
	rerunning = s.rerunning
	s.mu.Unlock()

	if dc.RevealSecrets {
		return c.blame(ctx, s)
	}

	// Send unconfirmed mix
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-blaming:
		err := c.sendDeadline(revealSecrets, sendTimeout)
		if err != nil {
			return err
		}
		return c.blame(ctx, s)
	case mix := <-c.out:
		err = c.sendDeadline(mix, sendTimeout)
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
	err = c.readDeadline(cm, recvTimeout)
	if err != nil {
		return err
	}

	log.Printf("recv(%v) CM RevealSecrets:%v", c.raddr(), cm.RevealSecrets)

	s.mu.Lock()
	c.cm = cm
	c.mix = mix
	s.confCount++
	if s.confCount == uint32(len(s.clients)) {
		close(s.allConfs)
	}
	blaming = s.blaming
	rerunning = s.rerunning
	s.mu.Unlock()

	if cm.RevealSecrets {
		return c.blame(ctx, s)
	}

	// Send signed mix
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-blaming:
		err := c.sendDeadline(revealSecrets, sendTimeout)
		if err != nil {
			return err
		}
		return c.blame(ctx, s)
	case out := <-c.out:
		err = c.sendDeadline(out, sendTimeout)
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
	// ECDH
	kx []*x25519.KX

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
			log.Printf("blamed peers %v", []int(blamed))
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
				log.Printf("blaming %v for false failure accusation", s.clients[pid].raddr())
				blamed = append(blamed, pid)
			}
			err = blamed
		}()
	}

	// Wait for all secrets, or timeout.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.allRSs:
		log.Print("received all RS messages")
	case <-time.After(5000 * time.Millisecond):
		s.mu.Lock()
		for i, c := range s.clients {
			if c.rs == nil {
				log.Printf("blaming %v for RS timeout", c.raddr())
				blamed = append(blamed, i)
			}
		}
		s.mu.Unlock()
		return blamed
	}

	defer s.mu.Unlock()
	s.mu.Lock()

	b := make([]blame, len(s.clients))
	starts := make([]int, 0, len(s.clients))
	ecdh := make([]*x25519.Public, 0, s.mtot)
KELoop:
	for i, c := range s.clients {
		if c.ke == nil {
			log.Printf("blaming %v for missing messages", c.raddr())
			blamed = append(blamed, i)
			continue
		}

		// Blame when revealed secrets do not match prior commitment to the secrets.
		if cm := c.rs.Commit(s.msgses); !bytes.Equal(cm, c.ke.Commitment) {
			log.Printf("blaming %v for false commitment", c.raddr())
			blamed = append(blamed, i)
			continue
		}

		// Blame peers with SR messages outside of the field.
		for _, m := range c.rs.SR {
			if !dcnet.InField(m) {
				log.Printf("blaming %v for SR message outside field", c.raddr())
				blamed = append(blamed, i)
				continue KELoop
			}
		}

		starts = append(starts, len(ecdh))
		ecdh = append(ecdh, c.ke.ECDH...)
		mcount := c.pr.MessageCount
		if len(c.rs.ECDH) != mcount {
			log.Printf("blaming %v for bad ECDH count", c.raddr())
			blamed = append(blamed, i)
			continue
		}
		b[i].kx = make([]*x25519.KX, 0, s.mtot)
		for j := range c.rs.ECDH {
			b[i].kx = append(b[i].kx, &x25519.KX{
				Public: *c.ke.ECDH[j],
				Scalar: *c.rs.ECDH[j],
			})
		}
		if len(c.rs.SR) != mcount || len(c.rs.M) != mcount {
			log.Printf("blaming %v for bad message count", c.raddr())
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
				log.Printf("blaming %v for shared SR message", s.clients[i].raddr())
			}
			blamed = append(blamed, pids...)
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

SRLoop:
	for i, c := range s.clients {
		// Recover shared secrets
		b[i].srKP, b[i].dcKP = dcnet.SharedKeys(b[i].kx, ecdh, s.sid, s.msize,
			s.run, starts[i], c.pr.MessageCount)

		for j, m := range b[i].srMsg {
			// Recover SR pads and mix with committed messages
			pads := dcnet.SRMixPads(b[i].srKP[j], starts[i]+j)
			srMix := dcnet.SRMix(m, pads)

			// Blame when committed mix does not match provided.
			for k := range srMix {
				if srMix[k].Cmp(c.sr.DCMix[j][k]) != 0 {
					log.Printf("blaming %v for bad SR mix", c.raddr())
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
			log.Printf("blaming %v for missing DC mix vectors", c.raddr())
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
					log.Printf("blaming %v for bad DC mix", c.raddr())
					blamed = append(blamed, i)
					continue DCLoop
				}
			}
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

	return nil
}

var errRerun = errors.New("rerun")

func (c *client) blame(ctx context.Context, s *session) error {
	rs := new(messages.RS)
	err := c.readDeadline(rs, recvTimeout)
	if err != nil {
		return err
	}

	s.mu.Lock()
	c.rs = rs
	s.rsCount++
	if s.rsCount == uint32(len(s.clients)) {
		close(s.allRSs)
	}
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case msg := <-c.out:
		err := c.sendDeadline(msg, sendTimeout)
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

// read reads a value from the gob decoder, without timeout, writing the error
// result to ch.
func (c *client) read(out interface{}, ch chan error) {
	if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
		ch <- err
		return
	}
	ch <- c.dec.Decode(out)
}

// readDeadline reads a value from the decoder with a relative timeout.
func (c *client) readDeadline(out interface{}, deadline time.Duration) (err error) {
	defer func() {
		if err != nil {
			_, file, line, _ := runtime.Caller(2)
			file = filepath.Base(file)
			log.Printf("read %T at caller %v:%v failed: %v", out, file, line, err)
		}
	}()
	log.Printf("awaiting(%v) %T", c.raddr(), out)
	if err = c.conn.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		return err
	}
	return c.dec.Decode(out)
}

// sendDeadline writes msg to the gob stream with a relative timeout.
func (c *client) sendDeadline(msg interface{}, deadline time.Duration) (err error) {
	if err = c.conn.SetWriteDeadline(time.Now().Add(deadline)); err != nil {
		return err
	}
	log.Printf("send(%v) %T", c.raddr(), msg)
	err = c.enc.Encode(msg)
	if err != nil {
		return err
	}
	return c.zw.Flush()
}
