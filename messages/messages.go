// Package messages implements the message types communicated between client and
// server.  The messaging in a successful run is sequenced as follows:
//
//   Client | Server
//      PR -->      Pair Request
//                  (wait for epoch)
//         <-- BR   Begin Run
//      KE -->      Key Exchange
//         <-- KEs  Server broadcasts all KE messages to all peers
//      SR -->      Slot Reserve
//         <-- RM   Recovered Messages
//      DC -->      DC-net broadcast
//         <-- CM   Confirm Messages (unsigned)
//      CM -->      Confirm Messages (signed)
//                  (server joins all signatures)
//         <-- CM   Confirm Messages (with all signatures)
//
// If a peer fails to find their message after either the exponential slot
// reservation or XOR DC-net, the DC or CM message indicates to the server that
// blame must be assigned to remove malicious peers from the mix.  This process
// requires secrets committed to by the KE to be revealed.
//
//   Client | Server
//      PR -->      Pair Request
//                  (wait for epoch)
//         <-- BR   Begin Run
//      KE -->      Key Exchange
//         <-- KEs  Server broadcasts all KE messages to all peers
//      SR -->      Slot Reserve
//         <-- RM   Recovered Messages
//      DC -->      DC-net broadcast (with RevealSecrets=true)
//         <-- CM   Confirm Messages (with RevealSecrets=true)
//      RS -->      Reveal Secrets
//                  (server discovers misbehaving peers)
//         <-- BR   Begin Run (with removed peers)
//         ...
//
// At any point, if the server times out receiving a client message, the
// following message contains a nonzero BR field, and a new run is performed,
// beginning with a new key exchange.
package messages

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"io"
	"math/big"
	"strconv"

	"decred.org/cspp/dcnet"
	"decred.org/cspp/x25519"
	"github.com/decred/dcrd/crypto/blake256"
	"golang.org/x/crypto/ed25519"
)

// ServerError describes an error message sent by the server.
// The peer cannot continue in the mix session if an error is received.
// The zero value indicates the absense of an error.
type ServerError int

// Server errors
const (
	ErrAbortedSession ServerError = iota + 1
	ErrInvalidUnmixed
)

func (e ServerError) Error() string {
	switch e {
	case 0:
		return "no error"
	case ErrAbortedSession:
		return "server aborted mix session"
	case ErrInvalidUnmixed:
		return "submitted unmixed data is invalid"
	default:
		return "unknown server error code " + strconv.Itoa(int(e))
	}
}

var (
	msgPR      = []byte("PR")
	msgSidH    = []byte("sidH")
	msgSidHPre = []byte("sidHPre")
	msgCommit  = []byte("COMMIT")
)

func putInt(scratch []byte, v int) []byte {
	binary.BigEndian.PutUint64(scratch, uint64(v))
	return scratch
}

func writeSignedByteSlice(w io.Writer, scratch []byte, data []byte) {
	w.Write(putInt(scratch, len(data)))
	w.Write(data)
}

// Signed indicates a session message carries an ed25519 signature that
// must be checked.
type Signed interface {
	VerifySignature(pub ed25519.PublicKey) bool
}

// Session describes a current mixing session and run.
type Session struct {
	sid     []byte
	vk      []ed25519.PublicKey
	run     int
	sidH    []byte
	sidHPre []byte
}

// NewSession creates a run session from a unique session identifier and peer
// ed25519 pubkeys ordered by peer index.
func NewSession(sid []byte, run int, vk []ed25519.PublicKey) *Session {
	runBytes := putInt(make([]byte, 8), run)

	h := blake256.New()
	h.Write(msgSidH)
	h.Write(sid)
	for _, k := range vk {
		if l := len(k); l != ed25519.PublicKeySize {
			panic("messages: bad ed25519 public key length: " + strconv.Itoa(l))
		}
		h.Write(k)
	}
	h.Write(runBytes)
	sidH := h.Sum(nil)

	h.Reset()
	h.Write(msgSidHPre)
	h.Write(sid)
	h.Write(runBytes)
	sidHPre := h.Sum(nil)

	return &Session{
		sid:     sid,
		vk:      vk,
		run:     run,
		sidH:    sidH,
		sidHPre: sidHPre,
	}
}

// BinaryRepresentable is a union of the BinaryMarshaler and BinaryUnmarshaler
// interfaces.
type BinaryRepresentable interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// PR is the client's pairing request message.
// It is only seen at the start of the protocol.
type PR struct {
	Identity       ed25519.PublicKey // Ephemeral session public key
	PairCommitment []byte            // Requirements for compatible mixes, e.g. same output amounts, tx versions, ...
	Unmixed        []byte            // Unmixed data contributed to a run result, e.g. transaction inputs and change outputs
	MessageCount   int               // Number of messages being mixed
	Signature      []byte
}

// PairRequest creates a signed request to be paired in a mix described by
// commitment, with possible initial unmixed data appearing in the final result.
// Ephemeral session keys pk and sk are used throughout the protocol.
func PairRequest(pk ed25519.PublicKey, sk ed25519.PrivateKey, commitment, unmixed []byte, mixes int) *PR {
	pr := &PR{
		Identity:       pk,
		PairCommitment: commitment,
		Unmixed:        unmixed,
		MessageCount:   mixes,
	}

	buf := new(bytes.Buffer)
	pr.WriteSigned(buf)
	pr.Signature = ed25519.Sign(sk, buf.Bytes())

	return pr
}

func (pr *PR) WriteSigned(w io.Writer) {
	scratch := make([]byte, 8)
	w.Write(msgPR)
	writeSignedByteSlice(w, scratch, pr.Identity)
	writeSignedByteSlice(w, scratch, pr.PairCommitment)
	writeSignedByteSlice(w, scratch, pr.Unmixed)
	w.Write(putInt(scratch, pr.MessageCount))
}

func (pr *PR) VerifySignature(pub ed25519.PublicKey) bool {
	if len(pr.Signature) != ed25519.SignatureSize {
		return false
	}
	buf := new(bytes.Buffer)
	pr.WriteSigned(buf)
	return ed25519.Verify(pub, buf.Bytes(), pr.Signature)
}

// BR is the begin run message.
// It is sent to all remaining valid peers when a new run begins.
type BR struct {
	Vk            []ed25519.PublicKey
	MessageCounts []int
	Sid           []byte
	Err           ServerError
}

// BeginRun creates the begin run message.
func BeginRun(vk []ed25519.PublicKey, mixes []int, sid []byte) *BR {
	return &BR{
		Vk:            vk,
		MessageCounts: mixes,
		Sid:           sid,
	}
}

func (br *BR) ServerError() error {
	if br.Err == 0 {
		return nil
	}
	return br.Err
}

// KE is the client's opening key exchange message of a run.
type KE struct {
	Run        int              // 0, 1, ...
	ECDH       []*x25519.Public // Public portions of x25519 key exchanges, one for each mixed message
	Commitment []byte           // Hash of RS (reveal secrets) message contents
}

// KeyExchange creates a signed key exchange message to verifiably provide the
// x25519 public portion.
func KeyExchange(ecdh []*x25519.Public, commitment []byte, ses *Session) *KE {
	return &KE{
		Run:        ses.run,
		ECDH:       ecdh,
		Commitment: commitment,
	}
}

// KEs is the server's broadcast of all received key exchange messages.
type KEs struct {
	KEs []*KE
	BR  // Indicates to begin new run after peer exclusion
	Err ServerError
}

func (kes *KEs) ServerError() error {
	if kes.Err == 0 {
		return nil
	}
	return kes.Err
}

// SR is the slot reservation broadcast.
type SR struct {
	Run   int
	DCMix [][]*big.Int
}

// SlotReserve creates a slot reservation message to discover random, anonymous
// slot assignments for an XOR DC-net by mixing random data in a exponential
// DC-mix.
func SlotReserve(dcmix [][]*big.Int, s *Session) *SR {
	return &SR{
		Run:   s.run,
		DCMix: dcmix,
	}
}

// RM is the recovered messages result of collecting all SR messages and solving for
// the mixed original messages.
type RM struct {
	Run           int
	Roots         []*big.Int
	RevealSecrets bool
	BR            // Indicates to begin new run after peer exclusion
	Err           ServerError
}

func (rm *RM) ServerError() error {
	if rm.Err == 0 {
		return nil
	}
	return rm.Err
}

// RecoveredMessages creates a recovered messages message.
func RecoveredMessages(roots []*big.Int, s *Session) *RM {
	return &RM{
		Run:   s.run,
		Roots: roots,
	}
}

// DC is the DC-net broadcast.
type DC struct {
	Run           int
	DCNet         []*dcnet.Vec
	RevealSecrets bool
}

// DCNet creates a message containing the previously-committed DC-mix vector and
// the shared keys of peers we have chosen to exclude.
func DCNet(dcs []*dcnet.Vec, s *Session) *DC {
	return &DC{
		Run:   s.run,
		DCNet: dcs,
	}
}

// CM is the confirmed mix message.
type CM struct {
	Mix           BinaryRepresentable
	RevealSecrets bool
	BR            // Indicates to begin new run after peer exclusion
	Err           ServerError
}

func (cm *CM) ServerError() error {
	if cm.Err == 0 {
		return nil
	}
	return cm.Err
}

// ConfirmedMix creates the confirmed mix message, sending either the confirmed
// mix or indication of a confirmation failure to the server.
func ConfirmMix(mix BinaryRepresentable) *CM {
	return &CM{Mix: mix}
}

// RS is the reveal secrets message.  It reveals x25519, SR and DC secrets at
// the end of a failed run for blame assignment and misbehaving peer removal.
type RS struct {
	ECDH []*x25519.Scalar
	SR   []*big.Int
	M    [][]byte
}

// RevealSecrets creates the reveal secrets message.
func RevealSecrets(ecdh []*x25519.KX, sr []*big.Int, m [][]byte) *RS {
	rs := &RS{
		ECDH: make([]*x25519.Scalar, len(ecdh)),
		SR:   sr,
		M:    m,
	}

	for i := range ecdh {
		rs.ECDH[i] = &ecdh[i].Scalar
	}

	return rs
}

// Commit commits to the contents of the reveal secrets message.
func (rs *RS) Commit(ses *Session) []byte {
	scratch := make([]byte, 4)
	h := blake256.New()
	h.Write(msgCommit)
	h.Write(ses.sid)
	binary.LittleEndian.PutUint32(scratch, uint32(ses.run))
	h.Write(scratch)
	for i := range rs.ECDH {
		h.Write(rs.ECDH[i][:])
	}
	for i := range rs.SR {
		h.Write(rs.SR[i].Bytes())
	}
	for i := range rs.M {
		h.Write(rs.M[i])
	}
	return h.Sum(nil)
}
