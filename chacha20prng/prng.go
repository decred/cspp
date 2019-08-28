package chacha20prng

import (
	"encoding/binary"
	"strconv"

	"decred.org/cspp/internal/chacha20" // Copy of golang.org/x/crypto/internal/chacha20
)

// SeedSize is the required length of seeds for New.
const SeedSize = 32

// Reader is a ChaCha20 PRNG for a DC-net run.  It implements io.Reader.
type Reader struct {
	cipher *chacha20.Cipher
}

// New creates a ChaCha20 PRNG seeded by a 32-byte key and a run iteration.  The
// returned reader is not safe for concurrent access.  This will panic if the
// length of seed is not SeedSize bytes.
func New(seed []byte, run uint32) *Reader {
	if l := len(seed); l != SeedSize {
		panic("chacha20prng: bad seed length " + strconv.Itoa(l))
	}

	var key = [8]uint32{
		binary.LittleEndian.Uint32(seed[0:4]),
		binary.LittleEndian.Uint32(seed[4:8]),
		binary.LittleEndian.Uint32(seed[8:12]),
		binary.LittleEndian.Uint32(seed[12:16]),
		binary.LittleEndian.Uint32(seed[16:20]),
		binary.LittleEndian.Uint32(seed[20:24]),
		binary.LittleEndian.Uint32(seed[24:28]),
		binary.LittleEndian.Uint32(seed[28:32]),
	}
	var nonce = [3]uint32{0: run}
	cipher := chacha20.New(key, nonce)
	return &Reader{cipher: cipher}
}

// Read implements io.Reader.
func (r *Reader) Read(b []byte) (int, error) {
	// Zero the source such that the destination is written with just the
	// keystream.  Destination and source are allowed to overlap (exactly).
	for i := range b {
		b[i] = 0
	}
	r.cipher.XORKeyStream(b, b)
	return len(b), nil
}

// Next returns the next n bytes from the reader.
func (r *Reader) Next(n int) []byte {
	b := make([]byte, n)
	r.cipher.XORKeyStream(b, b)
	return b
}
