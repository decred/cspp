package dcnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"decred.org/cspp/chacha20prng"
	"decred.org/cspp/x25519"
	"github.com/decred/dcrd/crypto/blake256"
)

// SRMixPads creates a vector of exponential DC-net pads from a vector of
// shared secrets with each participating peer in the DC-net.
func SRMixPads(kp [][]byte, my int) []*big.Int {
	h := blake256.New()
	scratch := make([]byte, 8)

	pads := make([]*big.Int, len(kp))
	partialPad := new(big.Int)
	for j := 0; j < len(kp); j++ {
		pads[j] = new(big.Int)
		for i := 0; i < len(kp); i++ {
			if my == i {
				continue
			}
			binary.LittleEndian.PutUint64(scratch, uint64(j)+1)
			h.Reset()
			h.Write(kp[i])
			h.Write(scratch)
			digest := h.Sum(nil)
			partialPad.SetBytes(digest)
			if my > i {
				pads[j].Add(pads[j], partialPad)
			} else {
				pads[j].Sub(pads[j], partialPad)
			}
		}
		pads[j].Mod(pads[j], F)
	}
	return pads
}

// SRMix creates the padded {m**1, m**2, ..., m**n} message exponentials
// vector.  Message must be bounded by the field prime and must be unique to
// every exponential SR run in a mix session to ensure anonymity.
func SRMix(m *big.Int, pads []*big.Int) []*big.Int {
	mix := make([]*big.Int, len(pads))
	exp := new(big.Int)
	for i := int64(0); i < int64(len(mix)); i++ {
		mexp := new(big.Int).Exp(m, exp.SetInt64(i+1), nil)
		mix[i] = mexp.Add(mexp, pads[i])
		mix[i].Mod(mix[i], F)
	}
	return mix
}

// AddVectors sums each vector element over F, returning a new vector.  When
// peers are honest (DC-mix pads sum to zero) this creates the unpadded vector
// of message power sums.
func AddVectors(vs ...[]*big.Int) []*big.Int {
	sums := make([]*big.Int, len(vs))
	for i := range sums {
		sums[i] = new(big.Int)
		for j := range vs {
			sums[i].Add(sums[i], vs[j][i])
		}
		sums[i].Mod(sums[i], F)
	}
	return sums
}

// Coefficients calculates a{0}..a{n} for the polynomial:
//   g(x) = a{0} + a{1}x + a{2}x**2 + ... + a{n-1}x**(n-1) + a{n}x**n  (mod F)
// where
//   a{n}   = -1
//   a{n-1} = -(1/1) *    a{n}*S{0}
//   a{n-2} = -(1/2) * (a{n-1}*S{0} +   a{n}*S{1})
//   a{n-3} = -(1/3) * (a{n-2}*S{0} + a{n-1}*S{1} + a{n}*S{2})
//   ...
//
// The roots of this polynomial are the set of recovered messages.
//
// Note that the returned slice of coefficients is one element larger than the
// slice of partial sums.
func Coefficients(S []*big.Int) []*big.Int {
	n := len(S) + 1
	a := make([]*big.Int, n)
	a[len(a)-1] = big.NewInt(-1)
	a[len(a)-1].Add(a[len(a)-1], F) // a{n} = -1 (mod F) = F - 1
	scratch := new(big.Int)
	for i := 0; i < len(a)-1; i++ {
		a[n-2-i] = new(big.Int)
		for j := 0; j <= i; j++ {
			a[n-2-i].Add(a[n-2-i], scratch.Mul(a[n-1-i+j], S[j]))
		}
		xinv := scratch.ModInverse(scratch.SetInt64(int64(i)+1), F)
		xinv.Neg(xinv)
		a[n-2-i].Mul(a[n-2-i], xinv)
		a[n-2-i].Mod(a[n-2-i], F)
	}
	return a
}

// IsRoot checks that the message m is a root of the polynomial with
// coefficients a (mod F) without solving for every root.
func IsRoot(m *big.Int, a []*big.Int) bool {
	sum := new(big.Int)
	scratch := new(big.Int)
	for i := range a {
		scratch.Exp(m, scratch.SetInt64(int64(i)), F)
		scratch.Mul(scratch, a[i])
		sum.Add(sum, scratch)
	}
	sum.Mod(sum, F)
	return sum.Sign() == 0
}

// Vec is a N-element vector of Msize []byte messages.
type Vec struct {
	N     int
	Msize int
	Data  []byte
}

// NewVec returns a zero vector for holding n messages of msize length.
func NewVec(n, msize int) *Vec {
	return &Vec{
		N:     n,
		Msize: msize,
		Data:  make([]byte, n*msize),
	}
}

// IsDim returns whether the Vec has dimensions n-by-msize.
func (v *Vec) IsDim(n, msize int) bool {
	return v.N == n && v.Msize == msize && len(v.Data) == n*msize
}

// Equals returns whether the two vectors have equal dimensions and data.
func (v *Vec) Equals(other *Vec) bool {
	return other.IsDim(v.N, v.Msize) && bytes.Equal(other.Data, v.Data)
}

// M returns the i'th message of the vector.
func (v *Vec) M(i int) []byte {
	return v.Data[i*v.Msize : i*v.Msize+v.Msize]
}

func (v *Vec) String() string {
	b := new(strings.Builder)
	b.Grow(2 + v.N*(2*v.Msize+1))
	b.WriteString("[")
	for i := 0; i < v.N; i++ {
		if i != 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(b, "%x", v.M(i))
	}
	b.WriteString("]")
	return b.String()
}

// SharedKeys creates the SR and DC shared secret keys for mcount mixes, where
// indexes [start, start+mcount) are a peer's pre-assigned non-anonymous
// positions.
func SharedKeys(secrets []*x25519.KX, publics []*x25519.Public, sid []byte, msize, run, start, mcount int) (sr [][][]byte, dc [][]*Vec, err error) {
	sr = make([][][]byte, mcount)
	dc = make([][]*Vec, mcount)
	mtot := len(publics)
	for i := 0; i < mcount; i++ {
		my := start + i
		sr[i] = make([][]byte, mtot)
		dc[i] = make([]*Vec, mtot)
		for from, pub := range publics {
			if from == my {
				continue
			}
			var sharedKey []byte
			sharedKey, err = secrets[i].SharedKey(pub)
			if err != nil {
				return
			}
			h := blake256.New()
			h.Write(sid)
			h.Write(sharedKey)
			prngSeed := h.Sum(nil)
			prng := chacha20prng.New(prngSeed, uint32(run))

			sr[i][from] = prng.Next(32)
			dc[i][from] = &Vec{
				N:     mtot,
				Msize: msize,
				Data:  prng.Next(mtot * msize),
			}
		}
	}
	return
}

// DCMixPads creates the vector of DC-net pads from shared secrets with each mix
// participant.
func DCMixPads(kp []*Vec, msize, my int) *Vec {
	n := len(kp)
	pads := &Vec{
		N:     n,
		Msize: msize,
		Data:  make([]byte, n*msize),
	}
	for i := range kp {
		if i == my {
			continue
		}
		pads.Xor(pads, kp[i])
	}
	return pads
}

// DCMix creates the DC-net vector of message m xor'd into m's reserved
// anonymous slot position of the pads DC-net pads.  Panics if len(m) is not the
// vector's message size.
func DCMix(pads *Vec, m []byte, slot int) *Vec {
	dcmix := *pads
	dcmix.Data = make([]byte, len(pads.Data))
	copy(dcmix.Data, pads.Data)
	slotm := dcmix.M(slot)
	if len(m) != len(slotm) {
		panic("message sizes are not equal")
	}
	for i := range m {
		slotm[i] ^= m[i]
	}
	return &dcmix
}

// Xor writes the xor of each vector element of src1 and src2 into v.
// Source and destination vectors are allowed to be equal.
// Panics if vectors do not share identical dimensions.
func (v *Vec) Xor(src1, src2 *Vec) {
	switch {
	case v.N != src1.N, v.Msize != src1.Msize, len(v.Data) != len(src1.Data):
		fallthrough
	case v.N != src2.N, v.Msize != src2.Msize, len(v.Data) != len(src2.Data):
		panic("dcnet: vectors do not share identical dimensions")
	}
	for i := range v.Data {
		v.Data[i] = src1.Data[i] ^ src2.Data[i]
	}
}

// XorVectors calculates the xor of all vectors.
// Panics if vectors do not share identical dimensions.
func XorVectors(vs []*Vec) *Vec {
	msize := vs[0].Msize
	res := NewVec(len(vs), msize)
	for _, v := range vs {
		res.Xor(res, v)
	}
	return res
}
