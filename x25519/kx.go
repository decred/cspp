// Package x25519 implements ECDHE over curve25519.
package x25519

import (
	"io"

	"golang.org/x/crypto/curve25519"
)

type Public [32]byte
type Scalar [32]byte

// KX is the client-generated public and secret portions of a key exchange.
type KX struct {
	Public
	Scalar // secret
}

// New begins a new key exchange by generating a public and secret value.
// Public portions must be exchanged between parties to derive a shared secret
// key.
func New(rand io.Reader) (*KX, error) {
	kx := new(KX)
	_, err := rand.Read(kx.Scalar[:])
	if err != nil {
		return nil, err
	}

	// https://cr.yp.to/ecdh.html; Computing secret keys.
	kx.Scalar[0] &= 248
	kx.Scalar[31] &= 127
	kx.Scalar[31] |= 64

	curve25519.ScalarBaseMult((*[32]byte)(&kx.Public), (*[32]byte)(&kx.Scalar))
	return kx, nil
}

// SharedKey computes a shared key with the other party from our secret value
// and their public value.  The result should be securely hashed before usage.
func (kx *KX) SharedKey(theirPublic *Public) []byte {
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, (*[32]byte)(&kx.Scalar), (*[32]byte)(theirPublic))
	return sharedKey[:]
}
