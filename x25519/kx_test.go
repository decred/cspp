package x25519

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKX(t *testing.T) {
	r := rand.Reader
	kx0, err := New(r)
	if err != nil {
		t.Fatal(err)
	}
	kx1, err := New(r)
	if err != nil {
		t.Fatal(err)
	}
	shared0, err := kx0.SharedKey(&kx1.Public)
	if err != nil {
		t.Fatal(err)
	}
	shared1, err := kx1.SharedKey(&kx0.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared0, shared1) {
		t.Fatal("non-agreement on shared key")
	}
}
