package dcnet

import (
	// "bytes"
	// "crypto/rand"
	"flag"
	"os"
	"testing"
	// "decred.org/cspp/chacha20prng"
)

var nFlag = flag.Int64("n", 3, "node count")

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

type SRNode struct {
	ID         int64    // Node index (zero-based) for a particular run, must be < Total
	Total      int64    // Count of unexcluded nodes, including self
	SK         []byte   // Our session signing private key
	PK         [][]byte // PK[i] is peer i's session pubkey, PK[ID] is unused
	M          []byte   // Message to mix, must be less than F. TODO: remove me
	Kp         [][]byte // Kp[i] is shared key with i'th node, Kp[ID] is unused
	SharedKeys []*Vec
}

/*
func TestSRMix(t *testing.T) {
	t.Logf("F: %x", F)

	// Generate nodes with random 20-byte messages (e.g. pubkey hashes).
	n := make([]SRNode, *nFlag)
	for i := range n {
		n[i].ID = int64(i)
		n[i].Total = *nFlag
		n[i].M = make([]byte, 20)
		_, err := rand.Read(n[i].M)
		if err != nil {
			t.Fatal(err)
		}
		n[i].Kp = make([][]byte, *nFlag)

		t.Logf("n[%d].M = %x", i, n[i].M)
	}

	// Key exchange such that n[i].Kp[j] == n[j].Kp[i].  A real run would
	// use x25519.
	for i := range n {
		for j := range n {
			if i == j {
				continue
			}
			if n[j].Kp[i] != nil {
				n[i].Kp[j] = n[j].Kp[i]
			} else {
				n[i].Kp[j] = make([]byte, 32)
				_, err := rand.Read(n[i].Kp[j])
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	// Calculate pads and verify all sum to a vector of zeros over F.
	pads := make([][]*big.Int, *nFlag)
	for i := range n {
		n[i].MakePadsExp()
		pads[i] = n[i].Pads
	}
	for i := range n {
		t.Logf("n[%d].Pads: %64x", i, n[i].Pads)
	}
	padSums := AddVectors(pads...)
	t.Logf("sums     : %64x", padSums)
	zero := new(big.Int)
	for i := range padSums {
		if padSums[i].Cmp(zero) != 0 {
			t.Fatal("pads do not zero")
		}
	}

	// Create DC-net exponential mixes.
	mixes := make([][]*big.Int, *nFlag)
	for i := range mixes {
		mixes[i] = n[i].DCMixExp(n[i].M)
	}

	// Sum all DC-net exponential mixes over F to produce power sums of each
	// message exponential.
	powerSums := AddVectors(mixes...)
	t.Logf("m**n sums: %64x", powerSums)

	// Verify recovered message power sums match the actual message sums.
	for i := range powerSums {
		expectedSum := new(big.Int)
		for j := range n {
			m := new(big.Int).SetBytes(n[j].M)
			m.Exp(m, big.NewInt(int64(i+1)), nil)
			expectedSum.Add(expectedSum, m)
		}
		expectedSum.Mod(expectedSum, F)
		t.Logf("n=%d: powersum=%x expected=%x", i, powerSums[i], expectedSum)
		if powerSums[i].Cmp(expectedSum) != 0 {
			t.Fatalf("m**%d power sums do not equal expected value", i+1)
		}
	}
}

func ke(t *testing.T, n []SRNode) {
	// Key exchange such that n[i].Kp[j] == n[j].Kp[i].  A real run would
	// use x25519.
	for i := range n {
		for j := range n {
			if i == j {
				continue
			}
			if n[j].Kp[i] != nil {
				n[i].Kp[j] = n[j].Kp[i]
			} else {
				n[i].Kp[j] = make([]byte, 32)
				_, err := rand.Read(n[i].Kp[j])
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	var err error
	for i := range n {
		n[i].SharedKeys = make([]*Vec, len(n))
		for j := range n {
			if j == i {
				continue
			}
			prng := chacha20prng.New(n[i].Kp[j], 0)
			n[i].SharedKeys[j], err = SharedKeys(prng, len(n), 20)
			if err != nil {
				t.Fatalf("%v", err)
			}
		}
	}
}

func TestDCMix(t *testing.T) {
	// Generate nodes with random 20-byte messages (e.g. pubkey hashes).
	n := make([]SRNode, *nFlag)
	for i := range n {
		n[i].ID = int64(i)
		n[i].Total = *nFlag
		n[i].M = make([]byte, 20)
		_, err := rand.Read(n[i].M)
		if err != nil {
			t.Fatal(err)
		}
		n[i].Kp = make([][]byte, *nFlag)

		t.Logf("n[%d].M = %x", i, n[i].M)
	}

	ke(t, n)

	pads := make([]*Vec, *nFlag)
	for i := range pads {
		t.Logf("SharedKeys %v", n[i].SharedKeys)
		pads[i] = DCMixPads(n[i].SharedKeys, 20, i)
		t.Logf("Pads %v", pads[i])
	}

	zerom := make([]byte, 20)
	res := NewVec(len(n), 20)
	for i := range pads {
		res.Xor(res, pads[i])
	}
	t.Log(res)
	for i := range n {
		if !bytes.Equal(res.M(i), zerom) {
			t.Errorf("pads do not xor to zero")
		}
	}

	mixes := make([]*Vec, *nFlag)
	for i := range mixes {
		mixes[i] = DCMix(pads[i], n[i].M, i)
	}

	res = NewVec(len(n), 20)
	for i := range mixes {
		res.Xor(res, mixes[i])
	}
	t.Log(res)
	for i := range n {
		if !bytes.Equal(res.M(i), n[i].M) {
			t.Errorf("message not recovered in expected position")
		}
	}
}
*/
