package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"decred.org/cspp/v2"
	"decred.org/cspp/v2/coinjoin"
	"decred.org/cspp/v2/internal/nettest"
	"decred.org/cspp/v2/server"
	"github.com/decred/dcrd/wire"
	"golang.org/x/crypto/ed25519"
)

const logFlags = log.LstdFlags | log.Lmicroseconds | log.Lshortfile

func init() {
	log.SetFlags(logFlags)
}

var nFlag = flag.Int64("n", 3, "node count")
var mFlag = flag.Int("m", 4, "message-per-node count")
var epochFlag = flag.Duration("epoch", 5*time.Second, "mix epoch")
var inputValue int64
var inputValueJSON []byte

func TestMain(m *testing.M) {
	flag.Parse()
	inputValue = int64(*mFlag) + 1
	inputValueJSON = []byte(fmt.Sprintf(`{"value":%v}`, inputValue))
	os.Exit(m.Run())
}

type testPeer struct {
	ses *cspp.Session
}

type confirmer struct {
	tx      *wire.MsgTx
	prevOut wire.OutPoint
	ms      [][]byte
}

func (c *confirmer) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Grow(c.tx.SerializeSize())
	err := c.tx.Serialize(buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *confirmer) UnmarshalBinary(b []byte) error {
	return c.tx.Deserialize(bytes.NewReader(b))
}

type missingMessage string

func (m missingMessage) Error() string   { return string(m) }
func (m missingMessage) MissingMessage() {}

func (c *confirmer) Confirm() error {
Nextm:
	for _, m := range c.ms {
		for _, out := range c.tx.TxOut {
			if bytes.Equal(out.PkScript, m) {
				continue Nextm
			}
		}
		return missingMessage(fmt.Sprintf("missing message %x", m))
	}
	for i, in := range c.tx.TxIn {
		if in.PreviousOutPoint == c.prevOut {
			c.tx.TxIn[i].SignatureScript = []byte("signature")
		}
	}
	return nil
}

func newConfirmer(input *wire.TxIn, change *wire.TxOut) cspp.GenConfirmer {
	return &confirmer{
		tx: &wire.MsgTx{
			Version: 1,
			TxIn:    []*wire.TxIn{input},
			TxOut:   []*wire.TxOut{change},
		},
		prevOut: input.PreviousOutPoint,
	}
}

func (c *confirmer) Gen() ([][]byte, error) {
	ms := make([][]byte, *mFlag)
	for i := range ms {
		ms[i] = make([]byte, cspp.MessageSize)
		_, err := rand.Read(ms[i])
		if err != nil {
			return nil, err
		}
	}
	c.ms = make([][]byte, *mFlag)
	for i := range ms {
		s := []byte{
			0:  0x76, // DUP
			1:  0xa9, // HASH160
			2:  20,   // DATA20
			23: 0x88, // EQUALVERIFY
			24: 0xac, // CHECKSIG
		}
		copy(s[3:23], ms[i])
		c.ms[i] = s
	}
	return ms, nil
}

type itJustWorks struct{}

func (itJustWorks) Call(ctx context.Context, method string, res interface{}, args ...interface{}) error {
	switch method {
	case "gettxout":
		return json.Unmarshal(inputValueJSON, res)
	case "sendrawtransaction":
		return nil
	default:
		return fmt.Errorf("unknown method %q", method)
	}
}

var change = []byte{
	0:  0x76, // DUP
	1:  0xa9, // HASH160
	2:  20,   // DATA20
	23: 0x88, // EQUALVERIFY
	24: 0xac, // CHECKSIG
}

func TestHonest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	newCoinJoin := func(desc []byte) (server.Mixer, error) {
		sc, amount, txVersion, lockTime, expiry, err := coinjoin.DecodeDesc(desc)
		if err != nil {
			return nil, err
		}
		return coinjoin.NewTx(itJustWorks{}, sc, amount, 0.0001e8, txVersion, lockTime, expiry)
	}
	svr, err := server.New(cspp.MessageSize, newCoinJoin, *epochFlag)
	if err != nil {
		t.Fatal(err)
	}
	s := nettest.NewTLSServer(func(lis net.Listener) {
		log.Print(svr.Run(ctx, lis))
	})
	defer func() {
		log.Print("shutting down nettest server")
		cancel()
		s.Close()
	}()

	peers := make([]testPeer, *nFlag)
	vk := make([]ed25519.PublicKey, *nFlag)
	for i := range peers {
		logger := log.New(os.Stderr, "", logFlags)
		logger.SetPrefix(fmt.Sprintf("peer%d ", i))
		commitment := coinjoin.EncodeDesc(coinjoin.P2PKHv0, 1e8, 1, 0, 0)
		ses, err := cspp.NewSession(rand.Reader, logger, commitment, *mFlag)
		if err != nil {
			t.Fatal(err)
		}
		peers[i].ses = ses
		vk[i] = ses.Pk
	}

	// TODO: server should determine order and send vk to each peer as part
	// of pairing protocol.
	sort.Slice(vk, func(i, j int) bool {
		return bytes.Compare(vk[i], vk[j]) < 0
	})

	var wg sync.WaitGroup
	wg.Add(len(peers))
	for i := range peers {
		i := i
		go func() {
			input := &wire.TxIn{
				ValueIn: inputValue * 1e8,
				PreviousOutPoint: wire.OutPoint{
					Index: uint32(i),
				},
			}
			change := &wire.TxOut{Value: 1e8 - int64(1+i)*0.001e8, PkScript: change}
			con := newConfirmer(input, change)
			conn, err := tls.Dial("tcp", s.Addr, nettest.ClientTLS)
			if err != nil {
				panic(err)
			}
			err = peers[i].ses.DiceMix(ctx, conn, con)
			if err != nil {
				panic(fmt.Sprintf("peer%d: %v", i, err))
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
