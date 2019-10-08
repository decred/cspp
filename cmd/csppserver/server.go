package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"decred.org/cspp"
	"decred.org/cspp/coinjoin"
	"decred.org/cspp/server"
	"github.com/jrick/wsrpc/v2"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

func defaultDcrdCA() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	def := filepath.Join(home, ".dcrd/rpc.cert")
	if _, err := os.Stat(def); err == nil {
		return def
	}
	return filepath.Join(home, ".csppserver/dcrd.pem")
}

var (
	fs           = flag.NewFlagSet("", flag.ExitOnError)
	lisFlag      = fs.String("lis", "127.0.0.1:5760,[::1]:5760", "comma-separated listen addresses of CoinShuffle++ server")
	portFlag     = fs.String("port", "5760", "alternate external port of CoinShuffle++ server")
	tlsFlag      = fs.String("tls", "", "(required) auto=domain to use LetsEncrypt (will bind to -acme) or manual=cert,key")
	acmeFlag     = fs.String("acme", ":80", "listen interface for ACME challenge; must be reachable at port 80 from internet")
	httpFlag     = fs.String("http", "", "listen address for public webserver (no TLS)")
	httpsFlag    = fs.String("https", ":443", "listen address for public webserver (uses same TLS config as from cspp listener)")
	epochFlag    = fs.Duration("epoch", 5*time.Minute, "mixing epoch")
	dcrdWSFlag   = fs.String("dcrd.ws", "wss://localhost:9109/ws", "dcrd websocket")
	dcrdCAFlag   = fs.String("dcrd.ca", defaultDcrdCA(), "dcrd certificate authority")
	dcrdUserFlag = fs.String("dcrd.user", "", "dcrd RPC username; uses DCRDUSER environment variable if unset")
	dcrdPassFlag = fs.String("dcrd.pass", "", "dcrd RPC password; uses DCRDPASS environment variable if unset")
	pprofFlag    = fs.String("pprof", "", "listen address of pprof server")
	reportFlag   = fs.String("report", "", "report stats of successful mixes to file")
)

func main() {
	fs.Parse(os.Args[1:])

	log.Printf("Starting csppserver")
	log.Printf("Go version %s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)

	if *pprofFlag != "" {
		mux := http.NewServeMux()
		mux.Handle("/", http.RedirectHandler("/debug/pprof/", http.StatusSeeOther))
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		lis, err := net.Listen("tcp", *pprofFlag)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("pprof server listening on %s", lis.Addr())
		s := http.Server{Handler: mux}
		go func() { log.Println(s.Serve(lis)) }()
	}

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal)
	signal.Notify(signals, os.Interrupt)
	go func() {
		for sig := range signals {
			log.Printf("signal: %v", sig)
			cancel()
		}
	}()

	newRPC := setupRPC(ctx)
	_, err := newRPC()
	if err != nil {
		log.Fatalf("dial dcrd: %v", err)
	}

	tc, selfsignedCert := setupTLS()

	httpServer := &http.Server{
		Handler: &indexHandler{
			ServerName: tc.ServerName,
			Address:    net.JoinHostPort(tc.ServerName, *portFlag),
			Epoch:      *epochFlag,
			SelfSigned: selfsignedCert,
		},
	}
	if *httpFlag != "" {
		lis, err := net.Listen("tcp", *httpFlag)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("http server listening on %s", lis.Addr())
		go func() { log.Println(httpServer.Serve(lis)) }()
	}
	if *httpsFlag != "" {
		lis, err := tls.Listen("tcp", *httpsFlag, tc)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("https server listening on %s", lis.Addr())
		go func() { log.Println(httpServer.Serve(lis)) }()
	}

	newm := func(desc []byte) (server.Mixer, error) {
		sc, amount, txVersion, lockTime, expiry, err := coinjoin.DecodeDesc(desc)
		if err != nil {
			return nil, err
		}
		rpc, err := newRPC()
		if err != nil {
			return nil, err
		}
		return coinjoin.NewTx(rpc, sc, amount, txVersion, lockTime, expiry)
	}
	s, err := server.New(cspp.MessageSize, newm, *epochFlag)
	if err != nil {
		log.Fatal(err)
	}
	if *reportFlag != "" {
		fi, err := os.OpenFile(*reportFlag, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		}
		defer fi.Close()
		s.SetReportEncoder(json.NewEncoder(fi))
	}
	listen := func(addr string) (lis net.Listener, err error) {
		defer func() {
			go func() {
				if lis != nil {
					<-ctx.Done()
					lis.Close()
				}
			}()
		}()
		return tls.Listen("tcp", addr, tc)
	}
	var wg sync.WaitGroup
	for _, addr := range strings.Split(*lisFlag, ",") {
		lis, err := listen(addr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("CoinShuffle++ server listening on %v", lis.Addr())
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Run(ctx, lis); ctx.Err() == nil {
				log.Fatal(err)
			}
		}()
	}
	<-ctx.Done()
	wg.Wait()
}

func setupTLS() (tc *tls.Config, selfsignedCert []byte) {
	tc = &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			// Only applies to TLS 1.2. TLS 1.3 ciphersuites are not configurable.
			// Run with GODEBUG=tls13=1 to opt into TLS 1.3 with Go 1.12.
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos: []string{acme.ALPNProto},
	}
	tlsFlag := *tlsFlag
	switch {
	case strings.HasPrefix(tlsFlag, "auto="):
		domain := tlsFlag[len("auto="):]
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("no home directory for cert cache: %v", err)
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(filepath.Join(home, ".csppserver")),
			HostPolicy: autocert.HostWhitelist(domain),
		}
		tc.ServerName = domain
		tc.GetCertificate = m.GetCertificate
		lis, err := net.Listen("tcp", *acmeFlag)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("ACME client listening on %s", lis.Addr())
		s := http.Server{Handler: m.HTTPHandler(nil)}
		go func() { log.Println(s.Serve(lis)) }()
	case strings.HasPrefix(tlsFlag, "manual="):
		certkey := tlsFlag[len("manual="):]
		comma := strings.IndexRune(certkey, ',')
		if comma == -1 {
			log.Fatal("-tls=manual= must be comma-separated cert,key file pair")
		}
		certFile, keyFile := certkey[:comma], certkey[comma+1:]
		if certFile == "" || keyFile == "" {
			log.Fatal("-tls=manual= must be comma-separated cert,key file pair")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal(err)
		}
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
		if x509Cert.IsCA {
			buf := new(bytes.Buffer)
			for _, c := range cert.Certificate {
				err := pem.Encode(buf, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: c,
				})
				if err != nil {
					log.Fatal(err)
				}
			}
			selfsignedCert = buf.Bytes()
		}
		if len(x509Cert.DNSNames) == 0 {
			log.Fatal("certificate has no valid Subject Alterante Name")
		}
		tc.ServerName = x509Cert.DNSNames[0]
		tc.Certificates = []tls.Certificate{cert}
	default:
		log.Print("bad -tls flag")
		fs.Usage()
		os.Exit(2)
	}
	return
}

func setupRPC(ctx context.Context) func() (*wsrpc.Client, error) {
	dcrdCA, err := ioutil.ReadFile(*dcrdCAFlag)
	if err != nil {
		log.Fatal(err)
	}
	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(dcrdCA); !ok {
		log.Fatal("unparsable certificate authority")
	}
	tc := &tls.Config{RootCAs: caPool}
	tlsOpt := wsrpc.WithTLSConfig(tc)

	user, pass := *dcrdUserFlag, *dcrdPassFlag
	if user == "" {
		user = os.Getenv("DCRDUSER")
	}
	if pass == "" {
		pass = os.Getenv("DCRDPASS")
	}
	authOpt := wsrpc.WithBasicAuth(user, pass)

	var mu sync.Mutex
	var c *wsrpc.Client
	return func() (*wsrpc.Client, error) {
		defer mu.Unlock()
		mu.Lock()

		if c != nil {
			select {
			case <-c.Done():
				log.Printf("RPC client errored (%v); reconnecting...", c.Err())
				c = nil
			default:
				return c, nil
			}
		}

		var err error
		c, err = wsrpc.Dial(ctx, *dcrdWSFlag, tlsOpt, authOpt)
		if err != nil {
			c = nil
			return nil, err
		}
		log.Printf("dialed dcrd websocket %v", *dcrdWSFlag)
		return c, nil
	}
}
