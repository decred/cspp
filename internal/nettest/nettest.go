/*
Package nettest provides a test server to test network listener handlers,
similar to how net/http/httptest provides HTTP handler testing.
*/
package nettest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

type Server struct {
	Addr   string
	lis    net.Listener
	cancel func()
	done   chan struct{}
}

func (s *Server) Close() error {
	defer func() { <-s.done }()
	s.cancel()
	return s.lis.Close()
}

// NewTLSServer creates a TLS TCP server listening on 127.0.0.1:0 and runs
// handler with the listener.
// The listen address with the chosen port can be read from the server's Addr field.
// Clients should tls.Dial using ClientTLS as the TLS config.
func NewTLSServer(handler func(lis net.Listener)) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("nettest: NewTLSServer: %v", err))
	}
	lis = tls.NewListener(lis, serverTLS)
	svr := &Server{
		Addr:   lis.Addr().String(),
		lis:    lis,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		handler(lis)
		close(svr.done)
	}()
	return svr
}
