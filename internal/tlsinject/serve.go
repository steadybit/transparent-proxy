// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package tlsinject

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"sync"
	"time"
)

// readHeaderTimeout bounds how long a client may take to send its request head
// after the handshake, so a silent client cannot pin a goroutine indefinitely.
const readHeaderTimeout = 10 * time.Second

// hopByHop headers are meaningful only to a single transport hop. They are
// stripped from caller-supplied headers because net/http owns framing, and
// because HTTP/2 rejects them outright.
var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding",
	"Te", "Trailer", "Upgrade",
}

// Response is the forged HTTP response written back to the intercepted client.
// The real dependency is never contacted, so every byte here is synthesized.
type Response struct {
	Status  int
	Body    string
	Headers map[string]string
}

// HandshakeError marks a failure to complete the TLS handshake with the client.
// In practice this means the minted certificate was rejected: the CA is not in
// the workload's truststore, or the client pins certificates. It is a distinct
// type so the caller can count it and surface that diagnosis rather than
// reporting a silent no-op.
type HandshakeError struct{ Err error }

func (e *HandshakeError) Error() string {
	return "tls handshake with client failed: " + e.Err.Error()
}
func (e *HandshakeError) Unwrap() error { return e.Err }

// ServeForged terminates TLS on conn using a certificate minted for the
// client's SNI, then answers the request with r and closes. clientHello replays
// the bytes already consumed while sniffing the SNI, so the handshake sees the
// original stream; pass nil when nothing was consumed.
//
// It blocks until the connection is finished — for HTTP/1.1 that is one
// request, for HTTP/2 until the client goes away — or until ctx is cancelled,
// which closes the connection so an attack teardown never leaks a goroutine.
func (c *CA) ServeForged(ctx context.Context, conn net.Conn, clientHello []byte, r Response, handshakeTimeout time.Duration) error {
	tc := tls.Server(replayConn(conn, clientHello), c.ServerTLSConfig())

	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		return &HandshakeError{Err: err}
	}

	// Cancellation must reach a connection parked inside net/http; closing it is
	// the only way to unblock the server loop.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = tc.Close()
		case <-stop:
		}
	}()

	return serveOne(tc, r)
}

// serveOne runs net/http over a single already-handshaken connection. Handing
// it to http.Server (rather than writing the response by hand) is what gets
// HTTP/2 support for free: a TLSConfig advertising h2 makes Serve install the
// stdlib's HTTP/2 handler, and net/http then dispatches on the protocol ALPN
// negotiated during the handshake above.
func serveOne(tc *tls.Conn, r Response) error {
	ln := newOneShotListener(tc)
	srv := &http.Server{
		Handler:           r.handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		// A TLSConfig advertising h2 is what makes Serve install the stdlib's
		// HTTP/2 handler. net/http then picks the protocol by type-asserting the
		// connection to *tls.Conn and reading the negotiated ALPN — so the
		// listener must hand over the *tls.Conn itself, unwrapped.
		TLSConfig: &tls.Config{NextProtos: []string{"h2", "http/1.1"}},
		// net/http logs client-side noise (malformed requests, resets) that is
		// expected here and would otherwise pollute the proxy's own log stream.
		ErrorLog: log.New(io.Discard, "", 0),
		// Completion is observed here rather than by wrapping the connection,
		// which would hide its *tls.Conn type and silently downgrade h2 to h1.
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				ln.finish()
			}
		},
	}

	if err := srv.Serve(ln); err != nil && !errors.Is(err, errServed) {
		return err
	}
	return nil
}

// handler writes the forged response. It is shared by the HTTP/1.1 and HTTP/2
// paths, so both produce an identical status, header set and body.
func (r Response) handler() http.Handler {
	body := r.resolvedBody()
	status := r.resolvedStatus()
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		for k, v := range r.Headers {
			h.Set(textproto.CanonicalMIMEHeaderKey(k), v)
		}
		for _, k := range hopByHop {
			h.Del(k)
		}
		h.Set("Content-Length", strconv.Itoa(len(body)))
		// One forged response per HTTP/1.1 connection: the client must not reuse
		// a connection we took over from its real dependency. Connection is
		// hop-by-hop and illegal in HTTP/2, where the client owns the lifetime —
		// so this is set per protocol rather than by disabling keep-alives, which
		// would make the HTTP/2 server send an immediate GOAWAY.
		if req.ProtoMajor == 1 {
			h.Set("Connection", "close")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func (r Response) resolvedStatus() int {
	if r.Status < 100 || r.Status > 599 {
		return http.StatusServiceUnavailable
	}
	return r.Status
}

// resolvedBody mirrors the cleartext injector's default one-liner, so a fault
// reads the same whether it landed on HTTP or HTTPS.
func (r Response) resolvedBody() string {
	if r.Body != "" {
		return r.Body
	}
	status := r.resolvedStatus()
	reason := http.StatusText(status)
	if reason == "" {
		reason = "Fault Injected"
	}
	return fmt.Sprintf("%d %s (injected by steadybit transparent-proxy)\n", status, reason)
}

// errServed is returned by the one-shot listener once its single connection has
// been fully served; it ends http.Server.Serve normally rather than as a fault.
var errServed = errors.New("tlsinject: connection served")

// oneShotListener adapts a single accepted connection to net.Listener. The
// second Accept blocks until that connection is finished, so Serve returns only
// once the response has actually been delivered. The connection is handed over
// exactly as given — see the ConnState note in serveOne.
type oneShotListener struct {
	mu   sync.Mutex
	conn net.Conn
	addr net.Addr
	done chan struct{}
	once sync.Once
}

func newOneShotListener(c net.Conn) *oneShotListener {
	return &oneShotListener{conn: c, addr: c.LocalAddr(), done: make(chan struct{})}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, errServed
}

// Close is a no-op: the listener owns no resources of its own, and net/http
// closes it on the way out of Serve while the connection is still being torn
// down.
func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.addr }

func (l *oneShotListener) finish() { l.once.Do(func() { close(l.done) }) }

// replayConn prepends already-consumed bytes to a connection's read side, so
// the TLS handshake sees the ClientHello the caller peeked at.
func replayConn(c net.Conn, prefix []byte) net.Conn {
	if len(prefix) == 0 {
		return c
	}
	return &prefixedConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}

type prefixedConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
