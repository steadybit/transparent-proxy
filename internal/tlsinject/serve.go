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
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
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

// RejectedError reports that the client refused the injected certificate —
// almost always because the CA is absent from the workload's truststore, or
// because the client pins certificates.
//
// It covers two stages, because refusal is not always visible at handshake
// time. Under TLS 1.2 the handshake itself fails. Under TLS 1.3 the server
// completes its handshake before learning the client's verdict, so a rejecting
// client (OpenSSL/curl among them) instead abandons the connection without ever
// sending a request. Both mean the fault was never delivered, so both are
// reported here rather than counted as a successful injection.
type RejectedError struct {
	// Stage is "handshake" or "post-handshake".
	Stage string
	// Err is the underlying failure; nil when the client simply went away
	// without sending a request.
	Err error
}

func (e *RejectedError) Error() string {
	msg := "client rejected the injected certificate (" + e.Stage + ")"
	if e.Err != nil {
		return msg + ": " + e.Err.Error()
	}
	return msg + ": no request was sent"
}
func (e *RejectedError) Unwrap() error { return e.Err }

// Serve terminates TLS on conn using a certificate minted for the client's SNI
// and serves every request on it with handler, over HTTP/1.1 or HTTP/2,
// whichever the client negotiates. clientHello replays the bytes already
// consumed while sniffing the SNI; pass nil when nothing was consumed.
//
// It blocks until the client closes the connection, or until ctx is cancelled,
// which closes it so an attack teardown never leaks a goroutine.
//
// The client accepting our certificate is only proven by it sending a request:
// a TLS 1.3 client completes the handshake before reporting a certificate it
// dislikes, by walking away. A connection that ends without any request is
// therefore a *RejectedError, or ErrNotDelivered when ctx was cancelled.
func (c *CA) Serve(ctx context.Context, conn net.Conn, clientHello []byte, handshakeTimeout time.Duration, handler http.Handler) error {
	tc := tls.Server(replayConn(conn, clientHello), c.ServerTLSConfig())

	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		switch {
		case ctx.Err() != nil:
			// Teardown closed the connection mid-handshake; not the client's doing,
			// and must not be blamed on the truststore.
			return nil
		case errors.Is(err, context.DeadlineExceeded):
			// Our own deadline elapsed. A slow client or a loaded proxy is not a
			// rejection, and reporting it as one sends the operator hunting for a
			// truststore problem that does not exist.
			return fmt.Errorf("tls handshake did not complete within %s: %w", handshakeTimeout, err)
		case isCertError(err):
			// We could not produce a certificate (expired CA, signing failure, no
			// SNI). Blaming the client's truststore here would point the operator at
			// the one thing that is not broken.
			return err
		default:
			return &RejectedError{Stage: "handshake", Err: err}
		}
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

	var state connState
	if err := serveOne(tc, state.track(handler)); err != nil {
		return err
	}
	if !state.endedWithoutRequest() {
		return nil // at least one request was served
	}
	if ctx.Err() != nil {
		// Torn down mid-connection: not the client's doing.
		return ErrNotDelivered
	}
	return &RejectedError{Stage: "post-handshake"}
}

// connState records whether a connection served any request. It is claimed
// with a CAS from both sides: an HTTP/2 handler goroutine can still be starting
// as the server returns, so a plain flag could have the caller count a
// rejection while that straggler serves a request — booking one connection
// into two mutually exclusive buckets.
type connState struct{ v atomic.Int32 }

const (
	connIdle   int32 = iota // no request yet
	connServed              // at least one request reached the handler
	connEnded               // ended without any request
)

// track drops a request arriving after the connection was reported as ended,
// which would otherwise be counted as both a rejection and a served request.
func (s *connState) track(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.v.CompareAndSwap(connIdle, connServed) && s.v.Load() == connEnded {
			panic(http.ErrAbortHandler)
		}
		handler.ServeHTTP(w, r)
	})
}

func (s *connState) endedWithoutRequest() bool { return s.v.CompareAndSwap(connIdle, connEnded) }

// ErrNotDelivered reports a connection that ended without a response and
// without the client refusing us — teardown, essentially. It is returned so the
// caller can account for the connection instead of silently losing it from the
// outcome counters.
var ErrNotDelivered = errors.New("tlsinject: connection ended without delivering a response")

// isCertError reports whether err came from our own certificate production.
func isCertError(err error) bool {
	var ce *CertError
	return errors.As(err, &ce)
}

// serveOne runs net/http over a single already-handshaken connection. Handing
// it to http.Server (rather than writing the response by hand) is what gets
// HTTP/2 support for free: a TLSConfig advertising h2 makes Serve install the
// stdlib's HTTP/2 handler, and net/http then dispatches on the protocol ALPN
// negotiated during the handshake above.
func serveOne(tc *tls.Conn, handler http.Handler) error {
	ln := newOneShotListener(tc)
	var handlers sync.WaitGroup
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlers.Add(1)
			defer handlers.Done()
			handler.ServeHTTP(w, r)
		}),
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
			switch state {
			case http.StateClosed:
				ln.finish()
			case http.StateHijacked:
				// The handler that took the connection over (a WebSocket tunnel
				// after a 101) still uses it: returning now would have the caller
				// close the connection under the tunnel.
				go func() {
					handlers.Wait()
					ln.finish()
				}()
			}
		},
	}

	if err := srv.Serve(ln); err != nil && !errors.Is(err, errServed) {
		return err
	}
	return nil
}

// ServeHTTP leaves the connection's lifetime to the caller, so a faulted
// request does not close a connection other requests may still use.
func (r Response) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	status := r.resolvedStatus()
	body := r.resolvedBody()
	// 204 and 304 must not carry a body; net/http would strip it and the
	// advertised Content-Length would be a lie.
	if status == http.StatusNoContent || status == http.StatusNotModified {
		body = ""
	}
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	for k, v := range r.Headers {
		k = textproto.CanonicalMIMEHeaderKey(k)
		// Only the rule's own headers are filtered: a hop-by-hop header the
		// caller set on w (Connection: close) is the caller's decision.
		if !slices.Contains(hopByHop, k) {
			h.Set(k, v)
		}
	}
	if body != "" {
		h.Set("Content-Length", strconv.Itoa(len(body)))
	}
	w.WriteHeader(status)
	if body != "" {
		_, _ = io.WriteString(w, body)
	}
}

// resolvedStatus rejects 1xx as out of range: net/http treats an informational
// status as non-committing, so a body written after it would silently commit
// 200 instead — the client would see success where a fault was configured.
func (r Response) resolvedStatus() int {
	if r.Status < 200 || r.Status > 599 {
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
