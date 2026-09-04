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

// Request is one interception: what to answer with, and how to report it.
type Request struct {
	Response         Response
	HandshakeTimeout time.Duration
	// OnDelivered is invoked the moment the first forged response is written,
	// at most once per connection.
	//
	// Delivery must be reported from here rather than inferred from ServeForged
	// returning: an HTTP/2 client pools the connection for the whole attack, so
	// waiting for the connection to end would leave a fault that is demonstrably
	// in effect counted as "matched but never faulted" — the proxy's canonical
	// silent-no-op signature.
	OnDelivered func()
}

// ServeForged terminates TLS on conn using a certificate minted for the
// client's SNI, then answers requests with req.Response. clientHello replays
// the bytes already consumed while sniffing the SNI, so the handshake sees the
// original stream; pass nil when nothing was consumed.
//
// It blocks until the connection is finished — for HTTP/1.1 that is one
// request, for HTTP/2 until the client goes away — or until ctx is cancelled,
// which closes the connection so an attack teardown never leaks a goroutine.
//
// A nil return means the connection ended without the client refusing us; it is
// not a claim that anything was delivered. Use OnDelivered for that.
func (c *CA) ServeForged(ctx context.Context, conn net.Conn, clientHello []byte, req Request) error {
	tc := tls.Server(replayConn(conn, clientHello), c.ServerTLSConfig())

	hctx, cancel := context.WithTimeout(ctx, req.HandshakeTimeout)
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
			return fmt.Errorf("tls handshake did not complete within %s: %w", req.HandshakeTimeout, err)
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

	// delivered is the only trustworthy proof the fault landed: a completed
	// handshake is not one, because a TLS 1.3 client reports a certificate it
	// dislikes only by walking away afterwards.
	var delivered atomic.Bool
	if err := serveOne(tc, req, &delivered); err != nil {
		return err
	}
	// Claim the flag rather than reading it. An HTTP/2 handler goroutine can
	// still be finishing as ServeConn returns, so a plain read could see "not
	// delivered", have the caller count a rejection, and then have the straggler
	// fire OnDelivered — booking one connection into two mutually exclusive
	// buckets. Winning this CAS means nothing was delivered and nothing can be.
	if !delivered.CompareAndSwap(false, true) {
		return nil // delivered; OnDelivered has fired or is firing
	}
	if ctx.Err() != nil {
		// Torn down mid-connection: not the client's doing.
		return ErrNotDelivered
	}
	return &RejectedError{Stage: "post-handshake"}
}

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
func serveOne(tc *tls.Conn, req Request, delivered *atomic.Bool) error {
	ln := newOneShotListener(tc)
	srv := &http.Server{
		Handler:           req.handler(delivered),
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
func (q Request) handler(delivered *atomic.Bool) http.Handler {
	r := q.Response
	status := r.resolvedStatus()
	body := r.resolvedBody()
	// 204 and 304 must not carry a body; net/http would strip it and the
	// advertised Content-Length would be a lie.
	if status == http.StatusNoContent || status == http.StatusNotModified {
		body = ""
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		for k, v := range r.Headers {
			h.Set(textproto.CanonicalMIMEHeaderKey(k), v)
		}
		for _, k := range hopByHop {
			h.Del(k)
		}
		if body != "" {
			h.Set("Content-Length", strconv.Itoa(len(body)))
		}
		// One forged response per HTTP/1.1 connection: the client must not reuse
		// a connection we took over from its real dependency. Connection is
		// hop-by-hop and illegal in HTTP/2, where the client owns the lifetime —
		// so this is set per protocol rather than by disabling keep-alives, which
		// would make the HTTP/2 server send an immediate GOAWAY.
		if req.ProtoMajor == 1 {
			h.Set("Connection", "close")
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = io.WriteString(w, body)
		}
		// Report at the point of writing, not when the connection ends: an HTTP/2
		// client holds the connection open for the whole attack.
		if delivered.CompareAndSwap(false, true) && q.OnDelivered != nil {
			q.OnDelivered()
		}
	})
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
