// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
)

// serveHTTP handles a matched cleartext HTTP/1.x connection request by
// request, so a keep-alive client gets the rule's probability applied to every
// request rather than once for the whole connection. Faulted requests are
// answered by the proxy while keeping the connection open; the others are
// forwarded over one persistent upstream connection.
//
// prefix is the request head already read while sniffing. early, if non-nil,
// is an upstream dialed while waiting on the client and is used for the first
// forwarded request.
func (s *Server) serveHTTP(ctx context.Context, log *slog.Logger, client *net.TCPConn, dst netip.AddrPort, identity string, prefix []byte, early *net.TCPConn) {
	c := &httpConn{s: s, log: log, client: client, dst: dst, identity: identity}
	c.clientR = bufio.NewReader(io.MultiReader(bytes.NewReader(prefix), client))
	c.setUpstream(early)
	defer c.closeUpstream()

	// Teardown must reach a loop blocked reading either side.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			c.closeUpstream()
		case <-stop:
		}
	}()

	for {
		req, err := http.ReadRequest(c.clientR)
		if err != nil {
			// EOF between requests is the client closing a keep-alive connection.
			if err != io.EOF {
				log.Debug("could not read http request", slog.Any("err", err))
			}
			break
		}
		if !c.serve(ctx, req) || req.Close {
			break
		}
	}

	if c.forwarded {
		s.Metrics.AddBytes(c.bytesUp, c.bytesDown)
		s.Metrics.Proxied()
	}
}

// httpConn is the per-connection state of serveHTTP.
type httpConn struct {
	s        *Server
	log      *slog.Logger
	client   *net.TCPConn
	clientR  *bufio.Reader
	dst      netip.AddrPort
	identity string

	// mu guards upstream, which teardown closes from another goroutine.
	mu        sync.Mutex
	upstream  *net.TCPConn
	upstreamR *bufio.Reader

	faulted            atomic.Bool
	forwarded          bool
	bytesUp, bytesDown int64
}

// serve answers one request and reports whether the connection can carry the
// next one.
func (c *httpConn) serve(ctx context.Context, req *http.Request) bool {
	host := hostWithoutPort(req.Host)
	action := c.s.Faults.Match(c.dst, host)
	c.s.countRequest(host, c.identity, action, &c.faulted)

	if action.Abort {
		c.s.Metrics.Aborted()
		c.log.Debug("aborting connection (reset)")
		reset(c.client)
		return false
	}

	if action.Latency > 0 {
		c.s.Metrics.LatencyInjected()
		select {
		case <-time.After(action.Latency):
		case <-ctx.Done():
			c.s.Metrics.Dropped()
			return false
		}
	}

	if action.HTTPStatus != 0 {
		if expectsContinue(req) {
			// The client has not sent its body and may or may not send it after
			// this early answer, so the connection cannot carry another request.
			req.Close = true
		} else {
			// The body must be consumed so the next request starts at its head.
			_, _ = io.Copy(io.Discard, req.Body)
		}
		if err := writeHTTPResponse(c.client, req, action.HTTPStatus, action.HTTPHeaders, action.HTTPBody); err != nil {
			c.log.Debug("failed to write injected status", slog.Any("err", err))
			return false
		}
		c.s.Metrics.HTTPInjected()
		c.log.Debug("injected http status", slog.Int("status", action.HTTPStatus))
		return true
	}

	return c.forward(ctx, req)
}

// forward sends req to the upstream and streams its response back.
func (c *httpConn) forward(ctx context.Context, req *http.Request) bool {
	// Servers close idle keep-alive connections on their side. Writing into one
	// would fail this request, so a closed upstream is replaced first.
	if c.upstream != nil && !c.upstreamReusable() {
		c.closeUpstream()
	}
	if c.upstream == nil {
		up, err := c.s.dial(ctx, c.dst)
		if err != nil {
			c.s.Metrics.UpstreamError()
			c.log.Warn("upstream dial failed", slog.Any("err", err))
			return false
		}
		c.setUpstream(up)
	}
	c.forwarded = true

	// A client sending "Expect: 100-continue" waits to be told before sending
	// its body. The proxy tells it and drops the expectation from the forwarded
	// request, as nginx does, so the upstream answers only once.
	if expectsContinue(req) {
		req.Header.Del("Expect")
		down := &countingWriter{w: c.client}
		_, err := io.WriteString(down, "HTTP/1.1 100 Continue\r\n\r\n")
		c.bytesDown += down.n
		if err != nil {
			c.log.Debug("failed to send 100 Continue", slog.Any("err", err))
			return false
		}
	}

	// Request.Write adds a Go User-Agent when the client sent none; an empty
	// value suppresses it so the upstream sees the client's headers.
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header["User-Agent"] = []string{""}
	}
	up := &countingWriter{w: c.upstream}
	err := req.Write(up)
	c.bytesUp += up.n
	if err != nil {
		c.log.Debug("failed to forward request", slog.Any("err", err))
		return false
	}

	resp, err := c.readFinalResponse(req)
	if err != nil {
		c.log.Debug("failed to read upstream response", slog.Any("err", err))
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		c.tunnel(resp)
		return false
	}

	down := &countingWriter{w: c.client}
	err = resp.Write(down)
	c.bytesDown += down.n
	if err != nil {
		c.log.Debug("failed to forward response", slog.Any("err", err))
		return false
	}
	// The upstream is closing, and resp.Write told the client so too.
	return !resp.Close
}

// readFinalResponse reads the upstream's response to req. Interim responses
// such as 103 Early Hints come before it; they are passed to the client as
// they arrive, otherwise the real response would be left on the connection and
// read as the answer to the next request. 101 is returned like a final
// response, since it ends HTTP on the connection.
func (c *httpConn) readFinalResponse(req *http.Request) (*http.Response, error) {
	for {
		resp, err := http.ReadResponse(c.upstreamR, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
		down := &countingWriter{w: c.client}
		err = resp.Write(down)
		c.bytesDown += down.n
		if err != nil {
			return nil, err
		}
	}
}

// expectsContinue reports whether the client waits for "100 Continue" before
// sending the request body.
func expectsContinue(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Expect"), "100-continue")
}

// tunnel completes a protocol upgrade such as WebSocket: it passes the
// server's 101 to the client and then copies raw bytes both ways until either
// side closes, because the connection no longer carries HTTP.
func (c *httpConn) tunnel(resp *http.Response) {
	down := &countingWriter{w: c.client}
	up := &countingWriter{w: c.upstream}
	defer func() {
		c.bytesUp += up.n
		c.bytesDown += down.n
	}()

	if err := resp.Write(down); err != nil {
		c.log.Debug("failed to forward upgrade response", slog.Any("err", err))
		return
	}
	// Either side may already have sent bytes of the new protocol, which our
	// readers buffered while parsing HTTP. They must go out before the splice.
	if err := writeBuffered(down, c.upstreamR); err != nil {
		return
	}
	if err := writeBuffered(up, c.clientR); err != nil {
		return
	}

	c.log.Debug("upgraded; passing bytes through")
	toUpstream, toClient := relay(c.client, c.upstream)
	up.n += toUpstream
	down.n += toClient
}

// writeBuffered writes out whatever r has already buffered, without reading
// any more from its source.
func writeBuffered(w io.Writer, r *bufio.Reader) error {
	b, _ := r.Peek(r.Buffered())
	_, err := w.Write(b)
	return err
}

func (c *httpConn) setUpstream(up *net.TCPConn) {
	if up == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.upstream = up
	c.upstreamR = bufio.NewReader(up)
}

func (c *httpConn) closeUpstream() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.upstream != nil {
		_ = c.upstream.Close()
	}
	c.upstream, c.upstreamR = nil, nil
}

// upstreamReusable reports whether the kept upstream connection can carry the
// next request: nothing left unread in our buffer, and still open on the
// server's side.
func (c *httpConn) upstreamReusable() bool {
	return c.upstreamR.Buffered() == 0 && idleConnAlive(c.upstream)
}

// countRequest records a request that matched a rule and, if its fault applies,
// that it was faulted. connFaulted makes the connection count as faulted once,
// also when its HTTP/2 requests run concurrently.
func (s *Server) countRequest(host, identity string, action fault.Action, connFaulted *atomic.Bool) {
	if action.Rule == "" {
		return
	}
	s.Metrics.MatchedRequest(host)
	if !action.Faulted() {
		return
	}
	s.Metrics.FaultedRequest(host)
	if connFaulted.CompareAndSwap(false, true) {
		s.Metrics.Faulted()
		s.Metrics.FaultedHost(identity)
	}
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}
