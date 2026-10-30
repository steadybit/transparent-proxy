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
	"sync"
	"time"
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

	br := bufio.NewReader(io.MultiReader(bytes.NewReader(prefix), client))
	for {
		req, err := http.ReadRequest(br)
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
	dst      netip.AddrPort
	identity string

	// mu guards upstream, which teardown closes from another goroutine.
	mu        sync.Mutex
	upstream  *net.TCPConn
	upstreamR *bufio.Reader

	faulted            bool
	forwarded          bool
	bytesUp, bytesDown int64
}

// serve answers one request and reports whether the connection can carry the
// next one.
func (c *httpConn) serve(ctx context.Context, req *http.Request) bool {
	action := c.s.Faults.Match(c.dst, hostWithoutPort(req.Host))

	if action.Abort {
		c.markFaulted()
		c.s.Metrics.Aborted()
		c.log.Debug("aborting connection (reset)")
		reset(c.client)
		return false
	}

	if action.Latency > 0 {
		c.markFaulted()
		c.s.Metrics.LatencyInjected()
		select {
		case <-time.After(action.Latency):
		case <-ctx.Done():
			c.s.Metrics.Dropped()
			return false
		}
	}

	if action.HTTPStatus != 0 {
		c.markFaulted()
		// The body must be consumed so the next request starts at its head.
		_, _ = io.Copy(io.Discard, req.Body)
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

	resp, err := http.ReadResponse(c.upstreamR, req)
	if err != nil {
		c.log.Debug("failed to read upstream response", slog.Any("err", err))
		return false
	}
	defer func() { _ = resp.Body.Close() }()

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
}

// markFaulted records the connection as faulted, once.
func (c *httpConn) markFaulted() {
	if c.faulted {
		return
	}
	c.faulted = true
	c.s.Metrics.Faulted()
	c.s.Metrics.FaultedHost(c.identity)
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
