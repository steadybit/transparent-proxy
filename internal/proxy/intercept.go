// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/steadybit/transparent-proxy/internal/tlsinject"
)

// serveIntercepted handles a matched HTTPS connection through the interception
// CA request by request, so the rule's probability applies to every request,
// also on a keep-alive HTTP/1.1 or a multiplexed HTTP/2 connection. Faulted
// requests are answered by the proxy; the others are forwarded to the real
// dependency over a TLS connection of the proxy's own.
func (s *Server) serveIntercepted(ctx context.Context, log *slog.Logger, client *net.TCPConn, dst netip.AddrPort, identity string, prefix []byte) {
	c := &interceptedConn{s: s, log: log, dst: dst, identity: identity}
	upstream := s.upstreamTransport(dst)
	defer upstream.CloseIdleConnections()
	c.proxy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "https"
			r.Out.URL.Host = r.In.Host
			if r.Out.URL.Host == "" {
				r.Out.URL.Host = identity
			}
		},
		Transport:    upstream,
		ErrorLog:     discardLog,
		ErrorHandler: c.upstreamFailed,
	}

	err := s.TLSInject.Serve(ctx, client, prefix, s.peekTimeout(), http.HandlerFunc(c.serve))

	var rejErr *tlsinject.RejectedError
	switch {
	case errors.As(err, &rejErr):
		// The client rejected our certificate, so no fault applied — counted
		// separately from faults, never as one. This is the signal that the CA is
		// missing from the workload's truststore.
		s.Metrics.TLSRejected()
		log.Warn("client rejected the injected certificate; is the CA trusted by the target?",
			slog.String("stage", rejErr.Stage),
			slog.Any("err", err))
	case errors.Is(err, tlsinject.ErrNotDelivered):
		// Teardown while the connection was open: expected, not a failure.
		s.Metrics.Dropped()
		log.Debug("interception ended before any request", slog.Any("err", err))
	case err != nil:
		// The connection was taken over and cannot be forwarded now, so it ends
		// here either way. Count it so matched still reconciles with the outcome
		// counters instead of silently losing a connection.
		s.Metrics.Dropped()
		log.Warn("failed to serve intercepted https connection", slog.Any("err", err))
	case c.forwarded.Load():
		s.Metrics.Proxied()
	}
}

// interceptedConn is the per-connection state of serveIntercepted. Its
// handler runs concurrently for the streams of an HTTP/2 connection.
type interceptedConn struct {
	s        *Server
	log      *slog.Logger
	dst      netip.AddrPort
	identity string
	proxy    *httputil.ReverseProxy

	faulted   atomic.Bool
	forwarded atomic.Bool
}

// serve answers one request: with the rule's fault if it applies this time,
// otherwise by forwarding it to the real dependency.
func (c *interceptedConn) serve(w http.ResponseWriter, r *http.Request) {
	host := hostWithoutPort(r.Host)
	action := c.s.Faults.Match(c.dst, host)
	c.s.countRequest(host, c.identity, action, &c.faulted)

	if action.Abort {
		c.s.Metrics.Aborted()
		c.log.Debug("aborting request")
		// Resets the stream on HTTP/2 and closes the connection on HTTP/1.1.
		panic(http.ErrAbortHandler)
	}

	if action.Latency > 0 {
		c.s.Metrics.LatencyInjected()
		select {
		case <-time.After(action.Latency):
		case <-r.Context().Done():
			return
		}
	}

	if action.HTTPStatus != 0 {
		tlsinject.Response{
			Status:  action.HTTPStatus,
			Body:    action.HTTPBody,
			Headers: action.HTTPHeaders,
		}.ServeHTTP(w, r)
		c.s.Metrics.HTTPInjected()
		c.log.Debug("injected https status", slog.Int("status", action.HTTPStatus))
		return
	}

	c.forwarded.Store(true)
	c.proxy.ServeHTTP(w, r)
}

// upstreamFailed answers a forwarded request whose dependency could not be
// reached. A 502 is what a gateway would answer; the request is not a fault
// the attack injected, so it is counted as an upstream error.
func (c *interceptedConn) upstreamFailed(w http.ResponseWriter, _ *http.Request, err error) {
	c.s.Metrics.UpstreamError()
	c.log.Warn("forwarding an intercepted request failed", slog.Any("err", err))
	w.WriteHeader(http.StatusBadGateway)
}

// upstreamTransport forwards an intercepted connection's requests to its
// original destination dst, whatever the request's host, over the proxy's own
// TLS connections: SNI is the request's host and the dependency's certificate
// is verified, so the proxy never forwards to an impostor. HTTP/2 is used when
// the dependency offers it.
func (s *Server) upstreamTransport(dst netip.AddrPort) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := s.dial(ctx, dst)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		TLSClientConfig:     &tls.Config{RootCAs: s.UpstreamRootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: s.peekTimeout(),
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
}

// discardLog silences net/http's own logging of client-side noise, which
// would otherwise bypass the proxy's structured logger.
var discardLog = log.New(io.Discard, "", 0)
