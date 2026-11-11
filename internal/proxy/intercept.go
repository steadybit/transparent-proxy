// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"context"
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

// serveIntercepted rolls the fault per request rather than per connection, so
// the probability also holds for keep-alive and multiplexed HTTP/2 clients.
func (s *Server) serveIntercepted(ctx context.Context, log *slog.Logger, client *net.TCPConn, dst netip.AddrPort, identity string, prefix []byte) {
	c := &interceptedConn{s: s, log: log, client: client, dst: dst, identity: identity}
	upstream := s.upstreamTransport(dst)
	defer upstream.CloseIdleConnections()
	c.proxy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "https"
			r.Out.URL.Host = r.In.Host
			if r.Out.URL.Host == "" {
				r.Out.URL.Host = identity
			}
			keepForwardedHeaders(r)
		},
		Transport:    upstream,
		ErrorLog:     discardLog,
		ErrorHandler: c.upstreamFailed,
	}

	err := s.TLSInject.Serve(ctx, client, prefix, s.peekTimeout(), http.HandlerFunc(c.faultOrForward))

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

// interceptedConn's flags are atomic because its handler runs concurrently for
// the streams of an HTTP/2 connection.
type interceptedConn struct {
	s        *Server
	log      *slog.Logger
	client   *net.TCPConn
	dst      netip.AddrPort
	identity string
	proxy    *httputil.ReverseProxy

	faulted   atomic.Bool
	forwarded atomic.Bool
}

func (c *interceptedConn) faultOrForward(w http.ResponseWriter, r *http.Request) {
	host := hostWithoutPort(r.Host)
	action := c.s.Faults.Match(c.dst, host)
	c.s.countRequest(host, c.identity, action, &c.faulted)

	if action.Abort {
		c.s.Metrics.Aborted()
		c.log.Debug("aborting request")
		// HTTP/1.1 carries one request at a time, so resetting the TCP
		// connection fails just this request, as on cleartext HTTP; a plain
		// close would read as a clean EOF instead of a reset. On HTTP/2 the
		// panic resets only this stream and the connection's other streams go on.
		if r.ProtoMajor == 1 {
			reset(c.client)
		}
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

// upstreamFailed answers 502, as a gateway would, and counts an upstream error
// rather than a fault: the attack did not cause it. A request the client gave
// up on is neither, and there is no one left to answer.
func (c *interceptedConn) upstreamFailed(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		c.log.Debug("client cancelled a forwarded request", slog.Any("err", err))
		return
	}
	c.s.Metrics.UpstreamError()
	c.log.Warn("forwarding an intercepted request failed", slog.Any("err", err))
	w.WriteHeader(http.StatusBadGateway)
}

// upstreamTransport dials the connection's original destination instead of
// resolving the request's host, so requests reach the dependency the workload
// chose. Its certificate is still verified for the request's host.
func (s *Server) upstreamTransport(dst netip.AddrPort) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := s.dial(ctx, dst)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		TLSClientConfig:     s.upstreamTLSConfig(),
		TLSHandshakeTimeout: s.peekTimeout(),
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
}

// keepForwardedHeaders restores what ReverseProxy strips when Rewrite is set:
// a request that is not faulted must reach the dependency as the workload sent
// it.
func keepForwardedHeaders(r *httputil.ProxyRequest) {
	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if v, ok := r.In.Header[h]; ok {
			r.Out.Header[h] = v
		}
	}
}

// discardLog silences net/http's own logging of client-side noise, which
// would otherwise bypass the proxy's structured logger.
var discardLog = log.New(io.Discard, "", 0)
