// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Package proxy implements a transparent L4 TCP proxy. Connections are captured
// by an out-of-band iptables REDIRECT/TPROXY rule; the proxy recovers each
// connection's original destination, optionally identifies the target by TLS
// SNI, applies a fault from the fault engine, and splices bytes through to the
// real upstream.
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
	"github.com/steadybit/transparent-proxy/internal/tlsinject"
)

const keepAlivePeriod = 30 * time.Second

// enableKeepAlive turns on TCP keepalive so the kernel eventually reaps a
// connection whose peer has gone away silently, bounding goroutine/socket leaks
// in the deadline-less relay.
func enableKeepAlive(c *net.TCPConn) {
	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(keepAlivePeriod)
}

// Server is a transparent TCP proxy.
type Server struct {
	// Listen is the address the proxy accepts redirected connections on
	// (e.g. "0.0.0.0:3128"). The iptables rule must REDIRECT to this port.
	Listen string

	// Faults decides what to do with each connection.
	Faults *fault.Engine

	// Logger receives structured logs. Defaults to slog.Default().
	Logger *slog.Logger

	// ResolveDst recovers a connection's original destination. Defaults to
	// the platform SO_ORIGINAL_DST lookup; overridable in tests.
	ResolveDst func(*net.TCPConn) (netip.AddrPort, error)

	// DialTimeout bounds establishing the upstream connection.
	DialTimeout time.Duration

	// PeekTimeout bounds the TLS ClientHello read when SNI inspection applies,
	// so server-speaks-first protocols (SMTP, MySQL, ...) don't deadlock the
	// peek. Defaults to 5s.
	PeekTimeout time.Duration

	// Mark, when non-zero, is stamped as SO_MARK on every upstream socket so the
	// interception rules can exempt (RETURN) the proxy's own traffic. Without it
	// the REDIRECT rule re-captures the proxy's upstream dial and self-loops.
	Mark uint32

	// Metrics, if set, records per-connection outcomes. A zero
	// ConnectionsMatched under load is the canonical silent-no-op signal.
	Metrics *metrics.Metrics

	// TLSInject, when non-nil, enables HTTPS response injection: a matched TLS
	// connection carrying an L7 status fault is terminated with a certificate
	// minted for its SNI, and the synthesized response is written inside TLS.
	// Nil (the default) means TLS is never decrypted — HTTPS connections are
	// spliced through untouched exactly as before.
	TLSInject *tlsinject.CA

	// listenPort and localAddrs are captured at Serve time for the self-loop
	// guard, so a redirected flow resolving back to this proxy (on loopback or
	// any local interface address) is refused rather than dialed in a storm.
	listenPort int
	localAddrs map[netip.Addr]bool
}

func (s *Server) peekTimeout() time.Duration {
	if s.PeekTimeout > 0 {
		return s.PeekTimeout
	}
	return 5 * time.Second
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) resolve(c *net.TCPConn) (netip.AddrPort, error) {
	if s.ResolveDst != nil {
		return s.ResolveDst(c)
	}
	return originalDst(c)
}

// Run binds Listen and serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled. ln is closed on exit.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.Faults == nil {
		s.Faults = fault.NewEngine(nil)
	}
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		s.listenPort = a.Port
	}
	s.localAddrs = localInterfaceAddrs()
	s.logger().Info("transparent-proxy listening",
		slog.String("addr", ln.Addr().String()),
		slog.Bool("sni_inspection", s.Faults.NeedsSNI()),
		slog.Bool("loop_protection", s.Mark != 0))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var backoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Keep serving on transient accept errors (e.g. EMFILE/ENFILE)
			// with capped exponential backoff instead of tearing the proxy
			// down and dropping every in-flight and future connection.
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff < time.Second {
				backoff *= 2
			}
			s.logger().Warn("accept error; backing off",
				slog.Any("err", err), slog.Duration("delay", backoff))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			continue
		}
		go s.handle(ctx, tcp)
	}
}

func (s *Server) handle(ctx context.Context, client *net.TCPConn) {
	defer func() { _ = client.Close() }()
	log := s.logger()

	enableKeepAlive(client)

	dst, err := s.resolve(client)
	if err != nil {
		log.Warn("could not resolve original destination", slog.Any("err", err))
		return
	}

	// A resolved connection is one the interception delivered to us; count it so
	// a zero ConnectionsMatched exposes a silent no-op (e.g. Cilium socketLB).
	done := s.Metrics.MatchedConnection()
	defer done()

	// Self-loop guard: never forward to our own listener. The SO_MARK exemption
	// is the primary defence, but if a redirected flow still resolves back to
	// this proxy, forwarding it would spiral into a connection storm.
	if s.isSelf(dst) {
		s.Metrics.Dropped()
		log.Warn("refusing to forward to own listener (loop guard)", slog.String("dst", dst.String()))
		return
	}

	// Sniff the payload only when a rule could match on identity or an L7 fault;
	// otherwise stay on the pure-splice fast path and never touch the bytes. The
	// read is deadline-bounded so a server-speaks-first protocol can't deadlock
	// it, and on any error we fail toward forwarding (never dropping).
	var (
		proto    = protoOther
		identity string
		prefix   []byte
	)
	if s.Faults.Inspect(dst) {
		_ = client.SetReadDeadline(time.Now().Add(s.peekTimeout()))
		proto, identity, prefix, err = sniff(client)
		_ = client.SetReadDeadline(time.Time{})
		if err != nil {
			// Uncertain input (timeout / partial / server-first): don't guess a
			// rule or drop — forward what we read untouched (fail open).
			log.Debug("payload sniff inconclusive; forwarding untouched",
				slog.Any("err", err), slog.String("dst", dst.String()))
			s.forward(ctx, log, client, dst, prefix)
			return
		}
	}

	action := s.Faults.Match(dst, identity)
	log = log.With(
		slog.String("dst", dst.String()),
		slog.String("rule", action.Rule),
	)
	// identity (the TLS SNI or HTTP Host) is potentially sensitive, so it is
	// only ever logged at debug — never at the info level that ships by default
	// — while still feeding the per-host statistics the operator sees.
	if identity != "" {
		log.Debug("matched dependency", slog.String("identity", identity))
	}
	if action.Rule != "" {
		s.Metrics.MatchedHost(identity)
	}
	// faulted is recorded at the point a fault actually applies — not
	// speculatively from the Action — so per-host and global "faulted" counts
	// stay in step and never over-report (e.g. an HTTP rule on a TLS connection,
	// which is forwarded untouched). It fires at most once per connection.
	faultRecorded := false
	markFaulted := func() {
		if !faultRecorded {
			faultRecorded = true
			s.Metrics.Faulted()
			s.Metrics.FaultedHost(identity)
		}
	}

	if action.Abort {
		markFaulted()
		s.Metrics.Aborted()
		log.Info("aborting connection (reset)")
		reset(client)
		return
	}

	if action.Latency > 0 {
		markFaulted()
		s.Metrics.LatencyInjected()
		select {
		case <-time.After(action.Latency):
		case <-ctx.Done():
			s.Metrics.Dropped()
			return
		}
	}

	// L7: synthesize an HTTP status response without contacting the upstream.
	// Cleartext HTTP is written directly. HTTPS is only decrypted when a CA is
	// configured and the client offered an SNI to mint a certificate for;
	// otherwise the connection falls through and is spliced untouched, which is
	// the pre-CA behaviour.
	if action.HTTPStatus != 0 {
		switch {
		case proto == protoHTTP:
			markFaulted()
			if err := writeHTTPResponse(client, action.HTTPStatus, action.HTTPHeaders, action.HTTPBody); err != nil {
				log.Debug("failed to write injected status", slog.Any("err", err))
			}
			s.Metrics.HTTPInjected()
			log.Info("injected http status", slog.Int("status", action.HTTPStatus))
			return

		case proto == protoTLS && s.TLSInject != nil && identity != "":
			// Counted from the delivery callback, not after ServeForged returns: an
			// HTTP/2 client keeps the connection pooled for the whole attack, so
			// counting on return would report a working fault as "matched but never
			// faulted" — the proxy's own silent-no-op signature.
			err := s.TLSInject.ServeForged(ctx, client, prefix, tlsinject.Request{
				Response: tlsinject.Response{
					Status:  action.HTTPStatus,
					Body:    action.HTTPBody,
					Headers: action.HTTPHeaders,
				},
				HandshakeTimeout: s.peekTimeout(),
				OnDelivered: func() {
					markFaulted()
					s.Metrics.HTTPInjected()
					log.Info("injected https status", slog.Int("status", action.HTTPStatus))
				},
			})

			var rejErr *tlsinject.RejectedError
			if errors.As(err, &rejErr) {
				// The client rejected our certificate, so the fault never applied —
				// counted separately from faults, never as one. This is the signal
				// that the CA is missing from the workload's truststore.
				s.Metrics.TLSRejected()
				log.Warn("client rejected the injected certificate; is the CA trusted by the target?",
					slog.String("stage", rejErr.Stage),
					slog.Any("err", err))
				return
			}
			if err != nil {
				// The connection was taken over and cannot be forwarded now, so it
				// ends here. Count it so matched still reconciles with the outcome
				// counters instead of silently losing a connection.
				s.Metrics.Dropped()
				log.Debug("failed to serve injected https response", slog.Any("err", err))
				return
			}
			// Success is reported by OnDelivered above, which fires when the
			// response is written rather than when the connection ends.
			return
		}
	}

	s.forward(ctx, log, client, dst, prefix)
}

// forward dials the upstream, replays any bytes consumed during sniffing, and
// splices the connection through. Every terminal counter is recorded here.
func (s *Server) forward(ctx context.Context, log *slog.Logger, client *net.TCPConn, dst netip.AddrPort, prefix []byte) {
	upstream, err := s.dial(ctx, dst)
	if err != nil {
		s.Metrics.UpstreamError()
		log.Warn("upstream dial failed", slog.Any("err", err))
		return
	}
	defer func() { _ = upstream.Close() }()

	if len(prefix) > 0 {
		if _, err := upstream.Write(prefix); err != nil {
			log.Debug("failed to replay sniffed prefix", slog.Any("err", err))
			return
		}
	}

	log.Debug("proxying")
	toUpstream, toClient := relay(client, upstream)
	s.Metrics.AddBytes(toUpstream+int64(len(prefix)), toClient)
	s.Metrics.Proxied()
}

func (s *Server) dial(ctx context.Context, dst netip.AddrPort) (*net.TCPConn, error) {
	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout, KeepAlive: keepAlivePeriod}
	if s.Mark != 0 {
		mark := s.Mark
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var markErr error
			if err := c.Control(func(fd uintptr) { markErr = setSocketMark(fd, mark) }); err != nil {
				return err
			}
			return markErr
		}
	}
	conn, err := d.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// isSelf reports whether dst points back at this proxy's own listener — on
// loopback or on any of this host's interface addresses.
func (s *Server) isSelf(dst netip.AddrPort) bool {
	if s.listenPort == 0 || int(dst.Port()) != s.listenPort {
		return false
	}
	addr := dst.Addr().Unmap()
	return addr.IsLoopback() || s.localAddrs[addr]
}

// localInterfaceAddrs snapshots this host's unicast IPs for the loop guard.
func localInterfaceAddrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out[ip.Unmap()] = true
			}
		}
	}
	return out
}

// reset closes c with a TCP RST rather than a graceful FIN, so the client sees
// a connection reset (mirroring a dependency that refuses/drops the connection).
func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}
