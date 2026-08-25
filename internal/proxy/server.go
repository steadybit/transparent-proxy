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
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
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

	// listenPort is captured at Serve time for the self-loop guard.
	listenPort int
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

	// Identify the target by SNI only when a host rule could match this
	// destination; otherwise stay on the pure-splice fast path and never touch
	// the payload in userspace. The peek is deadline-bounded so a
	// server-speaks-first protocol can't deadlock it.
	var (
		sni    string
		prefix []byte
	)
	if s.Faults.InspectSNI(dst) {
		_ = client.SetReadDeadline(time.Now().Add(s.peekTimeout()))
		sni, prefix, err = peekClientHello(client)
		_ = client.SetReadDeadline(time.Time{})
		if err != nil {
			// A failed/timed-out handshake read would leave us guessing the
			// rule and replaying a truncated ClientHello upstream. Drop it.
			s.Metrics.Dropped()
			log.Debug("client hello peek failed; dropping connection",
				slog.Any("err", err), slog.String("dst", dst.String()))
			return
		}
	}

	action := s.Faults.Match(dst, sni)
	log = log.With(
		slog.String("dst", dst.String()),
		slog.String("sni", sni),
		slog.String("rule", action.Rule),
	)

	if action.Abort {
		s.Metrics.Aborted()
		log.Info("aborting connection (reset)")
		reset(client)
		return
	}
	if action.Latency > 0 {
		select {
		case <-time.After(action.Latency):
		case <-ctx.Done():
			return
		}
	}

	upstream, err := s.dial(ctx, dst)
	if err != nil {
		s.Metrics.UpstreamError()
		log.Warn("upstream dial failed", slog.Any("err", err))
		return
	}
	defer func() { _ = upstream.Close() }()

	// Replay the bytes consumed during SNI inspection, then splice the rest.
	if len(prefix) > 0 {
		if _, err := upstream.Write(prefix); err != nil {
			log.Debug("failed to replay client hello", slog.Any("err", err))
			return
		}
	}

	log.Debug("proxying")
	toUpstream, toClient := relay(client, upstream)
	s.Metrics.AddBytes(toUpstream, toClient)
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

// isSelf reports whether dst points back at this proxy's own listener.
func (s *Server) isSelf(dst netip.AddrPort) bool {
	return s.listenPort != 0 && int(dst.Port()) == s.listenPort && dst.Addr().IsLoopback()
}

// reset closes c with a TCP RST rather than a graceful FIN, so the client sees
// a connection reset (mirroring a dependency that refuses/drops the connection).
func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}
