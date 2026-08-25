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
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
)

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
	inspect := s.Faults.NeedsSNI()
	s.logger().Info("transparent-proxy listening",
		slog.String("addr", ln.Addr().String()),
		slog.Bool("sni_inspection", inspect))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			continue
		}
		go s.handle(ctx, tcp, inspect)
	}
}

func (s *Server) handle(ctx context.Context, client *net.TCPConn, inspect bool) {
	defer func() { _ = client.Close() }()
	log := s.logger()

	dst, err := s.resolve(client)
	if err != nil {
		log.Warn("could not resolve original destination", slog.Any("err", err))
		return
	}

	// Identify the target by SNI only when a rule needs it; otherwise stay on
	// the pure-splice fast path and never touch the payload in userspace.
	var (
		sni    string
		prefix []byte
	)
	if inspect {
		sni, prefix, err = peekClientHello(client)
		if err != nil && len(prefix) == 0 {
			log.Debug("client hello peek failed", slog.Any("err", err))
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
	relay(client, upstream)
}

func (s *Server) dial(ctx context.Context, dst netip.AddrPort) (*net.TCPConn, error) {
	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// reset closes c with a TCP RST rather than a graceful FIN, so the client sees
// a connection reset (mirroring a dependency that refuses/drops the connection).
func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}
