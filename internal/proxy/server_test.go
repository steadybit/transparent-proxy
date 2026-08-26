// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
)

// startEcho starts a TCP echo server and returns its address.
func startEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

// startProxy runs a Server whose ResolveDst always points at dst.
func startProxy(t *testing.T, dst netip.AddrPort, engine *fault.Engine) netip.AddrPort {
	t.Helper()
	return serveProxy(t, &Server{Faults: engine}, dst)
}

// serveProxy serves s on a fresh loopback listener, defaulting ResolveDst to
// dst, and returns the address to dial. It lets a test supply a customised
// Server (e.g. PeekTimeout) while sharing the listen/serve boilerplate.
func serveProxy(t *testing.T, s *Server, dst netip.AddrPort) netip.AddrPort {
	t.Helper()
	if s.ResolveDst == nil {
		s.ResolveDst = func(*net.TCPConn) (netip.AddrPort, error) { return dst, nil }
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func TestServer_PassThrough(t *testing.T) {
	echo := startEcho(t)
	proxyAddr := startProxy(t, echo, fault.NewEngine(nil))

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping through the proxy")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestServer_AbortResetsConnection(t *testing.T) {
	echo := startEcho(t)
	engine := fault.NewEngine([]fault.Rule{{Name: "kill", Abort: true}})
	proxyAddr := startProxy(t, echo, engine)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		// On Linux the RST can race connect() and surface here — still a valid
		// abort outcome, not a test failure.
		return
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	// The proxy resets instead of proxying, so the read ends in EOF/reset.
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the aborted connection to fail, got a successful read")
	}
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

func TestServer_MetricsRecordProxiedConnection(t *testing.T) {
	echo := startEcho(t)
	m := metrics.New()
	proxyAddr := serveProxy(t, &Server{Faults: fault.NewEngine(nil), Metrics: m}, echo)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	msg := []byte("measure me")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	// Matched increments synchronously once the destination resolves.
	eventually(t, func() bool { return m.Snapshot().ConnectionsMatched == 1 })

	_ = conn.Close()
	// Proxied + byte counts settle once both halves close.
	eventually(t, func() bool {
		s := m.Snapshot()
		return s.ConnectionsProxied == 1 && s.BytesToUpstream == int64(len(msg)) && s.ConnectionsActive == 0
	})
}

func TestServer_MetricsRecordAbort(t *testing.T) {
	echo := startEcho(t)
	m := metrics.New()
	engine := fault.NewEngine([]fault.Rule{{Name: "kill", Abort: true}})
	proxyAddr := serveProxy(t, &Server{Faults: engine, Metrics: m}, echo)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = conn.Read(make([]byte, 1))
		_ = conn.Close()
	}
	eventually(t, func() bool {
		s := m.Snapshot()
		return s.ConnectionsMatched == 1 && s.ConnectionsAborted == 1
	})
}

func TestServer_SelfLoopGuard(t *testing.T) {
	// An upstream echo that must never be reached.
	echo := startEcho(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	self := ln.Addr().(*net.TCPAddr).AddrPort()

	// ResolveDst points every connection back at the proxy's own listener.
	s := &Server{
		Faults:     fault.NewEngine(nil),
		ResolveDst: func(*net.TCPConn) (netip.AddrPort, error) { return self, nil },
	}
	_ = echo
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()

	conn, err := net.DialTimeout("tcp", self.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// The loop guard should drop the connection rather than dialing itself.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the self-referential connection to be dropped")
	}
}

func TestServer_LatencyDelaysConnect(t *testing.T) {
	echo := startEcho(t)
	engine := fault.NewEngine([]fault.Rule{{Name: "slow", Latency: 300 * time.Millisecond}})
	proxyAddr := startProxy(t, echo, engine)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("first byte returned in %v, expected the injected ~300ms latency", elapsed)
	}
}
