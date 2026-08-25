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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	s := &Server{
		Faults:     engine,
		ResolveDst: func(*net.TCPConn) (netip.AddrPort, error) { return dst, nil },
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
	engine := fault.NewEngine([]fault.Rule{{Name: "kill", AbortProbability: 1.0}})
	proxyAddr := startProxy(t, echo, engine)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	// The proxy resets instead of proxying, so the read ends in EOF/reset.
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the aborted connection to fail, got a successful read")
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
