// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build linux && integration

// Full-path interception test: installs the real interception rules and drives
// a connection through client -> iptables REDIRECT -> proxy -> upstream, with
// SO_MARK loop protection active. Requires Linux, root, and iptables.
//
//	go test -tags integration ./internal/proxy/ -run TestRedirect -v
package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/interception"
)

func TestRedirect_FullCaptureWithLoopProtection(t *testing.T) {
	// Upstream echo the proxy must forward to.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	upPort := uint16(upLn.Addr().(*net.TCPAddr).Port)

	// Proxy listener. Mark is set so its own dial to the upstream is exempted
	// from the REDIRECT (otherwise it would redirect back to itself).
	pxLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer pxLn.Close()
	pxPort := uint16(pxLn.Addr().(*net.TCPAddr).Port)

	srv := &Server{Faults: fault.NewEngine(nil), Mark: interception.DefaultMark}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, pxLn) }()

	// Install interception: redirect TCP to 127.0.0.1:<upPort> to the proxy.
	cfg := interception.Config{
		ExecutionID: "e2e-redirect",
		ProxyPort:   pxPort,
		Filter: interception.Filter{
			Include: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			Ports:   []uint16{upPort},
		},
	}
	if err := cfg.Apply(ctx, interception.ExecRunner{}); err != nil {
		t.Fatalf("apply interception: %v", err)
	}
	defer func() {
		if err := cfg.Revert(context.Background(), interception.ExecRunner{}); err != nil {
			t.Errorf("revert interception: %v", err)
		}
	}()

	// Connect to the upstream address; the kernel redirects us to the proxy,
	// which recovers the original destination and forwards to the real upstream
	// (its marked dial escapes the redirect).
	conn, err := net.DialTimeout("tcp", upLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial redirected upstream: %v", err)
	}
	defer conn.Close()

	msg := []byte("through the redirect")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo (capture or loop-protection likely broken): %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}
