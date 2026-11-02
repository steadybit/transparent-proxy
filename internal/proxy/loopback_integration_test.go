// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build linux && integration

// Loopback capture under real iptables: loopback is left alone by default, with
// or without ports, and captured only when Filter.Loopback is set — except for
// LoopbackExcludePorts. Requires Linux, root, and iptables:
//
//	go test -tags integration ./internal/proxy/ -run TestRedirect_Loopback -v
package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/interception"
)

// countingListener counts the connections the proxy accepted, i.e. the ones
// the REDIRECT captured.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

func TestRedirect_Loopback(t *testing.T) {
	// testNet is TEST-NET-1: an include that is never dialled, so the all-ports
	// cases capture nothing on the host but loopback (when enabled).
	testNet := netip.MustParsePrefix("192.0.2.1/32")
	everywhere := netip.MustParsePrefix("0.0.0.0/0")

	cases := []struct {
		name         string
		allPorts     bool
		loopback     bool
		excludeOwn   bool
		wantCaptured bool
	}{
		{name: "ports, loopback excluded by default"},
		{name: "all ports, loopback excluded by default", allPorts: true},
		{name: "ports, loopback captured", loopback: true, wantCaptured: true},
		{name: "all ports, loopback captured", allPorts: true, loopback: true, wantCaptured: true},
		{name: "ports, loopback captured except own port", loopback: true, excludeOwn: true},
		{name: "all ports, loopback captured except own port", allPorts: true, loopback: true, excludeOwn: true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen proxy: %v", err)
			}
			pxLn := &countingListener{Listener: ln}
			defer pxLn.Close()
			srv := &Server{Faults: fault.NewEngine(nil), Mark: interception.DefaultMark}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = srv.Serve(ctx, pxLn) }()

			filter := interception.Filter{Loopback: tc.loopback}
			if tc.allPorts {
				filter.Include = []netip.Prefix{testNet, netip.MustParsePrefix("127.0.0.1/32")}
				filter.AllPorts = true
			} else {
				filter.Include = []netip.Prefix{everywhere}
				filter.Ports = []uint16{upPort}
			}
			if tc.excludeOwn {
				filter.LoopbackExcludePorts = []uint16{upPort}
			}
			cfg := interception.Config{
				ExecutionID: "e2e-loopback" + string(rune('a'+i)),
				ProxyPort:   uint16(ln.Addr().(*net.TCPAddr).Port),
				SkipFlush:   true,
				Filter:      filter,
			}
			if err := cfg.Apply(ctx, interception.ExecRunner{}); err != nil {
				t.Fatalf("apply interception: %v", err)
			}
			defer func() {
				if err := cfg.Revert(context.Background(), interception.ExecRunner{}); err != nil {
					t.Errorf("revert interception: %v", err)
				}
			}()

			conn, err := net.DialTimeout("tcp", upLn.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatalf("dial upstream: %v", err)
			}
			defer conn.Close()
			msg := []byte("over loopback")
			if _, err := conn.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, len(msg))
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if !bytes.Equal(buf, msg) {
				t.Fatalf("echo = %q, want %q", buf, msg)
			}

			if got := pxLn.accepted.Load() > 0; got != tc.wantCaptured {
				t.Errorf("captured by the proxy = %v, want %v", got, tc.wantCaptured)
			}
		})
	}
}
