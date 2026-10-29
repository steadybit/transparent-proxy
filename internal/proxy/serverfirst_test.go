// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
)

// startGreetingServer accepts connections, sends greeting immediately (as
// MySQL, SMTP or SSH do), then echoes whatever the client sends.
func startGreetingServer(t *testing.T, greeting string) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, greeting)
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

// TestServer_ServerFirstGreetingIsNotStalled proves a server-first protocol is
// not held for the whole peek timeout when ServerFirstTimeout is set: the
// upstream is dialed early and its greeting reaches the client promptly.
func TestServer_ServerFirstGreetingIsNotStalled(t *testing.T) {
	const greeting = "220 mail.example.com ESMTP\r\n"
	upstream := startGreetingServer(t, greeting)
	engine := fault.NewEngine([]fault.Rule{{Name: "h", Hosts: []string{"x.com"}, Latency: time.Second}})
	proxyAddr := serveProxy(t, &Server{Faults: engine, PeekTimeout: 5 * time.Second, ServerFirstTimeout: 50 * time.Millisecond}, upstream)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	buf := make([]byte, len(greeting))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if string(buf) != greeting {
		t.Fatalf("greeting = %q, want %q", buf, greeting)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("greeting took %v; the connection was stalled for the peek timeout", elapsed)
	}

	// The rest of the session is spliced through untouched.
	if _, err := io.WriteString(conn, "EHLO me\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len("EHLO me\r\n"))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != "EHLO me\r\n" {
		t.Fatalf("echo = %q", echo)
	}
}

// TestServer_LateClientIsStillFaulted proves a client that connects ahead of
// use (a pre-warmed pool) and speaks after ServerFirstTimeout is still
// identified and faulted, even though the upstream was dialed early.
func TestServer_LateClientIsStillFaulted(t *testing.T) {
	echo := startEcho(t)
	engine := fault.NewEngine([]fault.Rule{{Name: "503", Hosts: []string{"api.example.com"}, HTTPStatus: 503}})
	proxyAddr := serveProxy(t, &Server{Faults: engine, ServerFirstTimeout: 50 * time.Millisecond}, echo)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	time.Sleep(200 * time.Millisecond) // well past ServerFirstTimeout
	if _, err := io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: api.example.com\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.HasPrefix(buf[:n], []byte("HTTP/1.1 503")) {
		t.Fatalf("response = %q, want an injected 503", buf[:n])
	}
}

// TestServer_LateClientNotFaultedReusesEarlyUpstream proves a silent-then-
// speaking client that matches no rule is forwarded byte-identical.
func TestServer_LateClientNotFaultedReusesEarlyUpstream(t *testing.T) {
	echo := startEcho(t)
	engine := fault.NewEngine([]fault.Rule{{Name: "503", Hosts: []string{"blocked.example.com"}, HTTPStatus: 503}})
	proxyAddr := serveProxy(t, &Server{Faults: engine, ServerFirstTimeout: 50 * time.Millisecond}, echo)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	time.Sleep(200 * time.Millisecond)
	req := "GET /x HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(req))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != req {
		t.Fatalf("forwarded request altered:\n got %q\nwant %q", got, req)
	}
}
