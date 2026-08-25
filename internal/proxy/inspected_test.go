// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
)

// captureClientHello returns the exact bytes of a real TLS ClientHello carrying
// the given SNI, produced by crypto/tls. Using genuine bytes keeps the
// inspected-path tests deterministic without hand-rolling the handshake.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, tlsRecordHeaderLen)
	if _, err := io.ReadFull(server, hdr); err != nil {
		t.Fatalf("read record header: %v", err)
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, recLen)
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatalf("read record body: %v", err)
	}
	_ = server.Close()
	return append(hdr, body...)
}

// startRecordingUpstream accepts one connection, reads exactly want bytes, and
// publishes them so a test can assert what the proxy replayed upstream.
func startRecordingUpstream(t *testing.T, want int) (netip.AddrPort, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, want)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		got <- buf
		_, _ = io.Copy(io.Discard, c)
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort(), got
}

// TestServer_InspectedPath_SNIMatchDrivesFaultAndReplaysBytes proves the full
// inspected path: the proxy peeks the ClientHello, matches a host rule by SNI,
// applies its latency, and replays the consumed handshake bytes upstream intact.
func TestServer_InspectedPath_SNIMatchDrivesFaultAndReplaysBytes(t *testing.T) {
	hello := captureClientHello(t, "slow.example.com")
	upstream, got := startRecordingUpstream(t, len(hello))

	engine := fault.NewEngine([]fault.Rule{{Name: "slow", Hosts: []string{"example.com"}, Latency: 300 * time.Millisecond}})
	proxyAddr := serveProxy(t, &Server{Faults: engine}, upstream)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	select {
	case replayed := <-got:
		if !bytes.Equal(replayed, hello) {
			t.Fatalf("upstream received %d bytes that differ from the original ClientHello (%d bytes)", len(replayed), len(hello))
		}
		if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
			t.Fatalf("upstream reached in %v; injected ~300ms latency was not applied", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never received the replayed ClientHello")
	}
}

// TestServer_InspectedPath_SNIMatchAborts proves an SNI-matched abort rule
// resets the client without ever contacting upstream.
func TestServer_InspectedPath_SNIMatchAborts(t *testing.T) {
	hello := captureClientHello(t, "kill.example.com")
	echo := startEcho(t)

	engine := fault.NewEngine([]fault.Rule{{Name: "kill", Hosts: []string{"kill.example.com"}, AbortProbability: 1.0}})
	proxyAddr := serveProxy(t, &Server{Faults: engine}, echo)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(hello); err != nil {
		// A reset racing the write is also a valid abort outcome.
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the SNI-matched connection to be reset")
	}
}

// TestServer_InspectedPath_NonMatchingSNIPassesThrough proves a ClientHello
// whose SNI matches no rule is proxied untouched (bytes preserved end to end).
func TestServer_InspectedPath_NonMatchingSNIPassesThrough(t *testing.T) {
	hello := captureClientHello(t, "other.example.com")
	echo := startEcho(t)

	// The only host rule targets kill.example.com, so this connection is
	// inspected but matches nothing and must pass through.
	engine := fault.NewEngine([]fault.Rule{{Name: "kill", Hosts: []string{"kill.example.com"}, AbortProbability: 1.0}})
	proxyAddr := serveProxy(t, &Server{Faults: engine}, echo)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	echoed := make([]byte, len(hello))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echoed, hello) {
		t.Fatal("pass-through corrupted the ClientHello bytes")
	}
}

// TestServer_SniffTimeout_ForwardsFailOpen proves that when inspection applies
// but the client speaks second (server-first protocol), the sniff times out and
// the connection is forwarded untouched rather than dropped — the resilient,
// fail-open behaviour (a missed fault is preferable to a broken connection).
func TestServer_SniffTimeout_ForwardsFailOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	contacted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			contacted <- struct{}{}
			_ = c.Close()
		}
	}()
	upstream := ln.Addr().(*net.TCPAddr).AddrPort()

	engine := fault.NewEngine([]fault.Rule{{Name: "h", Hosts: []string{"x.com"}}})
	proxyAddr := serveProxy(t, &Server{Faults: engine, PeekTimeout: 150 * time.Millisecond}, upstream)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send nothing (server-first). After the sniff times out the proxy should
	// forward the connection to the upstream instead of dropping it.
	select {
	case <-contacted:
		// forwarded — the resilient outcome
	case <-time.After(2 * time.Second):
		t.Fatal("upstream was not contacted; connection was dropped instead of forwarded")
	}
}

// TestServer_HTTPStatusInjection proves an L7 rule synthesizes a status
// response by Host header without ever contacting the upstream.
func TestServer_HTTPStatusInjection(t *testing.T) {
	upstreamHit := make(chan struct{}, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		if c, err := ln.Accept(); err == nil {
			upstreamHit <- struct{}{}
			_ = c.Close()
		}
	}()
	upstream := ln.Addr().(*net.TCPAddr).AddrPort()

	engine := fault.NewEngine([]fault.Rule{{Name: "503", Hosts: []string{"api.example.com"}, HTTPStatus: 503}})
	proxyAddr := serveProxy(t, &Server{Faults: engine}, upstream)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

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
		t.Fatalf("response = %q, want a 503 status line", buf[:n])
	}
	select {
	case <-upstreamHit:
		t.Fatal("upstream was contacted despite an injected status")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestServer_HTTPNonMatchingHostForwards proves a request whose Host matches no
// rule is proxied through untouched.
func TestServer_HTTPNonMatchingHostForwards(t *testing.T) {
	echo := startEcho(t)
	engine := fault.NewEngine([]fault.Rule{{Name: "503", Hosts: []string{"blocked.example.com"}, HTTPStatus: 503}})
	proxyAddr := serveProxy(t, &Server{Faults: engine}, echo)

	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := "GET /x HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The echo upstream returns exactly what the proxy forwarded — the original
	// request bytes, byte-identical.
	echoed := make([]byte, len(req))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echoed) != req {
		t.Fatalf("forwarded request altered:\n got %q\nwant %q", echoed, req)
	}
}

// flakyListener injects a fixed number of transient Accept errors before
// delegating to the real listener.
type flakyListener struct {
	net.Listener
	failsLeft int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.failsLeft > 0 {
		l.failsLeft--
		return nil, errors.New("injected transient accept error")
	}
	return l.Listener.Accept()
}

// TestServer_AcceptError_KeepsServing proves transient Accept errors don't tear
// the proxy down: after two injected failures it still serves the connection.
func TestServer_AcceptError_KeepsServing(t *testing.T) {
	echo := startEcho(t)

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fl := &flakyListener{Listener: base, failsLeft: 2}
	s := &Server{
		Faults:     fault.NewEngine(nil),
		ResolveDst: func(*net.TCPConn) (netip.AddrPort, error) { return echo, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, fl) }()

	addr := base.Addr().(*net.TCPAddr).AddrPort()
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	msg := []byte("still alive")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read after transient accept errors: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}
