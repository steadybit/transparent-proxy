// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package tlsinject

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSNI = "api.anthropic.com"

// serveOnce accepts a single connection and serves it with handler, returning
// the listener address and a channel carrying Serve's result.
func serveOnce(t *testing.T, ca *CA, handler http.Handler) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ch := make(chan error, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			ch <- aerr
			return
		}
		ch <- ca.Serve(context.Background(), conn, nil, 5*time.Second, handler)
	}()
	return ln.Addr().String(), ch
}

// clientTrusting builds a client that trusts caPEM and pins the SNI, so the
// request looks like one aimed at the dependency regardless of the dial address.
func clientTrusting(t *testing.T, caPEM []byte, h2 bool) (*http.Client, *http.Transport) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to add test CA to pool")
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: testSNI, MinVersion: tls.VersionTLS12}
	if !h2 {
		cfg.NextProtos = []string{"http/1.1"}
	}
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: h2}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}, tr
}

func waitServed(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
		return nil
	}
}

func Test_Serve_http1(t *testing.T) {
	ca, caPEM := mustLoadTestCA(t)
	addr, ch := serveOnce(t, ca, Response{
		Status:  503,
		Body:    `{"error":"injected"}`,
		Headers: map[string]string{"Retry-After": "30", "Content-Type": "application/json"},
	})
	client, tr := clientTrusting(t, caPEM, false)

	resp, err := client.Get("https://" + addr + "/v1/messages")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("proto = %q, want HTTP/1.1", resp.Proto)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"error":"injected"}` {
		t.Fatalf("body = %q", body)
	}
	if got := resp.Header.Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After = %q, want 30", got)
	}
	// A caller-supplied Content-Type must win over the default.
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	// The connection is kept alive for further requests; releasing it lets the
	// server finish.
	tr.CloseIdleConnections()
	if err := waitServed(t, ch); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// Serve answers every request on a kept-alive connection, which is what lets
// the caller decide per request instead of per connection.
func Test_Serve_keepAliveServesEveryRequest(t *testing.T) {
	ca, caPEM := mustLoadTestCA(t)
	var served atomic.Int64
	addr, ch := serveOnce(t, ca, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	client, tr := clientTrusting(t, caPEM, false)

	for i := range 3 {
		resp, err := client.Get("https://" + addr + "/")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if got := served.Load(); got != 3 {
		t.Fatalf("served %d requests, want 3", got)
	}

	tr.CloseIdleConnections()
	if err := waitServed(t, ch); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// The dependency this targets speaks HTTP/2, so serving the forged response
// over h2 is the case that matters most in practice.
func Test_Serve_http2(t *testing.T) {
	ca, caPEM := mustLoadTestCA(t)
	addr, ch := serveOnce(t, ca, Response{Status: 503})
	client, tr := clientTrusting(t, caPEM, true)

	resp, err := client.Get("https://" + addr + "/v1/messages")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %q, want HTTP/2.0", resp.Proto)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if !strings.Contains(string(body), "injected by steadybit") {
		t.Fatalf("default body missing marker: %q", body)
	}

	// h2 keeps the connection open for further streams; releasing it lets the
	// server finish.
	tr.CloseIdleConnections()
	if err := waitServed(t, ch); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// The canonical failure mode: the workload does not trust our CA. It must be
// reported as a HandshakeError so the caller can count it and say so, rather
// than looking like a silent no-op.
func Test_Serve_untrustedClientYieldsHandshakeError(t *testing.T) {
	ca, _ := mustLoadTestCA(t)
	addr, ch := serveOnce(t, ca, Response{Status: 503})

	tr := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    x509.NewCertPool(), // trusts nothing
		ServerName: testSNI,
		MinVersion: tls.VersionTLS12,
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	if _, err := client.Get("https://" + addr + "/v1/messages"); err == nil {
		t.Fatal("expected the client to reject the injected certificate")
	}

	err := waitServed(t, ch)
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("err = %v, want a *RejectedError", err)
	}
}

// Under TLS 1.3 the server's handshake completes before the client reports that
// it dislikes the certificate — the client simply walks away without sending a
// request. Observed with curl/OpenSSL against a real proxy, where it made a
// rejected connection look like a successfully injected fault. A completed
// handshake is therefore not proof of trust; an actual request is.
func Test_Serve_rejectedAfterHandshakeIsNotDelivery(t *testing.T) {
	ca, caPEM := mustLoadTestCA(t)
	addr, ch := serveOnce(t, ca, Response{Status: 503})

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs: pool, ServerName: testSNI, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Complete the handshake, then leave without a request — exactly what a
	// client that refuses the certificate does.
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_ = conn.Close()

	err = waitServed(t, ch)
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("err = %v, want a *RejectedError (no request was ever sent)", err)
	}
	if rej.Stage != "post-handshake" {
		t.Fatalf("stage = %q, want post-handshake", rej.Stage)
	}
}

// Regression: an HTTP/2 client pools the connection for the whole attack, so
// each request must reach the handler while the connection is open — not when
// it ends. Otherwise the caller could only count a demonstrably working fault
// late, as "matched but never faulted", the proxy's silent-no-op signature.
func Test_Serve_handlesRequestsBeforeConnectionCloses(t *testing.T) {
	ca, caPEM := mustLoadTestCA(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	delivered := make(chan struct{}, 1)
	ch := make(chan error, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			ch <- aerr
			return
		}
		ch <- ca.Serve(context.Background(), conn, nil, 5*time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Response{Status: 503}.ServeHTTP(w, r)
			delivered <- struct{}{}
		}))
	}()

	client, tr := clientTrusting(t, caPEM, true)
	resp, err := client.Get("https://" + ln.Addr().String() + "/v1/messages")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %q, want HTTP/2.0 so the connection stays pooled", resp.Proto)
	}

	// The connection is still open here; delivery must already be reported.
	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request did not reach the handler while the h2 connection was open")
	}
	select {
	case err := <-ch:
		t.Fatalf("Serve returned early (%v); the h2 connection should still be open", err)
	default:
	}

	tr.CloseIdleConnections()
	if err := waitServed(t, ch); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// Teardown must never be booked as a request or a rejection: the client sent
// nothing, so the handler must not run.
func Test_Serve_cancelBeforeAnyRequest(t *testing.T) {
	ca, caPEM := mustLoadTestCA(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	var handled atomic.Int64
	ch := make(chan error, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			ch <- aerr
			return
		}
		ch <- ca.Serve(ctx, conn, nil, 5*time.Second, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			handled.Add(1)
		}))
	}()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs: pool, ServerName: testSNI, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cancel()
	if err := waitServed(t, ch); err != nil && !errors.Is(err, net.ErrClosed) {
		var rej *RejectedError
		if errors.As(err, &rej) {
			t.Fatalf("teardown was misreported as a client rejection: %v", err)
		}
	}
	if got := handled.Load(); got != 0 {
		t.Fatalf("the handler ran %d times on teardown; no request was sent", got)
	}
}

func Test_Serve_cancelledContextClosesConnection(t *testing.T) {
	ca, caPEM := mustLoadTestCA(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			ch <- aerr
			return
		}
		ch <- ca.Serve(ctx, conn, nil, 5*time.Second, Response{Status: 503})
	}()

	// HTTP/2 holds the connection open after the response, so once a reply has
	// been read the server is definitively parked inside net/http — exactly the
	// state an attack teardown has to unblock. Driving a real request first also
	// removes any race with the handshake still completing.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: testSNI, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %q, want HTTP/2.0 so the connection stays open", resp.Proto)
	}

	cancel()
	if err := waitServed(t, ch); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve after cancel: %v", err)
	}
}

func Test_Response_defaults(t *testing.T) {
	// An out-of-range status falls back to 503 rather than producing an invalid
	// response.
	for _, status := range []int{0, 42, 700} {
		r := Response{Status: status}
		if got := r.resolvedStatus(); got != http.StatusServiceUnavailable {
			t.Fatalf("resolvedStatus(%d) = %d, want 503", status, got)
		}
	}
	if got := (Response{Status: 418}).resolvedStatus(); got != 418 {
		t.Fatalf("resolvedStatus(418) = %d", got)
	}

	body := Response{Status: 503}.resolvedBody()
	if !strings.Contains(body, "503") || !strings.Contains(body, "injected by steadybit") {
		t.Fatalf("default body = %q", body)
	}
	if got := (Response{Status: 503, Body: "custom"}).resolvedBody(); got != "custom" {
		t.Fatalf("explicit body = %q", got)
	}
}

// Hop-by-hop headers are illegal in HTTP/2 and are owned by net/http in
// HTTP/1.1; a caller supplying one must not be able to corrupt the response.
func Test_Response_stripsHopByHopHeaders(t *testing.T) {
	ca, caPEM := mustLoadTestCA(t)
	addr, ch := serveOnce(t, ca, Response{
		Status:  503,
		Headers: map[string]string{"Connection": "close", "Transfer-Encoding": "chunked", "X-Kept": "yes"},
	})
	client, tr := clientTrusting(t, caPEM, false)

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	// Read to the end so the connection goes idle and can be released below.
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if got := resp.Header.Get("X-Kept"); got != "yes" {
		t.Fatalf("X-Kept = %q, want yes", got)
	}
	if got := resp.Header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding leaked through: %q", got)
	}
	// A rule's Connection header must not decide the connection's lifetime.
	if resp.Close {
		t.Fatal("the rule's Connection: close leaked through")
	}
	tr.CloseIdleConnections()
	if err := waitServed(t, ch); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func Test_replayConn(t *testing.T) {
	// Without a prefix the connection is handed through unwrapped.
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if got := replayConn(a, nil); got != a {
		t.Fatal("expected the original conn when there is no prefix")
	}

	// With a prefix the consumed bytes are replayed ahead of the live stream,
	// which is what lets the TLS handshake see the peeked ClientHello.
	c, d := net.Pipe()
	defer func() { _ = c.Close() }()
	go func() {
		_, _ = d.Write([]byte("world"))
		_ = d.Close()
	}()
	got, err := io.ReadAll(replayConn(c, []byte("hello ")))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("read %q, want %q", got, "hello world")
	}
}
