// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
)

// TestServer_TLSInject_WebSocketOutlivesTheUpgrade sends an upgrade request
// that is not faulted through an intercepted connection. The tunnel after the
// 101 must keep working: the connection is the handler's from then on, and
// must not be closed under it when the HTTP server lets go of it.
func TestServer_TLSInject_WebSocketOutlivesTheUpgrade(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = rw.Flush()
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			_, _ = rw.WriteString(line)
			_ = rw.Flush()
		}
	}))
	t.Cleanup(upstream.Close)
	dst := netip.MustParseAddrPort(upstream.Listener.Addr().String())

	ca, caPEM := newInterceptCA(t)
	proxyAddr := serveProxy(t, &Server{
		Faults:             fault.NewEngine([]fault.Rule{statusRule(upstreamHost, 0, http.StatusServiceUnavailable)}),
		TLSInject:          ca,
		UpstreamTrustedCAs: certPool(upstream),
	}, dst)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to add intercept CA to pool")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", proxyAddr.String(), &tls.Config{
		ServerName: upstreamHost,
		RootCAs:    pool,
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+upstreamHost+"\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	for i := range 3 {
		if _, err := io.WriteString(conn, "ping\n"); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("echo %d: %v", i, err)
		}
		if line != "ping\n" {
			t.Fatalf("echo %d = %q, want %q", i, line, "ping\n")
		}
	}
}

// TestServer_TLSInject_ForwardingKeepsForwardedHeaders forwards a request that
// was not faulted: the proxy headers the workload set must reach the
// dependency unchanged, as on the cleartext path.
func TestServer_TLSInject_ForwardingKeepsForwardedHeaders(t *testing.T) {
	got := make(chan http.Header, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
	}))
	t.Cleanup(upstream.Close)
	dst := netip.MustParseAddrPort(upstream.Listener.Addr().String())

	ca, caPEM := newInterceptCA(t)
	proxyAddr := serveProxy(t, &Server{
		Faults:             fault.NewEngine([]fault.Rule{statusRule(upstreamHost, 0, http.StatusServiceUnavailable)}),
		TLSInject:          ca,
		UpstreamTrustedCAs: certPool(upstream),
	}, dst)
	client := newKeepAliveHTTPSClient(t, proxyAddr, upstream, caPEM, false)

	sent := map[string]string{
		"Forwarded":         "for=203.0.113.7;proto=https",
		"X-Forwarded-For":   "203.0.113.7",
		"X-Forwarded-Host":  "shop.example.org",
		"X-Forwarded-Proto": "https",
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+upstreamHost+"/", nil)
	for k, v := range sent {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	h := <-got
	for k, v := range sent {
		if h.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, h.Get(k), v)
		}
	}
}

// TestServer_TLSInject_ClientCancellationIsNoUpstreamError cancels a forwarded
// request while the dependency is still answering. The client gave up, the
// dependency did not fail: it must not count as an upstream error.
func TestServer_TLSInject_ClientCancellationIsNoUpstreamError(t *testing.T) {
	cancelled := make(chan struct{})
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(cancelled)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	dst := netip.MustParseAddrPort(upstream.Listener.Addr().String())

	ca, caPEM := newInterceptCA(t)
	m := metrics.New()
	proxyAddr := serveProxy(t, &Server{
		Faults:             fault.NewEngine([]fault.Rule{statusRule(upstreamHost, 0, http.StatusServiceUnavailable)}),
		TLSInject:          ca,
		UpstreamTrustedCAs: certPool(upstream),
		Metrics:            m,
	}, dst)
	client := newKeepAliveHTTPSClient(t, proxyAddr, upstream, caPEM, true)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+upstreamHost+"/", nil)
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("request succeeded, want it cancelled")
	}

	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the cancellation never reached the dependency")
	}
	// The proxy's error path runs right after it cancels the upstream request.
	time.Sleep(100 * time.Millisecond)
	if n := m.Snapshot().UpstreamErrors; n != 0 {
		t.Fatalf("upstream errors = %d, want 0", n)
	}
}
