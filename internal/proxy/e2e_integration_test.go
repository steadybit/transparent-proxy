// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build linux && integration

// End-to-end tests that drive a real HTTP client through a real iptables
// REDIRECT into the proxy and out to a real upstream, exercising the whole
// system (capture + SO_ORIGINAL_DST + SO_MARK loop protection + fault + flush)
// the way an experiment would. Requires Linux, root, and iptables.
//
//	go test -tags integration ./internal/proxy/ -run TestE2E -v
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/interception"
	"github.com/steadybit/transparent-proxy/internal/metrics"
)

func startHTTPUpstream(t *testing.T, handler http.HandlerFunc) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// startRealProxy runs a Server on the real SO_ORIGINAL_DST path (no injected
// ResolveDst) with loop protection, and returns its port.
func startRealProxy(t *testing.T, engine *fault.Engine, m *metrics.Metrics) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	s := &Server{Faults: engine, Mark: interception.DefaultMark, Metrics: m}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func intercept(t *testing.T, proxyPort, upstreamPort uint16, execID string) {
	t.Helper()
	cfg := interception.Config{
		ExecutionID: execID,
		ProxyPort:   proxyPort,
		Filter: interception.Filter{
			Include: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			Ports:   []uint16{upstreamPort},
		},
	}
	if err := cfg.Apply(context.Background(), interception.ExecRunner{}); err != nil {
		t.Fatalf("apply interception: %v", err)
	}
	t.Cleanup(func() {
		if err := cfg.Revert(context.Background(), interception.ExecRunner{}); err != nil {
			t.Errorf("revert interception: %v", err)
		}
	})
}

func TestE2E_HTTPLatencyFaultApplied(t *testing.T) {
	up := startHTTPUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	})
	m := metrics.New()
	engine := fault.NewEngine([]fault.Rule{{
		Name:    "slow",
		CIDRs:   []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Latency: 300 * time.Millisecond,
	}})
	px := startRealProxy(t, engine, m)
	intercept(t, px, up, "e2e-latency")

	start := time.Now()
	body, status := httpGet(t, up)
	if status != 200 || body != "hello" {
		t.Fatalf("got status=%d body=%q", status, body)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("request took %v; injected ~300ms latency not applied (bypassed proxy?)", elapsed)
	}
	eventually(t, func() bool { return m.Snapshot().ConnectionsMatched >= 1 })
}

func TestE2E_PoolFlushResurrectsWarmConnection(t *testing.T) {
	var hits int
	var mu sync.Mutex
	up := startHTTPUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	})

	// A keep-alive client establishes a warm pooled connection BEFORE any
	// interception exists.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}}
	url := fmt.Sprintf("http://127.0.0.1:%d/", up)
	warm(t, client, url)

	// Now interpose the proxy + flush. Without the ESTABLISHED REJECT, the warm
	// pooled connection would bypass the proxy entirely (silent no-op).
	m := metrics.New()
	px := startRealProxy(t, fault.NewEngine(nil), m)
	intercept(t, px, up, "e2e-flush")

	// Reusing the same client: the warm connection must be reset by the flush,
	// and the retried request must land on the proxy.
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("second request failed (flush broke the connection without resurrection?): %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("second request status = %d", resp.StatusCode)
	}
	eventually(t, func() bool { return m.Snapshot().ConnectionsMatched >= 1 })
}

func TestE2E_HTTPStatusInjectionByHost(t *testing.T) {
	var upstreamCalls int
	var mu sync.Mutex
	up := startHTTPUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		upstreamCalls++
		mu.Unlock()
		_, _ = io.WriteString(w, "real upstream")
	})
	m := metrics.New()
	engine := fault.NewEngine([]fault.Rule{{Name: "down", Hosts: []string{"localhost"}, HTTPStatus: 503}})
	px := startRealProxy(t, engine, m)
	intercept(t, px, up, "e2e-http503")

	// http.Get to localhost:<up> is redirected into the proxy, which matches the
	// Host header ("localhost") and injects 503 without hitting the upstream.
	resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).
		Get(fmt.Sprintf("http://localhost:%d/", up))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("status = %d, want 503 (injected)", resp.StatusCode)
	}
	mu.Lock()
	calls := upstreamCalls
	mu.Unlock()
	if calls != 0 {
		t.Fatalf("upstream was called %d times; injected status must not reach it", calls)
	}
}

func TestE2E_NoLoopStormUnderConcurrentLoad(t *testing.T) {
	up := startHTTPUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	m := metrics.New()
	px := startRealProxy(t, fault.NewEngine(nil), m)
	intercept(t, px, up, "e2e-load")

	const n = 40
	url := fmt.Sprintf("http://127.0.0.1:%d/", up)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			// Fresh connection each time so each request is a distinct capture.
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
			if resp, err := client.Get(url); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			client.CloseIdleConnections()
		}()
	}
	wg.Wait()

	s := m.Snapshot()
	// SO_MARK must keep the proxy's own upstream dials out of the redirect, so
	// matched tracks client requests (~n), not an amplified storm.
	if s.ConnectionsMatched < n/2 {
		t.Fatalf("too few matched (%d); interception may not be capturing", s.ConnectionsMatched)
	}
	if s.ConnectionsMatched > n*3 {
		t.Fatalf("matched=%d for %d requests suggests a self-loop storm", s.ConnectionsMatched, n)
	}
	// The active gauge is async (proxy-side handle goroutines finish their relay
	// teardown after the client returns), so it must SETTLE to zero — a value
	// that never reaches zero would indicate a connection/goroutine leak.
	eventually(t, func() bool { return m.Snapshot().ConnectionsActive == 0 })
}

// --- helpers ---

func httpGet(t *testing.T, port uint16) (string, int) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode
}

func warm(t *testing.T, client *http.Client, url string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("warm-up request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
