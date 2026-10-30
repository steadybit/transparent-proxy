// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
)

// TestServer_ProbabilityAppliesPerRequestOnKeepAlive drives a keep-alive HTTP
// client through the proxy with a 50% status fault and asserts that roughly
// half of the requests are faulted. A pooled client reuses one connection for
// many requests, so a probability rolled once per connection would leave
// almost every request untouched.
func TestServer_ProbabilityAppliesPerRequestOnKeepAlive(t *testing.T) {
	const (
		host        = "dependency.test"
		requests    = 1000
		probability = 0.99
		// ±10 points is about 6 standard deviations at n=1000, so the test is
		// not flaky while still catching a per-connection roll (≈0%).
		tolerance = 0.10
	)

	upstream := startCountingUpstream(t)
	proxyAddr := startProxy(t, upstream.addr, fault.NewEngine([]fault.Rule{
		statusRule(host, probability, http.StatusServiceUnavailable),
	}))
	client := newKeepAliveClient(t, proxyAddr)

	got := client.sendGets(t, "http://"+host+"/", requests)

	rate := float64(got[http.StatusServiceUnavailable]) / requests
	t.Logf("statuses=%v rate=%.3f upstream_hits=%d client_dials=%d",
		got, rate, upstream.hits.Load(), client.dials.Load())

	if hits := upstream.hits.Load(); hits != int64(got[http.StatusOK]) {
		t.Errorf("upstream saw %d requests, client got %d successful responses", hits, got[http.StatusOK])
	}
	if rate < probability-tolerance || rate > probability+tolerance {
		t.Errorf("fault rate = %.3f, want %.2f ± %.2f", rate, probability, tolerance)
	}
}

// statusRule builds a rule that answers requests to host with status, applied
// with the given probability.
func statusRule(host string, probability float64, status int) fault.Rule {
	return fault.Rule{
		Name:        "flaky-http",
		Hosts:       []string{host},
		Probability: &probability,
		HTTPStatus:  status,
	}
}

// countingUpstream is an HTTP server that answers 200 "ok" and counts the
// requests that reach it, i.e. the ones the proxy did not fault.
type countingUpstream struct {
	addr netip.AddrPort
	hits atomic.Int64
}

func startCountingUpstream(t *testing.T) *countingUpstream {
	t.Helper()
	u := &countingUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		u.hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	u.addr = netip.MustParseAddrPort(srv.Listener.Addr().String())
	return u
}

// keepAliveClient is a pooled HTTP client that sends every request to the
// proxy, whatever the URL host, and counts the connections it opens.
type keepAliveClient struct {
	*http.Client
	dials atomic.Int64
}

func newKeepAliveClient(t *testing.T, proxyAddr netip.AddrPort) *keepAliveClient {
	t.Helper()
	c := &keepAliveClient{}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	c.Client = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				c.dials.Add(1)
				return dialer.DialContext(ctx, network, proxyAddr.String())
			},
			MaxIdleConnsPerHost: 1,
		},
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// sendGets sends n sequential GETs to url and returns how often each status
// code was received. Bodies are drained so the connection is reused.
func (c *keepAliveClient) sendGets(t *testing.T, url string, n int) map[int]int {
	t.Helper()
	statuses := map[int]int{}
	for i := range n {
		resp, err := c.Get(url)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		statuses[resp.StatusCode]++
	}
	return statuses
}
