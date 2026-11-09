// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
)

func latencyRule(host string, probability float64, latency time.Duration) fault.Rule {
	return fault.Rule{
		Name:        "slow-https",
		Hosts:       []string{host},
		Probability: &probability,
		Latency:     latency,
	}
}

// Spliced, only the first request on a connection would be delayed: the
// latency used to precede the upstream connect, once.
func TestServer_TLSInject_LatencyDelaysEveryRequestOnKeepAlive(t *testing.T) {
	const latency = 100 * time.Millisecond

	for _, tc := range []struct {
		name  string
		http2 bool
	}{
		{name: "HTTP/1.1", http2: false},
		{name: "HTTP/2", http2: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, dst := startH2CapableTLSUpstream(t)
			ca, caPEM := newInterceptCA(t)
			proxyAddr := serveProxy(t, &Server{
				Faults:             fault.NewEngine([]fault.Rule{latencyRule(upstreamHost, 1, latency)}),
				TLSInject:          ca,
				UpstreamTrustedCAs: certPool(upstream),
			}, dst)
			client := newKeepAliveHTTPSClient(t, proxyAddr, upstream, caPEM, tc.http2)

			for i := range 5 {
				start := time.Now()
				resp, err := client.Get("https://" + upstreamHost + "/")
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if elapsed := time.Since(start); elapsed < latency {
					t.Errorf("request %d took %v, want at least %v", i, elapsed, latency)
				}
				if resp.StatusCode != http.StatusOK || string(body) != "real-response" {
					t.Errorf("request %d = %d %q, want the dependency's 200", i, resp.StatusCode, body)
				}
			}
			if n := client.dials.Load(); n != 1 {
				t.Fatalf("client dials = %d, want every request on one connection", n)
			}
		})
	}
}

func TestServer_TLSInject_LatencyProbabilityAppliesPerRequest(t *testing.T) {
	const (
		requests    = 400
		probability = 0.5
		// ±10 points is about 4 standard deviations at n=400.
		tolerance = 0.10
	)

	for _, tc := range []struct {
		name  string
		http2 bool
	}{
		{name: "HTTP/1.1", http2: false},
		{name: "HTTP/2", http2: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, dst := startH2CapableTLSUpstream(t)
			ca, caPEM := newInterceptCA(t)
			m := metrics.New()
			proxyAddr := serveProxy(t, &Server{
				Faults:             fault.NewEngine([]fault.Rule{latencyRule(upstreamHost, probability, time.Millisecond)}),
				TLSInject:          ca,
				UpstreamTrustedCAs: certPool(upstream),
				Metrics:            m,
			}, dst)
			client := newKeepAliveHTTPSClient(t, proxyAddr, upstream, caPEM, tc.http2)

			statuses := client.sendGets(t, "https://"+upstreamHost+"/", requests)

			s := m.Snapshot()
			rate := float64(s.RequestsFaulted) / requests
			t.Logf("statuses=%v matched=%d faulted=%d rate=%.3f client_dials=%d",
				statuses, s.RequestsMatched, s.RequestsFaulted, rate, client.dials.Load())

			if statuses[http.StatusOK] != requests {
				t.Fatalf("statuses = %v, want all %d forwarded", statuses, requests)
			}
			if s.RequestsMatched != requests {
				t.Fatalf("requests matched = %d, want %d", s.RequestsMatched, requests)
			}
			if rate < probability-tolerance || rate > probability+tolerance {
				t.Errorf("delayed rate = %.3f, want %.2f ± %.2f", rate, probability, tolerance)
			}
		})
	}
}
