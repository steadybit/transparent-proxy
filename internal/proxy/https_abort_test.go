// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"io"
	"net/http"
	"testing"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
)

func abortRule(host string, probability float64) fault.Rule {
	return fault.Rule{
		Name:        "reset-https",
		Hosts:       []string{host},
		Probability: &probability,
		Abort:       true,
	}
}

// Rolled once per connection, a keep-alive client is reset until one
// connection wins the roll, which then carries every later request.
//
// On HTTP/1.1 the client resends a GET whose reused connection closed without
// a reply, so the proxy sees more requests than were sent and the share is
// taken from its counters. On HTTP/2 the stream is reset, which the client
// does not retry, so every reset request fails and the connection stays open.
func TestServer_TLSInject_AbortProbabilityAppliesPerRequest(t *testing.T) {
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
				Faults:             fault.NewEngine([]fault.Rule{abortRule(upstreamHost, probability)}),
				TLSInject:          ca,
				UpstreamTrustedCAs: certPool(upstream),
				Metrics:            m,
			}, dst)
			client := newKeepAliveHTTPSClient(t, proxyAddr, upstream, caPEM, tc.http2)

			failed := 0
			for range requests {
				resp, err := client.Get("https://" + upstreamHost + "/")
				if err != nil {
					failed++
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK || string(body) != "real-response" {
					t.Fatalf("response = %d %q, want the dependency's 200 or a reset", resp.StatusCode, body)
				}
			}

			s := m.Snapshot()
			t.Logf("failed=%d matched=%d faulted=%d aborted=%d client_dials=%d",
				failed, s.RequestsMatched, s.RequestsFaulted, s.ConnectionsAborted, client.dials.Load())

			if s.RequestsMatched < requests {
				t.Fatalf("requests matched = %d, want at least %d", s.RequestsMatched, requests)
			}
			if rate := float64(s.RequestsFaulted) / float64(s.RequestsMatched); rate < probability-tolerance || rate > probability+tolerance {
				t.Errorf("reset rate = %.3f, want %.2f ± %.2f", rate, probability, tolerance)
			}
			if s.ConnectionsAborted != s.RequestsFaulted {
				t.Errorf("aborted = %d, want one per faulted request (%d)", s.ConnectionsAborted, s.RequestsFaulted)
			}
			if tc.http2 {
				if int64(failed) != s.RequestsFaulted {
					t.Errorf("failed requests = %d, want one per faulted request (%d)", failed, s.RequestsFaulted)
				}
				if n := client.dials.Load(); n != 1 {
					t.Errorf("client dials = %d, want every request on one connection", n)
				}
			}
		})
	}
}
