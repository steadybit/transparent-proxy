// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
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
)

// TestServer_TLSInject_ProbabilityAppliesPerRequestOnKeepAlive is the HTTPS
// twin of TestServer_ProbabilityAppliesPerRequestOnKeepAlive: a keep-alive
// client goes through the proxy with an interception CA and a 50% status
// fault, and roughly half of its requests must be faulted. Rolled once per
// connection, an HTTP/2 client gets all or nothing, and an HTTP/1.1 client
// ends up on the first connection that won the roll.
func TestServer_TLSInject_ProbabilityAppliesPerRequestOnKeepAlive(t *testing.T) {
	const (
		requests    = 1000
		probability = 0.5
		// ±10 points is about 6 standard deviations at n=1000.
		tolerance = 0.10
	)

	for _, tc := range []struct {
		name  string
		http2 bool
		proto string
	}{
		{name: "HTTP/1.1", http2: false, proto: "HTTP/1.1"},
		{name: "HTTP/2", http2: true, proto: "HTTP/2.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, dst := startH2CapableTLSUpstream(t)
			ca, caPEM := newInterceptCA(t)
			proxyAddr := serveProxy(t, &Server{
				Faults:    fault.NewEngine([]fault.Rule{statusRule(upstreamHost, probability, http.StatusServiceUnavailable)}),
				TLSInject: ca,
			}, dst)
			client := newKeepAliveHTTPSClient(t, proxyAddr, upstream, caPEM, tc.http2)

			statuses, protos := client.sendGetsByProto(t, "https://"+upstreamHost+"/", requests)

			rate := float64(statuses[http.StatusServiceUnavailable]) / requests
			t.Logf("statuses=%v protos=%v rate=%.3f client_dials=%d", statuses, protos, rate, client.dials.Load())

			if protos[tc.proto] != requests {
				t.Fatalf("protocols = %v, want all %d requests over %s", protos, requests, tc.proto)
			}
			if rate < probability-tolerance || rate > probability+tolerance {
				t.Errorf("fault rate = %.3f, want %.2f ± %.2f", rate, probability, tolerance)
			}
		})
	}
}

// startH2CapableTLSUpstream is startTLSUpstream with HTTP/2 enabled, so a
// connection the proxy splices through negotiates the same protocol as one it
// intercepts.
func startH2CapableTLSUpstream(t *testing.T) (*httptest.Server, netip.AddrPort) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "real-response")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, netip.MustParseAddrPort(srv.Listener.Addr().String())
}

// newKeepAliveHTTPSClient is newKeepAliveClient for HTTPS: it presents
// upstreamHost as the SNI, trusts both the real upstream and the interception
// CA, and speaks HTTP/2 when asked to.
func newKeepAliveHTTPSClient(t *testing.T, proxyAddr netip.AddrPort, upstream *httptest.Server, caPEM []byte, http2 bool) *keepAliveClient {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to add intercept CA to pool")
	}
	c := &keepAliveClient{}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			c.dials.Add(1)
			return dialer.DialContext(ctx, network, proxyAddr.String())
		},
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   http2,
		MaxIdleConnsPerHost: 1,
	}
	c.Client = &http.Client{Transport: tr, Timeout: 5 * time.Second}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// sendGetsByProto is sendGets that also counts the protocol of every response.
func (c *keepAliveClient) sendGetsByProto(t *testing.T, url string, n int) (statuses map[int]int, protos map[string]int) {
	t.Helper()
	statuses, protos = map[int]int{}, map[string]int{}
	for i := range n {
		resp, err := c.Get(url)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		statuses[resp.StatusCode]++
		protos[resp.Proto]++
	}
	return statuses, protos
}
