// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
)

// A request that is not faulted is forwarded to the real dependency, which the
// proxy has to verify. These tests use httptest's certificate as a dependency
// with a private CA: one the system roots and the built-in ones do not know.

// TestServer_TLSInject_ForwardsToDependencyWithTrustedCA trusts the
// dependency's private CA explicitly: the request is forwarded.
func TestServer_TLSInject_ForwardsToDependencyWithTrustedCA(t *testing.T) {
	statuses, s := forwardOnce(t, upstreamHost, &Server{}, true)
	if statuses[http.StatusOK] != 1 {
		t.Fatalf("statuses = %v, want one 200 from the real dependency", statuses)
	}
	if s.UpstreamErrors != 0 {
		t.Fatalf("upstream errors = %d, want 0", s.UpstreamErrors)
	}
}

// TestServer_TLSInject_InsecureSkipVerifyForwardsAnyDependency skips the
// verification: a dependency nobody trusts is forwarded to anyway.
func TestServer_TLSInject_InsecureSkipVerifyForwardsAnyDependency(t *testing.T) {
	statuses, _ := forwardOnce(t, upstreamHost, &Server{UpstreamInsecureSkipVerify: true}, false)
	if statuses[http.StatusOK] != 1 {
		t.Fatalf("statuses = %v, want one 200 with verification skipped", statuses)
	}
}

// TestServer_TLSInject_TrustedCAStillChecksTheHostname trusts the CA but asks
// for a hostname the dependency's certificate is not for: trusting a CA must
// not mean accepting any certificate it signed.
func TestServer_TLSInject_TrustedCAStillChecksTheHostname(t *testing.T) {
	statuses, s := forwardOnce(t, "other.test", &Server{}, true)
	if statuses[http.StatusBadGateway] != 1 {
		t.Fatalf("statuses = %v, want one 502 for a certificate issued to another name", statuses)
	}
	if s.UpstreamErrors != 1 {
		t.Fatalf("upstream errors = %d, want 1", s.UpstreamErrors)
	}
}

// TestServer_TLSInject_WrongTrustedCAIsRejected trusts a CA, but not the one
// that signed the dependency's certificate: as with no trusted CA at all, the
// request gets a 502 counted as an upstream error.
func TestServer_TLSInject_WrongTrustedCAIsRejected(t *testing.T) {
	_, otherCAPEM := newInterceptCA(t)
	other := x509.NewCertPool()
	if !other.AppendCertsFromPEM(otherCAPEM) {
		t.Fatal("failed to add the other CA to the pool")
	}
	statuses, s := forwardOnce(t, upstreamHost, &Server{UpstreamTrustedCAs: other}, false)
	if statuses[http.StatusBadGateway] != 1 {
		t.Fatalf("statuses = %v, want one 502 for a dependency signed by another CA", statuses)
	}
	if s.UpstreamErrors != 1 || s.RequestsFaulted != 0 {
		t.Fatalf("upstream errors / requests faulted = %d / %d, want 1 / 0", s.UpstreamErrors, s.RequestsFaulted)
	}
}

// TestServer_TLSInject_ForwardsOverHTTP2WhenTheDependencyOffersIt checks the
// proxy's own leg to the dependency: whatever the client speaks, forwarded
// requests reach a dependency that offers HTTP/2 over HTTP/2.
func TestServer_TLSInject_ForwardsOverHTTP2WhenTheDependencyOffersIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		http2 bool
	}{
		{name: "HTTP/1.1 client", http2: false},
		{name: "HTTP/2 client", http2: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const requests = 5
			var mu sync.Mutex
			protos := map[string]int{}
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				protos[r.Proto]++
				mu.Unlock()
				_, _ = io.WriteString(w, "real-response")
			}))
			upstream.EnableHTTP2 = true
			upstream.StartTLS()
			t.Cleanup(upstream.Close)

			ca, caPEM := newInterceptCA(t)
			proxyAddr := serveProxy(t, &Server{
				Faults:             fault.NewEngine([]fault.Rule{statusRule(upstreamHost, 0, http.StatusServiceUnavailable)}),
				TLSInject:          ca,
				Metrics:            metrics.New(),
				UpstreamTrustedCAs: certPool(upstream),
			}, netip.MustParseAddrPort(upstream.Listener.Addr().String()))
			client := newKeepAliveHTTPSClient(t, proxyAddr, upstream, caPEM, tc.http2)

			statuses := client.sendGets(t, "https://"+upstreamHost+"/", requests)
			if statuses[http.StatusOK] != requests {
				t.Fatalf("statuses = %v, want %d 200s", statuses, requests)
			}
			mu.Lock()
			defer mu.Unlock()
			if protos["HTTP/2.0"] != requests {
				t.Fatalf("the dependency saw %v, want all %d requests over HTTP/2.0", protos, requests)
			}
		})
	}
}

// forwardOnce sends one request for host through an intercepting proxy built
// from base, with a rule that never faults, so the request is forwarded. With
// trustUpstream, the test upstream's certificate is added to the proxy's
// trusted CAs.
func forwardOnce(t *testing.T, host string, base *Server, trustUpstream bool) (map[int]int, metrics.Snapshot) {
	t.Helper()
	upstream, dst := startH2CapableTLSUpstream(t)
	ca, caPEM := newInterceptCA(t)
	m := metrics.New()

	base.Faults = fault.NewEngine([]fault.Rule{statusRule(host, 0, http.StatusServiceUnavailable)})
	base.TLSInject = ca
	base.Metrics = m
	if trustUpstream {
		base.UpstreamTrustedCAs = certPool(upstream)
	}
	proxyAddr := serveProxy(t, base, dst)
	client := newKeepAliveHTTPSClient(t, proxyAddr, upstream, caPEM, false)

	statuses := client.sendGets(t, "https://"+host+"/", 1)
	return statuses, m.Snapshot()
}
