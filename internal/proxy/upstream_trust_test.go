// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"net/http"
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
