// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
	"github.com/steadybit/transparent-proxy/internal/tlsinject"
)

// upstreamHost matches the name in httptest's built-in certificate, so a
// pass-through connection validates against the real upstream too.
const upstreamHost = "example.com"

func newInterceptCA(t *testing.T) (*tlsinject.CA, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Intercept CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	ca, err := tlsinject.LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return ca, certPEM
}

// startTLSUpstream stands in for the real dependency.
func startTLSUpstream(t *testing.T) (*httptest.Server, netip.AddrPort) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "real-response")
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}
	ap, err := netip.ParseAddrPort(u.Host)
	if err != nil {
		t.Fatalf("parse upstream addr: %v", err)
	}
	return srv, ap
}

// clientVia dials every request at the proxy while presenting upstreamHost as
// the SNI, so the proxy sees exactly what a redirected dependency call looks
// like. The pool trusts both the upstream and (when given) the intercept CA.
func clientVia(t *testing.T, proxyAddr netip.AddrPort, upstream *httptest.Server, interceptCAPEM []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	if len(interceptCAPEM) > 0 && !pool.AppendCertsFromPEM(interceptCAPEM) {
		t.Fatal("failed to add intercept CA to pool")
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr.String())
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func httpsRule() *fault.Engine {
	p := 1.0
	return fault.NewEngine([]fault.Rule{{
		Name:        "https-intercept",
		Hosts:       []string{upstreamHost},
		HTTPStatus:  503,
		Probability: &p,
	}})
}

// waitFor polls until cond holds, so assertions do not race the proxy
// goroutine finishing its bookkeeping.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", msg)
}

// With a CA configured, an HTTPS dependency call is terminated and answered
// with the forged response instead of reaching the real upstream.
func TestServer_TLSInject_ForgesResponse(t *testing.T) {
	upstream, dst := startTLSUpstream(t)
	ca, caPEM := newInterceptCA(t)
	m := metrics.New()

	proxyAddr := serveProxy(t, &Server{Faults: httpsRule(), Metrics: m, TLSInject: ca}, dst)
	client := clientVia(t, proxyAddr, upstream, caPEM)

	resp, err := client.Get("https://" + upstreamHost + "/v1/messages")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != 503 {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if strings.Contains(string(body), "real-response") {
		t.Fatal("the request reached the real upstream; it should have been forged")
	}
	if !strings.Contains(string(body), "injected by steadybit") {
		t.Fatalf("body = %q", body)
	}

	waitFor(t, func() bool { return m.Snapshot().HTTPResponsesInjected == 1 }, "an injected response")
	snap := m.Snapshot()
	if snap.ConnectionsFaulted != 1 {
		t.Fatalf("ConnectionsFaulted = %d, want 1", snap.ConnectionsFaulted)
	}
	if snap.TLSInterceptRejected != 0 {
		t.Fatalf("TLSInterceptRejected = %d, want 0", snap.TLSInterceptRejected)
	}
	if got := snap.PerHost[upstreamHost]; got.Faulted != 1 {
		t.Fatalf("per-host faulted = %d, want 1", got.Faulted)
	}
}

// Regression: HTTP/2 clients pool the connection for the whole attack. The
// fault counters must reflect the injection while that connection is still
// open — otherwise a working attack reports as "matched but never faulted",
// which the platform reads as a silent no-op.
func TestServer_TLSInject_CountsWhileHTTP2ConnectionStaysOpen(t *testing.T) {
	upstream, dst := startTLSUpstream(t)
	ca, caPEM := newInterceptCA(t)
	m := metrics.New()

	proxyAddr := serveProxy(t, &Server{Faults: httpsRule(), Metrics: m, TLSInject: ca}, dst)

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to add intercept CA to pool")
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr.String())
		},
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := client.Get("https://" + upstreamHost + "/v1/messages")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %q, want HTTP/2.0 so the connection stays pooled", resp.Proto)
	}

	// Deliberately do NOT close idle connections first — that is the bug.
	waitFor(t, func() bool { return m.Snapshot().ConnectionsFaulted == 1 },
		"the fault to be counted while the h2 connection is still open")
	snap := m.Snapshot()
	if snap.HTTPResponsesInjected != 1 {
		t.Fatalf("HTTPResponsesInjected = %d, want 1", snap.HTTPResponsesInjected)
	}
	if got := snap.PerHost[upstreamHost]; got.Faulted != 1 {
		t.Fatalf("per-host faulted = %d, want 1", got.Faulted)
	}
}

// Without a CA the same rule must leave HTTPS alone — the pre-existing
// behaviour, and the guarantee that enabling the feature is opt-in.
func TestServer_TLSInject_DisabledPassesThrough(t *testing.T) {
	upstream, dst := startTLSUpstream(t)
	m := metrics.New()

	proxyAddr := serveProxy(t, &Server{Faults: httpsRule(), Metrics: m}, dst)
	client := clientVia(t, proxyAddr, upstream, nil)

	resp, err := client.Get("https://" + upstreamHost + "/v1/messages")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "real-response" {
		t.Fatalf("got %d %q, want 200 real-response", resp.StatusCode, body)
	}
	if got := m.Snapshot().ConnectionsFaulted; got != 0 {
		t.Fatalf("ConnectionsFaulted = %d, want 0 (no CA configured)", got)
	}
}

// A workload that does not trust the CA is the expected first failure. It must
// be counted as a handshake failure and never as an applied fault, so the
// operator gets a pointed diagnosis instead of a silent no-op.
func TestServer_TLSInject_UntrustedClientIsCounted(t *testing.T) {
	upstream, dst := startTLSUpstream(t)
	ca, _ := newInterceptCA(t)
	m := metrics.New()

	proxyAddr := serveProxy(t, &Server{Faults: httpsRule(), Metrics: m, TLSInject: ca}, dst)
	// Trusts the upstream but not the intercept CA.
	client := clientVia(t, proxyAddr, upstream, nil)

	if _, err := client.Get("https://" + upstreamHost + "/v1/messages"); err == nil {
		t.Fatal("expected the client to reject the injected certificate")
	}

	waitFor(t, func() bool { return m.Snapshot().TLSInterceptRejected == 1 }, "a counted handshake failure")
	snap := m.Snapshot()
	if snap.ConnectionsFaulted != 0 {
		t.Fatalf("ConnectionsFaulted = %d, want 0 — the fault never applied", snap.ConnectionsFaulted)
	}
	if snap.HTTPResponsesInjected != 0 {
		t.Fatalf("HTTPResponsesInjected = %d, want 0", snap.HTTPResponsesInjected)
	}
}
