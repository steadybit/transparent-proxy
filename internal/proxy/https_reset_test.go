// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
)

func TestParseALPN(t *testing.T) {
	for _, tc := range []struct {
		name  string
		offer []string
	}{
		{name: "none", offer: nil},
		{name: "http/1.1", offer: []string{"http/1.1"}},
		{name: "h2 and http/1.1", offer: []string{"h2", "http/1.1"}},
		{name: "non-HTTP", offer: []string{"mqtt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hello := captureClientHelloOffering(t, "api.example.com", tc.offer)
			got := offeredALPN(hello)
			if strings.Join(got, ",") != strings.Join(tc.offer, ",") {
				t.Fatalf("offeredALPN = %q, want %q", got, tc.offer)
			}
			if sni := parseSNI(hello[tlsRecordHeaderLen:]); sni != "api.example.com" {
				t.Fatalf("parseSNI = %q, want api.example.com alongside the ALPN", sni)
			}
		})
	}
}

func TestWorthDecrypting(t *testing.T) {
	status := fault.Rule{HTTPStatus: 503}
	latency := fault.Rule{Latency: time.Second}
	reset := fault.Rule{Abort: true}

	for _, tc := range []struct {
		name string
		rule fault.Rule
		alpn []string
		port uint16
		want bool
	}{
		{name: "status, h2", rule: status, alpn: []string{"h2", "http/1.1"}, port: 8443, want: true},
		{name: "latency, http/1.1", rule: latency, alpn: []string{"http/1.1"}, port: 9000, want: true},
		{name: "reset, http/1.1", rule: reset, alpn: []string{"http/1.1"}, port: 443, want: true},
		{name: "no ALPN on 443", rule: status, port: 443, want: true},
		{name: "no ALPN elsewhere, e.g. Kafka over TLS", rule: latency, port: 9093, want: false},
		{name: "non-HTTP ALPN on 443, e.g. MQTT", rule: reset, alpn: []string{"mqtt"}, port: 443, want: false},
		{name: "no HTTP fault", rule: fault.Rule{}, alpn: []string{"h2"}, port: 443, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := worthDecrypting(tc.rule, tc.alpn, tc.port); got != tc.want {
				t.Fatalf("worthDecrypting = %v, want %v", got, tc.want)
			}
		})
	}
}

func resetRule(host string, probability float64) fault.Rule {
	return fault.Rule{
		Name:        "reset-https",
		Hosts:       []string{host},
		Probability: &probability,
		Abort:       true,
	}
}

// Spliced, a reset was rolled once for the whole connection: a keep-alive
// client that survived the roll was never reset again.
func TestServer_TLSInject_ResetAppliesPerRequest(t *testing.T) {
	const (
		requests    = 200
		probability = 0.5
		// ±15 points is about 4 standard deviations at n=200.
		tolerance = 0.15
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
				Faults:             fault.NewEngine([]fault.Rule{resetRule(upstreamHost, probability)}),
				TLSInject:          ca,
				UpstreamTrustedCAs: certPool(upstream),
				Metrics:            m,
			}, dst)
			client := newKeepAliveHTTPSClient(t, proxyAddr, upstream, caPEM, tc.http2)

			failed := 0
			for i := range requests {
				// POST is not retried by net/http, so each failure is one reset.
				resp, err := client.Post("https://"+upstreamHost+"/", "text/plain", strings.NewReader("x"))
				if err != nil {
					failed++
					// A reset must read as one on HTTP/1.1, as on cleartext, not as
					// the clean EOF of a closed connection.
					if !tc.http2 && !errors.Is(err, syscall.ECONNRESET) {
						t.Fatalf("request %d: %v, want a connection reset", i, err)
					}
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK || string(body) != "real-response" {
					t.Fatalf("request %d = %d %q, want the dependency's 200", i, resp.StatusCode, body)
				}
			}

			s := m.Snapshot()
			rate := float64(failed) / requests
			t.Logf("failed=%d matched=%d faulted=%d aborted=%d client_dials=%d",
				failed, s.RequestsMatched, s.RequestsFaulted, s.ConnectionsAborted, client.dials.Load())

			if s.RequestsMatched != requests {
				t.Fatalf("requests matched = %d, want %d", s.RequestsMatched, requests)
			}
			if int(s.RequestsFaulted) != failed {
				t.Fatalf("requests faulted = %d, want the %d that failed", s.RequestsFaulted, failed)
			}
			if rate < probability-tolerance || rate > probability+tolerance {
				t.Errorf("reset rate = %.3f, want %.2f ± %.2f", rate, probability, tolerance)
			}
			// On HTTP/2 a reset ends one stream; the connection carries on.
			if tc.http2 {
				if n := client.dials.Load(); n != 1 {
					t.Fatalf("client dials = %d, want every request on one connection", n)
				}
			}
		})
	}
}

// startTLSEcho stands in for a dependency that speaks TLS but not HTTP, such as
// Kafka or MQTT. It presents the httptest certificate, valid for upstreamHost.
func startTLSEcho(t *testing.T) (*x509.Certificate, netip.AddrPort) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	cert := srv.Certificate()
	tlsCert := srv.TLS.Certificates[0]
	srv.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"mqtt"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return cert, ln.Addr().(*net.TCPAddr).AddrPort()
}

// TLS that does not speak HTTP to a targeted hostname must never be decrypted:
// served as HTTP, it would break. It is spliced through, so the client sees the
// dependency's own certificate and talks to it end to end.
func TestServer_TLSInject_NonHTTPTLSIsSplicedThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		alpn []string
	}{
		{name: "no ALPN off port 443", alpn: nil},
		{name: "non-HTTP ALPN", alpn: []string{"mqtt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, dst := startTLSEcho(t)
			ca, _ := newInterceptCA(t)
			m := metrics.New()
			proxyAddr := serveProxy(t, &Server{
				Faults:    fault.NewEngine([]fault.Rule{latencyRule(upstreamHost, 1, time.Millisecond)}),
				TLSInject: ca,
				Metrics:   m,
			}, dst)

			// Trusts only the dependency, so an injected certificate would fail
			// the handshake.
			pool := x509.NewCertPool()
			pool.AddCert(cert)
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", proxyAddr.String(), &tls.Config{
				ServerName: upstreamHost, RootCAs: pool, NextProtos: tc.alpn, MinVersion: tls.VersionTLS12,
			})
			if err != nil {
				t.Fatalf("dial: %v, want the dependency's own certificate", err)
			}
			defer conn.Close()

			msg := []byte("not http")
			if _, err := conn.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != string(msg) {
				t.Fatalf("echo = %q, %v; want %q", buf, err, msg)
			}
			if s := m.Snapshot(); s.RequestsMatched != 0 {
				t.Fatalf("requests matched = %d, want 0: the connection must not be decrypted", s.RequestsMatched)
			}
		})
	}
}
