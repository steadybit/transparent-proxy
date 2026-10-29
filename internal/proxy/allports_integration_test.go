// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build linux && integration

// End-to-end tests for all-ports interception — what the extensions request
// when Dependency Ports is empty. Every destination port is redirected into
// the proxy, yet only HTTP(S) to the dependency hostname may be faulted: every
// other connection must still reach its server, promptly and byte-identical.
// Requires Linux, root, and iptables:
//
//	go test -tags integration ./internal/proxy/ -run TestE2E_AllPorts -v
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/interception"
	"github.com/steadybit/transparent-proxy/internal/metrics"
)

const (
	// allPortsDependency is the hostname the fault targets. It never needs to
	// resolve: clients send it as the HTTP Host header or the TLS SNI.
	allPortsDependency = "dependency.example.test"
	allPortsLatency    = 500 * time.Millisecond
	// promptly bounds how long an untouched connection may take: far below the
	// injected latency and the 5s peek timeout a stalled sniff would cost.
	promptly = 300 * time.Millisecond
)

func TestE2E_AllPorts_OnlyTheDependencyIsFaulted(t *testing.T) {
	// Loopback is never intercepted with every port captured, so the servers
	// listen on a non-loopback local address; traffic to it still traverses
	// the OUTPUT chain and is redirected.
	ip := localNonLoopbackIPv4(t)
	httpPort := startHTTPOn(t, ip)
	httpsPort := startHTTPSOn(t, ip)
	echoPort := startEchoOn(t, ip)
	greetingPort := startGreetingOn(t, ip, "220 smtp.example.test ESMTP\r\n")

	m := metrics.New()
	engine := fault.NewEngine([]fault.Rule{{Name: "dep", Hosts: []string{allPortsDependency}, Latency: allPortsLatency}})
	px := startAllPortsProxy(t, engine, m)
	interceptAllPorts(t, px, ip, "e2e-allports")

	t.Run("HTTP to the dependency is faulted", func(t *testing.T) {
		assertDuration(t, func() error { return httpGetHost(ip, httpPort, allPortsDependency) }, allPortsLatency, 0)
	})
	t.Run("HTTPS to the dependency is faulted", func(t *testing.T) {
		assertDuration(t, func() error { return httpsGetSNI(ip, httpsPort, allPortsDependency) }, allPortsLatency, 0)
	})
	t.Run("HTTP to another host is untouched", func(t *testing.T) {
		assertDuration(t, func() error { return httpGetHost(ip, httpPort, "other.example.test") }, 0, promptly)
	})
	t.Run("HTTPS to another host is untouched", func(t *testing.T) {
		assertDuration(t, func() error { return httpsGetSNI(ip, httpsPort, "other.example.test") }, 0, promptly)
	})
	t.Run("binary client-first protocol is reachable", func(t *testing.T) {
		// A binary first byte is classified opaque immediately and spliced.
		assertDuration(t, func() error { return echoRoundTrip(ip, echoPort, []byte{0x00, 0x01, 0x02, 0xff}) }, 0, promptly)
	})
	t.Run("server-first protocol is reachable", func(t *testing.T) {
		// The server speaks first (SMTP, MySQL, SSH): the client waits for the
		// greeting, so the proxy dials early after ServerFirstTimeout.
		assertDuration(t, func() error { return readGreeting(ip, greetingPort) }, 0, time.Second)
	})
}

// --- helpers ---

// startAllPortsProxy runs a Server configured as main() does when every port
// is intercepted: loop protection plus the early upstream dial for
// server-first protocols (main's defaultServerFirstTimeout).
func startAllPortsProxy(t *testing.T, engine *fault.Engine, m *metrics.Metrics) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	s := &Server{Faults: engine, Mark: interception.DefaultMark, Metrics: m, ServerFirstTimeout: 250 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// interceptAllPorts redirects every port to ip into the proxy. The flush is
// skipped: these tests are about what reaches the proxy, and the flush's
// interaction with all-ports capture is tested on its own.
func interceptAllPorts(t *testing.T, proxyPort uint16, ip, execID string) {
	t.Helper()
	cfg := interception.Config{
		ExecutionID: execID,
		ProxyPort:   proxyPort,
		SkipFlush:   true,
		Filter: interception.Filter{
			Include:  []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(ip), 32)},
			AllPorts: true,
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

// assertDuration runs op and checks it succeeds within [atLeast, atMost]
// (atMost 0 = no upper bound).
func assertDuration(t *testing.T, op func() error, atLeast, atMost time.Duration) {
	t.Helper()
	start := time.Now()
	if err := op(); err != nil {
		t.Fatalf("connection failed: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < atLeast {
		t.Fatalf("took %v, want at least %v (fault not applied?)", elapsed, atLeast)
	}
	if atMost > 0 && elapsed > atMost {
		t.Fatalf("took %v, want at most %v (delayed or stalled by the proxy?)", elapsed, atMost)
	}
}

func httpGetHost(ip string, port int, host string) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d/", ip, port), nil)
	if err != nil {
		return err
	}
	req.Host = host
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func httpsGetSNI(ip string, port int, sni string) error {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{ServerName: sni, InsecureSkipVerify: true},
	}}
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/", ip, port))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func echoRoundTrip(ip string, port int, payload []byte) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != string(payload) {
		return fmt.Errorf("echo = %q, want %q (bytes altered)", got, payload)
	}
	return nil
}

func readGreeting(ip string, port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	return err
}

func localNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("interface addrs: %v", err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			return n.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 address to run servers on")
	return ""
}

func listenOn(t *testing.T, ip string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatalf("listen on %s: %v", ip, err)
	}
	return ln
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
}

func startHTTPOn(t *testing.T, ip string) int {
	t.Helper()
	ln := listenOn(t, ip)
	srv := &http.Server{Handler: okHandler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func startHTTPSOn(t *testing.T, ip string) int {
	t.Helper()
	srv := httptest.NewUnstartedServer(okHandler())
	srv.Listener = listenOn(t, ip)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

func startEchoOn(t *testing.T, ip string) int {
	t.Helper()
	ln := listenOn(t, ip)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func startGreetingOn(t *testing.T, ip, greeting string) int {
	t.Helper()
	ln := listenOn(t, ip)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, greeting)
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}
