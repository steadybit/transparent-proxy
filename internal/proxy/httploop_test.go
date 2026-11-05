// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/metrics"
)

// TestServeHTTP_HeadKeepsConnectionUsable sends a HEAD and then a GET on one
// connection. A HEAD response has no body, so if the proxy wrote one anyway the
// leftover bytes would be read as the start of the GET's response.
func TestServeHTTP_HeadKeepsConnectionUsable(t *testing.T) {
	const host = "dependency.test"

	for _, tc := range []struct {
		name        string
		probability float64
		wantStatus  int
	}{
		{name: "faulted", probability: 1, wantStatus: http.StatusServiceUnavailable},
		{name: "forwarded", probability: 0, wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := startCountingUpstream(t)
			proxyAddr := startProxy(t, upstream.addr, fault.NewEngine([]fault.Rule{
				statusRule(host, tc.probability, http.StatusServiceUnavailable),
			}))
			conn := dialRaw(t, proxyAddr)

			head := conn.roundTrip(t, http.MethodHead, host)
			if head.StatusCode != tc.wantStatus {
				t.Fatalf("HEAD status = %d, want %d", head.StatusCode, tc.wantStatus)
			}

			get := conn.roundTrip(t, http.MethodGet, host)
			if get.StatusCode != tc.wantStatus {
				t.Fatalf("GET status = %d, want %d", get.StatusCode, tc.wantStatus)
			}
		})
	}
}

// TestServeHTTP_CountsRequests checks that the per-request counters match what
// the client saw, so the statistics can show the share of faulted requests even
// though every request went over one connection.
func TestServeHTTP_CountsRequests(t *testing.T) {
	const (
		host     = "dependency.test"
		requests = 200
	)

	m := metrics.New()
	upstream := startCountingUpstream(t)
	proxyAddr := serveProxy(t, &Server{
		Faults:  fault.NewEngine([]fault.Rule{statusRule(host, 0.5, http.StatusServiceUnavailable)}),
		Metrics: m,
	}, upstream.addr)
	client := newKeepAliveClient(t, proxyAddr)

	got := client.sendGets(t, "http://"+host+"/", requests)
	faulted := int64(got[http.StatusServiceUnavailable])

	s := m.Snapshot()
	if s.RequestsMatched != requests || s.RequestsFaulted != faulted {
		t.Fatalf("requests matched/faulted = %d/%d, want %d/%d", s.RequestsMatched, s.RequestsFaulted, requests, faulted)
	}
	if h := s.PerHost[host]; h.RequestsMatched != requests || h.RequestsFaulted != faulted {
		t.Fatalf("per-host requests matched/faulted = %d/%d, want %d/%d", h.RequestsMatched, h.RequestsFaulted, requests, faulted)
	}
}

// TestServeHTTP_ReconnectsWhenUpstreamClosedIdleConnection forwards two requests
// on one client connection to an upstream that closes its side after every
// response, like a server whose idle timeout expired. The second request must
// go over a new upstream connection instead of failing.
func TestServeHTTP_ReconnectsWhenUpstreamClosedIdleConnection(t *testing.T) {
	const host = "dependency.test"

	upstream := startClosingUpstream(t)
	proxyAddr := startProxy(t, upstream, fault.NewEngine([]fault.Rule{
		statusRule(host, 0, http.StatusServiceUnavailable),
	}))
	conn := dialRaw(t, proxyAddr)

	if resp := conn.roundTrip(t, http.MethodGet, host); resp.StatusCode != http.StatusOK {
		t.Fatalf("first GET status = %d, want 200", resp.StatusCode)
	}
	// Give the upstream's close time to arrive, as it would for a connection
	// that sat idle in a pool.
	time.Sleep(50 * time.Millisecond)
	if resp := conn.roundTrip(t, http.MethodGet, host); resp.StatusCode != http.StatusOK {
		t.Fatalf("second GET status = %d, want 200", resp.StatusCode)
	}
}

// startClosingUpstream starts an HTTP server that answers one request per
// connection with 200 "ok" and then closes the connection, without announcing
// it with "Connection: close".
func startClosingUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

// TestServeHTTP_UpgradeSwitchesToRawBytes opens a WebSocket-style upgrade
// through the proxy. After the server's 101 the connection no longer carries
// HTTP, so the proxy must pass bytes through in both directions — including
// ones the server sends right after the 101.
func TestServeHTTP_UpgradeSwitchesToRawBytes(t *testing.T) {
	const host = "dependency.test"

	upstream := startUpgradeUpstream(t, "hello")
	proxyAddr := startProxy(t, upstream, fault.NewEngine([]fault.Rule{
		statusRule(host, 0, http.StatusServiceUnavailable),
	}))
	conn := dialRaw(t, proxyAddr)

	req := newRequest(t, http.MethodGet, host)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp := conn.do(t, req)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", resp.StatusCode)
	}

	conn.readExactly(t, "hello")
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	conn.readExactly(t, "ping")
}

// startUpgradeUpstream starts a server that accepts one upgrade per
// connection: it answers 101, immediately sends greeting, and then echoes
// whatever raw bytes it receives.
func startUpgradeUpstream(t *testing.T, greeting string) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				if _, err := http.ReadRequest(r); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n"+
					"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"+greeting)
				_, _ = io.Copy(c, r)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

// expectContinueHead is the head of a 5-byte POST whose client waits for
// "100 Continue" before sending the body.
const expectContinueHead = "POST / HTTP/1.1\r\nHost: dependency.test\r\n" +
	"Content-Length: 5\r\nExpect: 100-continue\r\n\r\n"

// TestServeHTTP_ExpectContinueForwarded sends a request that waits for
// "100 Continue" before its body. The proxy must answer it, or the client
// waits for its own timeout (curl: 1s) before sending the body anyway.
func TestServeHTTP_ExpectContinueForwarded(t *testing.T) {
	const host = "dependency.test"

	upstream := startBodyEchoUpstream(t)
	proxyAddr := startProxy(t, upstream, fault.NewEngine([]fault.Rule{
		statusRule(host, 0, http.StatusServiceUnavailable),
	}))
	conn := dialRaw(t, proxyAddr)

	conn.send(t, expectContinueHead)
	if resp := conn.readResponse(t, 500*time.Millisecond); resp.StatusCode != http.StatusContinue {
		t.Fatalf("interim status = %d, want 100", resp.StatusCode)
	}
	conn.send(t, "hello")
	resp := conn.readResponse(t, 2*time.Second)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}
	if body, _ := io.ReadAll(resp.Body); string(body) != "hello" {
		t.Fatalf("upstream received body %q, want %q", body, "hello")
	}

	if resp := conn.roundTrip(t, http.MethodGet, host); resp.StatusCode != http.StatusOK {
		t.Fatalf("next GET status = %d, want 200", resp.StatusCode)
	}
}

// TestServeHTTP_ExpectContinueFaulted sends a request that waits for
// "100 Continue" to a faulted dependency. The injected status must come back
// at once, without waiting for a body the client has not sent.
func TestServeHTTP_ExpectContinueFaulted(t *testing.T) {
	const host = "dependency.test"

	upstream := startCountingUpstream(t)
	proxyAddr := startProxy(t, upstream.addr, fault.NewEngine([]fault.Rule{
		statusRule(host, 1, http.StatusServiceUnavailable),
	}))
	conn := dialRaw(t, proxyAddr)

	conn.send(t, expectContinueHead)
	resp := conn.readResponse(t, 500*time.Millisecond)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	// The client may or may not send the body after an early final response,
	// so the connection cannot carry another request.
	if !resp.Close {
		t.Fatal("response should close the connection")
	}
}

// TestServeHTTP_ForwardsInterimResponses forwards a request to an upstream
// that sends 103 Early Hints before the real response. Both must reach the
// client, and the connection must still carry the next request.
func TestServeHTTP_ForwardsInterimResponses(t *testing.T) {
	const host = "dependency.test"

	upstream := startEarlyHintsUpstream(t)
	proxyAddr := startProxy(t, upstream, fault.NewEngine([]fault.Rule{
		statusRule(host, 0, http.StatusServiceUnavailable),
	}))
	conn := dialRaw(t, proxyAddr)

	conn.send(t, "GET / HTTP/1.1\r\nHost: dependency.test\r\n\r\n")
	if resp := conn.readResponse(t, 2*time.Second); resp.StatusCode != http.StatusEarlyHints {
		t.Fatalf("interim status = %d, want 103", resp.StatusCode)
	}
	resp := conn.readResponse(t, 2*time.Second)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}
	if body, _ := io.ReadAll(resp.Body); string(body) != "ok" {
		t.Fatalf("final body = %q, want %q", body, "ok")
	}

	if resp := conn.roundTrip(t, http.MethodGet, host); resp.StatusCode != http.StatusEarlyHints {
		t.Fatalf("next GET status = %d, want 103 first", resp.StatusCode)
	}
}

// startBodyEchoUpstream starts an HTTP server that answers every request with
// its own body.
func startBodyEchoUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(srv.Close)
	return netip.MustParseAddrPort(srv.Listener.Addr().String())
}

// startEarlyHintsUpstream starts a keep-alive server that answers every
// request with 103 Early Hints followed by 200 "ok".
func startEarlyHintsUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return netip.MustParseAddrPort(srv.Listener.Addr().String())
}

// rawConn is one client connection to the proxy, used for sending requests in
// sequence and reading their responses, so a test controls exactly what goes
// over a single keep-alive connection.
type rawConn struct {
	net.Conn
	r *bufio.Reader
}

func dialRaw(t *testing.T, addr netip.AddrPort) *rawConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &rawConn{Conn: c, r: bufio.NewReader(c)}
}

// roundTrip sends one request without a body on the connection and reads its
// full response.
func (c *rawConn) roundTrip(t *testing.T, method, host string) *http.Response {
	t.Helper()
	return c.do(t, newRequest(t, method, host))
}

// do sends req on the connection and reads its full response.
func (c *rawConn) do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := req.Write(c); err != nil {
		t.Fatalf("write %s: %v", req.Method, err)
	}
	resp, err := http.ReadResponse(c.r, req)
	if err != nil {
		t.Fatalf("read %s response: %v", req.Method, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

// send writes raw bytes on the connection.
func (c *rawConn) send(t *testing.T, raw string) {
	t.Helper()
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// readResponse reads the next response, interim (1xx) or final, failing if it
// does not arrive within timeout. A final response's body is left unread.
func (c *rawConn) readResponse(t *testing.T, timeout time.Duration) *http.Response {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	resp, err := http.ReadResponse(c.r, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

// readExactly reads len(want) raw bytes from the connection and fails unless
// they equal want.
func (c *rawConn) readExactly(t *testing.T, want string) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c.r, got); err != nil {
		t.Fatalf("read %q: %v", want, err)
	}
	if string(got) != want {
		t.Fatalf("read %q, want %q", got, want)
	}
}

func newRequest(t *testing.T, method, host string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+host+"/", nil)
	if err != nil {
		t.Fatalf("new %s request: %v", method, err)
	}
	return req
}
