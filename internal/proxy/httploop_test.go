// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
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

// roundTrip sends one request on the connection and reads its full response.
func (c *rawConn) roundTrip(t *testing.T, method, host string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+host+"/", nil)
	if err != nil {
		t.Fatalf("new %s request: %v", method, err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := req.Write(c); err != nil {
		t.Fatalf("write %s: %v", method, err)
	}
	resp, err := http.ReadResponse(c.r, req)
	if err != nil {
		t.Fatalf("read %s response: %v", method, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}
