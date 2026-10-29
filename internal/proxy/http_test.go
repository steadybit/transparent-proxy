// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
)

// readSynthesized runs writeHTTPResponse over an in-memory pipe and parses the
// result back into an *http.Response.
func readSynthesized(t *testing.T, status int, headers map[string]string, body string) *http.Response {
	t.Helper()
	srv, cli := net.Pipe()
	go func() {
		_ = writeHTTPResponse(srv, status, headers, body)
		_ = srv.Close()
	}()
	resp, err := http.ReadResponse(bufio.NewReader(cli), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	return resp
}

func Test_writeHTTPResponse_defaults(t *testing.T) {
	resp := readSynthesized(t, 503, nil, "")
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if len(b) == 0 {
		t.Fatal("expected a default body")
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("default Content-Type = %q", got)
	}
	if resp.ContentLength != int64(len(b)) {
		t.Fatalf("Content-Length %d != body len %d", resp.ContentLength, len(b))
	}
}

func Test_writeHTTPResponse_customBodyAndHeaders(t *testing.T) {
	body := `{"error":"nope"}`
	resp := readSynthesized(t, 429, map[string]string{
		"content-type": "application/json", // lower-case, should be canonicalized + override default
		"Retry-After":  "30",
		"X-Fault":      "injected",
	}, body)
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := resp.Header.Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After = %q", got)
	}
	if got := resp.Header.Get("X-Fault"); got != "injected" {
		t.Fatalf("X-Fault = %q", got)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != body {
		t.Fatalf("body = %q, want %q", b, body)
	}
	// Content-Length is proxy-owned and must match the custom body.
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(body))
	}
}

func TestCheckRequestLine(t *testing.T) {
	cases := []struct {
		buf          string
		complete, ok bool
	}{
		{buf: "G", complete: false, ok: true},
		{buf: "GET /x HTTP/1", complete: false, ok: true},
		{buf: "GET /x HTTP/1.1\r\n", complete: true, ok: true},
		{buf: "PING\r", complete: false, ok: false},                         // line break before the method ends
		{buf: "Get", complete: false, ok: false},                            // lowercase method
		{buf: "CONNECT {\"verbose\":false}\r\n", complete: true, ok: false}, // not METHOD target HTTP/1.x
		{buf: "PRI * HTTP/2.0\r\n", complete: true, ok: false},              // HTTP/2 preface
	}
	for _, tc := range cases {
		complete, ok := checkRequestLine([]byte(tc.buf))
		if complete != tc.complete || ok != tc.ok {
			t.Errorf("checkRequestLine(%q) = (complete=%v, ok=%v), want (%v, %v)", tc.buf, complete, ok, tc.complete, tc.ok)
		}
	}
}
