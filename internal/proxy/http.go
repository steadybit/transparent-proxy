// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

// maxHeadBytes bounds how much of an HTTP request head we buffer while sniffing,
// so a client that never sends a blank line can't make us buffer unboundedly.
const maxHeadBytes = 8192

type protocol int

const (
	protoOther protocol = iota // opaque L4 (or a partial/unknown head)
	protoTLS                   // TLS ClientHello (identity = SNI)
	protoHTTP                  // cleartext HTTP/1.x (identity = Host header)
)

// sniff reads just enough of the client stream to classify it and, for TLS or
// HTTP, extract the identity (SNI or Host). It is byte-preserving: every byte it
// consumes is returned so the caller can replay it to the upstream unchanged,
// keeping non-faulted traffic byte-identical.
func sniff(c net.Conn) (proto protocol, identity string, consumed []byte, err error) {
	first := make([]byte, 1)
	if _, err := io.ReadFull(c, first); err != nil {
		return protoOther, "", nil, err
	}

	switch {
	case first[0] == tlsHandshakeRecord:
		return sniffTLS(c, first[0])
	case isHTTPMethodStart(first[0]):
		return sniffHTTP(c, first[0])
	default:
		return protoOther, "", first, nil
	}
}

func sniffTLS(c net.Conn, first byte) (protocol, string, []byte, error) {
	rest := make([]byte, tlsRecordHeaderLen-1)
	n, err := io.ReadFull(c, rest)
	consumed := append([]byte{first}, rest[:n]...)
	if err != nil {
		return protoTLS, "", consumed, err
	}
	recLen := int(consumed[3])<<8 | int(consumed[4])
	if recLen <= 0 || recLen > maxTLSRecordLen {
		return protoTLS, "", consumed, nil
	}
	body := make([]byte, recLen)
	n, err = io.ReadFull(c, body)
	consumed = append(consumed, body[:n]...)
	if err != nil {
		return protoTLS, "", consumed, err
	}
	return protoTLS, parseSNI(body), consumed, nil
}

func sniffHTTP(c net.Conn, first byte) (protocol, string, []byte, error) {
	buf := make([]byte, 0, 256)
	buf = append(buf, first)
	one := make([]byte, 1)
	for len(buf) < maxHeadBytes {
		if _, err := io.ReadFull(c, one); err != nil {
			return protoOther, "", buf, err
		}
		buf = append(buf, one[0])
		if bytes.HasSuffix(buf, []byte("\r\n\r\n")) {
			host, ok := parseHTTPHead(buf)
			if !ok {
				return protoOther, "", buf, nil
			}
			return protoHTTP, host, buf, nil
		}
	}
	// No blank line within the cap: treat as opaque and forward what we read.
	return protoOther, "", buf, nil
}

// parseHTTPHead validates the request line and returns the Host header value.
// ok is false when the first line is not an HTTP/1.x request line.
func parseHTTPHead(b []byte) (host string, ok bool) {
	lines := strings.Split(string(b), "\r\n")
	if len(lines) == 0 {
		return "", false
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return "", false
	}
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		k, v, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(k), "Host") {
			return hostWithoutPort(strings.TrimSpace(v)), true
		}
	}
	return "", true // valid HTTP request, just no Host header
}

// hostWithoutPort strips a trailing :port (and IPv6 brackets) from a Host header
// value, so rules match on hostname only — the same semantics as dns-inject's
// --hostname. A bare host is returned unchanged.
func hostWithoutPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func isHTTPMethodStart(b byte) bool {
	// HTTP methods start with an uppercase ASCII letter; TLS content types and
	// binary protocols do not collide with this range.
	return b >= 'A' && b <= 'Z'
}

// writeHTTPStatus synthesizes a minimal HTTP/1.1 response with the given status
// code — an injected fault that never reaches the upstream.
// writeHTTPResponse synthesizes a cleartext HTTP response. body, if empty,
// falls back to a default one-liner. Caller headers are added as-is (their
// Content-Type overrides the default); Content-Length and Connection are always
// set by the proxy so they stay correct and the connection closes cleanly.
func writeHTTPResponse(c net.Conn, status int, headers map[string]string, body string) error {
	reason := http.StatusText(status)
	if reason == "" {
		reason = "Fault Injected"
	}
	if body == "" {
		body = fmt.Sprintf("%d %s (injected by steadybit transparent-proxy)\n", status, reason)
	}

	h := map[string]string{"Content-Type": "text/plain; charset=utf-8"}
	for k, v := range headers {
		h[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
	// Proxy-owned headers: keep the framing correct regardless of caller input.
	h["Content-Length"] = strconv.Itoa(len(body))
	h["Connection"] = "close"

	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", status, reason)
	for k, v := range h {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)

	_, err := c.Write([]byte(sb.String()))
	return err
}
