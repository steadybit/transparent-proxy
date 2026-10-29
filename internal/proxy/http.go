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
	return sniffFrom(c, first[0])
}

// sniffFrom is sniff for a connection whose first byte was already read.
func sniffFrom(c net.Conn, first byte) (proto protocol, identity string, consumed []byte, err error) {
	switch {
	case first == tlsHandshakeRecord:
		return sniffTLS(c, first)
	case isHTTPMethodStart(first):
		return sniffHTTP(c, first)
	default:
		return protoOther, "", []byte{first}, nil
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
	requestLine := true
	for len(buf) < maxHeadBytes {
		if _, err := io.ReadFull(c, one); err != nil {
			return protoOther, "", buf, err
		}
		buf = append(buf, one[0])
		// Give up as soon as the first line cannot be an HTTP/1.x request line,
		// rather than waiting for a blank line that a text protocol starting
		// with an uppercase letter (Redis inline "PING", NATS "CONNECT {...}")
		// never sends — which would stall it for the whole peek timeout.
		if requestLine {
			complete, ok := checkRequestLine(buf)
			if !ok {
				return protoOther, "", buf, nil
			}
			requestLine = !complete
		}
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
	if !isHTTP1RequestLine(lines[0]) {
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

// maxMethodLen bounds the method token; the longest registered methods
// (e.g. "VERSION-CONTROL") are well under it.
const maxMethodLen = 20

// checkRequestLine inspects buf, the start of the head read so far, while the
// request line is still being read. ok is false as soon as buf can no longer
// be an HTTP/1.x request line; complete is true once the whole line (up to its
// CRLF) has been read and is valid, so it needs no further checking.
func checkRequestLine(buf []byte) (complete, ok bool) {
	if !plausibleRequestLine(buf) {
		return false, false
	}
	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		return false, true
	}
	return true, isHTTP1RequestLine(string(buf[:len(buf)-2]))
}

// plausibleRequestLine reports whether b, the request line read so far, can
// still become an HTTP request line: a method token of uppercase letters, '-'
// or '_' followed by a space, and no bare line break before the method ends.
func plausibleRequestLine(b []byte) bool {
	sp := bytes.IndexByte(b, ' ')
	method := b
	if sp >= 0 {
		method = b[:sp]
	}
	if len(method) == 0 || len(method) > maxMethodLen {
		return false
	}
	for _, ch := range method {
		if (ch < 'A' || ch > 'Z') && ch != '-' && ch != '_' {
			return false
		}
	}
	return true
}

// isHTTP1RequestLine reports whether line is "METHOD target HTTP/1.x".
func isHTTP1RequestLine(line string) bool {
	parts := strings.Fields(line)
	return len(parts) == 3 && strings.HasPrefix(parts[2], "HTTP/1.")
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
	// Normalised the same way as the HTTPS path, so one rule produces the same
	// response whether the matched dependency happened to be HTTP or HTTPS. 1xx
	// is informational and cannot carry a fault; 204/304 must not carry a body.
	if status < 200 || status > 599 {
		status = http.StatusServiceUnavailable
	}
	noBody := status == http.StatusNoContent || status == http.StatusNotModified
	reason := http.StatusText(status)
	if reason == "" {
		reason = "Fault Injected"
	}
	if body == "" && !noBody {
		body = fmt.Sprintf("%d %s (injected by steadybit transparent-proxy)\n", status, reason)
	}
	if noBody {
		body = ""
	}

	h := map[string]string{"Content-Type": "text/plain; charset=utf-8"}
	for k, v := range headers {
		h[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
	// Proxy-owned headers: keep the framing correct regardless of caller input.
	if !noBody {
		h["Content-Length"] = strconv.Itoa(len(body))
	}
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
