// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestSniff_ExtractsSNIFromTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Best-effort: the handshake blocks after the ClientHello; we only
		// care that the ClientHello bytes are written to the pipe.
		_ = tls.Client(client, &tls.Config{
			ServerName:         "api.example.com",
			InsecureSkipVerify: true,
		}).Handshake()
	}()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	proto, identity, consumed, err := sniff(server)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if proto != protoTLS {
		t.Fatalf("proto = %v, want protoTLS", proto)
	}
	if identity != "api.example.com" {
		t.Fatalf("sni = %q, want api.example.com", identity)
	}
	if len(consumed) == 0 || consumed[0] != tlsHandshakeRecord {
		t.Fatalf("consumed bytes look wrong: %v", consumed[:min(5, len(consumed))])
	}
}

func TestSniff_HTTPHostAndBytePreservation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("GET /path HTTP/1.1\r\nHost: api.example.com\r\nAccept: */*\r\n\r\n")
	go func() { _, _ = client.Write(payload) }()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	proto, identity, consumed, err := sniff(server)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if proto != protoHTTP {
		t.Fatalf("proto = %v, want protoHTTP", proto)
	}
	if identity != "api.example.com" {
		t.Fatalf("host = %q, want api.example.com", identity)
	}
	if string(consumed) != string(payload) {
		t.Fatalf("consumed = %q, want the full head byte-identical", consumed)
	}
}

func TestSniff_OpaqueProtocol(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte{0x00, 0x01, 0x02, 0x03}
	go func() { _, _ = client.Write(payload) }()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	proto, identity, consumed, err := sniff(server)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if proto != protoOther || identity != "" {
		t.Fatalf("proto = %v identity = %q, want opaque", proto, identity)
	}
	// Only the first byte is consumed for an opaque protocol.
	if len(consumed) != 1 || consumed[0] != 0x00 {
		t.Fatalf("consumed = %v, want first byte only", consumed)
	}
}

func TestParseHTTPHead(t *testing.T) {
	host, ok := parseHTTPHead([]byte("POST /x HTTP/1.0\r\nhOsT:  Example.COM \r\n\r\n"))
	if !ok || host != "Example.COM" {
		t.Fatalf("host=%q ok=%v", host, ok)
	}
	// The Host header's :port must be stripped so rules match on hostname only.
	host, ok = parseHTTPHead([]byte("GET / HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n"))
	if !ok || host != "api.example.com" {
		t.Fatalf("host=%q ok=%v, want api.example.com without port", host, ok)
	}
	if _, ok := parseHTTPHead([]byte("NOTHTTP garbage\r\n\r\n")); ok {
		t.Fatal("non-HTTP first line should not classify as HTTP")
	}
}

func TestParseSNI_Malformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{handshakeClientHello},
		{handshakeClientHello, 0, 0, 5, 1, 2, 3}, // truncated body
	}
	for i, b := range cases {
		if got := parseSNI(b); got != "" {
			t.Fatalf("case %d: parseSNI = %q, want empty", i, got)
		}
	}
}
