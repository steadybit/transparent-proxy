// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestPeekClientHello_ExtractsSNI(t *testing.T) {
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
	sni, consumed, err := peekClientHello(server)
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if sni != "api.example.com" {
		t.Fatalf("sni = %q, want api.example.com", sni)
	}
	if len(consumed) == 0 || consumed[0] != tlsHandshakeRecord {
		t.Fatalf("consumed bytes look wrong: %v", consumed[:min(5, len(consumed))])
	}
}

func TestPeekClientHello_NonTLSPassThrough(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	go func() { _, _ = client.Write(payload) }()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	sni, consumed, err := peekClientHello(server)
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if sni != "" {
		t.Fatalf("sni = %q, want empty for non-TLS", sni)
	}
	// Non-TLS: only the 5-byte record-header probe is consumed.
	if string(consumed) != string(payload[:tlsRecordHeaderLen]) {
		t.Fatalf("consumed = %q, want the first %d bytes", consumed, tlsRecordHeaderLen)
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
