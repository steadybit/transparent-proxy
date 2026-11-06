// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// TestUpstreamRoots_VerifyPublicDependenciesWithoutSystemRoots checks that a
// forwarded HTTPS request can verify a public dependency even where the
// machine has no root CAs. The proxy runs inside the extension's filesystem,
// and the extension images ship none: with only the system roots, every
// request that was not faulted would get a 502.
//
// Go reads the system roots from files on Linux, and SSL_CERT_FILE /
// SSL_CERT_DIR point it elsewhere, so the test runs itself again with both
// pointing at nothing. Elsewhere the platform verifier ignores them.
func TestUpstreamRoots_VerifyPublicDependenciesWithoutSystemRoots(t *testing.T) {
	if os.Getenv("TP_TEST_NO_SYSTEM_ROOTS") == "1" {
		verifyExampleComChain(t)
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("only Linux reads its system roots from files that can be taken away")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestUpstreamRoots_VerifyPublicDependenciesWithoutSystemRoots$", "-test.v")
	cmd.Env = append(os.Environ(),
		"TP_TEST_NO_SYSTEM_ROOTS=1",
		"SSL_CERT_FILE=/nonexistent",
		"SSL_CERT_DIR=/nonexistent",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("without system roots, a public dependency could not be verified: %v\n%s", err, out)
	}
}

// verifyExampleComChain verifies example.com's real certificate chain the way
// the proxy's TLS client does: against the system roots, with no pool of its
// own. The chain was captured from the live site; verifying at a fixed time
// inside its validity keeps the test independent of the network and of the
// certificate expiring.
func verifyExampleComChain(t *testing.T) {
	data, err := os.ReadFile("testdata/example.com-chain.pem")
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var certs []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) < 2 {
		t.Fatalf("chain has %d certificates, want a leaf and intermediates", len(certs))
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err = certs[0].Verify(x509.VerifyOptions{
		DNSName:       "example.com",
		Intermediates: intermediates,
		CurrentTime:   time.Date(2026, time.November, 5, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("verify example.com: %v", err)
	}
}
