// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestVerifyChain_PublicDependencyWithOnlyAPrivateCAMounted mounts a private
// CA the way extensions trust a custom CA (SSL_CERT_DIR pointing at it), in
// an image that has no other root CAs. Go then takes that one CA as the whole
// system pool and stops using the roots built into the binary, so a public
// dependency must still verify against those explicitly.
//
// Go reads SSL_CERT_DIR on Linux only, so the test runs itself again there
// with the variables set.
func TestVerifyChain_PublicDependencyWithOnlyAPrivateCAMounted(t *testing.T) {
	if os.Getenv("TP_TEST_PRIVATE_CA_ONLY") == "1" {
		chain := readChain(t, "../../testdata/example.com-chain.pem")
		at := time.Date(2026, time.November, 5, 12, 0, 0, 0, time.UTC)
		if err := verifyChain(chain, "example.com", nil, at); err != nil {
			t.Fatalf("verify example.com: %v", err)
		}
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("only Linux reads its system roots from SSL_CERT_DIR")
	}

	dir := t.TempDir()
	writePrivateCA(t, filepath.Join(dir, "private-ca.pem"))
	cmd := exec.Command(os.Args[0], "-test.run=^TestVerifyChain_PublicDependencyWithOnlyAPrivateCAMounted$", "-test.v")
	cmd.Env = append(os.Environ(),
		"TP_TEST_PRIVATE_CA_ONLY=1",
		"SSL_CERT_FILE=/nonexistent",
		"SSL_CERT_DIR="+dir,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("with only a private CA mounted, a public dependency could not be verified: %v\n%s", err, out)
	}
}

func readChain(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var chain []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		chain = append(chain, cert)
	}
	return chain
}

// writePrivateCA writes a self-signed CA certificate, standing in for a
// company CA, to path.
func writePrivateCA(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Private CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
