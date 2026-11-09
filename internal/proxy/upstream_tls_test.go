// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// A dependency with a private CA: one the system roots and the built-in ones
// do not know.

func TestVerifyChain_TrustedPrivateCA(t *testing.T) {
	ca, leaf := newPrivateCAWithLeaf(t, "dep.test")
	if err := verifyChain([]*x509.Certificate{leaf}, "dep.test", poolOf(ca), time.Time{}); err != nil {
		t.Fatalf("trusted private CA: %v", err)
	}
}

func TestVerifyChain_UntrustedPrivateCAIsRejected(t *testing.T) {
	_, leaf := newPrivateCAWithLeaf(t, "dep.test")
	if err := verifyChain([]*x509.Certificate{leaf}, "dep.test", nil, time.Time{}); err == nil {
		t.Fatal("a private CA nobody trusts must be rejected")
	}
}

// Trusting a CA must not mean accepting any certificate it signed.
func TestVerifyChain_TrustedCAStillChecksTheHostname(t *testing.T) {
	ca, leaf := newPrivateCAWithLeaf(t, "dep.test")
	if err := verifyChain([]*x509.Certificate{leaf}, "other.test", poolOf(ca), time.Time{}); err == nil {
		t.Fatal("a certificate for dep.test must not verify other.test")
	}
}

func TestUpstreamTLSConfig(t *testing.T) {
	verifying := (&Server{}).upstreamTLSConfig()
	if verifying.VerifyConnection == nil {
		t.Fatal("by default the dependency must be verified")
	}
	if skipping := (&Server{UpstreamInsecureSkipVerify: true}).upstreamTLSConfig(); skipping.VerifyConnection != nil {
		t.Fatal("with UpstreamInsecureSkipVerify nothing may be verified")
	}
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

func newPrivateCAWithLeaf(t *testing.T, host string) (ca, leaf *x509.Certificate) {
	t.Helper()
	caKey := newKey(t)
	ca = createCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Private CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}, nil, caKey, caKey)
	leaf = createCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, newKey(t), caKey)
	return ca, leaf
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func createCert(t *testing.T, tmpl, parent *x509.Certificate, key *ecdsa.PrivateKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
