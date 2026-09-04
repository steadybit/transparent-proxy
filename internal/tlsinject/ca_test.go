// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package tlsinject

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// newTestCAPEM builds a self-signed authority for tests. isCA=false yields a
// leaf-shaped certificate, used to prove non-CA input is rejected.
func newTestCAPEM(t *testing.T, notAfter time.Time, isCA bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Intercept CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func mustLoadTestCA(t *testing.T) (*CA, []byte) {
	t.Helper()
	certPEM, keyPEM := newTestCAPEM(t, time.Now().Add(30*24*time.Hour), true)
	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return ca, certPEM
}

func Test_LoadCA_acceptsSigningCA(t *testing.T) {
	ca, _ := mustLoadTestCA(t)
	if ca.Expired(time.Now()) {
		t.Fatal("freshly issued CA reported as expired")
	}
	if ca.NotAfter().Before(time.Now()) {
		t.Fatal("NotAfter is in the past")
	}
}

func Test_LoadCA_rejectsNonCA(t *testing.T) {
	certPEM, keyPEM := newTestCAPEM(t, time.Now().Add(time.Hour), false)
	_, err := LoadCA(certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected a non-CA certificate to be rejected")
	}
	if !strings.Contains(err.Error(), "not a signing CA") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_LoadCA_rejectsMismatchedKey(t *testing.T) {
	certPEM, _ := newTestCAPEM(t, time.Now().Add(time.Hour), true)
	_, otherKey := newTestCAPEM(t, time.Now().Add(time.Hour), true)
	if _, err := LoadCA(certPEM, otherKey); err == nil {
		t.Fatal("expected a mismatched key to be rejected")
	}
}

func Test_LoadCA_rejectsGarbage(t *testing.T) {
	if _, err := LoadCA([]byte("not a pem"), []byte("neither")); err == nil {
		t.Fatal("expected garbage input to be rejected")
	}
}

func Test_Expired(t *testing.T) {
	certPEM, keyPEM := newTestCAPEM(t, time.Now().Add(time.Hour), true)
	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !ca.Expired(time.Now().Add(2 * time.Hour)) {
		t.Fatal("expected a CA to be expired past its NotAfter")
	}
	if !ca.Expired(time.Now().Add(-2 * time.Hour)) {
		t.Fatal("expected a CA to be invalid before its NotBefore")
	}
}

func Test_leafFor_mintsForSNIAndCaches(t *testing.T) {
	ca, _ := mustLoadTestCA(t)

	first, err := ca.leafFor("api.anthropic.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if got := first.Leaf.DNSNames; len(got) != 1 || got[0] != "api.anthropic.com" {
		t.Fatalf("leaf SAN = %v, want [api.anthropic.com]", got)
	}
	// The leaf must actually chain to the CA a client would trust.
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := first.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "api.anthropic.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("minted leaf does not verify against the CA: %v", err)
	}

	second, err := ca.leafFor("api.anthropic.com")
	if err != nil {
		t.Fatalf("leafFor (cached): %v", err)
	}
	if first != second {
		t.Fatal("expected the second call to return the cached certificate")
	}

	other, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatalf("leafFor (other host): %v", err)
	}
	if other == first {
		t.Fatal("expected a distinct certificate per hostname")
	}
}

func Test_leafFor_usesIPSANForIPLiteral(t *testing.T) {
	ca, _ := mustLoadTestCA(t)
	cert, err := ca.leafFor("10.1.2.3")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if len(cert.Leaf.IPAddresses) != 1 || cert.Leaf.IPAddresses[0].String() != "10.1.2.3" {
		t.Fatalf("IP SANs = %v, want [10.1.2.3]", cert.Leaf.IPAddresses)
	}
	if len(cert.Leaf.DNSNames) != 0 {
		t.Fatalf("unexpected DNS SANs on an IP leaf: %v", cert.Leaf.DNSNames)
	}
}

// A leaf must never outlive the authority that signed it, however short-lived
// the customer chose to make their CA.
func Test_leafFor_clampsValidityToCA(t *testing.T) {
	caNotAfter := time.Now().Add(time.Hour) // shorter than leafValidity
	certPEM, keyPEM := newTestCAPEM(t, caNotAfter, true)
	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	cert, err := ca.leafFor("short.example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if cert.Leaf.NotAfter.After(ca.NotAfter()) {
		t.Fatalf("leaf NotAfter %s outlives CA NotAfter %s", cert.Leaf.NotAfter, ca.NotAfter())
	}
}

func Test_ServerTLSConfig_requiresSNI(t *testing.T) {
	ca, _ := mustLoadTestCA(t)
	cfg := ca.ServerTLSConfig()

	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("expected a ClientHello without SNI to be refused")
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.anthropic.com"}); err != nil {
		t.Fatalf("expected a certificate for a named host: %v", err)
	}

	// Both protocols must be offered so the forged response can be delivered
	// over whichever the client negotiates.
	want := map[string]bool{"h2": false, "http/1.1": false}
	for _, p := range cfg.NextProtos {
		want[p] = true
	}
	for p, seen := range want {
		if !seen {
			t.Fatalf("ALPN does not advertise %q (got %v)", p, cfg.NextProtos)
		}
	}
}

func Test_LoadCACombined(t *testing.T) {
	certPEM, keyPEM := newTestCAPEM(t, time.Now().Add(24*time.Hour), true)

	// Order must not matter: an orchestrator concatenates whichever way round.
	for _, combined := range [][]byte{
		append(append([]byte{}, certPEM...), keyPEM...),
		append(append([]byte{}, keyPEM...), certPEM...),
	} {
		ca, err := LoadCACombined(combined)
		if err != nil {
			t.Fatalf("LoadCACombined: %v", err)
		}
		if _, err := ca.leafFor("api.anthropic.com"); err != nil {
			t.Fatalf("minting from a combined PEM failed: %v", err)
		}
	}

	// A stream missing either half is rejected with a pointed message rather
	// than failing later on every handshake.
	if _, err := LoadCACombined(certPEM); err == nil ||
		!strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("expected a missing-key error, got %v", err)
	}
	if _, err := LoadCACombined(keyPEM); err == nil ||
		!strings.Contains(err.Error(), "CERTIFICATE") {
		t.Fatalf("expected a missing-certificate error, got %v", err)
	}
	if _, err := LoadCACombined([]byte("not pem at all")); err == nil {
		t.Fatal("expected garbage to be rejected")
	}
}

// A CA that expires mid-run must be reported as our failure, not as the client
// rejecting us — otherwise the operator is sent to inspect a truststore that is
// perfectly fine. This is the exact misdiagnosis the expiry check exists to
// prevent, so it must not be undone by the error classification above it.
func Test_mint_expiredCAIsCertErrorNotRejection(t *testing.T) {
	certPEM, keyPEM := newTestCAPEM(t, time.Now().Add(2*time.Second), true)
	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	// Force the CA past its NotAfter without waiting.
	ca.cert.NotAfter = time.Now().Add(-time.Minute)

	_, err = ca.ServerTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err == nil {
		t.Fatal("expected minting to fail once the CA has expired")
	}
	if !isCertError(err) {
		t.Fatalf("err = %v, want a *CertError so it is not misreported as a client rejection", err)
	}
}

func Test_ServerTLSConfig_noSNIIsCertError(t *testing.T) {
	ca, _ := mustLoadTestCA(t)
	_, err := ca.ServerTLSConfig().GetCertificate(&tls.ClientHelloInfo{})
	if !isCertError(err) {
		t.Fatalf("err = %v, want a *CertError", err)
	}
}

// With a fixed renew window, a CA with less than that window left would mark
// every cached leaf permanently stale — turning each handshake into a fresh
// signature under the mutex.
func Test_leafFor_cachesEvenWhenCANearExpiry(t *testing.T) {
	certPEM, keyPEM := newTestCAPEM(t, time.Now().Add(30*time.Minute), true) // < leafRenewBefore
	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	first, err := ca.leafFor("api.example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	second, err := ca.leafFor("api.example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if first != second {
		t.Fatal("cache thrashing: re-minted despite a still-valid leaf")
	}
}

func Test_LoadCACombined_rejectsEncryptedKey(t *testing.T) {
	certPEM, _ := newTestCAPEM(t, time.Now().Add(time.Hour), true)
	enc := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("nope")})
	_, err := LoadCACombined(append(append([]byte{}, certPEM...), enc...))
	if err == nil || !strings.Contains(err.Error(), "passphrase-protected") {
		t.Fatalf("err = %v, want a pointed passphrase-protected message", err)
	}
}

// An operator must never have to hand over a root key. Signing with an
// intermediate issued by their own PKI has to work: the client trusts only the
// root it already has, and the proxy supplies the intermediate so the path can
// be built.
func Test_LoadCA_worksWithAnIntermediate(t *testing.T) {
	// root (stays offline; only its certificate is trusted by the client)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Customer Root CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(72 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	// intermediate — this is what the operator hands the proxy
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Steadybit Intercept Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, interKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interKeyDER, _ := x509.MarshalECPrivateKey(interKey)

	// The operator supplies intermediate (+ root) and the intermediate's key.
	certPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: interKeyDER})

	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("an intermediate CA must be accepted: %v", err)
	}
	cert, err := ca.leafFor("api.example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}

	// The client trusts ONLY the root; the chain we present must let it verify.
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inters := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			t.Fatal(perr)
		}
		inters.AddCert(c)
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inters, DNSName: "api.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("a client trusting only the root could not verify the presented chain: %v", err)
	}
}
