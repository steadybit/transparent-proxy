// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Package tlsinject terminates TLS on an intercepted connection so an L7 fault
// can be synthesized for an HTTPS dependency.
//
// The proxy mints a short-lived leaf certificate for the connection's SNI,
// signed by a certificate authority the customer supplies. That CA is entirely
// theirs: they generate it, choose its validity, and install it in the
// truststores of the workloads they want to fault. The proxy only consumes the
// pair — it never creates, rotates, or expires a CA. With no CA configured the
// proxy never decrypts anything and HTTPS keeps flowing through untouched.
//
// Interception here is deliberately one-sided: the real dependency is never
// contacted. Nothing upstream is dialed, so the proxy makes no trust decision
// about the origin's certificate and a dependency behind mutual TLS is
// unaffected — the client-authenticated handshake to the origin simply never
// happens. The cost is that the response is fabricated rather than a modified
// real one.
package tlsinject

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// defaultLeafValidity bounds a minted leaf's lifetime when the caller does
	// not choose one. It is additionally clamped to the CA's own NotAfter, so a
	// leaf never outlives its issuer.
	defaultLeafValidity = 24 * time.Hour
	// leafBackdate tolerates modest clock skew between the proxy and the client.
	leafBackdate = 1 * time.Hour
	// leafRenewBefore re-mints a cached leaf this long before it expires, so a
	// long-running proxy never serves an expired certificate.
	leafRenewBefore = 1 * time.Hour
	// maxCachedLeaves bounds the per-SNI cache so traffic to a great many
	// hostnames cannot grow it without limit. Beyond the cap certificates are
	// still minted, just not retained.
	maxCachedLeaves = 1024
)

// CertError marks a failure to produce a certificate at all — an expired CA, a
// signing failure, a ClientHello with no SNI. It is our side failing, not the
// client refusing us, and the two must not be conflated: reporting a dead CA as
// "the client rejected the certificate" sends the operator to inspect a
// truststore that is perfectly fine.
type CertError struct{ Err error }

func (e *CertError) Error() string { return "could not mint a certificate: " + e.Err.Error() }
func (e *CertError) Unwrap() error { return e.Err }

// CA mints per-SNI leaf certificates from a customer-supplied authority.
// It is safe for concurrent use.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer

	// leafKey is generated once and shared by every minted leaf, so issuing a
	// certificate for a new hostname costs one signature rather than a fresh
	// keypair. It never leaves this process.
	leafKey *ecdsa.PrivateKey

	// leafValidity is how long a minted leaf is valid for. Shorter values limit
	// the window in which a leaf that escaped the proxy would be usable, at the
	// cost of re-signing more often.
	leafValidity time.Duration

	// chain is every certificate the operator supplied, signing certificate
	// first. Presenting all of them lets an intermediate CA be used: the client
	// trusts the root it already has, and we hand it the intermediates needed to
	// build the path. Signing with an intermediate means the operator never has
	// to part with a root key.
	chain [][]byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// SetLeafValidity overrides how long minted leaves are valid. Values below the
// renew window are raised to it, since a leaf shorter than that would be
// considered stale the moment it is issued and re-signed on every handshake.
func (c *CA) SetLeafValidity(d time.Duration) {
	if d <= 0 {
		return
	}
	if d < 2*leafRenewBefore {
		d = 2 * leafRenewBefore
	}
	c.mu.Lock()
	c.leafValidity = d
	// Existing leaves were cut to the old window; drop them so the new one applies.
	c.cache = map[string]*tls.Certificate{}
	c.mu.Unlock()
}

// LoadCA parses a PEM certificate and matching private key. The certificate
// must be a signing CA; anything else is rejected up front rather than failing
// later on every handshake.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid CA keypair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("CA certificate is empty")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("unparseable CA certificate: %w", err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("certificate is not a signing CA: it needs basicConstraints CA:TRUE and keyUsage certSign")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA private key does not implement crypto.Signer")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}
	return &CA{
		cert:         cert,
		key:          signer,
		chain:        pair.Certificate,
		leafKey:      leafKey,
		leafValidity: defaultLeafValidity,
		cache:        map[string]*tls.Certificate{},
	}, nil
}

// LoadCACombined parses one PEM stream carrying both the CA certificate and its
// private key, in any order.
//
// This is the form the proxy accepts on stdin, which is how an orchestrator
// hands over the key without writing it to a disk the target could reach or
// exposing it on the command line. It also sidesteps a filesystem asymmetry:
// the proxy may run inside an overlay of the orchestrator's root, and an
// overlay does not carry the orchestrator's submounts — so a key mounted there
// (a Kubernetes Secret, say) would simply not be visible by path.
func LoadCACombined(pemBytes []byte) (*CA, error) {
	var certPEM, keyPEM []byte
	rest := pemBytes
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch {
		case blk.Type == "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(blk)...)
		case strings.Contains(blk.Type, "ENCRYPTED PRIVATE KEY"):
			// Accepting it here would fail later inside X509KeyPair with an opaque
			// parse error, hiding the actual problem.
			return nil, errors.New("the CA key is passphrase-protected; supply an unencrypted PRIVATE KEY block")
		case strings.Contains(blk.Type, "PRIVATE KEY"):
			keyPEM = append(keyPEM, pem.EncodeToMemory(blk)...)
		}
	}
	if len(certPEM) == 0 {
		return nil, errors.New("no CERTIFICATE block in the supplied PEM")
	}
	if len(keyPEM) == 0 {
		return nil, errors.New("no PRIVATE KEY block in the supplied PEM")
	}
	return LoadCA(certPEM, keyPEM)
}

// LoadCAFromFiles reads a PEM certificate and key from disk.
func LoadCAFromFiles(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key: %w", err)
	}
	return LoadCA(certPEM, keyPEM)
}

// NotAfter reports when the CA expires, for startup logging.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// Expired reports whether the CA is outside its validity window at now. The
// customer owns the CA's lifecycle; this exists only so an unusable CA is
// reported at startup instead of failing every handshake later.
func (c *CA) Expired(now time.Time) bool {
	return now.Before(c.cert.NotBefore) || now.After(c.cert.NotAfter)
}

// ServerTLSConfig returns a config that mints a certificate for whatever SNI
// the client asks for. Both h2 and http/1.1 are advertised so the forged
// response can be delivered over whichever the client negotiates.
func (c *CA) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				// Without SNI there is no name to impersonate, so the handshake is
				// aborted. There is no falling back to forwarding at this point: the
				// ClientHello has been consumed and TLS records already written.
				// Callers avoid reaching here by only intercepting connections whose
				// SNI they already read.
				return nil, &CertError{Err: errors.New("client sent no SNI")}
			}
			cert, err := c.leafFor(hello.ServerName)
			if err != nil {
				return nil, &CertError{Err: err}
			}
			return cert, nil
		},
	}
}

// leafFor returns a cached certificate for host, minting one on first use and
// re-minting before the cached one expires. Without the expiry check a proxy
// outliving leafValidity would serve an expired certificate for every hostname
// it had ever seen, and every client would reject it — indistinguishable, from
// the operator's side, from the CA not being trusted.
func (c *CA) leafFor(host string) (*tls.Certificate, error) {
	now := time.Now()
	c.mu.Lock()
	if cert, ok := c.cache[host]; ok && fresh(cert, now) {
		c.mu.Unlock()
		return cert, nil
	}
	c.mu.Unlock()

	cert, err := c.mint(host)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Another goroutine may have minted the same host concurrently; prefer the
	// stored one so every caller for a host shares a single certificate — unless
	// it is the stale one we set out to replace.
	if existing, ok := c.cache[host]; ok && fresh(existing, now) {
		return existing, nil
	}
	// Replacing an existing (stale) entry never grows the map, so the cap only
	// gates genuinely new hostnames.
	if _, replacing := c.cache[host]; replacing || len(c.cache) < maxCachedLeaves {
		c.cache[host] = cert
	}
	return cert, nil
}

// fresh reports whether a cached leaf is far enough from expiry to keep using.
//
// The renew window is clamped to half the remaining validity: leaves are capped
// at the CA's own NotAfter, so once the CA has less than leafRenewBefore left,
// a fixed window would mark every cached leaf permanently stale and re-sign on
// every single handshake.
func fresh(cert *tls.Certificate, now time.Time) bool {
	renew := leafRenewBefore
	if remaining := cert.Leaf.NotAfter.Sub(now); remaining/2 < renew {
		renew = remaining / 2
	}
	return now.Before(cert.Leaf.NotAfter.Add(-renew))
}

func (c *CA) mint(host string) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	now := time.Now()
	c.mu.Lock()
	validity := c.leafValidity
	c.mu.Unlock()
	if validity <= 0 {
		validity = defaultLeafValidity
	}
	notAfter := now.Add(validity)
	// A leaf must never outlive the CA that signed it.
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	// The CA expiring mid-run is only caught here — the startup check cannot see
	// it. Minting a certificate that is already expired would surface to the
	// operator as "the client rejected us", pointing at the truststore instead of
	// at the real cause.
	if !notAfter.After(now) {
		return nil, fmt.Errorf("CA expired at %s; cannot mint a certificate for %q", c.cert.NotAfter.Format(time.RFC3339), host)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-leafBackdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// Clients validate the SAN, not the CN. An IP literal in SNI is unusual but
	// cheap to support correctly.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, c.leafKey.Public(), c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate for %q: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse minted certificate: %w", err)
	}
	// leaf first, then everything the operator supplied, so a client holding
	// only the root can still build the path through any intermediates.
	chain := make([][]byte, 0, len(c.chain)+1)
	chain = append(chain, der)
	chain = append(chain, c.chain...)

	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  c.leafKey,
		Leaf:        leaf,
	}, nil
}
