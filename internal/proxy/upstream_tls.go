// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/x509roots/fallback/bundle"
)

// upstreamTLSConfig verifies the dependency itself rather than through
// RootCAs: a pool set there would replace the system roots and disable the
// built-in fallback, while the trusted CAs are meant to come on top of them.
func (s *Server) upstreamTLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	if !s.UpstreamInsecureSkipVerify {
		cfg.VerifyConnection = verifyUpstream(s.UpstreamTrustedCAs)
	}
	return cfg
}

func verifyUpstream(trusted *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		return verifyChain(cs.PeerCertificates, cs.ServerName, trusted, time.Time{})
	}
}

// verifyChain tries the system roots, the built-in roots, then trusted; the
// first that verifies wins. A zero at means now.
//
// The built-in roots are checked explicitly because Go only falls back to them
// when the system has no roots at all. A custom CA mounted the way extensions
// trust one (SSL_CERT_DIR) becomes the whole system pool in an image without
// other roots, and public dependencies would then fail.
func verifyChain(chain []*x509.Certificate, host string, trusted *x509.CertPool, at time.Time) error {
	if len(chain) == 0 {
		return errors.New("the dependency presented no certificate")
	}
	opts := x509.VerifyOptions{DNSName: host, Intermediates: x509.NewCertPool(), CurrentTime: at}
	for _, c := range chain[1:] {
		opts.Intermediates.AddCert(c)
	}
	_, err := chain[0].Verify(opts)
	if err == nil {
		return nil
	}
	for _, roots := range []*x509.CertPool{builtInRoots(), trusted} {
		if roots == nil {
			continue
		}
		opts.Roots = roots
		if _, rootsErr := chain[0].Verify(opts); rootsErr == nil {
			return nil
		}
	}
	return err
}

// builtInRoots keeps each root's constraints, such as distrust-after dates.
var builtInRoots = sync.OnceValue(func() *x509.CertPool {
	pool := x509.NewCertPool()
	for root := range bundle.Roots() {
		cert, err := x509.ParseCertificate(root.Certificate)
		if err != nil {
			continue
		}
		pool.AddCertWithConstraint(cert, root.Constraint)
	}
	return pool
})
