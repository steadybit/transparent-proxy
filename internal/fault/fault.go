// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Package fault decides which fault (if any) to apply to an intercepted
// connection. Rules match on the connection's original destination (CIDR)
// and/or on the TLS SNI hostname, so the same engine targets both internal
// (in-cluster, IP-addressed) and external (internet, hostname-addressed)
// dependencies.
package fault

import (
	"math/rand/v2"
	"net/netip"
	"strings"
	"time"
)

// Rule describes a fault and the connections it applies to.
//
// A rule matches a connection when BOTH selectors match:
//   - CIDRs: empty means "any destination"; otherwise the destination IP must
//     fall inside one of the prefixes.
//   - Hosts: empty means "any host"; otherwise the SNI must equal or be a
//     subdomain of one of the entries (suffix match on a dot boundary).
type Rule struct {
	Name string

	CIDRs []netip.Prefix
	Hosts []string

	// Latency is added before the upstream connection is established,
	// simulating a slow-to-connect dependency.
	Latency time.Duration

	// AbortProbability in [0,1] is the chance the connection is reset
	// (RST) instead of being proxied, simulating a refused/flaky dependency.
	AbortProbability float64
}

// Action is the decision for a single connection.
type Action struct {
	Rule    string
	Latency time.Duration
	Abort   bool
}

// Engine holds an ordered rule set. The first matching rule wins.
type Engine struct {
	rules []Rule
	rng   *rand.Rand
}

// NewEngine builds an engine from rules. A nil/empty rule set yields an
// engine that never injects a fault (pure pass-through).
func NewEngine(rules []Rule) *Engine {
	// Deterministic seed keeps behaviour reproducible across restarts; the
	// probability roll only needs to be uniform, not cryptographically random.
	return &Engine{
		rules: rules,
		rng:   rand.New(rand.NewPCG(0x9E3779B97F4A7C15, 0xBF58476D1CE4E5B9)),
	}
}

// NeedsSNI reports whether any rule selects on hostname. When false, the proxy
// can take the pure-splice fast path and skip the ClientHello peek entirely.
func (e *Engine) NeedsSNI() bool {
	for _, r := range e.rules {
		if len(r.Hosts) > 0 {
			return true
		}
	}
	return false
}

// Match returns the Action for a connection to dst with the given SNI (empty
// if unknown or not TLS). The zero Action means "proxy through untouched".
func (e *Engine) Match(dst netip.AddrPort, sni string) Action {
	for _, r := range e.rules {
		if !cidrsMatch(r.CIDRs, dst.Addr()) {
			continue
		}
		if !hostsMatch(r.Hosts, sni) {
			continue
		}
		return Action{
			Rule:    r.Name,
			Latency: r.Latency,
			Abort:   r.AbortProbability > 0 && e.rng.Float64() < r.AbortProbability,
		}
	}
	return Action{}
}

func cidrsMatch(cidrs []netip.Prefix, ip netip.Addr) bool {
	if len(cidrs) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, p := range cidrs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func hostsMatch(hosts []string, sni string) bool {
	if len(hosts) == 0 {
		return true
	}
	if sni == "" {
		return false
	}
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if sni == h || strings.HasSuffix(sni, "."+h) {
			return true
		}
	}
	return false
}
