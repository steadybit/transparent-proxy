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

	// HTTPStatus, if non-zero, makes the proxy synthesize an HTTP response with
	// this status code instead of forwarding — an L7 fault that applies only to
	// cleartext HTTP (it is ignored on TLS/opaque connections). Selected by the
	// Host header, matched with the same semantics as Hosts.
	HTTPStatus int
}

// hasL7 reports whether the rule carries an L7-only fault.
func (r Rule) hasL7() bool { return r.HTTPStatus != 0 }

// Action is the decision for a single connection.
type Action struct {
	Rule       string
	Latency    time.Duration
	Abort      bool
	HTTPStatus int
}

// Engine holds an ordered rule set. The first matching rule wins.
type Engine struct {
	rules []Rule
}

// NewEngine builds an engine from rules. A nil/empty rule set yields an
// engine that never injects a fault (pure pass-through).
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// NeedsSNI reports whether any rule selects on hostname at all. Used only for a
// startup summary; per-connection gating uses InspectSNI so that connections no
// host rule could match are never peeked.
func (e *Engine) NeedsSNI() bool {
	for _, r := range e.rules {
		if len(r.Hosts) > 0 {
			return true
		}
	}
	return false
}

// InspectSNI reports whether reading the TLS SNI is worthwhile for a connection
// to dst — i.e. whether some host-selecting rule could match it (its CIDR
// constraint, if any, already admits dst). When false, the proxy skips the
// ClientHello peek for this connection and stays on the pure-splice fast path.
func (e *Engine) InspectSNI(dst netip.AddrPort) bool {
	for _, r := range e.rules {
		if len(r.Hosts) == 0 {
			continue
		}
		if cidrsMatch(r.CIDRs, dst.Addr()) {
			return true
		}
	}
	return false
}

// Inspect reports whether the proxy should read the connection payload for dst
// — to extract a TLS SNI or an HTTP Host header — i.e. whether any rule that
// selects on identity (Hosts) or carries an L7 fault could match dst. When
// false, the connection stays on the pure-splice fast path.
func (e *Engine) Inspect(dst netip.AddrPort) bool {
	for _, r := range e.rules {
		if len(r.Hosts) == 0 && !r.hasL7() {
			continue
		}
		if cidrsMatch(r.CIDRs, dst.Addr()) {
			return true
		}
	}
	return false
}

// Match returns the Action for a connection to dst with the given identity
// (a TLS SNI or an HTTP Host header; empty if unknown). The zero Action means
// "proxy through untouched".
func (e *Engine) Match(dst netip.AddrPort, identity string) Action {
	for _, r := range e.rules {
		if !cidrsMatch(r.CIDRs, dst.Addr()) {
			continue
		}
		if !hostsMatch(r.Hosts, identity) {
			continue
		}
		return Action{
			Rule:    r.Name,
			Latency: r.Latency,
			// Top-level rand.Float64 is safe for concurrent use by the
			// per-connection goroutines and independent across restarts.
			Abort:      r.AbortProbability > 0 && rand.Float64() < r.AbortProbability,
			HTTPStatus: r.HTTPStatus,
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
