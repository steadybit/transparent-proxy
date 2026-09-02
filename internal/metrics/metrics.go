// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Package metrics exposes lightweight counters so the platform can tell whether
// the proxy is actually intercepting traffic. ConnectionsMatched sitting at
// zero is the canonical "silent no-op" signal — the interception rules were
// installed but nothing hit them (e.g. a Cilium socketLB datapath that bypasses
// iptables entirely, which preflight cannot detect).
package metrics

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Metrics holds concurrency-safe counters shared across connection goroutines.
type Metrics struct {
	ConnectionsMatched    atomic.Int64 // original destination resolved (candidate for fault)
	ConnectionsActive     atomic.Int64 // currently proxied
	ConnectionsProxied    atomic.Int64 // completed pass-through/forward
	ConnectionsAborted    atomic.Int64 // reset by an abort rule
	ConnectionsDropped    atomic.Int64 // loop guard / peek failure / self-refusal
	ConnectionsFaulted    atomic.Int64 // connections a fault was actually applied to (once each)
	LatencyApplied        atomic.Int64 // connections a latency fault delayed
	HTTPResponsesInjected atomic.Int64 // connections given a synthesized HTTP response
	TLSInterceptRejected  atomic.Int64 // HTTPS interception rejected by the client (CA not trusted / pinning)
	UpstreamErrors        atomic.Int64 // dial failures
	BytesToUpstream       atomic.Int64
	BytesToClient         atomic.Int64

	// perHost breaks the matched/faulted counts down by the dependency hostname
	// (SNI or HTTP Host) a connection carried. It is the "which dependency, how
	// often" view the platform renders. Guarded by mu because hostnames are
	// dynamic keys. Hostnames here are the attacker-supplied targets, so exposing
	// them in the operator's own statistics is safe (unlike the process logs).
	mu      sync.Mutex
	perHost map[string]*hostCounters
}

type hostCounters struct {
	matched int64
	faulted int64
}

// New returns a ready-to-use Metrics.
func New() *Metrics { return &Metrics{perHost: map[string]*hostCounters{}} }

// HostStat is the per-hostname view in a Snapshot.
type HostStat struct {
	Matched int64 `json:"matched"`
	Faulted int64 `json:"faulted"`
}

// Snapshot is a point-in-time, JSON-serialisable view.
type Snapshot struct {
	ConnectionsMatched    int64               `json:"connections_matched"`
	ConnectionsActive     int64               `json:"connections_active"`
	ConnectionsProxied    int64               `json:"connections_proxied"`
	ConnectionsAborted    int64               `json:"connections_aborted"`
	ConnectionsDropped    int64               `json:"connections_dropped"`
	ConnectionsFaulted    int64               `json:"connections_faulted"`
	LatencyApplied        int64               `json:"latency_applied"`
	HTTPResponsesInjected int64               `json:"http_responses_injected"`
	TLSInterceptRejected  int64               `json:"tls_intercept_rejected"`
	UpstreamErrors        int64               `json:"upstream_errors"`
	BytesToUpstream       int64               `json:"bytes_to_upstream"`
	BytesToClient         int64               `json:"bytes_to_client"`
	PerHost               map[string]HostStat `json:"per_host,omitempty"`
}

// Snapshot reads all counters. It is not atomic across counters (values may
// come from slightly different instants), which is fine for observability.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	var perHost map[string]HostStat
	if len(m.perHost) > 0 {
		perHost = make(map[string]HostStat, len(m.perHost))
		for h, c := range m.perHost {
			perHost[h] = HostStat{Matched: c.matched, Faulted: c.faulted}
		}
	}
	m.mu.Unlock()
	return Snapshot{
		ConnectionsMatched:    m.ConnectionsMatched.Load(),
		ConnectionsActive:     m.ConnectionsActive.Load(),
		ConnectionsProxied:    m.ConnectionsProxied.Load(),
		ConnectionsAborted:    m.ConnectionsAborted.Load(),
		ConnectionsDropped:    m.ConnectionsDropped.Load(),
		ConnectionsFaulted:    m.ConnectionsFaulted.Load(),
		LatencyApplied:        m.LatencyApplied.Load(),
		HTTPResponsesInjected: m.HTTPResponsesInjected.Load(),
		TLSInterceptRejected:  m.TLSInterceptRejected.Load(),
		UpstreamErrors:        m.UpstreamErrors.Load(),
		BytesToUpstream:       m.BytesToUpstream.Load(),
		BytesToClient:         m.BytesToClient.Load(),
		PerHost:               perHost,
	}
}

// SortedHosts returns the per-host keys in a stable order, for deterministic
// rendering.
func (s Snapshot) SortedHosts() []string {
	hosts := make([]string, 0, len(s.PerHost))
	for h := range s.PerHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// Handler serves the current snapshot as JSON at any path.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m.Snapshot())
	})
}

// All the mutators below are nil-safe so the proxy can hold an optional
// *Metrics without guarding every call site.

// MatchedConnection records a connection whose original destination resolved
// (the interception delivered it to us) and returns a done func to call when it
// finishes, decrementing the active gauge.
func (m *Metrics) MatchedConnection() (done func()) {
	if m == nil {
		return func() {}
	}
	m.ConnectionsMatched.Add(1)
	m.ConnectionsActive.Add(1)
	return func() { m.ConnectionsActive.Add(-1) }
}

// Aborted, Dropped, Proxied, UpstreamError, and AddBytes are the outcome hooks.
func (m *Metrics) Aborted() {
	if m != nil {
		m.ConnectionsAborted.Add(1)
	}
}

func (m *Metrics) Dropped() {
	if m != nil {
		m.ConnectionsDropped.Add(1)
	}
}

func (m *Metrics) Proxied() {
	if m != nil {
		m.ConnectionsProxied.Add(1)
	}
}

// Faulted records that a fault was actually applied to a connection. Call it at
// most once per connection (a connection can carry both latency and an injected
// response, but is a single faulted connection).
func (m *Metrics) Faulted() {
	if m != nil {
		m.ConnectionsFaulted.Add(1)
	}
}

// LatencyInjected records a connection a latency fault delayed.
func (m *Metrics) LatencyInjected() {
	if m != nil {
		m.LatencyApplied.Add(1)
	}
}

// HTTPInjected records a connection given a synthesized HTTP response (instead
// of being forwarded upstream).
func (m *Metrics) HTTPInjected() {
	if m != nil {
		m.HTTPResponsesInjected.Add(1)
	}
}

// TLSRejected records an HTTPS connection on which the client refused the
// injected certificate — either by failing the handshake, or (under TLS 1.3,
// where the server's handshake completes before the client's verdict arrives)
// by abandoning the connection without ever sending a request. A non-zero count
// is the canonical "our CA is not trusted by the target, or the client pins
// certificates" signal. In both cases no response was delivered, so it is
// deliberately not counted as faulted.
func (m *Metrics) TLSRejected() {
	if m != nil {
		m.TLSInterceptRejected.Add(1)
	}
}

// MatchedHost records that a connection carrying the given dependency hostname
// matched a rule. FaultedHost records that a fault was actually applied to it
// (i.e. it passed the probability roll). Empty hosts are ignored.
func (m *Metrics) MatchedHost(host string) { m.addHost(host, true, false) }
func (m *Metrics) FaultedHost(host string) { m.addHost(host, false, true) }

func (m *Metrics) addHost(host string, matched, faulted bool) {
	if m == nil || host == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.perHost[host]
	if c == nil {
		c = &hostCounters{}
		m.perHost[host] = c
	}
	if matched {
		c.matched++
	}
	if faulted {
		c.faulted++
	}
}

func (m *Metrics) UpstreamError() {
	if m != nil {
		m.UpstreamErrors.Add(1)
	}
}

func (m *Metrics) AddBytes(toUpstream, toClient int64) {
	if m == nil {
		return
	}
	m.BytesToUpstream.Add(toUpstream)
	m.BytesToClient.Add(toClient)
}
