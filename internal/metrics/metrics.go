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
	"sync/atomic"
)

// Metrics holds concurrency-safe counters shared across connection goroutines.
type Metrics struct {
	ConnectionsMatched atomic.Int64 // original destination resolved (candidate for fault)
	ConnectionsActive  atomic.Int64 // currently proxied
	ConnectionsProxied atomic.Int64 // completed pass-through/forward
	ConnectionsAborted atomic.Int64 // reset by an abort rule
	ConnectionsDropped atomic.Int64 // loop guard / peek failure / self-refusal
	UpstreamErrors     atomic.Int64 // dial failures
	BytesToUpstream    atomic.Int64
	BytesToClient      atomic.Int64
}

// New returns a ready-to-use Metrics.
func New() *Metrics { return &Metrics{} }

// Snapshot is a point-in-time, JSON-serialisable view.
type Snapshot struct {
	ConnectionsMatched int64 `json:"connections_matched"`
	ConnectionsActive  int64 `json:"connections_active"`
	ConnectionsProxied int64 `json:"connections_proxied"`
	ConnectionsAborted int64 `json:"connections_aborted"`
	ConnectionsDropped int64 `json:"connections_dropped"`
	UpstreamErrors     int64 `json:"upstream_errors"`
	BytesToUpstream    int64 `json:"bytes_to_upstream"`
	BytesToClient      int64 `json:"bytes_to_client"`
}

// Snapshot reads all counters. It is not atomic across counters (values may
// come from slightly different instants), which is fine for observability.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		ConnectionsMatched: m.ConnectionsMatched.Load(),
		ConnectionsActive:  m.ConnectionsActive.Load(),
		ConnectionsProxied: m.ConnectionsProxied.Load(),
		ConnectionsAborted: m.ConnectionsAborted.Load(),
		ConnectionsDropped: m.ConnectionsDropped.Load(),
		UpstreamErrors:     m.UpstreamErrors.Load(),
		BytesToUpstream:    m.BytesToUpstream.Load(),
		BytesToClient:      m.BytesToClient.Load(),
	}
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
