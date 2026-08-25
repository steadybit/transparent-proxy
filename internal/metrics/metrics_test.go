// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package metrics

import (
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestMetrics_CountersAndActiveGauge(t *testing.T) {
	m := New()

	done1 := m.MatchedConnection()
	done2 := m.MatchedConnection()
	if s := m.Snapshot(); s.ConnectionsMatched != 2 || s.ConnectionsActive != 2 {
		t.Fatalf("after 2 matched: %+v", s)
	}

	m.AddBytes(100, 250)
	m.Proxied()
	done1()

	if s := m.Snapshot(); s.ConnectionsActive != 1 {
		t.Fatalf("active gauge should be 1 after one done, got %d", s.ConnectionsActive)
	}
	done2()

	m.Aborted()
	m.Dropped()
	m.UpstreamError()

	s := m.Snapshot()
	want := Snapshot{
		ConnectionsMatched: 2,
		ConnectionsActive:  0,
		ConnectionsProxied: 1,
		ConnectionsAborted: 1,
		ConnectionsDropped: 1,
		UpstreamErrors:     1,
		BytesToUpstream:    100,
		BytesToClient:      250,
	}
	if s != want {
		t.Fatalf("snapshot = %+v, want %+v", s, want)
	}
}

func TestMetrics_NilSafe(t *testing.T) {
	var m *Metrics // nil
	// None of these must panic.
	m.MatchedConnection()()
	m.Aborted()
	m.Dropped()
	m.Proxied()
	m.UpstreamError()
	m.AddBytes(1, 2)
	if s := m.Snapshot(); (s != Snapshot{}) {
		t.Fatalf("nil metrics should snapshot to zero, got %+v", s)
	}
}

func TestMetrics_Handler(t *testing.T) {
	m := New()
	m.MatchedConnection()
	m.Proxied()

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var got Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ConnectionsMatched != 1 || got.ConnectionsProxied != 1 {
		t.Fatalf("handler snapshot = %+v", got)
	}
}

func TestMetrics_ConcurrentIncrements(t *testing.T) {
	m := New()
	const goroutines, each = 20, 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				done := m.MatchedConnection()
				m.AddBytes(1, 1)
				m.Proxied()
				done()
			}
		}()
	}
	wg.Wait()

	s := m.Snapshot()
	if s.ConnectionsMatched != goroutines*each || s.ConnectionsProxied != goroutines*each {
		t.Fatalf("lost updates under concurrency: %+v", s)
	}
	if s.ConnectionsActive != 0 {
		t.Fatalf("active gauge should return to 0, got %d", s.ConnectionsActive)
	}
}
