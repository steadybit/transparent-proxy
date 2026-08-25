// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_Valid(t *testing.T) {
	data := `{
	  "rules": [
	    {"name": "r1", "cidrs": ["10.0.0.0/8"], "hosts": ["api.example.com"], "latency": "250ms", "abortProbability": 0.5}
	  ]
	}`
	path := filepath.Join(t.TempDir(), "faults.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}

	rules, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r := rules[0]
	if r.Name != "r1" || r.Latency != 250*time.Millisecond || r.AbortProbability != 0.5 {
		t.Fatalf("unexpected rule: %+v", r)
	}
	if len(r.CIDRs) != 1 || r.CIDRs[0].String() != "10.0.0.0/8" {
		t.Fatalf("unexpected cidrs: %v", r.CIDRs)
	}
	if len(r.Hosts) != 1 || r.Hosts[0] != "api.example.com" {
		t.Fatalf("unexpected hosts: %v", r.Hosts)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestToRules_Validation(t *testing.T) {
	cases := []struct {
		name    string
		dto     RuleDTO
		wantErr bool
	}{
		{"ok-empty", RuleDTO{Name: "ok"}, false},
		{"ok-full", RuleDTO{Name: "ok", CIDRs: []string{"192.168.0.0/16"}, Hosts: []string{"x.com"}, Latency: "1s", AbortProbability: 1}, false},
		{"bad-cidr", RuleDTO{Name: "bad", CIDRs: []string{"not-a-cidr"}}, true},
		{"bad-latency", RuleDTO{Name: "bad", Latency: "abc"}, true},
		{"negative-latency", RuleDTO{Name: "bad", Latency: "-5s"}, true},
		{"prob-too-high", RuleDTO{Name: "bad", AbortProbability: 1.5}, true},
		{"prob-negative", RuleDTO{Name: "bad", AbortProbability: -0.1}, true},
		{"ok-http-status", RuleDTO{Name: "ok", HTTPStatus: 503}, false},
		{"bad-http-status-low", RuleDTO{Name: "bad", HTTPStatus: 42}, true},
		{"bad-http-status-high", RuleDTO{Name: "bad", HTTPStatus: 700}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := File{Rules: []RuleDTO{tc.dto}}.ToRules()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %+v", tc.dto)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %+v: %v", tc.dto, err)
			}
		})
	}
}
