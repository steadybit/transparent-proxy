// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Package config loads the proxy's fault rules from a JSON file.
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/steadybit/transparent-proxy/internal/fault"
)

// File is the on-disk JSON schema.
type File struct {
	Rules []RuleDTO `json:"rules"`
}

// RuleDTO mirrors fault.Rule with string-encoded fields for JSON ergonomics.
type RuleDTO struct {
	Name             string   `json:"name"`
	CIDRs            []string `json:"cidrs,omitempty"`
	Hosts            []string `json:"hosts,omitempty"`
	Latency          string   `json:"latency,omitempty"`          // e.g. "250ms"
	AbortProbability float64  `json:"abortProbability,omitempty"` // 0..1
}

// Load reads and validates a rules file, returning the parsed fault rules.
func Load(path string) ([]fault.Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return f.ToRules()
}

// ToRules converts the DTOs into validated fault.Rule values.
func (f File) ToRules() ([]fault.Rule, error) {
	rules := make([]fault.Rule, 0, len(f.Rules))
	for i, dto := range f.Rules {
		r, err := dto.toRule()
		if err != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i, dto.Name, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (d RuleDTO) toRule() (fault.Rule, error) {
	r := fault.Rule{Name: d.Name, Hosts: d.Hosts, AbortProbability: d.AbortProbability}

	if d.AbortProbability < 0 || d.AbortProbability > 1 {
		return r, fmt.Errorf("abortProbability must be within [0,1], got %v", d.AbortProbability)
	}

	for _, c := range d.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return r, fmt.Errorf("invalid cidr %q: %w", c, err)
		}
		r.CIDRs = append(r.CIDRs, p)
	}

	if d.Latency != "" {
		dur, err := time.ParseDuration(d.Latency)
		if err != nil {
			return r, fmt.Errorf("invalid latency %q: %w", d.Latency, err)
		}
		if dur < 0 {
			return r, fmt.Errorf("latency must not be negative: %v", dur)
		}
		r.Latency = dur
	}

	return r, nil
}
