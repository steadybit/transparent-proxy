// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package main

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/steadybit/transparent-proxy/internal/fault"
)

func TestFlushDestinations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// No hostname rule: the flush is not scoped, so it covers the capture filter.
	dsts, scoped := flushDestinations([]fault.Rule{{Name: "cidr-only"}}, logger)
	if scoped || dsts != nil {
		t.Fatalf("CIDR-only rules: dsts=%v scoped=%v, want nil/false", dsts, scoped)
	}

	// A hostname rule that resolves to nothing (.invalid never resolves, RFC 6761)
	// is still scoped — to nothing.
	dsts, scoped = flushDestinations([]fault.Rule{{Name: "h", Hosts: []string{"dependency.invalid"}}}, logger)
	if !scoped || len(dsts) != 0 {
		t.Fatalf("unresolved hostname: dsts=%v scoped=%v, want empty/true", dsts, scoped)
	}
}

func TestSkipFlush(t *testing.T) {
	resolved := []netip.Prefix{netip.MustParsePrefix("93.184.216.34/32")}
	cases := []struct {
		name    string
		noFlush bool
		scoped  bool
		dsts    []netip.Prefix
		want    bool
	}{
		{name: "--no-flush", noFlush: true, scoped: true, dsts: resolved, want: true},
		{name: "CIDR attack flushes the capture filter", scoped: false, want: false},
		{name: "hostnames resolved: flush those addresses", scoped: true, dsts: resolved, want: false},
		{name: "hostnames resolved to nothing: skip, never flush everything", scoped: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := skipFlush(tc.noFlush, tc.scoped, tc.dsts); got != tc.want {
				t.Fatalf("skipFlush = %v, want %v", got, tc.want)
			}
		})
	}
}
