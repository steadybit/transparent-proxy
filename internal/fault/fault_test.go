// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package fault

import (
	"net/netip"
	"testing"
	"time"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func addrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("ParseAddrPort(%q): %v", s, err)
	}
	return ap
}

func TestMatch_ByCIDR(t *testing.T) {
	e := NewEngine([]Rule{{Name: "internal", CIDRs: []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}, Latency: time.Second}})

	if got := e.Match(addrPort(t, "10.1.2.3:443"), ""); got.Rule != "internal" || got.Latency != time.Second {
		t.Fatalf("in-range match = %+v, want rule internal with 1s latency", got)
	}
	if got := e.Match(addrPort(t, "8.8.8.8:443"), ""); got.Rule != "" {
		t.Fatalf("out-of-range match = %+v, want no rule", got)
	}
}

func TestMatch_ByHostSuffix(t *testing.T) {
	e := NewEngine([]Rule{{Name: "stripe", Hosts: []string{"stripe.com"}}})

	for _, sni := range []string{"stripe.com", "api.stripe.com", "API.Stripe.com."} {
		if got := e.Match(addrPort(t, "1.2.3.4:443"), sni); got.Rule != "stripe" {
			t.Fatalf("sni %q: got %+v, want rule stripe", sni, got)
		}
	}
	for _, sni := range []string{"", "notstripe.com", "stripe.com.evil.com"} {
		if got := e.Match(addrPort(t, "1.2.3.4:443"), sni); got.Rule != "" {
			t.Fatalf("sni %q: got %+v, want no match", sni, got)
		}
	}
}

func TestMatch_CombinedSelectors(t *testing.T) {
	e := NewEngine([]Rule{{
		Name:  "both",
		CIDRs: []netip.Prefix{mustPrefix(t, "203.0.113.0/24")},
		Hosts: []string{"example.com"},
	}})

	if got := e.Match(addrPort(t, "203.0.113.5:443"), "api.example.com"); got.Rule != "both" {
		t.Fatalf("both selectors satisfied: got %+v, want rule both", got)
	}
	if got := e.Match(addrPort(t, "203.0.113.5:443"), "other.com"); got.Rule != "" {
		t.Fatalf("host mismatch should not match: got %+v", got)
	}
	if got := e.Match(addrPort(t, "198.51.100.5:443"), "api.example.com"); got.Rule != "" {
		t.Fatalf("cidr mismatch should not match: got %+v", got)
	}
}

func TestMatch_AbortProbabilityExtremes(t *testing.T) {
	always := NewEngine([]Rule{{Name: "kill", AbortProbability: 1.0}})
	never := NewEngine([]Rule{{Name: "safe", AbortProbability: 0.0}})

	for i := 0; i < 100; i++ {
		if !always.Match(addrPort(t, "1.1.1.1:80"), "").Abort {
			t.Fatal("probability 1.0 should always abort")
		}
		if never.Match(addrPort(t, "1.1.1.1:80"), "").Abort {
			t.Fatal("probability 0.0 should never abort")
		}
	}
}

func TestNeedsSNI(t *testing.T) {
	if NewEngine([]Rule{{Name: "cidr", CIDRs: []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}}}).NeedsSNI() {
		t.Fatal("CIDR-only rules should not need SNI")
	}
	if !NewEngine([]Rule{{Name: "host", Hosts: []string{"x.com"}}}).NeedsSNI() {
		t.Fatal("host rules should need SNI")
	}
	if NewEngine(nil).NeedsSNI() {
		t.Fatal("empty engine should not need SNI")
	}
}

func TestFirstMatchWins(t *testing.T) {
	e := NewEngine([]Rule{
		{Name: "first", CIDRs: []netip.Prefix{mustPrefix(t, "0.0.0.0/0")}, Latency: time.Second},
		{Name: "second", CIDRs: []netip.Prefix{mustPrefix(t, "0.0.0.0/0")}, Latency: 2 * time.Second},
	})
	if got := e.Match(addrPort(t, "9.9.9.9:53"), ""); got.Rule != "first" {
		t.Fatalf("got %+v, want first rule to win", got)
	}
}
