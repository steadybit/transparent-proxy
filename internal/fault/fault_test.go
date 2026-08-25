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

func TestInspectSNI(t *testing.T) {
	// A host rule with no CIDR constraint => inspect every destination.
	anyHost := NewEngine([]Rule{{Name: "h", Hosts: []string{"x.com"}}})
	if !anyHost.InspectSNI(addrPort(t, "9.9.9.9:443")) {
		t.Fatal("unconstrained host rule should inspect any destination")
	}

	// A host rule scoped to a CIDR => inspect only inside that CIDR.
	scoped := NewEngine([]Rule{{Name: "h", Hosts: []string{"b.com"}, CIDRs: []netip.Prefix{mustPrefix(t, "1.2.3.0/24")}}})
	if !scoped.InspectSNI(addrPort(t, "1.2.3.4:443")) {
		t.Fatal("scoped host rule should inspect destinations inside its CIDR")
	}
	if scoped.InspectSNI(addrPort(t, "9.9.9.9:443")) {
		t.Fatal("scoped host rule should not inspect destinations outside its CIDR")
	}

	// CIDR-only rules never need SNI.
	if NewEngine([]Rule{{Name: "c", CIDRs: []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}}}).InspectSNI(addrPort(t, "10.0.0.1:443")) {
		t.Fatal("cidr-only rule should not trigger inspection")
	}

	if NewEngine(nil).InspectSNI(addrPort(t, "1.1.1.1:80")) {
		t.Fatal("empty engine should never inspect")
	}
}

func TestMatch_HTTPStatus(t *testing.T) {
	e := NewEngine([]Rule{{Name: "503", Hosts: []string{"api.example.com"}, HTTPStatus: 503}})
	if got := e.Match(addrPort(t, "1.2.3.4:80"), "api.example.com"); got.HTTPStatus != 503 {
		t.Fatalf("HTTPStatus = %d, want 503", got.HTTPStatus)
	}
	if got := e.Match(addrPort(t, "1.2.3.4:80"), "other.com"); got.HTTPStatus != 0 {
		t.Fatalf("non-matching host should not inject a status, got %d", got.HTTPStatus)
	}
}

func TestInspect(t *testing.T) {
	// A host rule triggers inspection (SNI or Host).
	host := NewEngine([]Rule{{Name: "h", Hosts: []string{"x.com"}}})
	if !host.Inspect(addrPort(t, "9.9.9.9:443")) {
		t.Fatal("host rule should require inspection")
	}
	// An L7 status rule with no host still requires inspection (to read the head).
	l7 := NewEngine([]Rule{{Name: "s", CIDRs: []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}, HTTPStatus: 500}})
	if !l7.Inspect(addrPort(t, "10.0.0.1:80")) {
		t.Fatal("http-status rule should require inspection")
	}
	if l7.Inspect(addrPort(t, "9.9.9.9:80")) {
		t.Fatal("http-status rule outside its CIDR should not require inspection")
	}
	// A plain CIDR latency rule never needs inspection.
	if NewEngine([]Rule{{Name: "c", CIDRs: []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}, Latency: 1}}).Inspect(addrPort(t, "10.0.0.1:80")) {
		t.Fatal("cidr-only latency rule should not require inspection")
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
