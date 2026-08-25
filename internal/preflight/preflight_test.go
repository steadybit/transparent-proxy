// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package preflight

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Real istio-iptables nat -S shape (istio/proxyv2). Egress is captured two
// levels deep: OUTPUT -> ISTIO_OUTPUT -> ISTIO_REDIRECT -> REDIRECT 15001.
const istioNat = `-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N ISTIO_INBOUND
-N ISTIO_IN_REDIRECT
-N ISTIO_OUTPUT
-N ISTIO_REDIRECT
-A PREROUTING -p tcp -j ISTIO_INBOUND
-A OUTPUT -p tcp -j ISTIO_OUTPUT
-A ISTIO_INBOUND -p tcp --dport 15008 -j RETURN
-A ISTIO_INBOUND -p tcp -j ISTIO_IN_REDIRECT
-A ISTIO_IN_REDIRECT -p tcp -j REDIRECT --to-ports 15006
-A ISTIO_OUTPUT -s 127.0.0.6/32 -o lo -j RETURN
-A ISTIO_OUTPUT -o lo -m owner ! --uid-owner 1337 -j ISTIO_REDIRECT
-A ISTIO_OUTPUT -m owner --uid-owner 1337 -j RETURN
-A ISTIO_OUTPUT -j ISTIO_REDIRECT
-A ISTIO_REDIRECT -p tcp -j REDIRECT --to-ports 15001`

// kube-proxy: lots of DNAT but no REDIRECT/TPROXY. Must NOT trip a refusal.
const kubeProxyNat = `-P PREROUTING ACCEPT
-N KUBE-SERVICES
-N KUBE-SVC-XXX
-N KUBE-SEP-YYY
-A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A KUBE-SERVICES -d 10.96.0.1/32 -p tcp --dport 443 -j KUBE-SVC-XXX
-A KUBE-SVC-XXX -j KUBE-SEP-YYY
-A KUBE-SEP-YYY -p tcp -m tcp -j DNAT --to-destination 10.0.0.5:6443`

func TestParse_IstioIsDetectedTwoLevelsDeep(t *testing.T) {
	fs := parseFindings(BackendLegacy, "nat", istioNat)

	var egress *Finding
	for i := range fs {
		if fs[i].ToPort == 15001 {
			egress = &fs[i]
		}
	}
	if egress == nil {
		t.Fatalf("did not find the OUTPUT->ISTIO_OUTPUT->ISTIO_REDIRECT egress capture; got %+v", fs)
	}
	if !egress.AllPorts {
		t.Errorf("istio egress redirect should be all-ports, got ports only")
	}
	if egress.Mesh != "istio" {
		t.Errorf("mesh = %q, want istio", egress.Mesh)
	}
	wantPath := "OUTPUT -> ISTIO_OUTPUT -> ISTIO_REDIRECT"
	if strings.Join(egress.Path, " -> ") != wantPath {
		t.Errorf("path = %q, want %q", strings.Join(egress.Path, " -> "), wantPath)
	}
}

func TestParse_KubeProxyIsNotAProxy(t *testing.T) {
	if fs := parseFindings(BackendNFT, "nat", kubeProxyNat); len(fs) != 0 {
		t.Fatalf("kube-proxy DNAT rules must not be reported as interception, got %+v", fs)
	}
}

func TestParse_ScopedRedirectPortMatching(t *testing.T) {
	dump := `-N MYPROXY
-A OUTPUT -p tcp -j MYPROXY
-A MYPROXY -p tcp --dport 443 -j REDIRECT --to-ports 8443`
	fs := parseFindings(BackendNFT, "nat", dump)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.AllPorts {
		t.Fatal("a --dport 443 redirect must not be all-ports")
	}
	if !f.conflictsWith([]uint16{443}) {
		t.Error("should conflict with 443")
	}
	if f.conflictsWith([]uint16{80}) {
		t.Error("should not conflict with 80")
	}
}

func TestParse_PortRangeMatching(t *testing.T) {
	dump := `-N P
-A OUTPUT -p tcp -j P
-A P -p tcp --dport 8000:8100 -j REDIRECT --to-ports 9000`
	f := parseFindings(BackendNFT, "nat", dump)[0]
	if !f.conflictsWith([]uint16{8050}) || f.conflictsWith([]uint16{7999}) {
		t.Errorf("range 8000:8100 matched wrong: %+v", f)
	}
}

func TestParse_TProxyInMangle(t *testing.T) {
	dump := `-N DIVERT
-A PREROUTING -p tcp -m socket -j DIVERT
-A PREROUTING -p tcp --dport 443 -j TPROXY --on-port 15001 --tproxy-mark 0x1/0x1`
	fs := parseFindings(BackendNFT, "mangle", dump)
	if len(fs) != 1 || fs[0].Target != "TPROXY" || fs[0].ToPort != 15001 {
		t.Fatalf("TPROXY not parsed from mangle: %+v", fs)
	}
}

func TestParse_NoInfiniteLoopOnCycle(t *testing.T) {
	dump := `-N A
-N B
-A OUTPUT -j A
-A A -j B
-A B -j A` // cycle, no redirect
	if fs := parseFindings(BackendNFT, "nat", dump); len(fs) != 0 {
		t.Fatalf("cyclic graph should yield no findings, got %+v", fs)
	}
}

// --- Detect / Result ------------------------------------------------------

type fakeRunner struct{ outputs map[string]string }

func (f fakeRunner) Run(_ context.Context, argv []string, _ []string) (string, error) {
	key := strings.Join(argv, " ")
	if out, ok := f.outputs[key]; ok {
		return out, nil
	}
	return "", errors.New("no such command / empty table")
}

func TestDetect_AggregatesBackendsAndTables(t *testing.T) {
	// Istio wrote to the legacy backend's nat table; nft is empty.
	r := fakeRunner{outputs: map[string]string{
		"iptables-legacy -t nat -S": istioNat,
		"iptables-nft -t nat -S":    "-P OUTPUT ACCEPT",
	}}
	res, err := Detect(context.Background(), r)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Backends) != 2 {
		t.Fatalf("expected both backends queried, got %v", res.Backends)
	}
	if _, conflict := res.Conflict([]uint16{80, 443}); !conflict {
		t.Fatal("istio (all-ports) should conflict with target 80,443")
	}
}

func TestDetect_ErrorsWhenNoBackendAvailable(t *testing.T) {
	if _, err := Detect(context.Background(), fakeRunner{}); err == nil {
		t.Fatal("Detect must error when no iptables backend can be queried")
	}
}

func TestDetect_GenericFallbackWhenNoVariants(t *testing.T) {
	// Only the plain `iptables` binary answers (Alpine/slim host). Detect must
	// fall back to it rather than refusing a host interception could work on.
	r := fakeRunner{outputs: map[string]string{
		"iptables -t nat -S":    istioNat,
		"iptables -t mangle -S": "-P PREROUTING ACCEPT",
	}}
	res, err := Detect(context.Background(), r)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Backends) != 1 || res.Backends[0] != BackendGeneric {
		t.Fatalf("expected the generic backend, got %v", res.Backends)
	}
	if _, conflict := res.Conflict([]uint16{443}); !conflict {
		t.Fatal("generic-backend istio ruleset should still conflict with 443")
	}
}

func TestDetect_VariantsPreemptGenericFallback(t *testing.T) {
	// When a variant answers, the generic binary must NOT be probed (avoids
	// double-counting the same rules on a normal host).
	r := fakeRunner{outputs: map[string]string{
		"iptables-nft -t nat -S": kubeProxyNat,
		"iptables -t nat -S":     istioNat, // would add a false conflict if probed
	}}
	res, err := Detect(context.Background(), r)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if _, conflict := res.Conflict([]uint16{443}); conflict {
		t.Fatal("generic fallback should not have been probed once nft answered")
	}
}

func TestDetect_CleanNamespaceNoConflict(t *testing.T) {
	r := fakeRunner{outputs: map[string]string{
		"iptables-nft -t nat -S":    kubeProxyNat,
		"iptables-nft -t mangle -S": "-P PREROUTING ACCEPT",
	}}
	res, err := Detect(context.Background(), r)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if _, conflict := res.Conflict([]uint16{80, 443}); conflict {
		t.Fatal("a kube-proxy-only namespace should not conflict")
	}
}

func TestFinding_Message(t *testing.T) {
	f := parseFindings(BackendLegacy, "nat", istioNat)
	var egress Finding
	for _, x := range f {
		if x.ToPort == 15001 {
			egress = x
		}
	}
	msg := egress.Message()
	for _, want := range []string{"istio", "legacy", "nat", "ISTIO_REDIRECT", "all tcp ports", "15001"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
}
