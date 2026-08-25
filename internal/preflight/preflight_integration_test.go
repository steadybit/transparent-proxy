// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build linux && integration

// Verifies that Detect parses the live output of a real iptables binary, not
// just fixtures. Installs an Istio-shaped REDIRECT chain graph and asserts it
// is found and conflicts. Requires Linux, root, and iptables.
//
//	go test -tags integration ./internal/preflight/ -run TestDetect_Live -v
package preflight

import (
	"context"
	"os/exec"
	"testing"
)

func ipt(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
		t.Fatalf("iptables %v: %v\n%s", args, err, out)
	}
}

func TestDetect_LiveIstioShapedRedirect(t *testing.T) {
	// Two-level chain graph mimicking OUTPUT -> SBTEST_OUT -> SBTEST_REDIR.
	ipt(t, "-t", "nat", "-N", "SBTEST_OUT")
	ipt(t, "-t", "nat", "-N", "SBTEST_REDIR")
	ipt(t, "-t", "nat", "-A", "SBTEST_REDIR", "-p", "tcp", "--dport", "9443", "-j", "REDIRECT", "--to-ports", "19443")
	ipt(t, "-t", "nat", "-A", "SBTEST_OUT", "-p", "tcp", "-j", "SBTEST_REDIR")
	ipt(t, "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "SBTEST_OUT")
	t.Cleanup(func() {
		_ = exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "SBTEST_OUT").Run()
		_ = exec.Command("iptables", "-t", "nat", "-F", "SBTEST_OUT").Run()
		_ = exec.Command("iptables", "-t", "nat", "-F", "SBTEST_REDIR").Run()
		_ = exec.Command("iptables", "-t", "nat", "-X", "SBTEST_OUT").Run()
		_ = exec.Command("iptables", "-t", "nat", "-X", "SBTEST_REDIR").Run()
	})

	res, err := Detect(context.Background(), execRunner{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	var found *Finding
	for i := range res.Findings {
		if res.Findings[i].ToPort == 19443 {
			found = &res.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("live REDIRECT not detected; findings: %+v", res.Findings)
	}
	if found.conflictsWith([]uint16{9443}) != true || found.conflictsWith([]uint16{80}) {
		t.Errorf("port conflict logic wrong for live finding: %+v", *found)
	}
	if _, conflict := res.Conflict([]uint16{9443}); !conflict {
		t.Error("Result.Conflict should report a conflict on 9443")
	}
}

// execRunner runs commands in the current namespace.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, argv []string, _ []string) (string, error) {
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	return string(out), err
}
