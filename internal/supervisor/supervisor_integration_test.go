// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build linux && integration

// Proves the fail-open guarantee against real iptables: the Guard must leave no
// interception rules behind on any exit path, so the target is never worse than
// untouched. Requires Linux, root, and iptables.
//
//	go test -tags integration ./internal/supervisor/ -run TestGuard_RealTeardown -v
package supervisor

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/steadybit/transparent-proxy/internal/interception"
)

type adapter struct {
	cfg    interception.Config
	runner interception.CommandRunner
}

func (a adapter) Apply(ctx context.Context) error  { return a.cfg.Apply(ctx, a.runner) }
func (a adapter) Revert(ctx context.Context) error { return a.cfg.Revert(ctx, a.runner) }

func natContains(t *testing.T, needle string) bool {
	t.Helper()
	out, err := exec.Command("iptables", "-t", "nat", "-S").CombinedOutput()
	if err != nil {
		t.Fatalf("iptables -S: %v\n%s", err, out)
	}
	return strings.Contains(string(out), needle)
}

func newGuard(execID string) (*Guard, string) {
	cfg := interception.Config{
		ExecutionID: execID,
		ProxyPort:   3199,
		Filter: interception.Filter{
			Include: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			Ports:   []uint16{9999},
		},
	}
	return &Guard{Interceptor: adapter{cfg: cfg, runner: interception.ExecRunner{}}}, "SB_TP_REDIR_" + execID
}

func TestGuard_RealTeardownOnReturn(t *testing.T) {
	g, chain := newGuard("e2e-return")
	err := g.Run(context.Background(), func(context.Context) error {
		if !natContains(t, chain) {
			t.Error("redirect chain not present during serve")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if natContains(t, chain) {
		t.Fatalf("fail-open violated: chain %s still present after Run", chain)
	}
}

func TestGuard_RealTeardownOnPanic(t *testing.T) {
	g, chain := newGuard("e2e-panic")
	err := g.Run(context.Background(), func(context.Context) error {
		panic("serve exploded mid-experiment")
	})
	if err == nil {
		t.Fatal("expected an error from the panicking serve")
	}
	if natContains(t, chain) {
		t.Fatalf("fail-open violated: chain %s still present after a panic", chain)
	}
}
