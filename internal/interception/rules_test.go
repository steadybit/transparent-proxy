// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package interception

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func baseConfig(t *testing.T) Config {
	return Config{
		ExecutionID: "execid123456", // 12 chars -> suffix is the whole thing
		ProxyPort:   3128,
		Filter: Filter{
			Include: []netip.Prefix{mustPrefix(t, "0.0.0.0/0")},
			Exclude: []netip.Prefix{mustPrefix(t, "10.1.2.3/32")},
			Ports:   []uint16{443},
		},
	}
}

func joined(s []string) string { return strings.Join(s, "\n") }

func TestAddScript_Structure(t *testing.T) {
	c := baseConfig(t)
	script := joined(c.AddScript())

	wantSubstrings := []string{
		"*nat",
		":SB_TP_REDIR_execid123456 - [0:0]",
		"-A SB_TP_REDIR_execid123456 -m mark --mark 0x5c -j RETURN",
		"-A SB_TP_REDIR_execid123456 -d 10.1.2.3/32 -j RETURN",
		"-A SB_TP_REDIR_execid123456 -p tcp -d 0.0.0.0/0 --dport 443 -j REDIRECT --to-ports 3128",
		"-I OUTPUT -p tcp -j SB_TP_REDIR_execid123456",
		"*filter",
		":SB_TP_FLUSH_execid123456 - [0:0]",
		"-A SB_TP_FLUSH_execid123456 -m mark --mark 0x5c -j RETURN",
		"-A SB_TP_FLUSH_execid123456 -p tcp -d 0.0.0.0/0 --dport 443 -m conntrack --ctstate ESTABLISHED -j REJECT --reject-with tcp-reset",
		"-I OUTPUT -j SB_TP_FLUSH_execid123456",
		"COMMIT",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(script, want) {
			t.Errorf("AddScript missing line:\n  %s\nfull script:\n%s", want, script)
		}
	}
}

func TestAddScript_MarkExemptionFirst(t *testing.T) {
	c := baseConfig(t)
	script := c.AddScript()
	// In each chain, the mark RETURN must precede the REDIRECT/REJECT so the
	// proxy's own traffic escapes before it can be captured or reset.
	markIdx, redirIdx := -1, -1
	for i, line := range script {
		if strings.Contains(line, "--mark 0x5c -j RETURN") && strings.Contains(line, "REDIR") && markIdx == -1 {
			markIdx = i
		}
		if strings.Contains(line, "-j REDIRECT") && redirIdx == -1 {
			redirIdx = i
		}
	}
	if markIdx == -1 || redirIdx == -1 || markIdx > redirIdx {
		t.Fatalf("mark RETURN (%d) must come before REDIRECT (%d)", markIdx, redirIdx)
	}
}

func TestDeleteScript_UnhookAndDropChains(t *testing.T) {
	c := baseConfig(t)
	script := joined(c.DeleteScript())
	for _, want := range []string{
		"-D OUTPUT -p tcp -j SB_TP_REDIR_execid123456",
		"-F SB_TP_REDIR_execid123456",
		"-X SB_TP_REDIR_execid123456",
		"-D OUTPUT -j SB_TP_FLUSH_execid123456",
		"-F SB_TP_FLUSH_execid123456",
		"-X SB_TP_FLUSH_execid123456",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("DeleteScript missing: %s\n%s", want, script)
		}
	}
}

func TestCustomMarkAndHooks(t *testing.T) {
	c := baseConfig(t)
	c.Mark = 0x99
	c.HookChains = []string{"OUTPUT", "PREROUTING"}
	script := joined(c.AddScript())
	if !strings.Contains(script, "--mark 0x99 -j RETURN") {
		t.Error("custom mark not honoured")
	}
	if !strings.Contains(script, "-I PREROUTING -p tcp -j SB_TP_REDIR_execid123456") {
		t.Error("custom hook chain not honoured")
	}
}

func TestIPv6IncludesAreSkipped(t *testing.T) {
	c := baseConfig(t)
	c.Filter.Include = append(c.Filter.Include, mustPrefix(t, "2001:db8::/32"))
	script := joined(c.AddScript())
	if strings.Contains(script, "2001:db8") {
		t.Error("IPv6 prefix should be skipped in the IPv4 script")
	}
}

func TestValidate(t *testing.T) {
	valid := baseConfig(t)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := map[string]func(*Config){
		"no proxy port": func(c *Config) { c.ProxyPort = 0 },
		"no includes":   func(c *Config) { c.Filter.Include = nil },
		"no ports":      func(c *Config) { c.Filter.Ports = nil },
		"only ipv6":     func(c *Config) { c.Filter.Include = []netip.Prefix{mustPrefix(t, "2001:db8::/32")} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := baseConfig(t)
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("expected %s to be rejected", name)
			}
		})
	}
}

// recordingRunner captures what Apply/Revert would execute.
type recordingRunner struct {
	argv  []string
	stdin []string
}

func (r *recordingRunner) Run(_ context.Context, argv []string, stdin []string) (string, error) {
	r.argv, r.stdin = argv, stdin
	return "", nil
}

func TestApplyUsesIptablesRestore(t *testing.T) {
	c := baseConfig(t)
	rr := &recordingRunner{}
	if err := c.Apply(context.Background(), rr); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if strings.Join(rr.argv, " ") != "iptables-restore -w -n" {
		t.Fatalf("unexpected argv: %v", rr.argv)
	}
	if !strings.Contains(joined(rr.stdin), "-j REDIRECT --to-ports 3128") {
		t.Fatalf("Apply did not pass the add script as stdin")
	}
}

func TestApplyRejectsInvalidConfig(t *testing.T) {
	c := baseConfig(t)
	c.ProxyPort = 0
	if err := c.Apply(context.Background(), &recordingRunner{}); err == nil {
		t.Fatal("Apply should reject an invalid config before running anything")
	}
}
