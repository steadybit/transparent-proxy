// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package interception

import (
	"context"
	"errors"
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

func TestAddScript_SkipFlushOmitsFilterChain(t *testing.T) {
	c := baseConfig(t)
	c.SkipFlush = true
	script := joined(c.AddScript())

	// The nat REDIRECT must still be installed...
	if !strings.Contains(script, "-A SB_TP_REDIR_execid123456 -p tcp -d 0.0.0.0/0 --dport 443 -j REDIRECT --to-ports 3128") {
		t.Fatalf("REDIRECT missing with SkipFlush:\n%s", script)
	}
	// ...but the filter flush chain must be entirely absent.
	for _, forbidden := range []string{"*filter", "SB_TP_FLUSH_execid123456", "ESTABLISHED"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("SkipFlush script should not contain %q:\n%s", forbidden, script)
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

func TestDeleteCommands_UnhookFlushDropOrder(t *testing.T) {
	c := baseConfig(t)
	var lines []string
	for _, cmd := range c.DeleteCommands() {
		lines = append(lines, strings.Join(cmd, " "))
	}
	joinedCmds := strings.Join(lines, "\n")

	for _, want := range []string{
		"-t nat -D OUTPUT -p tcp -j SB_TP_REDIR_execid123456",
		"-t nat -F SB_TP_REDIR_execid123456",
		"-t nat -X SB_TP_REDIR_execid123456",
		"-t filter -D OUTPUT -j SB_TP_FLUSH_execid123456",
		"-t filter -F SB_TP_FLUSH_execid123456",
		"-t filter -X SB_TP_FLUSH_execid123456",
	} {
		if !strings.Contains(joinedCmds, want) {
			t.Errorf("DeleteCommands missing: %s\n%s", want, joinedCmds)
		}
	}

	// The flush (-F), which removes the dead-port REDIRECT, must precede the
	// chain drop (-X) so teardown still neutralises the rule if -X later fails.
	flushIdx, dropIdx := -1, -1
	for i, l := range lines {
		if l == "-t nat -F SB_TP_REDIR_execid123456" {
			flushIdx = i
		}
		if l == "-t nat -X SB_TP_REDIR_execid123456" {
			dropIdx = i
		}
	}
	if flushIdx == -1 || dropIdx == -1 || flushIdx > dropIdx {
		t.Fatalf("flush (%d) must come before drop (%d)", flushIdx, dropIdx)
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

// scriptRunner records calls and lets a test control per-command responses.
type scriptRunner struct {
	calls   [][]string
	respond func(argv []string) (string, error)
}

func (s *scriptRunner) Run(_ context.Context, argv []string, _ []string) (string, error) {
	s.calls = append(s.calls, argv)
	if s.respond != nil {
		return s.respond(argv)
	}
	return "", nil
}

func argvHas(argv []string, tok string) bool {
	for _, a := range argv {
		if a == tok {
			return true
		}
	}
	return false
}

func TestRevert_BestEffortSucceedsWhenChainsGone(t *testing.T) {
	c := baseConfig(t)
	// Every delete "fails" (rules absent from a partial apply), and the verify
	// list reports the chains are gone. Revert must still report success.
	r := &scriptRunner{respond: func(argv []string) (string, error) {
		if argvHas(argv, "-S") {
			return "", errors.New("No chain/target/match by that name.")
		}
		return "", errors.New("iptables: Bad rule (does a matching rule exist in that chain?).")
	}}
	if err := c.Revert(context.Background(), r); err != nil {
		t.Fatalf("Revert should succeed when chains are gone despite delete errors: %v", err)
	}
	for _, call := range r.calls {
		if call[0] == "iptables-restore" {
			t.Fatal("Revert must use individual iptables commands, not a restore transaction")
		}
	}
}

func TestRevert_FailsVerificationWhenRulesRemain(t *testing.T) {
	c := baseConfig(t)
	// The nat redirect chain still contains a rule (e.g. an unhook failed and
	// -F somehow didn't take): verification must surface this as an error so the
	// supervisor retries rather than reporting a clean teardown.
	r := &scriptRunner{respond: func(argv []string) (string, error) {
		if argvHas(argv, "-S") && argvHas(argv, "nat") {
			return ":SB_TP_REDIR_execid123456 - [0:0]\n" +
				"-A SB_TP_REDIR_execid123456 -p tcp -d 0.0.0.0/0 --dport 443 -j REDIRECT --to-ports 3128\n", nil
		}
		return "", nil
	}}
	if err := c.Revert(context.Background(), r); err == nil {
		t.Fatal("Revert must fail verification while a chain still contains rules")
	}
}

// The capture filter is deliberately broad (0.0.0.0/0 on 80/443) because the
// proxy picks its victims by hostname. The flush cannot — it is a stateless
// REJECT that knows only addresses — so scoping it to the capture filter would
// reset every established HTTP/HTTPS connection in the target, not just the
// dependency under test.
func Test_flushIsScopedToResolvedDestinations(t *testing.T) {
	base := Config{
		ExecutionID: "exec",
		ProxyPort:   3128,
		Filter: Filter{
			Include: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			Ports:   []uint16{80, 443},
		},
	}

	// Without resolved destinations the flush covers the whole capture filter —
	// what a CIDR-targeted attack wants.
	broad := strings.Join(base.AddScript(), "\n")
	if !strings.Contains(broad, "-d 0.0.0.0/0 --dport 443 -m conntrack --ctstate ESTABLISHED -j REJECT") {
		t.Fatalf("expected a filter-wide flush without resolved hosts:\n%s", broad)
	}

	scoped := base
	scoped.FlushDestinations = []netip.Prefix{
		netip.MustParsePrefix("93.184.216.34/32"),
		netip.MustParsePrefix("1.2.3.4/32"),
	}
	got := strings.Join(scoped.AddScript(), "\n")

	for _, want := range []string{
		"-d 93.184.216.34/32 --dport 80 -m conntrack --ctstate ESTABLISHED -j REJECT",
		"-d 93.184.216.34/32 --dport 443 -m conntrack --ctstate ESTABLISHED -j REJECT",
		"-d 1.2.3.4/32 --dport 443 -m conntrack --ctstate ESTABLISHED -j REJECT",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing scoped flush rule %q in:\n%s", want, got)
		}
	}
	// The whole point: nothing else on those ports is reset.
	if strings.Contains(got, "-d 0.0.0.0/0 --dport 443 -m conntrack --ctstate ESTABLISHED -j REJECT") {
		t.Fatalf("flush still resets the entire capture filter:\n%s", got)
	}
	// Capture itself must stay broad — the proxy still needs to see everything
	// so it can match by hostname.
	if !strings.Contains(got, "-d 0.0.0.0/0 -p tcp -m tcp --dport 443 -j REDIRECT") &&
		!strings.Contains(got, "0.0.0.0/0") {
		t.Fatalf("capture filter was narrowed too:\n%s", got)
	}
}
