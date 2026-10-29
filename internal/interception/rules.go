// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Package interception generates and applies the iptables rules that steer a
// target's traffic into the transparent proxy. It follows the validated design:
//
//   - nat REDIRECT captures matching TCP flows and sends them to the proxy port.
//   - An SO_MARK exemption (RETURN on the proxy's own marked sockets) breaks the
//     self-loop the proxy would otherwise create when it dials upstream.
//   - A persistent filter REJECT on already-ESTABLISHED flows to the target
//     ports flushes warm connection pools so they re-establish *through* the
//     proxy. It is self-limiting: once redirected, a flow's destination port is
//     rewritten before the filter hook, so it can never match again.
//   - Exclude nets are honoured in both tables (protect agent/platform ports).
//
// Rules are emitted as an `iptables-restore -w -n` script (add and delete),
// matching action-kit's netfault convention. IPv6/UDP are out of scope here.
package interception

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// DefaultMark is set (via SO_MARK) on the proxy's upstream sockets so its own
// traffic is exempted from both the REDIRECT and the flush REJECT. 0x5C avoids
// collision with netfault's existing mangle mark (0x5B).
const DefaultMark uint32 = 0x5C

// Filter selects which traffic is captured.
type Filter struct {
	Include []netip.Prefix // destinations to capture (e.g. 0.0.0.0/0 for "any host")
	Exclude []netip.Prefix // destinations to never touch (agent/platform/self)
	Ports   []uint16       // target destination ports
	// AllPorts captures every destination port instead of Ports, so the proxy
	// can find HTTP/TLS wherever it runs. The proxy still decides per connection
	// (by Host/SNI) what to fault; everything else is spliced through untouched.
	// Loopback is never captured in this mode: with no port to narrow it, a
	// 0.0.0.0/0 include would otherwise pull in every app-to-sidecar and local
	// database connection.
	AllPorts bool
}

// loopbackV4 is the whole IPv4 loopback range: 127.0.0.1 (localhost) and every
// other 127.x.x.x address, which the kernel delivers inside the network
// namespace without ever leaving it. It is excluded from capture whenever
// AllPorts is set, so app-to-sidecar and local database traffic is untouched.
const loopbackV4 = "127.0.0.0/8"

// Config is a single interception rule set, scoped by ExecutionID.
type Config struct {
	ExecutionID string
	ProxyPort   uint16
	Mark        uint32   // 0 => DefaultMark
	HookChains  []string // 0 => ["OUTPUT"]
	Filter      Filter
	// SkipFlush omits the filter-table chain that resets already-ESTABLISHED
	// flows to the target ports. By default (false) warm connection pools are
	// reset so they re-establish through the proxy and immediately feel the
	// fault; set it when only new connections should be affected.
	SkipFlush bool
	// FlushDestinations narrows the connection-pool flush to these destinations
	// instead of the whole capture filter.
	//
	// The capture filter is deliberately broad — typically 0.0.0.0/0 on ports
	// 80 and 443 — because the proxy decides what to fault by hostname once it
	// has seen the request. The flush cannot do that: it is a stateless iptables
	// REJECT and knows only addresses. Applying it to the capture filter would
	// therefore reset every established HTTP/HTTPS connection in the target,
	// including ones to dependencies the attack never names. Resolving the
	// targeted hostnames up front and flushing only those addresses keeps the
	// collateral to the dependency actually under test.
	//
	// Empty keeps the old behaviour and flushes the whole capture filter, which
	// is what a CIDR-targeted attack (no hostnames) actually wants.
	FlushDestinations []netip.Prefix
}

func (c Config) mark() uint32 {
	if c.Mark == 0 {
		return DefaultMark
	}
	return c.Mark
}

func (c Config) hooks() []string {
	if len(c.HookChains) == 0 {
		return []string{"OUTPUT"}
	}
	return c.HookChains
}

func idSuffix(id string) string {
	if len(id) > 12 {
		id = id[len(id)-12:]
	}
	if id == "" {
		return "default"
	}
	return id
}

func (c Config) redirectChain() string { return "SB_TP_REDIR_" + idSuffix(c.ExecutionID) }
func (c Config) flushChain() string    { return "SB_TP_FLUSH_" + idSuffix(c.ExecutionID) }

// Validate rejects configurations that would be unsafe or a no-op.
func (c Config) Validate() error {
	if c.ProxyPort == 0 {
		return errors.New("proxy port must be set")
	}
	if len(includeV4(c.Filter.Include)) == 0 {
		return errors.New("at least one IPv4 include CIDR is required")
	}
	if c.Filter.AllPorts && len(c.Filter.Ports) > 0 {
		return errors.New("target ports and all-ports are mutually exclusive")
	}
	if !c.Filter.AllPorts && len(c.Filter.Ports) == 0 {
		// Requiring explicit ports (or an explicit all-ports opt-in) is what
		// prevents an accidental "any host, any port" catch-all.
		return errors.New("at least one target port is required")
	}
	return nil
}

// AddScript returns the iptables-restore script that installs the interception.
func (c Config) AddScript() []string {
	mark := fmt.Sprintf("0x%x", c.mark())
	redir := c.redirectChain()
	flush := c.flushChain()
	includes := includeV4(c.Filter.Include)
	excludes := includeV4(c.Filter.Exclude)
	if c.Filter.AllPorts {
		excludes = append(excludes, loopbackV4)
	}
	portMatches := c.portMatches()

	var s []string

	// nat table: REDIRECT matching flows to the proxy.
	s = append(s, "*nat", fmt.Sprintf(":%s - [0:0]", redir))
	s = append(s, fmt.Sprintf("-A %s -m mark --mark %s -j RETURN", redir, mark))
	for _, ex := range excludes {
		s = append(s, fmt.Sprintf("-A %s -d %s -j RETURN", redir, ex))
	}
	for _, in := range includes {
		for _, pm := range portMatches {
			s = append(s, fmt.Sprintf("-A %s -p tcp -d %s%s -j REDIRECT --to-ports %d", redir, in, pm, c.ProxyPort))
		}
	}
	for _, h := range c.hooks() {
		s = append(s, fmt.Sprintf("-I %s -p tcp -j %s", h, redir))
	}
	s = append(s, "COMMIT")

	// filter table: reset already-ESTABLISHED flows so pools reconnect. Skipped
	// when SkipFlush is set, so only new connections are affected.
	if !c.SkipFlush {
		s = append(s, "*filter", fmt.Sprintf(":%s - [0:0]", flush))
		s = append(s, fmt.Sprintf("-A %s -m mark --mark %s -j RETURN", flush, mark))
		for _, ex := range excludes {
			s = append(s, fmt.Sprintf("-A %s -d %s -j RETURN", flush, ex))
		}
		flushDsts := includes
		if len(c.FlushDestinations) > 0 {
			flushDsts = includeV4(c.FlushDestinations)
		}
		state := c.flushState()
		for _, in := range flushDsts {
			for _, pm := range portMatches {
				s = append(s, fmt.Sprintf("-A %s -p tcp -d %s%s -m conntrack %s -j REJECT --reject-with tcp-reset", flush, in, pm, state))
			}
		}
		for _, h := range c.hooks() {
			s = append(s, fmt.Sprintf("-I %s -j %s", h, flush))
		}
		s = append(s, "COMMIT")
	}

	return s
}

// portMatches returns the --dport fragment for each rule to emit: one per target
// port, or a single empty fragment (no port match) when AllPorts is set.
func (c Config) portMatches() []string {
	if c.Filter.AllPorts {
		return []string{""}
	}
	out := make([]string, len(c.Filter.Ports))
	for i, p := range c.Filter.Ports {
		out[i] = fmt.Sprintf(" --dport %d", p)
	}
	return out
}

// flushState is the conntrack match selecting the established flows to flush.
//
// The flush hooks OUTPUT, which carries every packet the target sends — its
// own requests and also its replies on connections others opened to it. With
// explicit ports, --dport keeps those replies out: they go to the peer's
// ephemeral port. Capturing every port drops --dport, so the flush would reset
// the target's replies to anyone in the flush destinations for the whole
// attack (e.g. a dependency that also calls the target, or everyone when the
// destinations fall back to 0.0.0.0/0). --ctdir ORIGINAL limits it to packets
// travelling in the direction the connection was opened: connections the
// target itself opened.
func (c Config) flushState() string {
	if c.Filter.AllPorts {
		return "--ctstate ESTABLISHED --ctdir ORIGINAL"
	}
	return "--ctstate ESTABLISHED"
}

// DeleteCommands returns the individual iptables commands (argv after the
// binary) that remove the interception. Unlike a single iptables-restore
// transaction — which aborts the whole table on the first missing rule and can
// leave a live REDIRECT behind after a partial apply — these run independently
// and best-effort. The ordering matters: the chain flush (`-F`), which is what
// actually removes the dead-port REDIRECT, runs regardless of whether unhooking
// a jump succeeded.
func (c Config) DeleteCommands() [][]string {
	redir := c.redirectChain()
	flush := c.flushChain()

	var cmds [][]string
	for _, h := range c.hooks() {
		cmds = append(cmds, []string{"-t", "nat", "-D", h, "-p", "tcp", "-j", redir})
	}
	cmds = append(cmds, []string{"-t", "nat", "-F", redir}, []string{"-t", "nat", "-X", redir})

	// The filter flush chain is only installed when SkipFlush is false, so only
	// then does it need removing — otherwise these deletes always fail against a
	// non-existent chain and add noise that can mask a genuine cleanup failure.
	if !c.SkipFlush {
		for _, h := range c.hooks() {
			cmds = append(cmds, []string{"-t", "filter", "-D", h, "-j", flush})
		}
		cmds = append(cmds, []string{"-t", "filter", "-F", flush}, []string{"-t", "filter", "-X", flush})
	}

	return cmds
}

// CommandRunner runs a command with the given stdin lines. Extensions inject a
// runner that executes inside the target's network namespace; the default
// ExecRunner runs in the current namespace.
type CommandRunner interface {
	Run(ctx context.Context, argv []string, stdin []string) (string, error)
}

// ExecRunner runs commands locally.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, argv []string, stdin []string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if len(stdin) > 0 {
		cmd.Stdin = strings.NewReader(strings.Join(stdin, "\n") + "\n")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s failed: %w: %s", argv[0], err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Apply validates and installs the interception via iptables-restore.
func (c Config) Apply(ctx context.Context, r CommandRunner) error {
	if err := c.Validate(); err != nil {
		return err
	}
	_, err := r.Run(ctx, []string{"iptables-restore", "-w", "-n"}, c.AddScript())
	return err
}

// Revert removes the interception. Every delete runs best-effort (a missing
// rule/chain from a partial apply is not an error), then a verification pass
// confirms neither chain still contains rules — so the caller (the fail-open
// supervisor) only sees success once the dead-port REDIRECT is provably gone.
func (c Config) Revert(ctx context.Context, r CommandRunner) error {
	for _, cmd := range c.DeleteCommands() {
		// Ignore per-command errors: "does not exist" is the expected outcome
		// for rules a partial apply never installed.
		_, _ = r.Run(ctx, append([]string{"iptables", "-w"}, cmd...), nil)
	}
	return c.verifyClean(ctx, r)
}

// verifyClean fails if either interception chain still holds rules (an -A line),
// i.e. the dangerous REDIRECT/REJECT is still installed. A missing chain (the
// list command errors) is clean.
func (c Config) verifyClean(ctx context.Context, r CommandRunner) error {
	checks := []struct{ table, chain string }{
		{"nat", c.redirectChain()},
		{"filter", c.flushChain()},
	}
	for _, chk := range checks {
		out, err := r.Run(ctx, []string{"iptables", "-w", "-t", chk.table, "-S", chk.chain}, nil)
		if err != nil {
			continue // chain absent => nothing left to remove
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "-A ") {
				return fmt.Errorf("interception chain %s in table %s still contains rules after teardown", chk.chain, chk.table)
			}
		}
	}
	return nil
}

// includeV4 returns the string form of every IPv4 (or v4-mapped) prefix; IPv6
// is out of scope for this phase and silently skipped.
func includeV4(prefixes []netip.Prefix) []string {
	var out []string
	for _, p := range prefixes {
		if a := p.Addr(); a.Is4() || a.Is4In6() {
			out = append(out, p.Masked().String())
		}
	}
	return out
}
