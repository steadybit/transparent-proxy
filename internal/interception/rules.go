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
}

// Config is a single interception rule set, scoped by ExecutionID.
type Config struct {
	ExecutionID string
	ProxyPort   uint16
	Mark        uint32   // 0 => DefaultMark
	HookChains  []string // 0 => ["OUTPUT"]
	Filter      Filter
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
	if len(c.Filter.Ports) == 0 {
		// Requiring explicit ports is what prevents an "any host, any port"
		// catch-all from resetting the whole namespace.
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

	var s []string

	// nat table: REDIRECT matching flows to the proxy.
	s = append(s, "*nat", fmt.Sprintf(":%s - [0:0]", redir))
	s = append(s, fmt.Sprintf("-A %s -m mark --mark %s -j RETURN", redir, mark))
	for _, ex := range excludes {
		s = append(s, fmt.Sprintf("-A %s -d %s -j RETURN", redir, ex))
	}
	for _, in := range includes {
		for _, p := range c.Filter.Ports {
			s = append(s, fmt.Sprintf("-A %s -p tcp -d %s --dport %d -j REDIRECT --to-ports %d", redir, in, p, c.ProxyPort))
		}
	}
	for _, h := range c.hooks() {
		s = append(s, fmt.Sprintf("-I %s -p tcp -j %s", h, redir))
	}
	s = append(s, "COMMIT")

	// filter table: reset already-ESTABLISHED flows so pools reconnect.
	s = append(s, "*filter", fmt.Sprintf(":%s - [0:0]", flush))
	s = append(s, fmt.Sprintf("-A %s -m mark --mark %s -j RETURN", flush, mark))
	for _, ex := range excludes {
		s = append(s, fmt.Sprintf("-A %s -d %s -j RETURN", flush, ex))
	}
	for _, in := range includes {
		for _, p := range c.Filter.Ports {
			s = append(s, fmt.Sprintf("-A %s -p tcp -d %s --dport %d -m conntrack --ctstate ESTABLISHED -j REJECT --reject-with tcp-reset", flush, in, p))
		}
	}
	for _, h := range c.hooks() {
		s = append(s, fmt.Sprintf("-I %s -j %s", h, flush))
	}
	s = append(s, "COMMIT")

	return s
}

// DeleteScript returns the iptables-restore script that removes the rules.
func (c Config) DeleteScript() []string {
	redir := c.redirectChain()
	flush := c.flushChain()

	var s []string
	s = append(s, "*nat")
	for _, h := range c.hooks() {
		s = append(s, fmt.Sprintf("-D %s -p tcp -j %s", h, redir))
	}
	s = append(s, fmt.Sprintf("-F %s", redir), fmt.Sprintf("-X %s", redir), "COMMIT")

	s = append(s, "*filter")
	for _, h := range c.hooks() {
		s = append(s, fmt.Sprintf("-D %s -j %s", h, flush))
	}
	s = append(s, fmt.Sprintf("-F %s", flush), fmt.Sprintf("-X %s", flush), "COMMIT")

	return s
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

// Revert removes the interception via iptables-restore.
func (c Config) Revert(ctx context.Context, r CommandRunner) error {
	_, err := r.Run(ctx, []string{"iptables-restore", "-w", "-n"}, c.DeleteScript())
	return err
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
