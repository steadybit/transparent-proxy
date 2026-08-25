// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Package preflight detects a pre-existing transparent proxy (service mesh) in
// the target network namespace so we refuse rather than silently fight it.
//
// It follows the validated design:
//
//   - Walk the iptables chain graph from OUTPUT/PREROUTING, following `-j`
//     jumps into user chains (a flat scan misses Istio's
//     OUTPUT → ISTIO_OUTPUT → ISTIO_REDIRECT, two levels deep).
//   - Consider only REDIRECT and TPROXY targets (not DNAT — kube-proxy service
//     rules are DNAT and must not trip a refusal).
//   - A rule with no `--dport` match means *all ports* (cannot infer
//     specificity), which conflicts with any target.
//   - Query BOTH iptables backends: meshes such as Istio write `legacy` while
//     our own tooling uses `nft`; a single-backend scan is a false negative in
//     the dangerous direction.
package preflight

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Backend identifies which iptables variant a finding came from.
type Backend string

const (
	BackendLegacy Backend = "legacy"
	BackendNFT    Backend = "nft"
)

// backends lists the iptables binaries to probe, in report order.
var backends = []struct {
	name Backend
	bin  string
}{
	{BackendLegacy, "iptables-legacy"},
	{BackendNFT, "iptables-nft"},
}

// Runner runs a command and returns its combined output. interception.ExecRunner
// satisfies this structurally, as does a namespace-aware runner.
type Runner interface {
	Run(ctx context.Context, argv []string, stdin []string) (string, error)
}

type portRange struct{ from, to uint16 }

func (pr portRange) contains(p uint16) bool { return p >= pr.from && p <= pr.to }

// Finding is one REDIRECT/TPROXY interception point already present.
type Finding struct {
	Backend  Backend
	Table    string   // "nat" (REDIRECT) | "mangle" (TPROXY)
	Chain    string   // chain holding the terminal REDIRECT/TPROXY rule
	Path     []string // OUTPUT -> ISTIO_OUTPUT -> ISTIO_REDIRECT
	Target   string   // "REDIRECT" | "TPROXY"
	ToPort   uint16   // --to-ports / --on-port
	AllPorts bool     // no --dport anywhere on the path => matches everything
	ports    []portRange
	Mesh     string // "istio" | "linkerd" | "service-mesh" | ""
}

// conflictsWith reports whether this finding captures any of the target ports.
func (f Finding) conflictsWith(target []uint16) bool {
	if f.AllPorts {
		return true
	}
	for _, p := range target {
		for _, r := range f.ports {
			if r.contains(p) {
				return true
			}
		}
	}
	return false
}

// Message renders an operator-facing refusal for a finding.
func (f Finding) Message() string {
	scope := "all tcp ports"
	if !f.AllPorts {
		scope = "tcp ports " + f.portsString()
	}
	mesh := ""
	if f.Mesh != "" {
		mesh = f.Mesh + " "
	}
	return fmt.Sprintf(
		"the target network namespace already contains a %stransparent proxy "+
			"(iptables %s backend, %s table, chain %s reached via %s, %s %s to port %d). "+
			"Transparent fault injection cannot be combined with it.",
		mesh, f.Backend, f.Table, f.Chain, strings.Join(f.Path, " -> "), f.Target, scope, f.ToPort,
	)
}

func (f Finding) portsString() string {
	parts := make([]string, 0, len(f.ports))
	for _, r := range f.ports {
		if r.from == r.to {
			parts = append(parts, strconv.Itoa(int(r.from)))
		} else {
			parts = append(parts, fmt.Sprintf("%d:%d", r.from, r.to))
		}
	}
	return strings.Join(parts, ",")
}

// Result is the outcome of a preflight scan.
type Result struct {
	// Backends that were successfully queried. If empty, the scan could not
	// verify anything and the caller must not assume the namespace is clean.
	Backends []Backend
	Findings []Finding
}

// Conflict returns the first finding that overlaps the intended target ports.
func (r Result) Conflict(targetPorts []uint16) (Finding, bool) {
	for _, f := range r.Findings {
		if f.conflictsWith(targetPorts) {
			return f, true
		}
	}
	return Finding{}, false
}

// tables scanned per backend: REDIRECT lives in nat, TPROXY in mangle.
var tables = []string{"nat", "mangle"}

// Detect scans both iptables backends across the nat and mangle tables. It
// errors only if no backend could be queried at all (so "clean" is never
// inferred from a total probe failure).
func Detect(ctx context.Context, runner Runner) (Result, error) {
	var res Result
	queried := map[Backend]bool{}
	for _, b := range backends {
		for _, table := range tables {
			out, err := runner.Run(ctx, []string{b.bin, "-t", table, "-S"}, nil)
			if err != nil {
				// Binary missing or table unavailable: skip.
				continue
			}
			queried[b.name] = true
			res.Findings = append(res.Findings, parseFindings(b.name, table, out)...)
		}
	}
	for _, b := range backends {
		if queried[b.name] {
			res.Backends = append(res.Backends, b.name)
		}
	}
	if len(res.Backends) == 0 {
		return res, fmt.Errorf("could not query any iptables backend (%s)", backendBins())
	}
	return res, nil
}

func backendBins() string {
	names := make([]string, len(backends))
	for i, b := range backends {
		names[i] = b.bin
	}
	return strings.Join(names, ", ")
}

// --- parsing -------------------------------------------------------------

type rule struct {
	target       string
	dports       []portRange
	hasPortMatch bool
	toPort       uint16
}

// parseFindings parses `iptables -t <table> -S` output and walks the chain graph.
func parseFindings(backend Backend, table string, dump string) []Finding {
	graph := map[string][]rule{}
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		chain := fields[1]
		graph[chain] = append(graph[chain], parseRule(fields[2:]))
	}

	var out []Finding
	for _, entry := range []string{"OUTPUT", "PREROUTING"} {
		if _, ok := graph[entry]; !ok {
			continue
		}
		walk(graph, backend, table, entry, []string{entry}, nil, map[string]bool{entry: true}, &out)
	}
	return out
}

func parseRule(tokens []string) rule {
	var r rule
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "-j", "-g":
			if i+1 < len(tokens) {
				r.target = tokens[i+1]
				i++
			}
		case "--dport", "--dports":
			if i+1 < len(tokens) {
				r.dports = append(r.dports, parsePorts(tokens[i+1])...)
				r.hasPortMatch = true
				i++
			}
		case "--to-ports", "--to-port", "--on-port":
			if i+1 < len(tokens) {
				if pr := parsePorts(tokens[i+1]); len(pr) > 0 {
					r.toPort = pr[0].from
				}
				i++
			}
		}
	}
	return r
}

func parsePorts(s string) []portRange {
	var out []portRange
	for _, part := range strings.Split(s, ",") {
		if lo, hi, ok := strings.Cut(part, ":"); ok {
			from, err1 := strconv.ParseUint(lo, 10, 16)
			to, err2 := strconv.ParseUint(hi, 10, 16)
			if err1 == nil && err2 == nil {
				out = append(out, portRange{uint16(from), uint16(to)})
			}
			continue
		}
		if p, err := strconv.ParseUint(part, 10, 16); err == nil {
			out = append(out, portRange{uint16(p), uint16(p)})
		}
	}
	return out
}

func walk(graph map[string][]rule, backend Backend, table, chain string, path []string, ports []portRange, visited map[string]bool, out *[]Finding) {
	for _, r := range graph[chain] {
		rp := ports
		if r.hasPortMatch {
			rp = append(append([]portRange{}, ports...), r.dports...)
		}
		if r.target == "REDIRECT" || r.target == "TPROXY" {
			f := Finding{
				Backend: backend,
				Table:   table,
				Chain:   chain,
				Path:    append([]string{}, path...),
				Target:  r.target,
				ToPort:  r.toPort,
				Mesh:    classifyMesh(path, r.toPort),
			}
			if len(rp) == 0 {
				f.AllPorts = true
			} else {
				f.ports = dedupePorts(rp)
			}
			*out = append(*out, f)
			continue
		}
		if _, ok := graph[r.target]; ok && !visited[r.target] {
			next := make(map[string]bool, len(visited)+1)
			for k, v := range visited {
				next[k] = v
			}
			next[r.target] = true
			walk(graph, backend, table, r.target, append(append([]string{}, path...), r.target), rp, next, out)
		}
	}
}

func classifyMesh(path []string, toPort uint16) string {
	for _, c := range path {
		switch {
		case strings.HasPrefix(c, "ISTIO"):
			return "istio"
		case strings.HasPrefix(c, "PROXY_INIT"):
			return "linkerd"
		}
	}
	if toPort == 15001 || toPort == 15006 {
		return "service-mesh"
	}
	return ""
}

func dedupePorts(in []portRange) []portRange {
	seen := map[portRange]bool{}
	var out []portRange
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].from != out[j].from {
			return out[i].from < out[j].from
		}
		return out[i].to < out[j].to
	})
	return out
}
