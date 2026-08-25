# transparent-proxy

A low-overhead, transparent **L4 TCP proxy** for injecting network faults against
**internal and external dependencies**. It is designed to be steered into place by
an out-of-band iptables `REDIRECT`/`TPROXY` rule (the same namespace-injection
machinery Steadybit's `action-kit` already uses for network attacks), so the
target application needs **no reconfiguration**.

> ⚠️ **Status: early scaffold / work in progress.** The L4 relay, original-
> destination recovery, SNI-based targeting, and fault engine are implemented and
> tested. The interception (iptables/eBPF) backends, preflight detection, and the
> one-shot connection-reset resurrection are on the roadmap below.

## Why a proxy (and not just tc/iptables)?

Packet-level faults (delay, loss, corruption) are already well covered by
`tc`/`netfilter`. A proxy earns its place when you need things those can't do:

| Capability                                   | tc / netfilter | this proxy |
| -------------------------------------------- | :------------: | :--------: |
| Delay / loss / bandwidth by IP+port          |       ✅       |     ✅     |
| Target by **hostname / SNI** (volatile IPs)  |       ❌       |     ✅     |
| Fail a **percentage** of connections         |      hard      |     ✅     |
| Distinguish slow-connect vs slow-response    |       ❌       |     ✅     |
| Per-connection stateful behaviour            |       ❌       |     ✅     |

The hostname/SNI targeting is what makes **one** tool work for both internal
(IP-addressed) and external (hostname-addressed, volatile-IP) dependencies.

## How it works

```
                 iptables REDIRECT / TPROXY
   app ─────────────────┐  (out of band)
   (unchanged)          ▼
              ┌─────────────────────┐        real upstream
              │  transparent-proxy  │ ───────────────────────▶  dependency
              │                     │ ◀───────────────────────
              └─────────────────────┘
                1. recover original destination (SO_ORIGINAL_DST)
                2. (optional) read TLS SNI — cleartext, no decryption
                3. match a fault rule (by CIDR and/or hostname)
                4. apply: latency | reset | pass-through
                5. splice(2) the bytes through (zero-copy on Linux)
```

- **Fast path:** when no rule targets a hostname, the ClientHello peek is skipped
  entirely and the connection is a pure `splice(2)` relay — kernel-to-kernel, no
  userspace payload copy.
- **Inspected path:** when a rule targets by hostname, the proxy reads only the
  first TLS record to extract the SNI (cleartext — **no MITM, no certificates**),
  replays those bytes to the upstream, then splices the remainder.

## Fault rules

Rules are JSON; the first matching rule wins. A rule matches when **both** its
selectors match — an empty selector means "any".

```json
{
  "rules": [
    { "name": "slow-payments", "hosts": ["api.stripe.com"], "latency": "500ms" },
    { "name": "flaky-db",      "cidrs": ["10.0.0.0/8"],     "abortProbability": 0.25 },
    { "name": "kill-cdn",      "hosts": ["cdn.example.com"], "abortProbability": 1.0 }
  ]
}
```

- `cidrs` — match the original destination IP (internal targeting).
- `hosts` — match the TLS SNI, exact or subdomain (external targeting).
- `latency` — Go duration string, added before the upstream connect.
- `abortProbability` — `[0,1]` chance to reset (RST) the connection.

## Build & test

```bash
make build     # host binary
make linux     # static linux amd64 + arm64 (deployment targets)
make test      # go test -race ./...
make run       # run locally with examples/faults.json
```

## Roadmap

Refined by internal design research (validated against EKS/AL2023, GKE/COS,
linuxkit, and `istio/proxyv2:1.24.2`). The research **confirms** REDIRECT +
`splice` + Go stdlib; the items below capture its refinements.

- [ ] **Self-loop protection (mandatory, do first).** `SO_MARK 0x5C` on the
      proxy's upstream sockets + a `filter`-table RETURN exemption, plus a proxy
      self-refusal when the recovered original destination is our own listener.
      Without it a single request was measured producing **17,527 self-connections
      in 8s**. (Mark `0x5C` avoids netfault's existing `0x5B`.)
- [ ] **Connection-pool flush = persistent `filter` REJECT**, not one-shot
      `ss -K`. Rule matches `-m conntrack --ctstate ESTABLISHED --dport <target>
      -j REJECT --reject-with tcp-reset`; it fires on connection *use*, is
      self-limiting (redirected flows can't re-match), and works on kernels
      without `CONFIG_INET_DIAG_DESTROY`. `ss -K` only as a supplement, and only
      after re-listing sockets to confirm it actually killed them (it exits 0
      while killing nothing on unsupported kernels).
- [ ] **Preflight detection.** Walk the iptables chain graph **2+ levels deep**
      (flat OUTPUT scan misses Istio's `ISTIO_OUTPUT`→`ISTIO_REDIRECT`), query
      **both** backends (Istio writes `legacy`; our tooling uses `nft`), scope to
      `REDIRECT`/`TPROXY` only (not DNAT — else every host-network target is
      refused), and treat a missing `--dport` as all-ports. Refuse under Istio /
      Linkerd sidecars. eBPF-based redirection (Cilium socketLB) is undetectable
      here — covered by the metric below.
- [ ] **Silent no-op detection.** Expose `connections_matched` /
      `requests_matched` so the platform can surface "0 connections intercepted"
      (the Cilium/sockmap blind spot, and any mismatched selector).
- [ ] **Fail-open supervisor.** A `nat` rule pointing at a dead proxy port
      blackholes matched traffic — on proxy exit, tear down all rules and report
      `Errored`.
- [ ] **Over-broad selector guards.** Explicit default port list, exclude-nets
      **replicated into the filter table** (protect agent/platform/extension
      ports from reset), self-exclusion, and refuse `0.0.0.0/0` + "any port".
- [ ] **L7 HTTP faults** via **parse-decide-replay**, *not* `httputil.ReverseProxy`
      (which canonicalizes header casing/order and injects `X-Forwarded-For` /
      `Accept-Encoding`). Host-header selection, case-insensitive. Sniff protocol
      at ingress; non-HTTP on a matched port stays a raw byte-splice.
- [ ] **`action-kit` integration**: per-execution chains `SB_HTTP_<last-12-of-exec-id>`,
      participate in `netfault.doesConflictWith()`, reuse `mapToNetworkFilter` /
      dnsinject `Exited()` teardown contract, sidecar delivery.
- [ ] Relay **idle timeout** (activity-resetting deadlines) atop TCP keepalive.
- [ ] Deferred: TPROXY (ingress / source preservation), IPv6, UDP, HTTP/2 (h2c),
      SNI-based L4 faults (delay/reset/stall/byte-slice/bandwidth, no termination).

Overhead reference: userspace hop measured at **+117µs p50 / +149µs p95** (not a
meaningful fault on its own); static `CGO=0` binary ~8–14 MB.

## License

MIT — see [LICENSE](./LICENSE).
