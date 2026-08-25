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

- [ ] **Interception backends**: iptables `REDIRECT` (default), `TPROXY` (UDP /
      source preservation), eBPF (`sk_lookup`) for Cilium-owned datapaths.
- [ ] **Preflight detection**: fingerprint Istio sidecar / ambient / Cilium
      socketLB and pick a backend (or fail loud) instead of silently no-op'ing.
- [ ] **One-shot connection reset** to churn warm connection pools so existing
      flows re-establish *through* the proxy (long-lived pools otherwise bypass a
      REDIRECT that only catches new conntrack flows).
- [ ] **Fail-open supervisor**: tear down interception rules if the proxy dies so
      traffic falls back to direct.
- [ ] Loop-prevention (uid/mark exemption incl. mesh proxy uid).
- [ ] More faults: bandwidth throttle, jitter, partial/slow reads, L7 handlers.
- [ ] `action-kit` integration (discovery + action wiring, sidecar delivery).

## License

MIT — see [LICENSE](./LICENSE).
