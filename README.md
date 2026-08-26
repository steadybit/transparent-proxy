# transparent-proxy

A low-overhead, transparent **L4 TCP proxy** for injecting network faults against
**internal and external dependencies**. It is designed to be steered into place by
an out-of-band iptables `REDIRECT`/`TPROXY` rule (the same namespace-injection
machinery Steadybit's `action-kit` already uses for network attacks), so the
target application needs **no reconfiguration**.

> ⚠️ **Status: work in progress.** Implemented and tested: the L4 relay,
> original-destination recovery (`SO_ORIGINAL_DST`), SNI-based targeting, the
> fault engine, the **iptables interception layer** (REDIRECT capture, `SO_MARK`
> self-loop protection, persistent connection-pool flush), **preflight mesh
> detection**, **silent-no-op metrics**, a **fail-open supervisor** that
> guarantees rule teardown on every exit path, and **L7 HTTP faults** (Host-header
> selection, status-code injection, byte-identical pass-through). The capture
> path, connection-pool flush, L7 injection, and fail-open teardown are all
> verified end to end under real iptables (see the `integration`-tagged tests),
> and it is wired into a Steadybit host action (extension-host) that bundles this
> binary and drives it in the target's network namespace.

It ships as a small static binary bundled into Steadybit extensions (like
`memfill`, `nsmount`, and `dns-inject`): the extension fetches
`transparent-proxy.<arch>` from a release and launches it in the target's network
namespace, where it self-manages its iptables interception and fault injection.

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

## Releases

Pushing a `v*` tag builds stripped static linux binaries and publishes them as
release assets named `transparent-proxy.amd64` / `transparent-proxy.arm64` (see
`.github/workflows/ci.yml`). Extensions consume a pinned version by fetching that
asset in their build (e.g. the `TRANSPARENT_PROXY_VERSION` env + a `curl` in the
extension's goreleaser hook). Tags containing a hyphen (e.g. `v0.0.1-beta`) are
marked as prereleases.

## Roadmap

Refined by internal design research (validated against EKS/AL2023, GKE/COS,
linuxkit, and `istio/proxyv2:1.24.2`). The research **confirms** REDIRECT +
`splice` + Go stdlib; the items below capture its refinements.

- [x] **REDIRECT interception** (`internal/interception`): `iptables-restore`
      script generation for nat REDIRECT to the proxy port, per-execution chains
      `SB_TP_REDIR_<id12>` / `SB_TP_FLUSH_<id12>`, add/delete, and an injectable
      `CommandRunner` for netns execution.
- [x] **Self-loop protection (mandatory).** `SO_MARK 0x5C` on the proxy's
      upstream sockets + a `filter`/`nat` RETURN exemption, plus a proxy
      self-refusal when the recovered original destination is our own listener.
      Without it a single request was measured producing **17,527 self-connections
      in 8s**. (Mark `0x5C` avoids netfault's existing `0x5B`.)
- [x] **Connection-pool flush = persistent `filter` REJECT**, not one-shot
      `ss -K`. Rule matches `-m conntrack --ctstate ESTABLISHED --dport <target>
      -j REJECT --reject-with tcp-reset`; it fires on connection *use*, is
      self-limiting (redirected flows can't re-match), and works on kernels
      without `CONFIG_INET_DIAG_DESTROY`. `ss -K` only as a supplement, and only
      after re-listing sockets to confirm it actually killed them (it exits 0
      while killing nothing on unsupported kernels) — *supplement not yet added*.
- [x] **Preflight detection** (`internal/preflight`). Walks the iptables chain
      graph **2+ levels deep** (flat OUTPUT scan misses Istio's
      `ISTIO_OUTPUT`→`ISTIO_REDIRECT`), queries **both** backends (Istio writes
      `legacy`; our tooling uses `nft`) across the nat + mangle tables, scopes to
      `REDIRECT`/`TPROXY` only (not DNAT — kube-proxy is not flagged), treats a
      missing `--dport` as all-ports, and refuses only on a real port overlap.
      Classifies Istio / Linkerd. Wired via `--preflight-ports`; verified against
      a live Istio-shaped ruleset. eBPF redirection (Cilium socketLB) is
      undetectable here — covered by the metric below.
- [x] **Silent no-op detection** (`internal/metrics`). `connections_matched`
      (plus active/proxied/aborted/dropped/upstream-errors/bytes) exposed as JSON
      via `--metrics-addr`, so the platform can surface "0 connections
      intercepted" (the Cilium/sockmap blind spot, and any mismatched selector).
- [x] **Fail-open supervisor** (`internal/supervisor`). A `Guard` ties the
      interception rules to the proxy's lifetime and **guarantees teardown on
      every exit path** — normal return, serve error, context cancellation,
      panic, or a deadman (`--max-duration`) — idempotently and with retries. A
      failed apply rolls back. Verified against real iptables (return + panic).
      (A `SIGKILL` residual is the orchestrator's job via an `Exited()` hook,
      which can call `Guard.Teardown` directly.)
- [ ] **Over-broad selector guards.** Explicit default port list, exclude-nets
      **replicated into the filter table** (protect agent/platform/extension
      ports from reset), self-exclusion, and refuse `0.0.0.0/0` + "any port".
- [x] **L7 HTTP faults** via **parse-decide-replay**, *not* `httputil.ReverseProxy`.
      The proxy sniffs each connection at ingress (TLS vs HTTP vs opaque), and for
      cleartext HTTP selects by **Host header** (case-insensitive, port-stripped —
      same semantics as `dns-inject`) to **synthesize a status code** without
      contacting the upstream. Non-matching / non-HTTP traffic is forwarded
      **byte-identical** (header casing and order preserved), and on any sniff
      timeout the connection is forwarded untouched (fail-open). *Still to come:
      response-body tampering, per-request faulting on keep-alive connections,
      and HTTP/2 (h2c).*
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
