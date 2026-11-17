# Text protocols lab

Checks that, when **every port is captured** (empty "Dependency Ports" in
extension-container and extension-host), clients of dependencies the attack
does **not** target are not delayed (Kanbanize 27640).

To find an HTTP `Host`, the proxy reads a connection whose first byte is an
uppercase letter until it sees a blank line (`\r\n\r\n`). A text protocol that
starts with an uppercase letter but never sends one is held until the 5s peek
timeout, then forwarded untouched. This happens on every new connection, to any
host, even at 0%. PR #7 (`fix/sniff-non-http-early`) stops reading as soon as
the first line cannot be `METHOD target HTTP/1.x`.

The attack is `--fault-hosts web.test --fault-latency 200ms
--fault-probability 0`. Every other dependency is not targeted, so nothing
should change for it.

Runs on any machine with Docker (macOS included: the proxy runs in a Linux
container).

- `web` — nginx on `web.test`, the targeted HTTP dependency: `:80`, plus the
  same site behind the PROXY protocol on `:8080` (HTTP) and `:8443` (TLS, a
  self-signed certificate from `gen-certs.sh`).
- `redis` (`redis.test:6379`), `nats` (`nats.test:4222`), `ssh`
  (`ssh.test:22`, OpenSSH): real servers, not targeted.
- `lines` (`lines.test:7000`) — answers `OK <line>` to each line it reads, to
  stand in for IRC, STOMP and other line-based protocols.
- `client` — real clients (`redis-cli`, `nats`, `curl`, `ssh`) and `probe`
  (`probe/`, built on the host by `run.sh`). `probe` times each client, or
  sends raw protocol bytes in one write and times the answer.
- `proxy` — the binary, in the client's network namespace (as the extension
  runs it in the target's), capturing every port (`--intercept-ports ''`).

```bash
./run.sh            # build the proxy and probe, start the lab, run every case
./run.sh 4 12       # only some cases
PROXY_SRC=../../../transparent-proxy.worktrees/sniff-non-http-early ./run.sh   # against PR #7
./run.sh down       # remove the containers
```

`PROXY_SRC` (default `../..`, this checkout) is the source the proxy is built
from. For a PR:
`git worktree add --detach ../transparent-proxy.worktrees/<name> origin/<branch>`.

A client counts as held when its answer takes over 1000ms. Each case also
checks that the proxy did not take the connection for a request to `web.test`
(`requests_matched` 0).

| case | client | first bytes | expected |
| ---- | ------ | ----------- | -------- |
| 0 | every client below, no proxy | | its answer, under 1s |
| 1 | curl to the targeted `web.test`, 0% | `GET / HTTP/1.1` | `200` at once, the request matched |
| 2 | the same at 100% | | `200` after ~200ms: the attack is live |
| 3 | `redis-cli PING` (RESP) | `*1\r\n$4...` | `PONG` at once (control: not uppercase) |
| 4 | Redis inline command | `PING\r\n` | `PONG` at once |
| 5 | `nats pub` (NATS CLI) | none: waits for the server's `INFO` | success at once |
| 6 | NATS `CONNECT` before reading `INFO` | `CONNECT {...}\r\n` | `PONG` at once |
| 7 | `curl --haproxy-protocol`, HTTP | `PROXY TCP4 ...\r\nGET ...` | `200` at once |
| 8 | `curl --haproxy-protocol`, TLS | `PROXY TCP4 ...\r\n` + ClientHello | `200` at once |
| 9 | IRC-style registration | `NICK lab\r\nUSER ...\r\n` | answer at once |
| 10 | STOMP, LF line ends, `host:web.test` | `CONNECT\naccept-version...` | answer at once, not matched |
| 11 | STOMP, CRLF line ends, `host:web.test` | `CONNECT\r\n...\r\n\r\n` | answer at once, not matched |
| 12 | `ssh` (OpenSSH) | `SSH-2.0-OpenSSH_10.0\r\n` | key exchange at once (login refused: no key) |

## Results

On `main` (82e1e55), cases 4, 6, 8, 9, 10 and 12 fail. Each client is held
about 5s, then works:

```
== 4. Redis inline command 'PING\r\n'                          ms=5006   (no proxy: 0)
== 6. NATS 'CONNECT {...}' sent before reading INFO            ms=5006   (no proxy: 0)
== 8. curl --haproxy-protocol over TLS                         ms=5016   (no proxy: 6)
== 9. IRC-style 'NICK ...\r\nUSER ...\r\n'                     ms=5007   (no proxy: 0)
== 10. STOMP CONNECT with LF line ends                         ms=5009   (no proxy: 0)
== 12. ssh                                                     ms=5069   (no proxy: 59)
```

On PR #7 (fb7783e), all 13 cases pass. Every client answers as fast as without
the proxy (case 4 1ms, 8 6ms, 12 60ms), and HTTP to `web.test` is still matched
and faulted (cases 1–2).

What that shows:

- **The bug is real**, and it isn't limited to Redis or NATS. Every client-first
  protocol whose first byte is an uppercase letter and that sends no
  `\r\n\r\n` is held 5s per connection. That includes destinations the attack
  doesn't target, and attacks at 0%.
- **OpenSSH is the most common affected client** (case 12). Every `ssh`, `scp`,
  `git` over SSH or Ansible connection from the target is held 5s. Load
  balancers or proxies sending the PROXY protocol ahead of TLS (case 8) are
  also hit.
- **Not affected:** RESP Redis clients (`redis-cli` and the client libraries,
  case 3); real NATS clients, because NATS is server-first (case 5); HTTP
  behind the PROXY protocol (case 7); and STOMP with CRLF line ends (case 11).
  Redis inline commands (case 4) only come from hand-written `nc`/`telnet`
  checks. A NATS client sending `CONNECT` before `INFO` (case 6) is not how
  real NATS clients behave. The card's Redis and NATS examples are the weakest
  ones.
- STOMP's `host:web.test` header is never taken for an HTTP `Host`: the
  request line is checked first, on `main` and on the PR (cases 10–11).
- Separate from this card: server-first protocols (NATS in case 5, ~266ms
  against 10ms without the proxy) pay the 250ms `--server-first-timeout` on
  every connection when every port is captured, on `main` and on the PR. And
  HTTP behind the PROXY protocol (case 7) is never matched, so it is not
  faulted even when its host is targeted.

## Running it by hand

`./run.sh --manual` starts the lab without a proxy and prints the commands.
Then, in one terminal:

```bash
./run.sh shell
./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports '' \
  --fault-hosts web.test --fault-latency 200ms --fault-probability 0 \
  --metrics-addr 127.0.0.1:9090
```

and in another:

```bash
docker exec text-protocols-lab-client-1 probe tcp -addr redis.test:6379 -send 'PING\r\n' -expect PONG
docker exec text-protocols-lab-client-1 probe exec -- ssh -o BatchMode=yes -o StrictHostKeyChecking=no lab@ssh.test true
docker exec text-protocols-lab-client-1 probe exec -- curl -sk -o /dev/null -w '%{http_code}' --haproxy-protocol https://web.test:8443/
docker exec text-protocols-lab-client-1 curl -s http://127.0.0.1:9090/
```

Ctrl-C stops the proxy and logs its final metrics. A proxy started by
`./run.sh` that was left running: `docker stop text-protocols-lab-proxy`. The
whole lab: `./run.sh down`.
