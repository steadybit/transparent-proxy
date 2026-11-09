# HTTPS lab

Exercises HTTPS response injection end to end, on any machine with Docker
(macOS included: the proxy runs in a Linux container). Cases 11–14 run the same
faults over plain HTTP, for comparison.

- `upstream` — nginx on `https://upstream.test`, with a certificate from a
  **private upstream CA**, and on `http://upstream.test` (port 80).
- `client` — curl, trusting only the CA each case passes with `--cacert`.
- `proxy` — this repo's binary, in the client's network namespace (as the
  extension runs it in the target's), capturing its outbound `:80` and `:443` with its own
  iptables rules and faulting `upstream.test` with `503` at probability `0.5`.

`gen-certs.sh` creates two CAs into `certs/` (git-ignored): the **interception
CA** the proxy mints leaves with and the client trusts, and the **upstream CA**
that signed the server's certificate, which only the proxy is given
(`--upstream-ca-file`).

`run.sh` runs it on first use; nothing is committed. The certificates are valid
for 30 days, so regenerate them (and restart the lab, so nginx picks up the new
server certificate) with:

```bash
rm -rf certs && ./gen-certs.sh && ./run.sh down
```

```bash
./run.sh          # build the linux binary, start the lab, run every case
./run.sh 2 5      # only some cases
./run.sh -n 100 2  # 100 requests per case instead of 20 (or REQUESTS=100)
./run.sh down     # remove the containers
```

Each case but 1 and 12 sends its requests over a single keep-alive connection,
so the share of `503`s shows the probability is rolled per request; cases 1 and
12 open a new connection per request. Each case reports how many connections it opened.

Each case then checks its results against the table below: a green `✓` when
they match, otherwise a yellow `✗` per mismatch, with what it got. "About half"
allows 3 standard deviations (4 to 16 of 20), so a working proxy misses it about
0.3% of the time. `run.sh` exits 1 when any case is not as expected.

| case | setup | expected |
| ---- | ----- | -------- |
| 0 | no proxy | `200` trusting the upstream CA; `000` trusting only the interception CA |
| 1 | each request on a new connection (`Connection: close`) | ~half `503`, the rest `200`; as many connections as requests |
| 2 | no `--upstream-ca-file` | ~half `503`, the rest `502`; `upstream_errors` > 0 |
| 3 | `--upstream-ca-file` | ~half `503`, the rest `200` |
| 4 | `--upstream-insecure-skip-verify` | as case 3, plus the skip-verify warning |
| 5 | client does not trust the interception CA | all `000`; `tls_intercept_rejected` > 0 |
| 6 | client speaks HTTP/2 | `HTTP/2` to the client; forwarded requests reach nginx as `HTTP/2.0` |
| 7 | `--upstream-ca-file` with a CA that did not sign nginx | as case 2 |
| 8 | a public site (`PUBLIC_HOST`, default `example.com`), no flags; the proxy's system roots are alpine's, none, then only a private CA | ~half `503`, the rest `200`, in every variant |
| 9 | `--fault-latency 200ms`, no `--fault-http-status` | on one connection, all `200`, ~half after ~200ms, the rest at once |
| 10 | `--fault-latency 200ms --fault-http-status 503` | on one connection, ~half `503` after ~200ms, the rest `200` at once |
| 11 | plain HTTP | on one connection, ~half `503`, the rest `200` |
| 12 | plain HTTP, each request on a new connection | ~half `503`, the rest `200`; as many connections as requests |
| 13 | plain HTTP, `--fault-latency 200ms` | as case 9 |
| 14 | plain HTTP, `--fault-latency 200ms --fault-http-status 503` | as case 10 |

The proxy uses HTTP/2 towards the upstream whenever nginx offers it, so the
forwarded requests of cases 3–4 reach it over HTTP/2 as well; case 6 adds
HTTP/2 on the client side.

Plain HTTP needs no certificates: the proxy selects the request by its `Host`
header instead of the TLS SNI, and reads the requests directly instead of
decrypting them. It is HTTP/1.1 only; the proxy does not handle cleartext HTTP/2
(h2c).

## Running it by hand

`./run.sh --manual` starts the lab **without a proxy and without testing**.
Then, in one terminal, open a shell in the client's network namespace (where
`./transparent-proxy` and `certs/` are in the working directory):

```bash
./run.sh shell
```

and run the proxy there. Ctrl-C stops it: it removes its iptables rules and
logs its final metrics.

```bash
# forwarded requests verified against the private upstream CA -> 503 / 200
./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \
  --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
  --upstream-ca-file certs/upstream-ca.crt \
  --fault-hosts upstream.test --fault-http-status 503 --fault-probability 0.5 \
  --metrics-addr 127.0.0.1:9090

# no upstream CA: the proxy cannot verify nginx -> 503 / 502 (upstream_errors)
./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \
  --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
  --fault-hosts upstream.test --fault-http-status 503 --fault-probability 0.5 \
  --metrics-addr 127.0.0.1:9090

# forwarded without verifying nginx -> 503 / 200, and a warning at startup
./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \
  --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
  --upstream-insecure-skip-verify \
  --fault-hosts upstream.test --fault-http-status 503 --fault-probability 0.5 \
  --metrics-addr 127.0.0.1:9090

# latency only, no httpStatus: decrypted like a status, rolled per request;
# a selected request is forwarded after 200ms, the others at once -> all 200
./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \
  --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
  --upstream-ca-file certs/upstream-ca.crt \
  --fault-hosts upstream.test --fault-latency 200ms --fault-probability 0.5 \
  --metrics-addr 127.0.0.1:9090

# latency and a status: decrypted, rolled per request; a selected request gets the
# 503 after 200ms, the others are forwarded at once -> 503 after 200ms / 200
./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \
  --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
  --upstream-ca-file certs/upstream-ca.crt \
  --fault-hosts upstream.test --fault-latency 200ms --fault-http-status 503 --fault-probability 0.5 \
  --metrics-addr 127.0.0.1:9090

# the CA as one PEM stream on stdin, as the extension passes it
cat certs/intercept-ca.crt certs/intercept-ca.key |
  ./transparent-proxy --tls-ca-stdin --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \
    --upstream-ca-file certs/upstream-ca.crt \
    --fault-hosts upstream.test --fault-http-status 503 --fault-probability 0.5
```

In another terminal, the client:

```bash
# one request, trusting the interception CA
docker exec https-lab-client-1 curl -s --cacert /certs/intercept-ca.crt https://upstream.test/

# see the certificate the proxy minted (issuer: HTTPS Lab Interception CA)
docker exec https-lab-client-1 curl -sv -o /dev/null --cacert /certs/intercept-ca.crt https://upstream.test/ 2>&1 | grep -E 'subject:|issuer:|HTTP/'

# 10 requests over one keep-alive connection: the probability is rolled per request
docker exec https-lab-client-1 curl -s --http1.1 --cacert /certs/intercept-ca.crt -w '%{http_code} new_connection=%{num_connects}\n' -o /dev/null 'https://upstream.test/[1-10]'

# the same over HTTP/2
docker exec https-lab-client-1 curl -s --http2 --cacert /certs/intercept-ca.crt -w '%{http_code} %{http_version}\n' -o /dev/null 'https://upstream.test/[1-10]'

# latency only: 10 requests over one keep-alive connection, each a 200 after 200ms
# or at once
docker exec https-lab-client-1 curl -s --http1.1 --cacert /certs/intercept-ca.crt -w '%{http_code} %{time_total}s new_connection=%{num_connects}\n' -o /dev/null 'https://upstream.test/[1-10]'

# latency and a status: 10 requests over one keep-alive connection, each a 503
# after 200ms or a 200 at once
docker exec https-lab-client-1 curl -s --http1.1 --cacert /certs/intercept-ca.crt -w '%{http_code} %{time_total}s new_connection=%{num_connects}\n' -o /dev/null 'https://upstream.test/[1-10]'

# trusting only the real upstream CA: fails (exit 60) while a proxy with an httpStatus or a latency runs, since it answers the handshake
docker exec https-lab-client-1 curl -s --cacert /certs/upstream-ca.crt https://upstream.test/; echo "exit=$?"

# not trusting the interception CA: fails and counts as tls_intercept_rejected
docker exec https-lab-client-1 curl -s https://upstream.test/; echo "exit=$?"

# the proxy's live metrics (loopback is never captured)
docker exec https-lab-client-1 curl -s http://127.0.0.1:9090/

# what the upstream received (protocol per request)
docker logs --tail 10 https-lab-upstream-1
```

## Stopping the proxy

The proxy shuts down cleanly on `SIGINT` or `SIGTERM`: it removes its iptables
rules, so the client goes straight to nginx again, and logs its final metrics
(`"proxy stopped"`).

- In the shell where it runs: Ctrl-C.
- From another terminal, when the shell is busy or detached:

  ```bash
  docker exec "$(docker ps -q --filter label=com.docker.compose.service=proxy)" pkill transparent-proxy
  ```

- A proxy started by `./run.sh` (container `https-lab-proxy`, e.g. after the
  script was interrupted mid-case): `docker stop https-lab-proxy`.
- The whole lab: `./run.sh down`. It kills the proxy rather than stopping it,
  which is fine here: the iptables rules live in the client's network
  namespace and go away with its container.

If a proxy is killed rather than stopped (e.g. the shell's container removed
with `docker rm -f`), its iptables rules stay behind and the next proxy's
preflight refuses to start on top of them. Clear them from the shell with
`./transparent-proxy --revert --intercept-cidrs 0.0.0.0/0 --intercept-ports 443`,
or re-run `./run.sh --manual`, which does the same.
