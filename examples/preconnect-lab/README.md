# Preconnect lab

Checks how the proxy treats an HTTPS connection opened **ahead of time**
(connection-pool warm-up, browser preconnect) that stays idle before its first
request, while a **latency attack at 0%** runs with the interception CA. With
the CA, every matched HTTPS connection is decrypted, not only the faulted
share, so the proxy's own HTTP server is in the path of every one of them.
Nothing should change for the client, and nothing should be reported as a
rejected certificate.

The suspected problem (Kanbanize 27639): on HTTP/1.1 the 10s
`readHeaderTimeout` in `internal/tlsinject/serve.go` also bounds the **first**
request, so the proxy closes a connection that stays silent for 10s after the
handshake. A connection that ends without any request is then reported as a
post-handshake rejection: `tls_intercept_rejected` rises and the proxy warns
"is the CA trusted by the target?". Cases 2, 3 and 6 check for this and fail
while it is there; cases 7–9 are genuine rejections, which a fix must still
report.

Runs on any machine with Docker (macOS included: the proxy runs in a Linux
container).

- `upstream` — nginx on `https://upstream.test`, with a certificate from a
  private upstream CA. Its own limit for a silent client is
  `client_header_timeout` (60s), so without the proxy an idle connection
  survives the lab's idle times (case 0).
- `client` — curl, plus `preconnect` (`client/`, built on the host by `run.sh`),
  which opens a TLS connection, leaves it idle, then sends a request on it.
  While idle it reads the connection, so it reports when the other side closed
  it.
- `proxy` — this repo's binary, in the client's network namespace (as the
  extension runs it in the target's), capturing outbound `:443` and running
  `--fault-latency 200ms --fault-probability 0` on `upstream.test`, with
  `--upstream-ca-file` so forwarding works.

`gen-certs.sh` creates the two CAs into `certs/` (git-ignored) on first use:
the **interception CA** the proxy mints leaves with and the client trusts, and
the **upstream CA** that signed nginx's certificate. A client trusting only the
upstream CA rejects the proxy's certificate (cases 7–9). They are valid for 30
days; regenerate them with `rm -rf certs && ./gen-certs.sh && ./run.sh down`.

```bash
./run.sh          # build the proxy and the client, start the lab, run every case
./run.sh 2 6      # only some cases
IDLE=30s ./run.sh 2   # a longer idle time (default 15s; SHORT_IDLE, default 5s, for case 1)
PROBABILITY=1 ./run.sh   # the latency applied to every request instead of none
./run.sh down     # remove the containers
```

`preconnect` prints one line per run:

```
result=200 closed_after=- retried=0 err=-
```

`result` is the final status, `000` when no response came; `closed_after` how
long after the handshake the peer closed the idle connection (`-`: it did not);
`retried` whether the request was retried on a new connection (`-retry`); `err`
the error that ended the attempt.

| case | client | expected |
| ---- | ------ | -------- |
| 0 | no proxy; HTTP/1.1, HTTP/2 and HTTP/2 without an early preface, idle 15s | `200`, never closed |
| 1 | HTTP/1.1, idle 5s (below the proxy's 10s) | `200`, no rejection |
| 2 | HTTP/1.1, idle 15s | as without a proxy: `200`, not closed, no rejection, no CA warning |
| 3 | as case 2, retrying a failed request on a new connection (`-retry`) | `200` on the first try, no rejection |
| 4 | HTTP/1.1, one request, then idle 15s before the second (`-warm`) | `200`, not closed: keep-alive idling is not bounded |
| 5 | HTTP/2, preface sent at connect, idle 15s | `200`, not closed, no rejection |
| 6 | HTTP/2, only the TLS handshake ahead of time, preface with the request after 15s (`-proto h2-lazy`) | `200`, not closed, no rejection |
| 7 | Go client not trusting the interception CA, TLS 1.3 | `000`, one rejection and one CA warning |
| 8 | the same, TLS 1.2 (`-tls12`) | `000`, one rejection and one CA warning |
| 9 | curl (OpenSSL) not trusting the interception CA | `000`, one rejection and one CA warning |

Each case reports a green `✓` when its results match, otherwise a yellow `✗`
per mismatch with what it got, and the proxy's counters and warnings (with the
rejection `stage` and `err`). `run.sh` exits 1 when any case is not as
expected.

## Results on `82e1e55`

Cases 0, 1, 4, 5 and 7–9 pass; 2, 3 and 6 fail:

```
== 2. HTTP/1.1, idle 15s before the first request
  client: result=000 closed_after=10.0s retried=0 err=unexpected_EOF
  proxy metrics: requests_matched:0 ... tls_intercept_rejected:1
  warn: "client rejected the injected certificate; is the CA trusted by the target?" "stage":"post-handshake" "err":"... no request was sent"

== 3. as case 2, with a client that retries a failed request on a new connection
  client: result=200 closed_after=10.0s retried=1 err=-
  proxy metrics: requests_matched:1 ... tls_intercept_rejected:1

== 6. HTTP/2, only the TLS handshake ahead of time
  client: result=000 closed_after=10.0s retried=0 err=write_tcp_..._broken_pipe
  proxy metrics: requests_matched:0 ... tls_intercept_rejected:1
```

What that shows:

- The proxy closes a connection silent for 10s after the handshake, on HTTP/1.1
  and on HTTP/2 before the client preface (net/http's own 10s preface
  timeout). nginx alone keeps it open.
- A client that does not retry sees the request fail; one that retries on a new
  connection gets its `200`, but the proxy still counts a rejection and warns
  about the CA either way.
- Not affected: idling after a request (case 4), and HTTP/2 clients that send
  their preface when connecting (case 5), as Go, gRPC and most HTTP/2 clients
  do.
- curl's genuine rejection (case 9) is logged exactly like the idle close
  (`post-handshake`, "no request was sent"): OpenSSL sends its alert after the
  handshake, and the proxy does not read it. Go's (cases 7–8) arrive during the
  handshake. A fix telling them apart must look at that alert (e.g.
  `bad_certificate`/`unknown_ca`) versus a plain EOF.

Whether real workloads hit this depends on their HTTP client opening
connections ahead of time and leaving them idle for more than 10s;
`preconnect` reproduces that shape, not a specific library.

## Running it by hand

`./run.sh --manual` starts the lab without a proxy and prints the commands.
Then, in one terminal:

```bash
./run.sh shell
./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \
  --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
  --upstream-ca-file certs/upstream-ca.crt \
  --fault-hosts upstream.test --fault-latency 200ms --fault-probability 0 \
  --metrics-addr 127.0.0.1:9090
```

and in another (`preconnect` takes `-proto h1|h2|h2-lazy`, `-idle`, `-warm`,
`-retry`, `-tls12`, `-cacert`, `-url`):

```bash
docker exec preconnect-lab-client-1 preconnect -proto h1 -idle 15s -cacert /certs/intercept-ca.crt
docker exec preconnect-lab-client-1 preconnect -proto h1 -idle 15s -retry -cacert /certs/intercept-ca.crt
docker exec preconnect-lab-client-1 preconnect -proto h1 -idle 0s -cacert /certs/upstream-ca.crt   # a genuine rejection
docker exec preconnect-lab-client-1 curl -s http://127.0.0.1:9090/                                 # live metrics
```

Ctrl-C stops the proxy: it removes its iptables rules and logs its final
metrics. A proxy started by `./run.sh` that was left running:
`docker stop preconnect-lab-proxy`. The whole lab: `./run.sh down`.
