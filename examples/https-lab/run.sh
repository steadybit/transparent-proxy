#!/usr/bin/env bash
# Walks through HTTPS interception end to end: a client calls
# https://upstream.test, whose certificate comes from a private CA, while the
# proxy runs in the client's network namespace and faults half the requests.
#
#   ./run.sh            all cases
#   ./run.sh 2 5        only cases 2 and 5
#   ./run.sh -n 100 2   100 requests per batch instead of 20 (or REQUESTS=100)
#   ./run.sh --manual   start the lab without testing, and print the
#                       ./transparent-proxy commands and curls to run by hand
#   ./run.sh shell      a shell in the client's network namespace, to run
#                       ./transparent-proxy in
#   ./run.sh down       remove the lab's containers
set -euo pipefail
cd "$(dirname "$0")"

# Cases faulting another host override both (bash locals are dynamically scoped).
URL=https://upstream.test/
FAULT_HOST=upstream.test
FAULT=(--fault-http-status 503) # the fault besides the host and probability
PUBLIC_HOST=${PUBLIC_HOST:-example.com}
PROXY_ENV=() # -e flags for the proxy's container
REQUESTS=${REQUESTS:-20}
PROXY=https-lab-proxy
dc() { docker compose "$@"; }

if [[ ${1:-} == down ]]; then
  docker rm -f "$PROXY" >/dev/null 2>&1 || true
  dc --profile proxy down --remove-orphans
  exit 0
fi

setup() {
  [[ -f certs/intercept-ca.crt ]] || ./gen-certs.sh
  echo "building the linux proxy binary"
  local arch
  arch=$(docker version -f '{{.Server.Arch}}')
  (cd ../.. && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o examples/https-lab/bin/transparent-proxy .)
  dc --profile proxy build -q proxy
  dc up -d upstream client
}

CAPTURE=(--intercept-cidrs 0.0.0.0/0 --intercept-ports 443)

# revert_leftovers: stops a proxy this script started and clears any capture a
# killed proxy left behind (the next one's preflight refuses to stack on it).
revert_leftovers() {
  docker stop -t 10 "$PROXY" >/dev/null 2>&1 || true
  docker rm "$PROXY" >/dev/null 2>&1 || true
  dc run --rm -T proxy ./transparent-proxy --revert "${CAPTURE[@]}" >/dev/null 2>&1
}

# start_proxy <extra flags...>: starts the proxy and waits for its iptables capture.
start_proxy() {
  revert_leftovers
  dc run -d -T --name "$PROXY" ${PROXY_ENV[@]+"${PROXY_ENV[@]}"} proxy ./transparent-proxy "${CAPTURE[@]}" \
    --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
    --fault-hosts "$FAULT_HOST" ${FAULT[@]+"${FAULT[@]}"} --fault-probability 0.5 \
    "$@" >/dev/null 2>&1
  for _ in $(seq 50); do
    if docker exec "$PROXY" iptables -t nat -S 2>/dev/null | grep -q SB_TP_REDIR; then return; fi
    sleep 0.2
  done
  echo "proxy did not install its capture:" >&2
  docker logs "$PROXY" >&2
  exit 1
}

# stop_proxy: stops the proxy (it tears its rules down) and prints its counters
# and any warnings it logged.
stop_proxy() {
  docker stop -t 10 "$PROXY" >/dev/null
  local logs
  logs=$(docker logs "$PROXY" 2>&1)
  docker rm "$PROXY" >/dev/null
  local final
  final=$(grep '"proxy stopped"' <<<"$logs" || true)
  printf '  proxy metrics:'
  for k in requests_matched requests_faulted latency_applied upstream_errors tls_intercept_rejected; do
    printf ' %s' "$(grep -oE "\"$k\":[0-9]+" <<<"$final" | head -1 | tr -d '"')"
  done
  echo
  grep -E '"level":"WARN"' <<<"$logs" | grep -oE '"msg":"[^"]*"' | sort | uniq -c | sed 's/^/  warn: /' || true
}

# curl_batch <write-out> <curl flags...>: sends $REQUESTS requests over ONE curl
# invocation, so they share a keep-alive connection, and prints <write-out> per
# response (nothing when curl got none). curl speaks HTTP/1.1 unless the case
# asks for --http2.
curl_batch() {
  local fmt=$1 args=() out err
  shift
  for _ in $(seq "$REQUESTS"); do args+=(-o /dev/null "$URL"); done
  err=$(mktemp)
  out=$(dc exec -T client curl -sS -w "$fmt\n" --http1.1 "$@" "${args[@]}" 2>"$err" || true)
  if [[ -n $out ]]; then
    echo "$out"
  else
    echo "  no response from curl: $(sort -u "$err" | head -3)" >&2
  fi
  rm -f "$err"
}

# requests <curl flags...>: tallies the status codes of a curl_batch.
requests() {
  curl_batch '%{http_code} HTTP/%{http_version}' "$@" | sort | uniq -c | sed 's/^/  /'
}

# timed_requests <curl flags...>: tallies the status codes of a curl_batch by
# whether each response took the 1s delay, and counts the connections opened.
timed_requests() {
  curl_batch '%{http_code} %{time_total} %{num_connects}' "$@" |
    awk '{ print $1, ($2 >= 0.9 ? "after ~1s" : "at once"); conns += $3 }
         END { if (NR) print "connections opened: " conns }' |
    sort | uniq -c | sed 's/^/  /'
}

upstream_log() { dc logs --no-log-prefix upstream 2>/dev/null; }

# upstream_protocols <lines>: protocols of the upstream requests logged after
# its first <lines> log lines.
upstream_protocols() {
  printf '  upstream saw:'
  upstream_log | tail -n +"$(($1 + 1))" | grep -oE 'HTTP/[0-9.]+$' | sort | uniq -c | tr '\n' ' '
  echo
}

case_0() {
  echo "== 0. baseline, no proxy"
  echo "  trusting the upstream CA (expect 200):"
  requests --cacert /certs/upstream-ca.crt
  echo "  trusting only the interception CA (expect 000: nobody is minting certificates yet):"
  requests --cacert /certs/intercept-ca.crt
}

case_1() {
  echo "== 1. no --upstream-ca-file (expect ~half 503, the rest 502 counted as upstream_errors)"
  start_proxy
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
}

case_2() {
  echo "== 2. --upstream-ca-file (expect ~half 503, the rest 200)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
}

case_3() {
  echo "== 3. --upstream-insecure-skip-verify (expect ~half 503, the rest 200, and a warning)"
  start_proxy --upstream-insecure-skip-verify
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
}

case_4() {
  echo "== 4. client does not trust the interception CA (expect 000 and tls_intercept_rejected > 0)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  requests
  stop_proxy
}

case_5() {
  echo "== 5. HTTP/2 on both legs (expect HTTP/2 to the client and HTTP/2.0 at the upstream)"
  local before
  before=$(upstream_log | wc -l)
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  requests --http2 --cacert /certs/intercept-ca.crt
  stop_proxy
  sleep 1
  upstream_protocols "$before"
}

case_6() {
  echo "== 6. --upstream-ca-file with a CA that did not sign nginx (expect ~half 503, the rest 502 counted as upstream_errors)"
  start_proxy --upstream-ca-file certs/intercept-ca.crt
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
}

# public_requests <title>: faults $PUBLIC_HOST through a proxy given no trust
# flags, with the system roots set by the caller's PROXY_ENV.
public_requests() {
  echo "  $1:"
  start_proxy
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
}

# Only the proxy's environment changes between the variants: Go reads its system
# roots from SSL_CERT_FILE / SSL_CERT_DIR when set.
case_7() {
  local URL=https://$PUBLIC_HOST/ FAULT_HOST=$PUBLIC_HOST PROXY_ENV=()
  echo "== 7. public CA ($PUBLIC_HOST), no flags (expect ~half 503, the rest 200, in every variant)"
  echo "  baseline, no proxy, the client's own roots (expect 200):"
  requests
  public_requests "a. alpine's system roots"
  PROXY_ENV=(-e SSL_CERT_FILE=/nonexistent -e SSL_CERT_DIR=/nonexistent)
  public_requests "b. no system roots: the Mozilla roots built into the binary"
  PROXY_ENV=(-e SSL_CERT_FILE=/lab/certs/upstream-ca.crt -e SSL_CERT_DIR=/nonexistent)
  public_requests "c. a private CA as the only system root, as extensions mount one"
}

case_8() {
  local FAULT=(--fault-latency 1s)
  echo "== 8. delay only, no httpStatus (expect decrypted, rolled per request on one connection:"
  echo "      all 200, ~half after ~1s, the rest at once)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  timed_requests --cacert /certs/intercept-ca.crt
  stop_proxy
}

case_9() {
  local FAULT=(--fault-latency 1s --fault-http-status 503)
  echo "== 9. delay and a status (expect decrypted, rolled per request on one connection:"
  echo "      ~half 503 after ~1s, the rest 200 at once)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  timed_requests --cacert /certs/intercept-ca.crt
  stop_proxy
}

print_manual() {
  cat <<'EOF2'
The lab is up, without a proxy. In one terminal open a shell in the client's
network namespace:

  ./run.sh shell

and run the proxy there (Ctrl-C stops it, removes its iptables rules and logs
its final metrics). It faults half the requests to upstream.test with 503:

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

  # delay only, no httpStatus: decrypted like a status, rolled per request;
  # a selected request is forwarded after 1s, the others at once -> all 200
  ./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \
    --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
    --upstream-ca-file certs/upstream-ca.crt \
    --fault-hosts upstream.test --fault-latency 1s --fault-probability 0.5 \
    --metrics-addr 127.0.0.1:9090

  # delay and a status: decrypted, rolled per request; a selected request gets the
  # 503 after 1s, the others are forwarded at once -> 503 after 1s / 200
  ./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \
    --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
    --upstream-ca-file certs/upstream-ca.crt \
    --fault-hosts upstream.test --fault-latency 1s --fault-http-status 503 --fault-probability 0.5 \
    --metrics-addr 127.0.0.1:9090

  # the CA as one PEM stream on stdin, as the extension passes it:
  cat certs/intercept-ca.crt certs/intercept-ca.key | ./transparent-proxy --tls-ca-stdin ...

In another terminal, the client:

  # one request, trusting the interception CA
  docker exec https-lab-client-1 curl -s --cacert /certs/intercept-ca.crt https://upstream.test/

  # see the certificate the proxy minted (issuer: HTTPS Lab Interception CA)
  docker exec https-lab-client-1 curl -sv -o /dev/null --cacert /certs/intercept-ca.crt https://upstream.test/ 2>&1 | grep -E 'subject:|issuer:|HTTP/'

  # 10 requests over one keep-alive connection: the probability is rolled per request
  docker exec https-lab-client-1 curl -s --http1.1 --cacert /certs/intercept-ca.crt -w '%{http_code} new_connection=%{num_connects}\n' -o /dev/null 'https://upstream.test/[1-10]'

  # the same over HTTP/2
  docker exec https-lab-client-1 curl -s --http2 --cacert /certs/intercept-ca.crt -w '%{http_code} %{http_version}\n' -o /dev/null 'https://upstream.test/[1-10]'

  # delay only: 10 requests over one keep-alive connection, each a 200 after 1s
  # or at once
  docker exec https-lab-client-1 curl -s --http1.1 --cacert /certs/intercept-ca.crt -w '%{http_code} %{time_total}s new_connection=%{num_connects}\n' -o /dev/null 'https://upstream.test/[1-10]'

  # delay and a status: 10 requests over one keep-alive connection, each a 503
  # after 1s or a 200 at once
  docker exec https-lab-client-1 curl -s --http1.1 --cacert /certs/intercept-ca.crt -w '%{http_code} %{time_total}s new_connection=%{num_connects}\n' -o /dev/null 'https://upstream.test/[1-10]'

  # trusting only the real upstream CA: fails (exit 60) while a proxy with an httpStatus or a latency runs, since it answers the handshake
  docker exec https-lab-client-1 curl -s --cacert /certs/upstream-ca.crt https://upstream.test/; echo "exit=$?"

  # not trusting the interception CA: fails and counts as tls_intercept_rejected
  docker exec https-lab-client-1 curl -s https://upstream.test/; echo "exit=$?"

  # the proxy's live metrics (loopback is never captured)
  docker exec https-lab-client-1 curl -s http://127.0.0.1:9090/

  # what the upstream received (protocol per request)
  docker logs --tail 10 https-lab-upstream-1

Tear down: ./run.sh down
EOF2
}

case ${1:-} in
  --manual)
    setup
    revert_leftovers
    echo
    print_manual
    exit 0
    ;;
  shell)
    exec docker compose run --rm proxy
    ;;
esac

cases=()
while [[ $# -gt 0 ]]; do
  case $1 in
    -n)
      [[ ${2:-} =~ ^[1-9][0-9]*$ ]] || { echo "-n needs a positive number of requests" >&2; exit 2; }
      REQUESTS=$2
      shift 2
      ;;
    *)
      cases+=("$1")
      shift
      ;;
  esac
done
setup
[[ ${#cases[@]} -gt 0 ]] || cases=(0 1 2 3 4 5 6 7 8 9)
for c in "${cases[@]}"; do
  echo
  "case_$c"
done
echo
echo "done; './run.sh down' removes the lab"
