#!/usr/bin/env bash
# Walks through HTTPS interception end to end: a client calls
# https://upstream.test, whose certificate comes from a private CA, while the
# proxy runs in the client's network namespace and faults half the requests.
# Cases 11-14 do the same over plain HTTP (http://upstream.test, port 80), and
# cases 15-19 reset half the requests (--fault-reset) over HTTPS and HTTP.
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
  # nginx is recreated every time: a running one keeps the config it started
  # with, and its file mount can even pin the old file once an editor replaces it.
  dc up -d --force-recreate upstream
  dc up -d client
}

CAPTURE=(--intercept-cidrs 0.0.0.0/0 --intercept-ports 80,443)

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
# and any warnings it logged, keeping them in METRICS and WARNS for the checks.
# Then checks the proxy left nothing behind: no capture rules, and the
# dependency answers the client directly again on both ports.
stop_proxy() {
  docker stop -t 10 "$PROXY" >/dev/null
  local logs left direct
  logs=$(docker logs "$PROXY" 2>&1)
  docker rm "$PROXY" >/dev/null
  left=$(dc run --rm -T proxy sh -c 'for t in nat mangle filter raw; do iptables -t $t -S; done' 2>/dev/null | grep -c SB_TP || true)
  direct="$(dc exec -T client curl -s -o /dev/null -m 5 -w '%{http_code}' http://upstream.test/ || true) $(dc exec -T client curl -s -o /dev/null -m 5 -w '%{http_code}' --cacert /certs/upstream-ca.crt https://upstream.test/ || true)"
  echo "  after stop: capture rules left $left, direct http/https $direct"
  expect "capture rules left after stop" "$left" 0
  expect "direct http/https responses after stop" "$direct" "200 200"
  METRICS=$(grep '"proxy stopped"' <<<"$logs" || true)
  printf '  proxy metrics:'
  for k in requests_matched requests_faulted latency_applied connections_aborted upstream_errors tls_intercept_rejected; do
    printf ' %s:%s' "$k" "$(metric "$k")"
  done
  echo
  WARNS=$(grep -E '"level":"WARN"' <<<"$logs" | grep -oE '"msg":"[^"]*"' || true)
  [[ -z $WARNS ]] || sort <<<"$WARNS" | uniq -c | sed 's/^/  warn: /'
}

# metric <name>: the proxy's final value of a top-level counter.
metric() { grep -oE "\"$1\":[0-9]+" <<<"$METRICS" | head -1 | cut -d: -f2; }

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

LATE=0.18 # seconds; a response this slow took the injected 200ms latency

# requests <curl flags...>: tallies the status codes of a curl_batch, and counts
# the connections opened. LAST keeps one "<code> <protocol> <connections>" line
# per response for the checks.
requests() {
  LAST=$(curl_batch '%{http_code} HTTP/%{http_version} %{num_connects}' "$@")
  tally '{ print $1, $2 }'
}

# timed_requests <curl flags...>: as requests, tallying the status codes by
# whether each response took the 200ms latency; LAST has seconds as its 2nd field.
timed_requests() {
  LAST=$(curl_batch '%{http_code} %{time_total} %{num_connects}' "$@")
  tally '{ print $1, ($2 >= late ? "after ~200ms" : "at once") }'
}

# reset_requests <curl flags...>: as requests, tallying the status codes with
# curl's exit code, which tells how a reset request failed (000: no response).
reset_requests() {
  LAST=$(curl_batch '%{http_code} curl_exit=%{exitcode} %{num_connects}' "$@")
  tally '{ print $1, $2 }'
}

# tally <awk program>: counts the lines it prints for LAST, and the connections.
tally() {
  [[ -n $LAST ]] || return 0
  awk -v late="$LATE" "$1"' { conns += $3 } END { print "connections opened: " conns }' <<<"$LAST" |
    sort | uniq -c | sed 's/^/  /'
}

# Checks: each case states what it expects with expect*, and verdict reports the
# case green when it met every expectation, or each failed one in yellow.
FAILS=()
FAILED_CASES=()
if [[ -t 1 ]]; then GREEN=$'\e[32m' YELLOW=$'\e[33m' RESET=$'\e[0m'; else GREEN='' YELLOW='' RESET=''; fi

# expect <what> <actual> <expected>. A variant of a case sets CONTEXT to name it.
expect() { [[ $2 == "$3" ]] || FAILS+=("${CONTEXT:+$CONTEXT: }$1: got $2, expected $3"); }

# count <awk condition>: the responses in LAST that meet it ($1 the status code).
count() { awk -v late="$LATE" "$1"' { n++ } END { print n + 0 }' <<<"$LAST"; }

connections() { awk '{ n += $3 } END { print n + 0 }' <<<"$LAST"; }

# expect_all <what> <awk condition>: every response meets it.
expect_all() { expect "$1" "$(count "$2") of $REQUESTS" "$REQUESTS of $REQUESTS"; }

# expect_about_half <what> <awk condition>: within 3 standard deviations of
# half the responses, so a working proxy misses it about 0.3% of the time.
expect_about_half() {
  local n d
  n=$(count "$2")
  d=$((2 * n - REQUESTS))
  ((d * d <= 9 * REQUESTS)) || FAILS+=("${CONTEXT:+$CONTEXT: }$1: got $n of $REQUESTS, expected about half")
}

# expect_split <faulted code> <other code>: every response is one of them, about
# half the faulted one, and the proxy counted every request and the faults.
expect_split() {
  expect_all "responses $1 or $2" "\$1 == $1 || \$1 == $2"
  expect_about_half "$1 responses" "\$1 == $1"
  expect requests_matched "$(metric requests_matched)" "$REQUESTS"
  expect requests_faulted "$(metric requests_faulted)" "$(count "\$1 == $1")"
}

# expect_reset_split: every response is a 200 or none (000), about half none,
# and the proxy counted every request and reset exactly the ones that got none.
expect_reset_split() {
  expect_all "responses 200 or 000" '$1 == 200 || $1 == "000"'
  expect_about_half "000 responses (reset)" '$1 == "000"'
  expect requests_matched "$(metric requests_matched)" "$REQUESTS"
  expect requests_faulted "$(metric requests_faulted)" "$(count '$1 == "000"')"
  expect connections_aborted "$(metric connections_aborted)" "$(count '$1 == "000"')"
}

# expect_reset_retried: a reset on a reused HTTP/1.1 connection is retried by
# curl on a new one, so a request gets a 000 only when that retry is reset too.
# The proxy sees the retries as requests of their own: about half of all it
# matched are reset, and each reset ends a connection.
expect_reset_retried() {
  local matched faulted d
  matched=$(metric requests_matched)
  faulted=$(metric requests_faulted)
  expect_all "responses 200 or 000" '$1 == 200 || $1 == "000"'
  ((matched >= REQUESTS)) || FAILS+=("requests_matched: got $matched, expected at least $REQUESTS")
  d=$((2 * faulted - matched))
  ((d * d <= 9 * matched)) || FAILS+=("requests_faulted: got $faulted of $matched, expected about half")
  expect connections_aborted "$(metric connections_aborted)" "$faulted"
}

# verdict <case>
verdict() {
  if [[ ${#FAILS[@]} -eq 0 ]]; then
    echo "  ${GREEN}✓ case $1 as expected${RESET}"
  else
    FAILED_CASES+=("$1")
    for f in "${FAILS[@]}"; do echo "  ${YELLOW}✗ $f${RESET}"; done
  fi
  FAILS=()
}

upstream_log() { dc logs --no-log-prefix upstream 2>/dev/null; }

# upstream_protocols <lines>: protocols of the upstream requests logged after
# its first <lines> log lines, one per line in UPSTREAM.
upstream_protocols() {
  UPSTREAM=$(upstream_log | tail -n +"$(($1 + 1))" | grep -oE 'HTTP/[0-9.]+$' || true)
  printf '  upstream saw:'
  [[ -z $UPSTREAM ]] || sort <<<"$UPSTREAM" | uniq -c | tr '\n' ' '
  echo
}

case_0() {
  echo "== 0. baseline, no proxy"
  echo "  trusting the upstream CA (expect 200):"
  requests --cacert /certs/upstream-ca.crt
  expect_all "responses 200 trusting the upstream CA" '$1 == 200'
  echo "  trusting only the interception CA (expect 000: nobody is minting certificates yet):"
  requests --cacert /certs/intercept-ca.crt
  expect_all "responses 000 trusting only the interception CA" '$1 == "000"'
}

case_1() {
  echo "== 1. a new connection per request (expect ~half 503, the rest 200, and one connection per request)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  requests --cacert /certs/intercept-ca.crt -H 'Connection: close'
  stop_proxy
  expect_split 503 200
  expect "connections" "$(connections)" "$REQUESTS"
}

case_2() {
  echo "== 2. no --upstream-ca-file (expect ~half 503, the rest 502 counted as upstream_errors)"
  start_proxy
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
  expect_502s
}

# expect_502s: half the requests faulted, the rest failed to be forwarded.
expect_502s() {
  expect_split 503 502
  expect upstream_errors "$(metric upstream_errors)" "$(count '$1 == 502')"
  expect "connections" "$(connections)" 1
}

case_3() {
  echo "== 3. --upstream-ca-file (expect ~half 503, the rest 200)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
  expect_200s
}

# expect_200s: half the requests faulted, the rest forwarded on one connection.
expect_200s() {
  expect_split 503 200
  expect upstream_errors "$(metric upstream_errors)" 0
  expect "connections" "$(connections)" 1
}

case_4() {
  echo "== 4. --upstream-insecure-skip-verify (expect ~half 503, the rest 200, and a warning)"
  start_proxy --upstream-insecure-skip-verify
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
  expect_200s
  expect "skip-verify warnings" "$(grep -c 'without verifying' <<<"$WARNS")" 1
}

case_5() {
  echo "== 5. client does not trust the interception CA (expect 000 and tls_intercept_rejected > 0)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  requests
  stop_proxy
  expect_all "responses 000" '$1 == "000"'
  expect tls_intercept_rejected "$(metric tls_intercept_rejected)" "$REQUESTS"
}

case_6() {
  echo "== 6. HTTP/2 on both legs (expect HTTP/2 to the client and HTTP/2.0 at the upstream)"
  local before
  before=$(upstream_log | wc -l)
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  requests --http2 --cacert /certs/intercept-ca.crt
  # read nginx's log before stop_proxy, whose cleanup check sends requests of its own
  sleep 1
  upstream_protocols "$before"
  stop_proxy
  expect_200s
  expect_all "responses over HTTP/2" '$2 == "HTTP/2"'
  expect "forwarded requests nginx saw" "$(grep -c . <<<"$UPSTREAM")" "$(count '$1 == 200')"
  expect "of them over HTTP/2.0" "$(grep -c '^HTTP/2.0$' <<<"$UPSTREAM")" "$(count '$1 == 200')"
}

case_7() {
  echo "== 7. --upstream-ca-file with a CA that did not sign nginx (expect ~half 503, the rest 502 counted as upstream_errors)"
  start_proxy --upstream-ca-file certs/intercept-ca.crt
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
  expect_502s
}

# public_requests <title>: faults $PUBLIC_HOST through a proxy given no trust
# flags, with the system roots set by the caller's PROXY_ENV.
public_requests() {
  local CONTEXT="variant ${1%%.*}"
  echo "  $1:"
  start_proxy
  requests --cacert /certs/intercept-ca.crt
  stop_proxy
  expect_200s
}

# Only the proxy's environment changes between the variants: Go reads its system
# roots from SSL_CERT_FILE / SSL_CERT_DIR when set.
case_8() {
  local URL=https://$PUBLIC_HOST/ FAULT_HOST=$PUBLIC_HOST PROXY_ENV=()
  echo "== 8. public CA ($PUBLIC_HOST), no flags (expect ~half 503, the rest 200, in every variant)"
  echo "  baseline, no proxy, the client's own roots (expect 200):"
  requests
  expect_all "responses 200 without a proxy" '$1 == 200'
  public_requests "a. alpine's system roots"
  PROXY_ENV=(-e SSL_CERT_FILE=/nonexistent -e SSL_CERT_DIR=/nonexistent)
  public_requests "b. no system roots: the Mozilla roots built into the binary"
  PROXY_ENV=(-e SSL_CERT_FILE=/lab/certs/upstream-ca.crt -e SSL_CERT_DIR=/nonexistent)
  public_requests "c. a private CA as the only system root, as extensions mount one"
}

case_9() {
  local FAULT=(--fault-latency 200ms)
  echo "== 9. latency only, no httpStatus (expect decrypted, rolled per request on one connection:"
  echo "       all 200, ~half after ~200ms, the rest at once)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  timed_requests --cacert /certs/intercept-ca.crt
  stop_proxy
  expect_all "responses 200" '$1 == 200'
  expect_about_half "responses after ~200ms" '$2 >= late'
  expect requests_matched "$(metric requests_matched)" "$REQUESTS"
  expect latency_applied "$(metric latency_applied)" "$(count '$2 >= late')"
  expect "connections" "$(connections)" 1
}

case_10() {
  local FAULT=(--fault-latency 200ms --fault-http-status 503)
  echo "== 10. latency and a status (expect decrypted, rolled per request on one connection:"
  echo "       ~half 503 after ~200ms, the rest 200 at once)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  timed_requests --cacert /certs/intercept-ca.crt
  stop_proxy
  expect_split 503 200
  expect_all "responses 503 exactly when after ~200ms" '($1 == 503) == ($2 >= late)'
  expect latency_applied "$(metric latency_applied)" "$(count '$1 == 503')"
  expect "connections" "$(connections)" 1
}

# Plain HTTP: no certificates, and the proxy selects by the Host header instead
# of the SNI. Only the faults differ between the cases.
case_11() {
  local URL=http://upstream.test/
  echo "== 11. plain HTTP, keep-alive (expect ~half 503, the rest 200, on one connection)"
  start_proxy
  requests
  stop_proxy
  expect_split 503 200
  expect "connections" "$(connections)" 1
}

case_12() {
  local URL=http://upstream.test/
  echo "== 12. plain HTTP, a new connection per request (expect ~half 503, the rest 200, one connection per request)"
  start_proxy
  requests -H 'Connection: close'
  stop_proxy
  expect_split 503 200
  expect "connections" "$(connections)" "$REQUESTS"
}

case_13() {
  local URL=http://upstream.test/ FAULT=(--fault-latency 200ms)
  echo "== 13. plain HTTP, latency only (expect rolled per request on one connection:"
  echo "       all 200, ~half after ~200ms, the rest at once)"
  start_proxy
  timed_requests
  stop_proxy
  expect_all "responses 200" '$1 == 200'
  expect_about_half "responses after ~200ms" '$2 >= late'
  expect requests_matched "$(metric requests_matched)" "$REQUESTS"
  expect latency_applied "$(metric latency_applied)" "$(count '$2 >= late')"
  expect "connections" "$(connections)" 1
}

case_14() {
  local URL=http://upstream.test/ FAULT=(--fault-latency 200ms --fault-http-status 503)
  echo "== 14. plain HTTP, latency and a status (expect rolled per request on one connection:"
  echo "       ~half 503 after ~200ms, the rest 200 at once)"
  start_proxy
  timed_requests
  stop_proxy
  expect_split 503 200
  expect_all "responses 503 exactly when after ~200ms" '($1 == 503) == ($2 >= late)'
  expect latency_applied "$(metric latency_applied)" "$(count '$1 == 503')"
  expect "connections" "$(connections)" 1
}

# Resets: the proxy answers nothing, so a reset request gets no response (000).
case_15() {
  local FAULT=(--fault-reset)
  echo "== 15. reset only, HTTPS keep-alive over HTTP/1.1 (expect decrypted, rolled per request:"
  echo "       ~half the requests the proxy sees reset; curl retries most of them on a new connection)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  reset_requests --cacert /certs/both-cas.crt
  stop_proxy
  expect_reset_retried
}

case_16() {
  local FAULT=(--fault-reset)
  echo "== 16. reset only, HTTPS over HTTP/2 (expect ~half 000 from a stream reset, the rest 200, on one connection)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  reset_requests --http2 --cacert /certs/both-cas.crt
  stop_proxy
  expect_reset_split
  expect "connections" "$(connections)" 1
}

case_17() {
  local FAULT=(--fault-reset)
  echo "== 17. reset only, HTTPS, a new connection per request (expect ~half 000, the rest 200, one connection per request)"
  start_proxy --upstream-ca-file certs/upstream-ca.crt
  reset_requests --cacert /certs/both-cas.crt -H 'Connection: close'
  stop_proxy
  expect_reset_split
  expect "connections" "$(connections)" "$REQUESTS"
}

case_18() {
  local URL=http://upstream.test/ FAULT=(--fault-reset)
  echo "== 18. reset only, plain HTTP keep-alive (expect rolled per request:"
  echo "       ~half the requests the proxy sees reset; curl retries most of them on a new connection)"
  start_proxy
  reset_requests
  stop_proxy
  expect_reset_retried
}

case_19() {
  local URL=http://upstream.test/ FAULT=(--fault-reset)
  echo "== 19. reset only, plain HTTP, a new connection per request (expect ~half 000, the rest 200, one connection per request)"
  start_proxy
  reset_requests -H 'Connection: close'
  stop_proxy
  expect_reset_split
  expect "connections" "$(connections)" "$REQUESTS"
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

  # reset only, over HTTPS and plain HTTP (both ports captured): rolled per
  # request; a selected request is reset, the others forwarded -> 000 / 200
  ./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 80,443 \
    --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
    --upstream-ca-file certs/upstream-ca.crt \
    --fault-hosts upstream.test --fault-reset --fault-probability 0.5 \
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

  # latency only: 10 requests over one keep-alive connection, each a 200 after 200ms
  # or at once
  docker exec https-lab-client-1 curl -s --http1.1 --cacert /certs/intercept-ca.crt -w '%{http_code} %{time_total}s new_connection=%{num_connects}\n' -o /dev/null 'https://upstream.test/[1-10]'

  # latency and a status: 10 requests over one keep-alive connection, each a 503
  # after 200ms or a 200 at once
  docker exec https-lab-client-1 curl -s --http1.1 --cacert /certs/intercept-ca.crt -w '%{http_code} %{time_total}s new_connection=%{num_connects}\n' -o /dev/null 'https://upstream.test/[1-10]'

  # reset only: 10 requests each over HTTPS keep-alive, HTTP/2 and plain HTTP,
  # each a 200 or a 000 with curl's exit code (curl retries a reset on a reused
  # HTTP/1.1 connection, so compare requests_faulted with requests_matched too)
  docker exec https-lab-client-1 curl -s --http1.1 --cacert /certs/both-cas.crt -w '%{http_code} exit=%{exitcode} new_connection=%{num_connects}\n' -o /dev/null 'https://upstream.test/[1-10]'
  docker exec https-lab-client-1 curl -s --http2 --cacert /certs/both-cas.crt -w '%{http_code} exit=%{exitcode} %{http_version}\n' -o /dev/null 'https://upstream.test/[1-10]'
  docker exec https-lab-client-1 curl -s -w '%{http_code} exit=%{exitcode} new_connection=%{num_connects}\n' -o /dev/null 'http://upstream.test/[1-10]'

  # trusting only the real upstream CA: fails (exit 60) while the proxy runs, since it answers the handshake
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
[[ ${#cases[@]} -gt 0 ]] || cases=(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19)
for c in "${cases[@]}"; do
  echo
  "case_$c"
  verdict "$c"
done
echo
if [[ ${#FAILED_CASES[@]} -eq 0 ]]; then
  echo "${GREEN}✓ all ${#cases[@]} cases as expected${RESET}"
else
  echo "${YELLOW}✗ not as expected: case ${FAILED_CASES[*]}${RESET}"
fi
echo "done; './run.sh down' removes the lab"
[[ ${#FAILED_CASES[@]} -eq 0 ]]
