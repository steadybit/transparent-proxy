#!/usr/bin/env bash
# Checks how the proxy treats an HTTPS connection opened ahead of time
# (connection-pool warm-up, browser preconnect) that stays idle before its first
# request, while a latency attack at 0% runs with the interception CA: nothing
# should change for the client, and nothing should be reported as a rejected
# certificate. Cases 7-9 are genuine rejections, which must still be reported.
#
#   ./run.sh            all cases
#   ./run.sh 2 6        only cases 2 and 6
#   ./run.sh --manual   start the lab without testing, and print the
#                       ./transparent-proxy command and clients to run by hand
#   ./run.sh shell      a shell in the client's network namespace, to run
#                       ./transparent-proxy in
#   ./run.sh down       remove the lab's containers
#
# IDLE (default 15s) is how long a connection idles before its request: above
# the proxy's 10s first-request timeout. SHORT_IDLE (default 5s) stays below it.
set -euo pipefail
cd "$(dirname "$0")"

URL=https://upstream.test/
IDLE=${IDLE:-15s}
SHORT_IDLE=${SHORT_IDLE:-5s}
# The attack: latency at 0%, so every request is decrypted and forwarded
# untouched. Any difference from the baseline is the proxy's own doing.
FAULT=(--fault-hosts upstream.test --fault-latency 200ms --fault-probability "${PROBABILITY:-0}")
PROXY=preconnect-lab-proxy
dc() { docker compose "$@"; }

if [[ ${1:-} == down ]]; then
  docker rm -f "$PROXY" >/dev/null 2>&1 || true
  dc --profile proxy down --remove-orphans
  exit 0
fi

setup() {
  [[ -f certs/intercept-ca.crt ]] || ./gen-certs.sh
  echo "building the linux proxy and client binaries"
  local arch
  arch=$(docker version -f '{{.Server.Arch}}')
  (cd ../.. && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o examples/preconnect-lab/bin/transparent-proxy .)
  (cd client && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o ../bin/preconnect .)
  dc --profile proxy build -q proxy
  # nginx is recreated every time: a running one keeps the config it started
  # with, and its file mount can even pin the old file once an editor replaces it.
  dc up -d --force-recreate upstream
  # recreated too, so it mounts the freshly built client binary
  dc up -d --force-recreate client
}

CAPTURE=(--intercept-cidrs 0.0.0.0/0 --intercept-ports 443)

# revert_leftovers: stops a proxy this script started and clears any capture a
# killed proxy left behind (the next one's preflight refuses to stack on it).
revert_leftovers() {
  docker stop -t 10 "$PROXY" >/dev/null 2>&1 || true
  docker rm "$PROXY" >/dev/null 2>&1 || true
  dc run --rm -T proxy ./transparent-proxy --revert "${CAPTURE[@]}" >/dev/null 2>&1
}

# start_proxy: starts the proxy and waits for its iptables capture.
start_proxy() {
  revert_leftovers
  dc run -d -T --name "$PROXY" proxy ./transparent-proxy "${CAPTURE[@]}" \
    --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
    --upstream-ca-file certs/upstream-ca.crt "${FAULT[@]}" >/dev/null 2>&1
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
stop_proxy() {
  docker stop -t 10 "$PROXY" >/dev/null
  local logs
  logs=$(docker logs "$PROXY" 2>&1)
  docker rm "$PROXY" >/dev/null
  METRICS=$(grep '"proxy stopped"' <<<"$logs" || true)
  printf '  proxy metrics:'
  for k in requests_matched requests_faulted connections_aborted upstream_errors tls_intercept_rejected; do
    printf ' %s:%s' "$k" "$(metric "$k")"
  done
  echo
  # each warning's message, with the rejection stage and error when it has them
  WARNS=$(grep -E '"level":"WARN"' <<<"$logs" | awk '{
    line = ""
    while (match($0, /"(msg|stage|err)":"[^"]*"/)) {
      line = line (line == "" ? "" : " ") substr($0, RSTART, RLENGTH)
      $0 = substr($0, RSTART + RLENGTH)
    }
    print line
  }' || true)
  [[ -z $WARNS ]] || sort <<<"$WARNS" | uniq -c | sed 's/^/  warn: /'
}

# metric <name>: the proxy's final value of a top-level counter.
metric() { grep -oE "\"$1\":[0-9]+" <<<"$METRICS" | head -1 | cut -d: -f2; }

# preconnect <flags...>: runs the client once; its key=value line goes to LAST.
preconnect() {
  LAST=$(dc exec -T client preconnect -url "$URL" "$@" 2>&1 || true)
  echo "  client: $LAST"
}

# field <key>: a value from the client's line.
field() { grep -oE "(^| )$1=[^ ]*" <<<"$LAST" | head -1 | cut -d= -f2; }

# Checks: each case states what it expects with expect*, and verdict reports the
# case green when it met every expectation, or each failed one in yellow.
FAILS=()
FAILED_CASES=()
if [[ -t 1 ]]; then GREEN=$'\e[32m' YELLOW=$'\e[33m' RESET=$'\e[0m'; else GREEN='' YELLOW='' RESET=''; fi

# expect <what> <actual> <expected>. A variant of a case sets CONTEXT to name it.
expect() { [[ $2 == "$3" ]] || FAILS+=("${CONTEXT:+$CONTEXT: }$1: got $2, expected $3"); }

ca_warnings() { grep -c 'is the CA trusted' <<<"$WARNS" || true; }

# expect_untouched [requests]: the idle connection got its 200 as if no proxy
# ran: not closed while idle, not retried, nothing reported as a rejection.
expect_untouched() {
  expect "response" "$(field result)" 200
  expect "idle connection closed by the peer after" "$(field closed_after)" -
  expect "retried on a new connection" "$(field retried)" 0
  expect requests_matched "$(metric requests_matched)" "${1:-1}"
  expect tls_intercept_rejected "$(metric tls_intercept_rejected)" 0
  expect "'is the CA trusted' warnings" "$(ca_warnings)" 0
}

# expect_rejected: a client that does not trust the interception CA is
# reported, once, as rejecting it.
expect_rejected() {
  expect "response" "$(field result)" 000
  expect requests_matched "$(metric requests_matched)" 0
  expect tls_intercept_rejected "$(metric tls_intercept_rejected)" 1
  expect "'is the CA trusted' warnings" "$(ca_warnings)" 1
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

case_0() {
  echo "== 0. baseline, no proxy: connections idle $IDLE before their request (expect 200, never closed by nginx)"
  local CONTEXT
  for p in h1 h2 h2-lazy; do
    CONTEXT=$p
    preconnect -proto "$p" -idle "$IDLE" -cacert /certs/upstream-ca.crt
    expect "response" "$(field result)" 200
    expect "idle connection closed by the peer after" "$(field closed_after)" -
  done
}

case_1() {
  echo "== 1. HTTP/1.1, idle $SHORT_IDLE before the first request, below the proxy's 10s (expect 200, no rejection)"
  start_proxy
  preconnect -proto h1 -idle "$SHORT_IDLE" -cacert /certs/intercept-ca.crt
  stop_proxy
  expect_untouched
}

case_2() {
  echo "== 2. HTTP/1.1, idle $IDLE before the first request (expect as without a proxy: 200, not closed, no rejection)"
  start_proxy
  preconnect -proto h1 -idle "$IDLE" -cacert /certs/intercept-ca.crt
  stop_proxy
  expect_untouched
}

case_3() {
  echo "== 3. as case 2, with a client that retries a failed request on a new connection"
  echo "      (expect 200 on the first try; a silent reconnect would still hide a rejection count)"
  start_proxy
  preconnect -proto h1 -idle "$IDLE" -retry -cacert /certs/intercept-ca.crt
  stop_proxy
  expect_untouched
}

case_4() {
  echo "== 4. HTTP/1.1, one request, then idle $IDLE before the second on the same connection (expect 200, not closed)"
  start_proxy
  preconnect -proto h1 -idle "$IDLE" -warm -cacert /certs/intercept-ca.crt
  stop_proxy
  expect_untouched 2
}

case_5() {
  echo "== 5. HTTP/2, preface sent at connect, idle $IDLE before the first request (expect 200, not closed, no rejection)"
  start_proxy
  preconnect -proto h2 -idle "$IDLE" -cacert /certs/intercept-ca.crt
  stop_proxy
  expect_untouched
}

case_6() {
  echo "== 6. HTTP/2, only the TLS handshake ahead of time, preface and request after $IDLE (expect 200, not closed, no rejection)"
  start_proxy
  preconnect -proto h2-lazy -idle "$IDLE" -cacert /certs/intercept-ca.crt
  stop_proxy
  expect_untouched
}

case_7() {
  echo "== 7. Go client does not trust the interception CA, TLS 1.3 (expect one rejection)"
  start_proxy
  preconnect -proto h1 -idle 0s -cacert /certs/upstream-ca.crt
  stop_proxy
  expect_rejected
}

case_8() {
  echo "== 8. Go client does not trust the interception CA, TLS 1.2 (expect one rejection)"
  start_proxy
  preconnect -proto h1 -idle 0s -tls12 -cacert /certs/upstream-ca.crt
  stop_proxy
  expect_rejected
}

case_9() {
  echo "== 9. curl (OpenSSL) does not trust the interception CA (expect one rejection)"
  start_proxy
  LAST="result=$(dc exec -T client curl -s -o /dev/null -w '%{http_code}' --cacert /certs/upstream-ca.crt "$URL" || true)"
  echo "  client: $LAST"
  stop_proxy
  expect_rejected
}

print_manual() {
  cat <<EOF2
The lab is up, without a proxy. In one terminal open a shell in the client's
network namespace:

  ./run.sh shell

and run the proxy there, as a latency attack at 0% (Ctrl-C stops it, removes its
iptables rules and logs its final metrics):

  ./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports 443 \\
    --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \\
    --upstream-ca-file certs/upstream-ca.crt \\
    --fault-hosts upstream.test --fault-latency 200ms --fault-probability 0 \\
    --metrics-addr 127.0.0.1:9090

In another terminal, the client (-proto h1|h2|h2-lazy, -idle, -warm, -retry, -tls12):

  # a connection opened ahead of time, idle 15s before its request
  docker exec preconnect-lab-client-1 preconnect -proto h1 -idle 15s -cacert /certs/intercept-ca.crt

  # the same, retrying on a new connection when the idle one fails
  docker exec preconnect-lab-client-1 preconnect -proto h1 -idle 15s -retry -cacert /certs/intercept-ca.crt

  # a genuine rejection: the client does not trust the interception CA
  docker exec preconnect-lab-client-1 preconnect -proto h1 -idle 0s -cacert /certs/upstream-ca.crt

  # the proxy's live metrics (loopback is never captured)
  docker exec preconnect-lab-client-1 curl -s http://127.0.0.1:9090/

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

cases=("$@")
setup
[[ ${#cases[@]} -gt 0 ]] || cases=(0 1 2 3 4 5 6 7 8 9)
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
