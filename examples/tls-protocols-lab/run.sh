#!/usr/bin/env bash
# Checks that HTTPS interception leaves non-HTTP TLS alone: with the interception
# CA configured and every port captured (empty "Dependency Ports"), a latency
# attack on upstream.test must delay MQTT over TLS to that same hostname, not
# break it, while HTTPS to it is still delayed per request.
#
#   ./run.sh            all cases
#   ./run.sh 2 9        only cases 2 and 9
#   ./run.sh -n 40 4    40 requests/connections per batch instead of 20 (or REQUESTS=40)
#   ./run.sh --manual   start the lab without testing, and print the
#                       ./transparent-proxy command and clients to run by hand
#   ./run.sh shell      a shell in the client's network namespace, to run
#                       ./transparent-proxy in
#   ./run.sh down       remove the lab's containers
#
# PROXY_SRC (default ../..: this working tree) is the source the proxy is built
# from, so the same cases run against another branch's worktree, e.g.
#   PROXY_SRC=../../../transparent-proxy.worktrees/tls-protocols-lab-pr15 ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

PROXY_SRC=${PROXY_SRC:-../..}
REQUESTS=${REQUESTS:-20}
PROBABILITY=${PROBABILITY:-0.5} # the "50%" cases; the "0%" cases always use 0
HOSTS=upstream.test,broker.test
PROXY=tls-protocols-lab-proxy
dc() { docker compose "$@"; }

if [[ ${1:-} == down ]]; then
  docker rm -f "$PROXY" >/dev/null 2>&1 || true
  dc --profile proxy down --remove-orphans
  exit 0
fi

setup() {
  [[ -f certs/intercept-ca.crt ]] || ./gen-certs.sh
  echo "building the linux proxy binary from $PROXY_SRC ($(git -C "$PROXY_SRC" log --oneline -1))"
  local arch out
  arch=$(docker version -f '{{.Server.Arch}}')
  out=$PWD/bin/transparent-proxy
  mkdir -p bin
  (cd "$PROXY_SRC" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$out" .)
  dc --profile proxy build -q proxy client
  # recreated every time: a running server keeps the config it started with
  dc up -d --force-recreate upstream mqtt broker
  dc up -d client
  # a proxy left by an interrupted run would still be capturing the client's
  # traffic, the baseline included
  revert_leftovers
}

# Every port captured, as the extension does with "Dependency Ports" empty.
CAPTURE=(--intercept-cidrs 0.0.0.0/0)

# revert_leftovers: stops a proxy this script started and clears any capture a
# killed proxy left behind (the next one's preflight refuses to stack on it).
revert_leftovers() {
  docker stop -t 10 "$PROXY" >/dev/null 2>&1 || true
  docker rm "$PROXY" >/dev/null 2>&1 || true
  dc run --rm -T proxy ./transparent-proxy --revert "${CAPTURE[@]}" >/dev/null 2>&1
}

# An interrupted run (Ctrl-C, a failed command under set -e) must not leave its
# proxy capturing the client's traffic for the next run.
trap 'revert_leftovers' EXIT

# start_proxy <probability> <fault flags...>: starts the proxy and waits for
# its iptables capture.
start_proxy() {
  local p=$1
  shift
  revert_leftovers
  dc run -d -T --name "$PROXY" proxy ./transparent-proxy "${CAPTURE[@]}" \
    --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
    --upstream-ca-file certs/upstream-ca.crt \
    --fault-hosts "$HOSTS" --fault-probability "$p" "$@" >/dev/null 2>&1
  for _ in $(seq 50); do
    if docker exec "$PROXY" iptables -t nat -S 2>/dev/null | grep -q SB_TP_REDIR; then return; fi
    sleep 0.2
  done
  echo "proxy did not install its capture:" >&2
  docker logs "$PROXY" >&2
  exit 1
}

# stop_proxy: stops the proxy (it tears its rules down) and prints its counters
# and warnings, keeping them in METRICS and WARNS for the checks.
stop_proxy() {
  docker stop -t 10 "$PROXY" >/dev/null
  local logs
  logs=$(docker logs "$PROXY" 2>&1)
  docker rm "$PROXY" >/dev/null
  METRICS=$(grep '"proxy stopped"' <<<"$logs" || true)
  printf '  proxy metrics:'
  for k in connections_matched requests_matched latency_applied requests_faulted connections_aborted tls_intercept_rejected; do
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

# mqtt_batch <mosquitto_pub flags...>: $REQUESTS publishes at QoS 1, each on a
# connection of its own, timed inside the client container (docker exec's own
# overhead would hide 200ms). LAST keeps one "<exit code> <ms>" line per
# connection. mosquitto_pub at QoS 1 takes ~1050ms here however fast the broker
# is (its network loop), so a connection that took the 200ms latency takes
# ~1250ms; MQTT_LATE sits in between.
MQTT_LATE=${MQTT_LATE:-1150}
mqtt_batch() {
  LAST=$(dc exec -T client sh -c '
    n=$1; shift
    for _ in $(seq "$n"); do
      s=$(date +%s%3N)
      mosquitto_pub --cafile /certs/both-cas.crt -t lab -m hi -q 1 "$@" >/dev/null 2>&1
      e=$?
      echo "$e $(( $(date +%s%3N) - s ))"
    done' sh "$REQUESTS" "$@")
  awk -v late="$MQTT_LATE" '{ if ($1 == 0) print "ok", ($2 >= late ? "after ~200ms" : "at once"); else print "failed, exit " $1, "after ~" int($2 / 1000 + 0.5) "s"; if ($2 > max) max = $2 }
    END { print "slowest: " max "ms" }' <<<"$LAST" | sort | uniq -c | sed 's/^/  /'
}

# curl_batch <write-out> <curl flags...>: $REQUESTS requests over ONE curl
# invocation, so they share a keep-alive connection; LAST keeps <write-out>
# per response.
curl_batch() {
  local fmt=$1 url=$2 args=()
  shift 2
  for _ in $(seq "$REQUESTS"); do args+=(-o /dev/null "$url"); done
  LAST=$(dc exec -T client curl -s -w "$fmt\n" --http1.1 --cacert /certs/both-cas.crt "$@" "${args[@]}" || true)
}

LATE=0.18 # seconds; an HTTPS response this slow took the injected 200ms latency

# timed_requests <url> <curl flags...>: tallies the responses by status and
# whether they took the latency; LAST is "<code> <seconds> <connections>".
timed_requests() {
  curl_batch '%{http_code} %{time_total} %{num_connects}' "$@"
  awk -v late="$LATE" '{ print $1, ($2 >= late ? "after ~200ms" : "at once"); conns += $3 } END { print "connections opened: " conns }' <<<"$LAST" |
    sort | uniq -c | sed 's/^/  /'
}

# reset_requests <url> <curl flags...>: each request on a new connection,
# tallied by status and curl's exit code (000: no response).
reset_requests() {
  curl_batch '%{http_code} curl_exit=%{exitcode}' "$@" -H 'Connection: close'
  sort <<<"$LAST" | uniq -c | sed 's/^/  /'
}

# Checks: each case states what it expects with expect*, and verdict reports the
# case green when it met every expectation, or each failed one in yellow.
FAILS=()
FAILED_CASES=()
if [[ -t 1 ]]; then GREEN=$'\e[32m' YELLOW=$'\e[33m' RESET=$'\e[0m'; else GREEN='' YELLOW='' RESET=''; fi

# expect <what> <actual> <expected>. A variant of a case sets CONTEXT to name it.
expect() { [[ $2 == "$3" ]] || FAILS+=("${CONTEXT:+$CONTEXT: }$1: got $2, expected $3"); }

# count <awk condition>: the lines of LAST that meet it.
count() { awk -v late="$LATE" -v mlate="$MQTT_LATE" "$1"' { n++ } END { print n + 0 }' <<<"$LAST"; }

expect_all() { expect "$1" "$(count "$2") of $REQUESTS" "$REQUESTS of $REQUESTS"; }

# expect_about_half <what> <awk condition>: within 3 standard deviations of
# half, so a working proxy misses it about 0.3% of the time.
expect_about_half() {
  local n d
  n=$(count "$2")
  d=$((2 * n - REQUESTS))
  ((d * d <= 9 * REQUESTS)) || FAILS+=("${CONTEXT:+$CONTEXT: }$1: got $n of $REQUESTS, expected about half")
}

ca_warnings() { grep -c 'is the CA trusted' <<<"$WARNS" || true; }

# expect_mqtt_untouched: every MQTT connection succeeded at once, was spliced
# through (never decrypted), and nothing was reported as a rejection.
expect_mqtt_untouched() {
  expect_all "MQTT connections succeeding" '$1 == 0'
  expect_all "MQTT connections not delayed" '$2 < mlate'
  expect_mqtt_spliced
}

# expect_mqtt_delayed_per_connection: every MQTT connection succeeded, about
# half of them delayed, each delay counted once.
expect_mqtt_delayed_per_connection() {
  expect_all "MQTT connections succeeding" '$1 == 0'
  expect_about_half "MQTT connections delayed ~200ms" '$1 == 0 && $2 >= mlate'
  expect latency_applied "$(metric latency_applied)" "$(count '$1 == 0 && $2 >= mlate')"
  expect_mqtt_spliced
}

expect_mqtt_spliced() {
  expect "requests_matched (decrypted requests)" "$(metric requests_matched)" 0
  expect tls_intercept_rejected "$(metric tls_intercept_rejected)" 0
  expect "'is the CA trusted' warnings" "$(ca_warnings)" 0
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
  echo "== 0. baseline, no proxy (expect every client to succeed, MQTT under ${MQTT_LATE}ms, HTTPS at once)"
  local CONTEXT
  for v in "upstream.test:8883 no ALPN|-h upstream.test -p 8883" \
    "upstream.test:8883 ALPN mqtt|-h upstream.test -p 8883 --tls-alpn mqtt" \
    "broker.test:443 no ALPN|-h broker.test -p 443" \
    "broker.test:443 ALPN x-amzn-mqtt-ca|-h broker.test -p 443 --tls-alpn x-amzn-mqtt-ca"; do
    CONTEXT="MQTT ${v%%|*}"
    echo "  $CONTEXT:"
    # shellcheck disable=SC2086
    mqtt_batch ${v#*|}
    expect_all "connections succeeding" '$1 == 0'
    expect_all "connections under ${MQTT_LATE}ms" '$2 < mlate'
  done
  for v in "https://upstream.test/|" "https://upstream.test:8443/|--no-alpn"; do
    CONTEXT="HTTPS ${v%%|*} ${v#*|}"
    echo "  $CONTEXT:"
    # shellcheck disable=SC2086
    timed_requests "${v%%|*}" ${v#*|}
    expect_all "responses 200 at once" '$1 == 200 && $2 < late'
  done
}

case_1() {
  echo "== 1. control: HTTPS to upstream.test:443, latency at 50% (expect decrypted, ~half the requests on one connection delayed)"
  start_proxy "$PROBABILITY" --fault-latency 200ms
  timed_requests https://upstream.test/
  stop_proxy
  expect_all "responses 200" '$1 == 200'
  expect_about_half "responses after ~200ms" '$2 >= late'
  expect requests_matched "$(metric requests_matched)" "$REQUESTS"
  expect latency_applied "$(metric latency_applied)" "$(count '$2 >= late')"
}

case_2() {
  echo "== 2. MQTT over TLS to upstream.test:8883, no ALPN, latency at 0% (expect untouched)"
  start_proxy 0 --fault-latency 200ms
  mqtt_batch -h upstream.test -p 8883
  stop_proxy
  expect_mqtt_untouched
}

case_3() {
  echo "== 3. MQTT over TLS to upstream.test:8883, ALPN mqtt, latency at 0% (expect untouched)"
  start_proxy 0 --fault-latency 200ms
  mqtt_batch -h upstream.test -p 8883 --tls-alpn mqtt
  stop_proxy
  expect_mqtt_untouched
}

case_4() {
  echo "== 4. MQTT over TLS to upstream.test:8883, no ALPN, latency at 50% (expect all succeed, ~half the connections delayed)"
  start_proxy "$PROBABILITY" --fault-latency 200ms
  mqtt_batch -h upstream.test -p 8883
  stop_proxy
  expect_mqtt_delayed_per_connection
}

case_5() {
  echo "== 5. MQTT over TLS to upstream.test:8883, ALPN mqtt, latency at 50% (expect all succeed, ~half the connections delayed)"
  start_proxy "$PROBABILITY" --fault-latency 200ms
  mqtt_batch -h upstream.test -p 8883 --tls-alpn mqtt
  stop_proxy
  expect_mqtt_delayed_per_connection
}

case_6() {
  echo "== 6. HTTPS without ALPN to upstream.test:443, latency at 50% (expect still decrypted: ~half the requests on one connection delayed)"
  start_proxy "$PROBABILITY" --fault-latency 200ms
  timed_requests https://upstream.test/ --no-alpn
  stop_proxy
  expect_all "responses 200" '$1 == 200'
  expect_about_half "responses after ~200ms" '$2 >= late'
  expect requests_matched "$(metric requests_matched)" "$REQUESTS"
}

case_7() {
  echo "== 7. trade-off: HTTPS without ALPN to upstream.test:8443, latency at 50% (reported, not checked:"
  echo "      decrypted and delayed per request, or spliced and delayed per connection)"
  start_proxy "$PROBABILITY" --fault-latency 200ms
  timed_requests https://upstream.test:8443/ --no-alpn
  stop_proxy
  expect_all "responses 200" '$1 == 200'
  if [[ $(metric requests_matched) -gt 0 ]]; then
    echo "  mode: decrypted, the latency rolled per request ($(metric latency_applied) of $REQUESTS delayed)"
  else
    echo "  mode: spliced through, the latency rolled once for the connection ($(metric latency_applied) of 1 connection delayed)"
  fi
}

case_8() {
  echo "== 8. limitation: MQTT over TLS to broker.test:443, no ALPN, latency at 0% (reported, not checked:"
  echo "      no ALPN on 443 is taken as HTTPS by the ALPN guard, so it is decrypted)"
  start_proxy 0 --fault-latency 200ms
  mqtt_batch -h broker.test -p 443
  stop_proxy
  echo "  outcome: $(count '$1 == 0') of $REQUESTS MQTT connections succeeded, $(metric tls_intercept_rejected) reported as rejections"
}

case_9() {
  echo "== 9. MQTT over TLS to broker.test:443, ALPN x-amzn-mqtt-ca (as AWS IoT Core on 443), latency at 0% (expect untouched)"
  start_proxy 0 --fault-latency 200ms
  mqtt_batch -h broker.test -p 443 --tls-alpn x-amzn-mqtt-ca
  stop_proxy
  expect_mqtt_untouched
}

case_10() {
  echo "== 10. reference: plain HTTP reset at 50%, a new connection per request (how a reset reads: ~half 000 with curl exit 56)"
  start_proxy "$PROBABILITY" --fault-reset
  reset_requests http://upstream.test/
  stop_proxy
  expect_all "responses 200 or 000" '$1 == 200 || $1 == "000"'
  expect_about_half "000 responses" '$1 == "000"'
  expect_all "000 responses read as a connection reset (curl exit 56)" '$1 == 200 || $2 == "curl_exit=56"'
}

case_11() {
  echo "== 11. HTTPS reset at 50% over HTTP/1.1, a new connection per request (expect as plain HTTP: ~half 000 with curl exit 56)"
  start_proxy "$PROBABILITY" --fault-reset
  reset_requests https://upstream.test/
  stop_proxy
  expect_all "responses 200 or 000" '$1 == 200 || $1 == "000"'
  expect_about_half "000 responses" '$1 == "000"'
  expect_all "000 responses read as a connection reset (curl exit 56)" '$1 == 200 || $2 == "curl_exit=56"'
  expect requests_faulted "$(metric requests_faulted)" "$(count '$1 == "000"')"
}

print_manual() {
  cat <<'EOF2'
The lab is up, without a proxy. In one terminal open a shell in the client's
network namespace:

  ./run.sh shell

and run the proxy there, capturing every port (Ctrl-C stops it, removes its
iptables rules and logs its final metrics):

  ./transparent-proxy --intercept-cidrs 0.0.0.0/0 \
    --tls-ca-cert certs/intercept-ca.crt --tls-ca-key certs/intercept-ca.key \
    --upstream-ca-file certs/upstream-ca.crt \
    --fault-hosts upstream.test,broker.test --fault-latency 200ms --fault-probability 0 \
    --metrics-addr 127.0.0.1:9090

In another terminal, the client:

  # MQTT over TLS to the HTTPS hostname, without and with ALPN
  docker exec tls-protocols-lab-client-1 mosquitto_pub -h upstream.test -p 8883 --cafile /certs/both-cas.crt -t lab -m hi -q 1 -d
  docker exec tls-protocols-lab-client-1 mosquitto_pub -h upstream.test -p 8883 --tls-alpn mqtt --cafile /certs/both-cas.crt -t lab -m hi -q 1 -d

  # MQTT over TLS on 443, without and with ALPN
  docker exec tls-protocols-lab-client-1 mosquitto_pub -h broker.test -p 443 --cafile /certs/both-cas.crt -t lab -m hi -q 1 -d
  docker exec tls-protocols-lab-client-1 mosquitto_pub -h broker.test -p 443 --tls-alpn x-amzn-mqtt-ca --cafile /certs/both-cas.crt -t lab -m hi -q 1 -d

  # HTTPS, with and without ALPN, on 443 and 8443 (issuer: the interception CA when decrypted)
  docker exec tls-protocols-lab-client-1 curl -sv -o /dev/null --cacert /certs/both-cas.crt https://upstream.test/ 2>&1 | grep -E 'issuer:|ALPN'
  docker exec tls-protocols-lab-client-1 curl -sv -o /dev/null --no-alpn --cacert /certs/both-cas.crt https://upstream.test:8443/ 2>&1 | grep -E 'issuer:|ALPN'

  # the proxy's live metrics (loopback is never captured)
  docker exec tls-protocols-lab-client-1 curl -s http://127.0.0.1:9090/

Tear down: ./run.sh down
EOF2
}

case ${1:-} in
  --manual)
    setup
    trap - EXIT
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
[[ ${#cases[@]} -gt 0 ]] || cases=(0 1 2 3 4 5 6 7 8 9 10 11)
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
