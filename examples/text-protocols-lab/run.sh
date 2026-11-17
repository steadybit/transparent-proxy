#!/usr/bin/env bash
# Checks that, with every port captured (empty "Dependency Ports"), clients of
# dependencies the attack does NOT target are not delayed. The proxy reads a
# connection starting with an uppercase letter as a possible HTTP request until
# a blank line; text protocols that start that way but never send one (Redis
# inline commands, IRC, STOMP, SSH, the PROXY protocol before TLS) would be held for
# the 5s peek timeout on every connection. The attack is a latency on web.test
# at 0%: nothing should change for anyone.
#
#   ./run.sh            all cases
#   ./run.sh 4 8        only cases 4 and 8
#   ./run.sh --manual   start the lab without testing, and print the
#                       ./transparent-proxy command and clients to run by hand
#   ./run.sh shell      a shell in the client's network namespace, to run
#                       ./transparent-proxy in
#   ./run.sh down       remove the lab's containers
#
# PROXY_SRC (default ../.., this checkout) is the transparent-proxy source the
# proxy is built from, e.g. a worktree of a PR branch.
set -euo pipefail
cd "$(dirname "$0")"

PROXY_SRC=${PROXY_SRC:-../..}
SLOW_MS=1000 # a response slower than this was held by the proxy
PROBABILITY=0
PROXY=text-protocols-lab-proxy
dc() { docker compose "$@"; }

if [[ ${1:-} == down ]]; then
  docker rm -f "$PROXY" >/dev/null 2>&1 || true
  dc --profile proxy down --remove-orphans
  exit 0
fi

setup() {
  [[ -f certs/server.crt ]] || ./gen-certs.sh
  local arch src lab=$PWD
  arch=$(docker version -f '{{.Server.Arch}}')
  src=$(cd "$PROXY_SRC" && pwd)
  echo "building the linux proxy from $src ($(git -C "$src" log -1 --format='%h %s' 2>/dev/null || echo 'not a git checkout'))"
  (cd "$src" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$lab/bin/transparent-proxy" .)
  (cd probe && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o ../bin/probe .)
  dc --profile proxy build -q proxy client ssh
  # recreated every time, so they mount the freshly built binaries and config
  dc up -d --force-recreate web redis nats ssh lines client >/dev/null 2>&1
}

# Every port captured, as the extension does when "Dependency Ports" is empty.
CAPTURE=(--intercept-cidrs 0.0.0.0/0 --intercept-ports '')

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
    --fault-hosts web.test --fault-latency 200ms --fault-probability "$PROBABILITY" >/dev/null 2>&1
  for _ in $(seq 50); do
    if docker exec "$PROXY" iptables -t nat -S 2>/dev/null | grep -q SB_TP_REDIR; then return; fi
    sleep 0.2
  done
  echo "proxy did not install its capture:" >&2
  docker logs "$PROXY" >&2
  exit 1
}

# stop_proxy: stops the proxy (it tears its rules down) and prints its
# counters, keeping them in METRICS for the checks.
stop_proxy() {
  docker stop -t 10 "$PROXY" >/dev/null
  METRICS=$(docker logs "$PROXY" 2>&1 | grep '"proxy stopped"' || true)
  docker rm "$PROXY" >/dev/null
  printf '  proxy metrics:'
  for k in requests_matched requests_faulted latency_applied; do
    printf ' %s:%s' "$k" "$(metric "$k")"
  done
  echo
}

# metric <name>: the proxy's final value of a top-level counter.
metric() { grep -oE "\"$1\":[0-9]+" <<<"$METRICS" | head -1 | cut -d: -f2; }

# probe <args...>: runs the stopwatch in the client; its key=value line goes to LAST.
probe() {
  LAST=$(dc exec -T client probe "$@" 2>&1 || true)
  echo "  ${LABEL:-client}: $LAST"
}

# field <key>: a value from the probe's line.
field() { grep -oE "(^| )$1=[^ ]*" <<<"$LAST" | head -1 | cut -d= -f2; }

# The clients, each a probe run named by a key; case 0 runs them all without a
# proxy, the other cases one each through it. check_<key> states its result.
client_curl() { probe exec -- curl -s -o /dev/null -w '%{http_code}' http://web.test/; }
check_curl() { expect "status" "$(field out)" '"200"'; }
client_redis_cli() { probe exec -- redis-cli -h redis.test PING; }
check_redis_cli() { expect "reply" "$(field out)" '"PONG"'; }
client_redis_inline() { probe tcp -addr redis.test:6379 -send 'PING\r\n' -expect PONG; }
check_redis_inline() { expect "reply received" "$(field ok)" 1; }
client_nats() { probe exec -- nats --server nats://nats.test:4222 pub lab hello; }
check_nats() { expect "nats pub exit code" "$(field exit)" 0; }
client_nats_raw() { probe tcp -addr nats.test:4222 -send 'CONNECT {"verbose":false}\r\nPING\r\n' -expect PONG; }
check_nats_raw() { expect "PONG received" "$(field ok)" 1; }
client_proxy_http() { probe exec -- curl -s -o /dev/null -w '%{http_code}' --haproxy-protocol http://web.test:8080/; }
check_proxy_http() { expect "status" "$(field out)" '"200"'; }
client_proxy_tls() { probe exec -- curl -sk -o /dev/null -w '%{http_code}' --haproxy-protocol https://web.test:8443/; }
check_proxy_tls() { expect "status" "$(field out)" '"200"'; }
client_irc() { probe tcp -addr lines.test:7000 -send 'NICK lab\r\nUSER lab 0 * :lab\r\n' -expect 'OK NICK'; }
check_irc() { expect "reply received" "$(field ok)" 1; }
client_stomp() { probe tcp -addr lines.test:7000 -send 'CONNECT\naccept-version:1.2\nhost:web.test\n\n\x00' -expect 'OK CONNECT'; }
check_stomp() { expect "reply received" "$(field ok)" 1; }
client_stomp_crlf() { probe tcp -addr lines.test:7000 -send 'CONNECT\r\naccept-version:1.2\r\nhost:web.test\r\n\r\n\x00' -expect 'OK CONNECT'; }
check_stomp_crlf() { expect "reply received" "$(field ok)" 1; }

# ssh as a real client: it sends its banner at once, then fails to log in
# (no key), which takes the whole key exchange.
client_ssh() { probe exec -- ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 lab@ssh.test true; }
check_ssh() { expect "key exchange done, login refused" "$(grep -c 'Permission_denied' <<<"$LAST")" 1; }

CLIENTS=(curl redis_cli redis_inline nats nats_raw proxy_http proxy_tls irc stomp stomp_crlf ssh)

# Checks: each case states what it expects with expect*, and verdict reports the
# case green when it met every expectation, or each failed one in yellow.
FAILS=()
FAILED_CASES=()
if [[ -t 1 ]]; then GREEN=$'\e[32m' YELLOW=$'\e[33m' RESET=$'\e[0m'; else GREEN='' YELLOW='' RESET=''; fi

# expect <what> <actual> <expected>. A variant of a case sets CONTEXT to name it.
expect() { [[ $2 == "$3" ]] || FAILS+=("${CONTEXT:+$CONTEXT: }$1: got $2, expected $3"); }

# expect_fast: the client got its answer without being held.
expect_fast() {
  local ms
  ms=$(field ms)
  ((${ms:-99999} < SLOW_MS)) || FAILS+=("${CONTEXT:+$CONTEXT: }answered after ${ms}ms, expected under ${SLOW_MS}ms")
}

# through_proxy <client> <title>: one client through the proxy, which must
# neither delay it nor take it for a request to the targeted web.test.
through_proxy() {
  echo "$2"
  start_proxy
  "client_$1"
  stop_proxy
  "check_$1"
  expect_fast
  expect requests_matched "$(metric requests_matched)" 0
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
  echo "== 0. baseline, no proxy: every client (expect its answer, under ${SLOW_MS}ms)"
  revert_leftovers
  local c CONTEXT LABEL
  for c in "${CLIENTS[@]}"; do
    CONTEXT=$c LABEL=$c
    "client_$c"
    "check_$c"
    expect_fast
  done
}

case_1() {
  echo "== 1. HTTP to the targeted web.test, attack at 0% (expect 200 at once, the request matched)"
  start_proxy
  client_curl
  stop_proxy
  check_curl
  expect_fast
  expect requests_matched "$(metric requests_matched)" 1
  expect latency_applied "$(metric latency_applied)" 0
}

case_2() {
  local PROBABILITY=1
  echo "== 2. the same at 100%, to show the attack is live (expect 200 after ~200ms, latency applied)"
  start_proxy
  client_curl
  stop_proxy
  check_curl
  expect latency_applied "$(metric latency_applied)" 1
  local ms
  ms=$(field ms)
  ((ms >= 180)) || FAILS+=("answered after ${ms}ms, expected the 200ms latency")
}

case_3() { through_proxy redis_cli "== 3. redis-cli PING (RESP, starts with '*') (expect PONG at once)"; }
case_4() { through_proxy redis_inline "== 4. Redis inline command 'PING\\r\\n' (expect PONG at once)"; }
case_5() { through_proxy nats "== 5. nats CLI publish (server-first: INFO before CONNECT) (expect success at once)"; }
case_6() { through_proxy nats_raw "== 6. NATS 'CONNECT {...}' sent before reading INFO (expect PONG at once)"; }
case_7() { through_proxy proxy_http "== 7. curl --haproxy-protocol over HTTP: 'PROXY TCP4 ...' then a request (expect 200 at once)"; }
case_8() { through_proxy proxy_tls "== 8. curl --haproxy-protocol over TLS: 'PROXY TCP4 ...' then a ClientHello (expect 200 at once)"; }
case_9() { through_proxy irc "== 9. IRC-style 'NICK ...\\r\\nUSER ...\\r\\n' (expect an answer at once)"; }
case_10() { through_proxy stomp "== 10. STOMP CONNECT with LF line ends and 'host:web.test' (expect an answer at once, not matched)"; }
case_11() { through_proxy stomp_crlf "== 11. STOMP CONNECT with CRLF line ends and 'host:web.test' (expect an answer at once, not matched)"; }

case_12() { through_proxy ssh "== 12. ssh (both sides send their 'SSH-2.0-...' banner at connect) (expect the key exchange at once)"; }

print_manual() {
  cat <<'EOF2'
The lab is up, without a proxy. In one terminal open a shell in the client's
network namespace:

  ./run.sh shell

and run the proxy there, capturing every port, with a latency attack on
web.test at 0% (Ctrl-C stops it and logs its final metrics):

  ./transparent-proxy --intercept-cidrs 0.0.0.0/0 --intercept-ports '' \
    --fault-hosts web.test --fault-latency 200ms --fault-probability 0 \
    --metrics-addr 127.0.0.1:9090

In another terminal, the clients (each prints ms=<elapsed>):

  docker exec text-protocols-lab-client-1 probe exec -- redis-cli -h redis.test PING
  docker exec text-protocols-lab-client-1 probe tcp -addr redis.test:6379 -send 'PING\r\n' -expect PONG
  docker exec text-protocols-lab-client-1 probe exec -- nats --server nats://nats.test:4222 pub lab hello
  docker exec text-protocols-lab-client-1 probe exec -- curl -sk -o /dev/null -w '%{http_code}' --haproxy-protocol https://web.test:8443/
  docker exec text-protocols-lab-client-1 probe tcp -addr lines.test:7000 -send 'NICK lab\r\nUSER lab 0 * :lab\r\n' -expect 'OK NICK'
  docker exec text-protocols-lab-client-1 curl -s http://127.0.0.1:9090/

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
[[ ${#cases[@]} -gt 0 ]] || cases=(0 1 2 3 4 5 6 7 8 9 10 11 12)
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
