#!/usr/bin/env sh
# Generates a self-signed certificate for web.test into ./certs, for nginx's
# TLS listener behind the PROXY protocol (clients connect with -k). Runs openssl
# in a container so macOS's LibreSSL is not involved.
set -eu
cd "$(dirname "$0")"
mkdir -p certs
docker run --rm -v "$PWD/certs:/w" -w /w --entrypoint sh alpine/openssl -euc '
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=web.test" \
  -addext "subjectAltName=DNS:web.test" -keyout server.key -out server.crt 2>/dev/null
chmod 644 server.key
'
echo "certificate written to $PWD/certs"
