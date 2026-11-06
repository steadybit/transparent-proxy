#!/usr/bin/env sh
# Generates the lab's two private CAs and the upstream server certificate into
# ./certs. Runs openssl in a container so macOS's LibreSSL is not involved.
#
#   intercept-ca  — the proxy mints per-SNI leaves with it; the client trusts it.
#   upstream-ca   — signs the upstream server's certificate; only the proxy is
#                   told about it (--upstream-ca-file).
set -eu
cd "$(dirname "$0")"
mkdir -p certs
docker run --rm -v "$PWD/certs:/w" -w /w --entrypoint sh alpine/openssl -euc '
gen_ca() {
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$1.key" -out "$1.crt" 2>/dev/null
}
gen_ca intercept-ca "HTTPS Lab Interception CA"
gen_ca upstream-ca  "HTTPS Lab Upstream CA"

openssl req -newkey rsa:2048 -nodes -subj "/CN=upstream.test" \
  -keyout server.key -out server.csr 2>/dev/null
printf "subjectAltName=DNS:upstream.test\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA upstream-ca.crt -CAkey upstream-ca.key \
  -CAcreateserial -days 30 -extfile server.ext -out server.crt 2>/dev/null
rm -f server.csr server.ext upstream-ca.srl
chmod 644 *.key
'
echo "certificates written to $PWD/certs"
