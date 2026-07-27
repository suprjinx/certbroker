#!/usr/bin/env bash
# End-to-end EST exercise against the running dev stack: /cacerts, then
# /simpleenroll with a bootstrap client cert, then /simplereenroll using the
# certificate that enrollment just produced.
#
# Requires the stack to be up (make dev-up) plus curl and openssl.
set -euo pipefail

BASE="${BASE:-https://localhost:8443/.well-known/est}"
PKI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pki"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CN="${CN:-device01.example.com}"

# The broker's server cert is signed by the dev bootstrap CA.
CURL=(curl --silent --show-error --fail-with-body --cacert "$PKI/bootstrap-ca.pem")

# p7_to_pem base64-PKCS#7 on stdin -> certificate PEM on stdout.
p7_to_pem() {
  { echo "-----BEGIN PKCS7-----"; cat; echo "-----END PKCS7-----"; } |
    openssl pkcs7 -print_certs -outform PEM
}

echo "==> [1/4] GET /cacerts"
"${CURL[@]}" "$BASE/cacerts" | p7_to_pem > "$WORK/cacerts.pem"
echo "    CA chain:"
openssl crl2pkcs7 -nocrl -certfile "$WORK/cacerts.pem" 2>/dev/null |
  openssl pkcs7 -print_certs -noout | sed 's/^/      /' | grep -v '^ *$'

echo
echo "==> [2/4] generating a device key and CSR (CN=$CN)"
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/device.key" \
  -out "$WORK/device.csr" -subj "/CN=$CN" 2>/dev/null
openssl req -in "$WORK/device.csr" -outform DER -out "$WORK/device.der" 2>/dev/null

echo
echo "==> [3/4] POST /simpleenroll (bootstrap client cert)"
base64 -w0 < "$WORK/device.der" > "$WORK/device.b64"
"${CURL[@]}" \
  --cert "$PKI/device01.pem" --key "$PKI/device01.key" \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  --data-binary "@$WORK/device.b64" \
  "$BASE/simpleenroll" | p7_to_pem > "$WORK/issued.pem"

echo "    issued:"
openssl x509 -in "$WORK/issued.pem" -noout -subject -issuer -dates -ext subjectAltName |
  sed 's/^/      /'

echo
echo "==> [4/4] POST /simplereenroll (using the certificate just issued)"
# Re-enrollment is verified against the DEVICE trust anchor, not the bootstrap
# one — this step is what proves the two anchors are wired up separately.
openssl req -new -key "$WORK/device.key" -out "$WORK/renew.csr" -subj "/CN=$CN" 2>/dev/null
openssl req -in "$WORK/renew.csr" -outform DER -out "$WORK/renew.der" 2>/dev/null
base64 -w0 < "$WORK/renew.der" > "$WORK/renew.b64"

"${CURL[@]}" \
  --cert "$WORK/issued.pem" --key "$WORK/device.key" \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  --data-binary "@$WORK/renew.b64" \
  "$BASE/simplereenroll" | p7_to_pem > "$WORK/renewed.pem"

echo "    renewed:"
openssl x509 -in "$WORK/renewed.pem" -noout -subject -issuer -dates |
  sed 's/^/      /'

echo
echo "enroll + re-enroll succeeded"
