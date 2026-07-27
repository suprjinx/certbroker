#!/usr/bin/env bash
# Generate the local key material the dev stack needs.
#
#   - bootstrap CA + a device bootstrap cert  (gates /simpleenroll)
#   - server TLS cert for the broker's mTLS listener
#
# The *device* CA is NOT generated here: re-enrollment is anchored on whatever
# CA actually issued the device certs, which in this stack is OpenBao's own PKI
# mount. provision-openbao.sh writes that one out.
#
# DEV ONLY. Real deployments get these from an existing PKI, not a shell script.
set -euo pipefail

OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pki"
mkdir -p "$OUT"
cd "$OUT"

# Keep private keys owner-readable from the moment they exist.
umask 077

echo "==> generating bootstrap CA"
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout bootstrap-ca.key -out bootstrap-ca.pem \
  -subj "/CN=certbroker dev bootstrap CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

echo "==> generating broker server cert (CN=certbroker, SAN: certbroker/localhost/127.0.0.1)"
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=certbroker" 2>/dev/null

# SAN must cover both the compose service name and localhost, so the same cert
# works from inside the network and from the host.
cat > server.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:certbroker,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA bootstrap-ca.pem -CAkey bootstrap-ca.key \
  -CAcreateserial -out server.pem -days 825 -sha256 -extfile server.ext 2>/dev/null

echo "==> generating a device bootstrap cert (CN=device01.example.com)"
openssl req -newkey rsa:2048 -nodes \
  -keyout device01.key -out device01.csr \
  -subj "/CN=device01.example.com/OU=devices" 2>/dev/null

# clientAuth EKU is required: est.VerifyPeer asks for it explicitly.
cat > device01.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:device01.example.com
EOF

openssl x509 -req -in device01.csr -CA bootstrap-ca.pem -CAkey bootstrap-ca.key \
  -CAcreateserial -out device01.pem -days 825 -sha256 -extfile device01.ext 2>/dev/null

rm -f server.csr server.ext device01.csr device01.ext

chmod 644 ./*.pem
chmod 600 ./*.key

# The broker container runs as uid 65532 (distroless :nonroot) and reads its TLS
# key over a bind mount, which preserves host ownership — so a mode that only
# the host user can read makes the container fail to start. Widening it is
# acceptable for throwaway dev material and is why this script is dev-only; a
# real deployment injects the key as a secret owned by the runtime uid instead.
chmod 644 server.key

echo
echo "wrote:"
ls -1 "$OUT"
echo
echo "NOTE: these are development credentials. Do not reuse them anywhere real."
