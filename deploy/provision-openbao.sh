#!/usr/bin/env sh
# Provision the dev OpenBao: PKI mount, an issuing role, and a least-privilege
# AppRole for the broker. Runs once, inside the openbao image (which carries the
# `bao` CLI), against a dev-mode server.
#
# Outputs to the shared volume for the broker to consume:
#   /shared/approle-secret-id   the AppRole SecretID
#   /shared/device-ca.pem       the CA that signs device certs -> re-enroll anchor
#
# DEV ONLY. A real deployment provisions OpenBao out of band, uses an
# intermediate signed by an offline root, and rotates the SecretID.
set -eu

: "${BAO_ADDR:?BAO_ADDR must be set}"
: "${BAO_TOKEN:?BAO_TOKEN must be set}"
export BAO_ADDR BAO_TOKEN

MOUNT="${PKI_MOUNT:-pki_int}"
ROLE="${PKI_ROLE:-device-role}"
APPROLE="${APPROLE_NAME:-certbroker}"
# Fixed so the broker's static config can reference it. OpenBao would otherwise
# generate a random RoleID that nothing could predict at config-authoring time.
ROLE_ID="${APPROLE_ROLE_ID:-certbroker-dev-role-id}"
SHARED="${SHARED_DIR:-/shared}"

echo "==> waiting for OpenBao at $BAO_ADDR"
i=0
until bao status >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "OpenBao did not become ready in time" >&2
    bao status || true
    exit 1
  fi
  sleep 1
done

# The whole script is idempotent so `docker compose up` can be re-run.
if bao secrets list -format=json | grep -q "\"${MOUNT}/\""; then
  echo "==> PKI mount ${MOUNT} already present"
else
  echo "==> enabling PKI at ${MOUNT}"
  bao secrets enable -path="${MOUNT}" pki
  bao secrets tune -max-lease-ttl=87600h "${MOUNT}"

  echo "==> generating the CA"
  # A self-signed root inside the mount is a dev shortcut. The broker's design
  # assumes this mount is an INTERMEDIATE authorized to issue leaves; nothing in
  # the broker depends on which it is, but production should sign this mount's
  # CSR with an offline root instead.
  bao write -field=certificate "${MOUNT}/root/generate/internal" \
    common_name="certbroker dev issuing CA" \
    issuer_name="certbroker-dev" \
    ttl=87600h > /dev/null

  bao write "${MOUNT}/config/urls" \
    issuing_certificates="${BAO_ADDR}/v1/${MOUNT}/ca" \
    crl_distribution_points="${BAO_ADDR}/v1/${MOUNT}/crl" > /dev/null
fi

echo "==> writing PKI role ${ROLE}"
# max_ttl matches the broker's policy.max_validity. Both layers enforce it:
# the broker constrains what it asks for, OpenBao caps what it will grant.
bao write "${MOUNT}/roles/${ROLE}" \
  allowed_domains="example.com" \
  allow_subdomains=true \
  allow_bare_domains=false \
  allow_localhost=false \
  allow_ip_sans=false \
  server_flag=true \
  client_flag=true \
  key_type=any \
  max_ttl=2160h \
  ttl=720h > /dev/null

echo "==> enabling approle auth"
bao auth list -format=json | grep -q '"approle/"' || bao auth enable approle

echo "==> writing the broker policy"
# Least privilege: sign/issue under this mount, and read the chain for /cacerts
# and the readiness probe. Nothing else — notably no ability to alter roles,
# read issued certs, or touch the CA key.
bao policy write certbroker - <<EOF > /dev/null
path "${MOUNT}/sign/${ROLE}" {
  capabilities = ["create", "update"]
}

path "${MOUNT}/issue/${ROLE}" {
  capabilities = ["create", "update"]
}

path "${MOUNT}/ca_chain" {
  capabilities = ["read"]
}
EOF

echo "==> writing approle ${APPROLE}"
bao write "auth/approle/role/${APPROLE}" \
  token_policies="certbroker" \
  token_ttl=20m \
  token_max_ttl=1h \
  secret_id_ttl=0 \
  secret_id_num_uses=0 > /dev/null

bao write "auth/approle/role/${APPROLE}/role-id" role_id="${ROLE_ID}" > /dev/null

echo "==> issuing a SecretID"
mkdir -p "${SHARED}"
bao write -f -field=secret_id "auth/approle/role/${APPROLE}/secret-id" > "${SHARED}/approle-secret-id"

echo "==> exporting the device CA (re-enrollment trust anchor)"
# Certs issued by this mount are the "device" identities, so this mount's CA is
# what /simplereenroll must verify client certs against.
bao read -field=certificate "${MOUNT}/cert/ca" > "${SHARED}/device-ca.pem"

# The broker container runs as uid 65532 and only reads these.
chmod 644 "${SHARED}/device-ca.pem"
chmod 644 "${SHARED}/approle-secret-id"

echo
echo "provisioning complete:"
echo "  mount:    ${MOUNT}"
echo "  role:     ${ROLE}"
echo "  role_id:  ${ROLE_ID}"
echo "  secret:   ${SHARED}/approle-secret-id"
echo "  ca:       ${SHARED}/device-ca.pem"
