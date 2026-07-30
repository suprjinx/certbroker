#!/usr/bin/env bash
# Interop run against the broker using globalsign/est's estclient — an
# independent RFC 7030 implementation.
#
# Exercises the happy path (cacerts -> enroll -> reenroll) and then the cases a
# real switch would hit: an unauthorized CN, and HTTP Basic credentials, which
# the broker does not implement. See docs/runbook.md "EST client interop".
set -uo pipefail

SERVER="${SERVER:-certbroker:8443}"
PKI="${PKI:-/pki}"
CN="${CN:-device01.example.com}"
APS="${APS:-}"                      # EST label / additional path segment
# Set when the broker runs with policy.allow_unauthenticated_enrollment: true,
# so step 7 expects the enrollment to succeed rather than be refused.
EXPECT_OPEN="${EXPECT_OPEN:-0}"
W=/tmp/est
mkdir -p "$W"

pass=0
fail=0
gap=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail + 1)); }
note() { printf '  \033[33mNOTE\033[0m %s\n' "$1"; }
hdr()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

# est runs estclient with the shared anchor + APS options, retrying once after a
# pause if the broker rate-limits us. Without this the negative cases below can
# "pass" on a 429 rather than on the authorization decision they mean to check.
est() {
  local op="$1"; shift
  local out rc
  for attempt in 1 2; do
    if [ -n "$APS" ]; then
      out=$(estclient "$op" -server "$SERVER" -explicit "$PKI/bootstrap-ca.pem" -aps "$APS" "$@" 2>&1); rc=$?
    else
      out=$(estclient "$op" -server "$SERVER" -explicit "$PKI/bootstrap-ca.pem" "$@" 2>&1); rc=$?
    fi
    if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qi 'rate limit'; then
      sleep 8
      continue
    fi
    break
  done
  printf '%s' "$out" > "$W/err"
  return $rc
}

# rate_limited reports whether the last est call died on the limiter rather than
# on a policy decision.
rate_limited() { grep -qi 'rate limit' "$W/err"; }

echo "EST interop: server=$SERVER cn=$CN aps=${APS:-<none>}"
echo "client: $(estclient version 2>&1 | head -1)"

# --- 1. /cacerts -------------------------------------------------------------
hdr "1. cacerts"
if est cacerts -out "$W/cacerts.pem"; then
  subj=$(openssl x509 -in "$W/cacerts.pem" -noout -subject 2>/dev/null)
  ok "retrieved CA chain — ${subj:-unparseable}"
else
  bad "cacerts: $(tr -d '\n' < "$W/err")"
fi

# --- 2. device key + CSR -----------------------------------------------------
hdr "2. generate device key and CSR"
openssl req -newkey rsa:2048 -nodes -keyout "$W/device.key" -out "$W/device.csr" \
  -subj "/CN=$CN" >/dev/null 2>&1 \
  && ok "key + CSR for CN=$CN" || bad "openssl CSR generation"

# --- 3. /simpleenroll with the bootstrap client certificate ------------------
hdr "3. simpleenroll (mTLS bootstrap certificate)"
if est enroll -certs "$PKI/device01.pem" -key "$PKI/device01.key" \
       -csr "$W/device.csr" -out "$W/issued.pem"; then
  ok "issued: $(openssl x509 -in "$W/issued.pem" -noout -subject 2>/dev/null)"
  note "issuer:  $(openssl x509 -in "$W/issued.pem" -noout -issuer 2>/dev/null)"
  note "SANs:    $(openssl x509 -in "$W/issued.pem" -noout -ext subjectAltName 2>/dev/null | tail -1 | xargs)"
else
  bad "enroll: $(tr -d '\n' < "$W/err")"
fi

# --- 4. /simplereenroll with the certificate just issued ---------------------
hdr "4. simplereenroll (using the issued certificate)"
if [ -s "$W/issued.pem" ]; then
  openssl req -new -key "$W/device.key" -out "$W/renew.csr" -subj "/CN=$CN" >/dev/null 2>&1
  if est reenroll -certs "$W/issued.pem" -key "$W/device.key" \
         -csr "$W/renew.csr" -out "$W/renewed.pem"; then
    ok "renewed: $(openssl x509 -in "$W/renewed.pem" -noout -subject -serial 2>/dev/null | tr '\n' ' ')"
  else
    bad "reenroll: $(tr -d '\n' < "$W/err")"
  fi
else
  bad "reenroll skipped — no issued certificate"
fi

# --- 5. re-enrollment must reject a bootstrap-only credential ----------------
hdr "5. simplereenroll with only the bootstrap certificate (must be refused)"
openssl req -new -key "$W/device.key" -out "$W/r2.csr" -subj "/CN=$CN" >/dev/null 2>&1
if est reenroll -certs "$PKI/device01.pem" -key "$PKI/device01.key" \
       -csr "$W/r2.csr" -out "$W/r2.pem"; then
  bad "a bootstrap certificate was accepted for renewal — the two trust anchors are not separated"
elif rate_limited; then
  bad "inconclusive: rate limited, not an authorization decision"
else
  ok "refused: $(tail -c 60 "$W/err" | tr -d '\n')"
fi

# --- 6. a CN the inventory does not permit ----------------------------------
hdr "6. enroll a CN absent from the inventory (must be refused)"
openssl req -newkey rsa:2048 -nodes -keyout "$W/rogue.key" -out "$W/rogue.csr" \
  -subj "/CN=rogue.example.com" >/dev/null 2>&1
if est enroll -certs "$PKI/device01.pem" -key "$PKI/device01.key" \
       -csr "$W/rogue.csr" -out "$W/rogue.pem"; then
  bad "issued a certificate for an uninventoried CN"
elif rate_limited; then
  bad "inconclusive: rate limited, not an authorization decision"
else
  ok "refused: $(tail -c 60 "$W/err" | tr -d '\n')"
fi

# --- 7. HTTP Basic credentials, no client certificate -----------------------
# RFC 7030 section 3.2.3 permits HTTP Basic, and real clients (Aruba AOS-CX,
# Cisco IOS) can be configured with only a username and password. The broker
# does not read the Authorization header, so this request proves nothing — the
# authentication gate must refuse it unless open enrollment is configured.
hdr "7. HTTP Basic credentials only, no client certificate"
openssl req -newkey rsa:2048 -nodes -keyout "$W/basic.key" -out "$W/basic.csr" \
  -subj "/CN=$CN" >/dev/null 2>&1
if est enroll -user someuser -pass somepass \
       -csr "$W/basic.csr" -out "$W/basic.pem"; then
  if [ "$EXPECT_OPEN" = "1" ]; then
    ok "enrolled — expected, open enrollment is configured"
    note "the password was still never read; the gate is simply open"
  else
    bad "SECURITY: enrolled with a credential the broker never validated"
    gap=1
  fi
elif rate_limited; then
  bad "inconclusive: rate limited, not an authorization decision"
elif [ "$EXPECT_OPEN" = "1" ]; then
  bad "open enrollment is configured but the request was refused: $(tail -c 70 "$W/err" | tr -d '\n')"
else
  ok "refused: $(tail -c 70 "$W/err" | tr -d '\n')"
  note "refused by the authentication gate — the password itself is still not read"
fi

# --- summary ----------------------------------------------------------------
printf '\n\033[1msummary\033[0m: %d passed, %d failed\n' "$pass" "$fail"
[ "$gap" -eq 0 ] || printf '\033[33mopen gap\033[0m: unauthenticated enrollment succeeded (step 7)\n'
[ "$fail" -eq 0 ] || exit 1
