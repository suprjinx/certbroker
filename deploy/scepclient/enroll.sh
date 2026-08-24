#!/usr/bin/env bash
# SCEP interop against the running stack, using sscep — an independent RFC 8894
# implementation. Mirrors deploy/estclient/enroll.sh for the other protocol.
set -uo pipefail

URL="${URL:-http://certbroker:8080/}"
CN="${CN:-device01.example.com}"
CHALLENGE="${CHALLENGE:-dev-challenge-secret}"
W=/tmp/scep
mkdir -p "$W"

pass=0
fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail + 1)); }
note() { printf '  \033[33mNOTE\033[0m %s\n' "$1"; }
hdr()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

# scep_enroll runs sscep, retrying once after a pause if the broker rate-limits
# us. Without this the negative cases below "pass" on a 429 rather than on the
# authorization decision they mean to check — mirrors deploy/estclient/enroll.sh.
scep_enroll() {
  local out
  for attempt in 1 2; do
    out=$(sscep enroll -u "$URL" "$@" -S sha256 -E aes 2>&1)
    if rate_limited "$out"; then
      sleep 8
      continue
    fi
    break
  done
  printf '%s' "$out"
}

# The limiter answers before any SCEP layer runs, so the reply is an HTTP 429
# rather than a CertRep, which sscep reports only as "error while sending
# message" — it never surfaces the status code. Verified against sscep 0.10.0.
rate_limited() {
  printf '%s' "$1" | grep -qiE 'error while sending message|429|too many requests'
}

# csrconf writes an openssl config; challengePassword needs a config file since
# there is no command-line flag for a PKCS#9 attribute.
csrconf() {
  cat > "$W/$1.cnf" <<CNF
[req]
distinguished_name = dn
attributes         = attrs
prompt             = no
[dn]
CN = $2
[attrs]
challengePassword = $3
CNF
}

echo "SCEP interop: url=$URL cn=$CN"
echo "client: $(sscep 2>&1 | grep -i version | head -1)"

# --- 1. GetCACaps ------------------------------------------------------------
hdr "1. GetCACaps"
caps=$(sscep getcaps -u "$URL" 2>&1)
if echo "$caps" | grep -q 'POSTPKIOperation'; then
  ok "$(echo "$caps" | tail -1 | sed 's/.*capabilities: //')"
  for weak in 'SHA-1' 'DES3' 'GetNextCACert'; do
    echo "$caps" | grep -q "$weak" && bad "advertises $weak"
  done
else
  bad "getcaps: $caps"
fi

# --- 2. GetCACert ------------------------------------------------------------
hdr "2. GetCACert (must carry the RA as well as the CA)"
if sscep getca -u "$URL" -c "$W/ca.pem" >/dev/null 2>&1 && [ -s "$W/ca.pem-0" ]; then
  subjects=$(for f in "$W"/ca.pem-*; do openssl x509 -in "$f" -noout -subject 2>/dev/null; done)
  ok "$(echo "$subjects" | tr '\n' ' ')"
  echo "$subjects" | grep -qi 'RA' || bad "no RA certificate — clients cannot encrypt to the broker"
else
  bad "getca failed"
fi

# --- 3. enroll without a challengePassword (must be refused) -----------------
# SCEP has no mTLS and its PKCSReq signer is self-signed, so the challenge is
# the only bootstrap authenticator. Without it the request proves nothing.
hdr "3. enroll with no challengePassword (must be refused)"
openssl genrsa -out "$W/nochal.key" 2048 2>/dev/null
openssl req -new -key "$W/nochal.key" -out "$W/nochal.csr" -subj "/CN=$CN" 2>/dev/null
out=$(scep_enroll -k "$W/nochal.key" -r "$W/nochal.csr" \
        -c "$W/ca.pem-0" -l "$W/nochal.pem")
if echo "$out" | grep -qi 'pkistatus: SUCCESS'; then
  bad "SECURITY: enrolled with nothing authenticating the request"
elif rate_limited "$out"; then
  bad "inconclusive: rate limited, not an authorization decision"
else
  ok "refused ($(echo "$out" | grep -i 'pkistatus\|reason' | tail -1 | xargs))"
fi

# --- 4. enroll with a challengePassword --------------------------------------
hdr "4. enroll with a challengePassword"
csrconf dev "$CN" "$CHALLENGE"
openssl genrsa -out "$W/dev.key" 2048 2>/dev/null
openssl req -new -key "$W/dev.key" -out "$W/dev.csr" -config "$W/dev.cnf" 2>/dev/null
out=$(scep_enroll -k "$W/dev.key" -r "$W/dev.csr" \
        -c "$W/ca.pem-0" -l "$W/issued.pem")
if echo "$out" | grep -qi 'pkistatus: SUCCESS' && [ -s "$W/issued.pem" ]; then
  ok "issued: $(openssl x509 -in "$W/issued.pem" -noout -subject 2>/dev/null)"
  note "issuer: $(openssl x509 -in "$W/issued.pem" -noout -issuer 2>/dev/null)"
else
  bad "enroll: $(echo "$out" | grep -i 'pkistatus\|reason' | tail -2 | xargs)"
fi

# --- 5. enroll a CN the inventory does not permit ----------------------------
# NOT *.example.com: the dev inventory carries a deliberate "*.example.com" glob,
# so a rogue name under that suffix is genuinely inventoried and issuing it is
# correct. EST refuses the same name for an unrelated reason — san_constraint
# pins names to the mTLS identity — but SCEP has no client cert, so here the
# inventory is the only name gate and the CN must fall outside it to test it.
hdr "5. enroll an uninventoried CN (must be refused)"
csrconf rogue "rogue.example.net" "$CHALLENGE"
openssl genrsa -out "$W/rogue.key" 2048 2>/dev/null
openssl req -new -key "$W/rogue.key" -out "$W/rogue.csr" -config "$W/rogue.cnf" 2>/dev/null
out=$(scep_enroll -k "$W/rogue.key" -r "$W/rogue.csr" \
        -c "$W/ca.pem-0" -l "$W/rogue.pem")
if echo "$out" | grep -qi 'pkistatus: SUCCESS'; then
  bad "issued a certificate for an uninventoried CN"
elif rate_limited "$out"; then
  bad "inconclusive: rate limited, not an authorization decision"
else
  ok "refused"
fi

# --- 6. wrong challengePassword (must be refused) ----------------------------
hdr "6. wrong challengePassword (must be refused)"
csrconf badchal "$CN" "not-the-secret"
openssl genrsa -out "$W/badchal.key" 2048 2>/dev/null
openssl req -new -key "$W/badchal.key" -out "$W/badchal.csr" -config "$W/badchal.cnf" 2>/dev/null
out=$(scep_enroll -k "$W/badchal.key" -r "$W/badchal.csr" \
        -c "$W/ca.pem-0" -l "$W/badchal.pem")
if echo "$out" | grep -qi 'pkistatus: SUCCESS'; then
  bad "SECURITY: a wrong challengePassword was accepted"
elif rate_limited "$out"; then
  bad "inconclusive: rate limited, not an authorization decision"
else
  ok "refused"
fi

printf '\n\033[1msummary\033[0m: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
