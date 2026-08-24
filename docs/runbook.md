# certbroker runbook

Operating guide. For the adversary model see
[`docs/threat-model.md`](threat-model.md); for the code layout see
[`CLAUDE.md`](../CLAUDE.md).

---

## 1. What this service does

certbroker is a **Registration Authority**. It authenticates enrolling devices
over EST (RFC 7030) and SCEP (RFC 8894), decides whether each may hold the
certificate it is asking for, and only then forwards a constrained issuance
request to OpenBao's PKI mount.

```
Device --mTLS, EST-----> [L4 passthrough] --+
                                            +--> certbroker --AppRole--> OpenBao pki/sign
Device --CMS/HTTP, SCEP---------------------+
```

Compromising the broker does not yield a CA key. It yields the ability to
request certificates within the bounds of the AppRole policy and the PKI role's
constraints — which is why both are scoped tightly (§6). Enabling SCEP does put
an **RA** key on the broker: it decrypts requests and signs responses with it.

---

## 2. Local development stack

Requirements: Docker with Compose v2, `openssl`, `curl`, `make`.

```bash
make dev-up          # generate dev certs, build the image, start OpenBao + broker
make dev-enroll      # real EST enroll + re-enroll (curl/openssl)
make dev-estclient   # EST interop:  globalsign/est      (§9)
make dev-scepclient  # SCEP interop: certnanny/sscep     (§9, needs scep.enabled)
make dev-logs
make dev-down        # stop everything and delete volumes
```

`make dev-up` runs, in order:

1. `deploy/gen-certs.sh` — bootstrap CA, broker server cert, one device
   bootstrap cert, and the SCEP RA cert, into `deploy/pki/` (git-ignored).
2. `docker compose up --build -d openbao provision certbroker`.
3. `deploy/provision-openbao.sh` in the OpenBao container — enables the
   `pki_int` mount, generates a CA, writes the `device-role` issuing role,
   enables AppRole, writes a least-privilege policy, and drops the SecretID and
   device CA into a shared volume.
4. A one-shot `healthcheck` sidecar that polls `/readyz` until the broker is up.

Verify:

```bash
curl -s http://localhost:9090/healthz   # liveness  -> ok
curl -s http://localhost:9090/readyz    # readiness -> probes OpenBao
make dev-enroll                         # full EST round trip
```

**The dev stack is not a security demonstration.** OpenBao runs in dev mode
(in-memory, auto-unsealed, fixed root token, plaintext HTTP) and the keys come
from a shell script. See §6 before deploying anything.

---

## 3. Listeners and endpoints

| Listener | Default | Transport |
|---|---|---|
| EST | `:8443` | TLS, mTLS optional-but-verified |
| SCEP | `:8080` | plain HTTP, off unless `scep.enabled` |
| Health | `:9090` | plain HTTP, management interface only |

### EST — `/.well-known/est/` (optionally `/.well-known/est/{label}/`)

| Endpoint | Method | Client cert | Notes |
|---|---|---|---|
| `/cacerts` | GET | not required | CA chain as certs-only PKCS#7 |
| `/simpleenroll` | POST | optional, **bootstrap** anchor | initial enrollment |
| `/simplereenroll` | POST | **required, device** anchor | renewal |
| `/serverkeygen` | POST | device anchor, else bootstrap | broker-generated key |
| `/csrattrs` | GET | not required | 204 when unset |

A presented certificate that does not verify against the anchor for the
operation is **ignored, not rejected**: initial enrollment degrades to
anonymous and policy decides (threat-model T6). Re-enrollment has no such
fallback and returns 403.

### SCEP — any path, dispatched on `?operation=`

`GetCACert`, `GetCACaps`, `PKIOperation` — the last taking its CMS message
either as a POST body or as a base64 `message` query parameter on a GET.
Everything else is a 400. `GetCert`, `GetCRL`, `GetNextCACert` and
`GetCertInitial` are deliberately absent — each unimplemented operation is one
less parser at a hostile boundary.

### The two trust anchors

The central distinction, and the most common misconfiguration:

- `trust.bootstrap_ca_file` gates **first** enrollment — a factory or
  provisioning CA.
- `trust.device_ca_file` gates **renewal** — the CA that issued the device's
  current certificate, i.e. the OpenBao mount.

Pointing both at the same bundle makes a bootstrap credential a permanent
renewal credential, which defeats the point of a bootstrap phase.

---

## 4. Configuration

Full schema: [`internal/config/config.go`](../internal/config/config.go).
Worked example: [`deploy/config.yaml`](../deploy/config.yaml).

Secrets are **never** inlined — the config holds a path (`secret_id_file`) or an
env var name (`secret_id_env`). Prefer the file: a mounted secret rotates in
place and does not appear in process listings or crash dumps.

Config is validated at startup and the process exits non-zero on any problem.
Unknown YAML keys are rejected, so a typo fails loudly instead of silently
disabling a control.

### Knobs most likely to need tuning

| Key | Default | Raise/lower when |
|---|---|---|
| `limits.per_client_rate` / `_burst` | 1/s, 5 | A NAT'd site shares one source IP and is limited as a unit |
| `limits.global_rate` / `_burst` | 50/s, 100 | Fleet-wide reboot storms shed legitimate traffic |
| `limits.max_concurrent` | 32 | CPU saturates on signature verification, or slots run out under normal load |
| `limits.upstream_timeout` | 20s | OpenBao is consistently slower than this |
| `policy.max_validity` | 90d | Shorter lifetimes are wanted; the role's `max_ttl` caps this independently |
| `server.max_request_bytes` | 256 KiB (SCEP: 512 KiB) | Effectively never — a CSR is ~1 KiB |

Setting a rate to `0` is rejected as ambiguous. Omit the key for the default;
use a **negative** value to disable a limiter deliberately.

---

## 5. Routine operations

### Add a device to the allowlist

Edit the file named by `inventory.path`:

```yaml
devices:
  - cn: device42.example.com
    allowed_dns:
      - device42.example.com
```

Match keys are `cn`, `serial` (exact hex) and `fingerprint` (sha256 of the cert
DER); every key set on an entry must match. `cn` supports only `*` and
`*.suffix` — a mid-string wildcard like `device*.example.com` is compared
literally and matches nothing. **Restart to reload**: `FileInventory.Reload()`
exists but nothing calls it on a signal.

Keep `allowed_dns` tight. A broad glob turns the inventory from an authorization
gate into a rubber stamp.

### Rotate the AppRole SecretID

```bash
bao write -f -field=secret_id auth/approle/role/certbroker/secret-id > /path/to/secret-id
# restart the broker to pick it up
```

The SecretID is read once at startup. The broker re-authenticates automatically
when its *token* expires, but only with the SecretID it already holds.

### Change what a device may request

Two independent layers, both enforced:

1. **Broker** — `policy.san_constraint`, the inventory record's `allowed_dns`,
   `policy.max_validity`.
2. **OpenBao role** — `allowed_domains`, `allow_subdomains`, `max_ttl`.

Loosening only the broker will not widen issuance; OpenBao still refuses. That
is the usual explanation for "policy says yes but issuance fails".

### Rotate TLS or RA key material

Replace `server.tls_cert_file` / `server.tls_key_file` (or `scep.ra_cert_file` /
`scep.ra_key_file`) and restart. Everything is loaded once at startup; there is
no hot reload.

---

## 6. Before deploying anywhere real

- [ ] **OpenBao over TLS.** `openbao.address` on `https://` with
      `openbao.ca_cert_file`. Over plaintext the SecretID and every issued
      certificate are on the wire.
- [ ] **`use_csr_sans=false` and `use_csr_common_name=false` on every PKI role
      the broker uses.** These are *not* OpenBao's defaults. Left at `true`,
      OpenBao merges the CSR's own subject and SANs into the certificate
      alongside the broker's parameters, so a device authorized for one name can
      obtain any other name `allowed_domains` permits. The broker re-checks what
      came back and withholds an over-broad certificate (§8), but that is a
      backstop, not the control.
- [ ] **Real PKI.** The dev script self-signs a root *inside* the mount.
      Production should make the mount an intermediate signed by an offline root.
- [ ] **Distinct trust anchors.** Bootstrap ≠ device CA (§3).
- [ ] **Never `-dev-insecure-allow-all`.** It authorizes every request with no
      checks and logs a loud warning; treat that warning in production as an
      incident.
- [ ] **Inventory backend configured.** `backend: none` permits every device
      that clears the other gates.
- [ ] **`allow_unauthenticated_enrollment` left false** unless open enrollment
      is genuinely wanted. With it set, any host that can reach the listener may
      enroll any name the inventory and role allow. It WARNs at startup; confirm
      that line reflects a deliberate decision.
- [ ] **Challenge backend for unauthenticated bootstrap.** Without a bootstrap
      client cert — always the case for SCEP — the challengePassword is the only
      authenticator. Prefer single-use OTPs over a fleet-wide static secret.
- [ ] **Least-privilege AppRole.** `create`/`update` on `<mount>/sign/<role>` and
      `<mount>/issue/<role>`, `read` on `<mount>/ca_chain`, nothing else. See
      `deploy/provision-openbao.sh`.
- [ ] **Short token TTLs.** The dev stack uses `token_ttl=20m`,
      `token_max_ttl=1h`; keep them short.
- [ ] **Health and SCEP listeners not publicly exposed.** `/readyz` reveals
      OpenBao reachability; SCEP is plain HTTP and belongs on a trusted network.
- [ ] **L4 passthrough, not L7.** TLS terminates in-app. An L7 proxy strips the
      client certificate, and rate limiting keys on `RemoteAddr`, which would
      collapse to the proxy's address.
- [ ] **Audit log shipped off-box.** Decisions go to stdout as JSON; collect them.
- [ ] **Read-only root filesystem, dropped capabilities, non-root uid.** The
      compose file sets `read_only`, `cap_drop: ALL` and `no-new-privileges`;
      the image is distroless running as uid 65532.

---

## 7. Observability

Structured JSON on stdout. Every enrollment decision logs `msg="enrollment
decision"`:

| Field | Meaning |
|---|---|
| `op` | EST: `simpleenroll` / `simplereenroll` / `serverkeygen`. SCEP: the CMS message type (`PKCSReq`, `RenewalReq`) |
| `outcome` | `issued`, `deny`, `error`, `issue-error`, `constraint-violation` |
| `reason` | the authorizer's rationale — why it was denied |
| `remote` | client address |
| `requested_cn` / `granted_cn` | what the CSR asked for vs what policy authorized |
| `role` | OpenBao role used |
| `client_cn` | EST only: authenticated client cert CN, if any |
| `protocol`, `transaction_id`, `authenticated` | SCEP only |

`requested_cn` diverging from `granted_cn` means policy constrained the request.
A sustained pattern from one device is worth investigating.

Other lines worth alerting on:

| Line | Level | Meaning |
|---|---|---|
| `SECURITY: issued certificate exceeds authorized constraints` | ERROR | See §8 — role misconfiguration |
| `request rate limited` | WARN | `reason` is `per-client rate limit` or `global rate limit` |
| `request shed: no concurrency slot` | WARN | `limits.max_concurrent` exhausted |
| `scep: request refused` | INFO | The real reason; the client only ever sees `badRequest` |

There is no metrics endpoint yet.

---

## 8. Troubleshooting

**`/readyz` returns 503**
OpenBao is unreachable, AppRole login is failing, or the token lacks `read` on
`<mount>/ca_chain`. The response body carries the underlying error.

**`secret id file "..." is empty` at startup**
Provisioning has not run, or the file is not mounted. In compose, confirm the
`provision` service exited successfully.

**All enrollments return 403**
The pipeline fails closed at the first gap and `reason` names the stage:

1. `device not permitted by inventory`
2. `challenge required but no validator configured` / `challenge validation failed`
3. `unauthenticated: no client certificate and no validated challenge` — an
   unverifiable client certificate is ignored, not rejected, so it lands here
4. `no OpenBao role for identity` — no rule matched and `role_map.default` is unset
5. a constraint-policy message naming the CN or SANs

**Re-enrollment returns 403 but initial enrollment works**
The client certificate does not verify against `trust.device_ca_file`, or lacks
the `clientAuth` EKU (`est.VerifyPeer` requires it explicitly).

**`requested CN ... is not part of the authenticated identity`**
`san_constraint: identity` pins issued names to the authenticated certificate: a
device may re-key but not rename itself. A device that legitimately needs a new
name must bootstrap again rather than renew.

**429s under normal load**
Per-client limits key on source IP, so devices behind one NAT share a bucket.
Raise `limits.per_client_rate`/`_burst`.

**Issuance fails with an OpenBao error naming the common name**
The broker authorized it, the PKI role did not. Check the role's
`allowed_domains` / `allow_subdomains` / `max_ttl`.

**`SECURITY: issued certificate exceeds authorized constraints`, clients get 502**
The role issued a certificate broader than what the broker authorized and the
broker withheld it — almost always `use_csr_sans` / `use_csr_common_name` left at
their permissive defaults (§6). The log line carries `authorized_cn`/
`authorized_dns` versus `issued_cn`/`issued_dns` and the serial.

The certificate **was already issued** before the check ran. Revoke it, then fix
the role:

```bash
bao write <mount>/revoke serial_number=<serial from the log>
bao write <mount>/roles/<role> use_csr_sans=false use_csr_common_name=false ...
```

---

## 9. Client interop

`make dev-estclient` and `make dev-scepclient` drive the broker with third-party
implementations, unlike `deploy/enroll.sh`, which uses curl and openssl and so
shares our assumptions about the wire format. Each walks a happy path, then
asserts the negative cases.

**Both assert on the authorization decision, not merely on a non-zero exit.**
The per-client limiter (`1/s`, burst `5`) would otherwise make the negative
steps pass for the wrong reason. Both scripts retry once after a pause and
report `inconclusive: rate limited` rather than `PASS`. Note the asymmetry: the
EST client reports a readable `rate limit` error, while `sscep` only ever prints
`error while sending message`.

### EST — `make dev-estclient`

[globalsign/est](https://github.com/globalsign/est)'s `estclient`: cacerts →
enroll → reenroll, then a bootstrap certificate refused for renewal, an
uninventoried CN refused, and finally HTTP Basic credentials with no client
certificate — the open-enrollment gate (threat-model T6), which the harness
expects to be refused unless `EXPECT_OPEN=1`.

### SCEP — `make dev-scepclient`

[certnanny/sscep](https://github.com/certnanny/sscep), a C client sharing no code
with the broker. Needs `scep.enabled`; `deploy/config.yaml` sets it.

| Step | Asserts |
|---|---|
| 1. `GetCACaps` | `POSTPKIOperation` advertised; SHA-1, DES3 and `GetNextCACert` are not |
| 2. `GetCACert` | The reply carries the **RA** as well as the CA — without it a client has nothing to encrypt to |
| 3. Enroll, no challengePassword | Refused. No mTLS, and a `PKCSReq` signer is self-signed, so nothing else authenticates the request |
| 4. Enroll with a challengePassword | Issued |
| 5. Enroll an uninventoried CN | Refused — the choice of CN matters, see below |
| 6. Wrong challengePassword | Refused |

There is no re-enrollment step: `RenewalReq` needs a current device certificate
as the CMS signer, which the script cannot obtain independently.

### What the dev inventory permits

`deploy/inventory.yaml` deliberately carries a broad `*.example.com` entry
alongside the pinned one, to demonstrate the hazard §5 warns about. So
`rogue.example.com` **is** legitimately inventoried and issuing it is correct;
a negative test for the inventory gate must use a name outside that suffix,
which is why the SCEP script uses `rogue.example.net`.

The EST script gets away with `rogue.example.com` for a different reason:
`san_constraint: identity` pins issued names to the authenticated mTLS identity
(`CN=device01.example.com`), so the request never reaches the inventory
question. SCEP has no client certificate, so the inventory is the **only** name
gate there. That difference is the concrete form of the warning in threat-model
§8: under a fleet-wide static challengePassword, any holder of the shared secret
can obtain any name the inventory glob permits. Single-use OTPs close it.

### Why not a real vendor image

Cisco XRd and FortiGate-VM would be closer stand-ins, but both are licensed
images distributed only to entitled accounts and cannot live in a self-contained
stack. With an entitlement, point the appliance at
`https://<host>:8443/.well-known/est` or `http://<host>:8080/` — but read the
next section first.

### Known client incompatibilities

EST:

| Client behaviour | Effect here |
|---|---|
| HTTP Basic auth (`username`/`password`) | Not read. The request counts as unauthenticated and the authentication gate refuses it unless `allow_unauthenticated_enrollment` is set. Fails closed, but the error will not mention the password |
| No challengePassword support (e.g. Aruba AOS-CX) | `require_challenge_password` and per-device `require_challenge` make those devices permanently undeployable |
| ECDSA P-521 | Rejected — not in the default `policy.allowed_key_types`. Add `ec-p521` |
| Full subject DN (C/ST/L/O/OU) with no SANs | Only the CN survives unless the OpenBao role sets the rest |
| Re-enrollment falling back to bootstrap on failure (AOS-CX) | The bootstrap credential must stay valid and inventoried for the device's whole life — so it cannot be a single-use OTP |
| A client cert that does not chain to the bootstrap anchor | Logged and **ignored**; the request degrades to anonymous (threat-model T6) |

SCEP — most of these are deliberate omissions:

| Client behaviour | Effect here |
|---|---|
| SHA-1 signing only | Refused unless `scep.allow_sha1` is set, which logs a loud warning. SHA-1 is collision-broken |
| DES/3DES content encryption | Unsupported; `internal/cms` does AES only. `sscep` needs `-E aes` |
| Polling `GetCertInitial` for a PENDING request | Not implemented — issuance is synchronous, so the reply is always final |
| `GetCert`, `GetCRL`, `GetNextCACert` | Not implemented |
| Expecting a CA-only `GetCACert` reply | The reply is a `-ra-` chain carrying RA **and** CA; a client assuming a bare CA certificate finds no key to encrypt to |
| Renewal without the current device certificate | `RenewalReq` must be CMS-signed by the cert being renewed, verified against the device anchor. A self-signed signer is a `PKCSReq` and is treated as a first enrollment |

---

## 10. CI

`make check` (fmt, vet, unit tests) is the gate for every change. `make
test-race` and `make vuln` are worth running before a release. `make
test-integration` needs a live OpenBao; see §2.
