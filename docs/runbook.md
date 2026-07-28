# certbroker runbook

Operating guide for the EST enrollment broker. For architecture and roadmap see
[`PLAN.md`](../PLAN.md); for the adversary model see
[`docs/threat-model.md`](threat-model.md).

---

## 1. What this service does

certbroker is a **Registration Authority**. It authenticates enrolling devices,
decides whether each one may hold the certificate it is asking for, and only
then forwards a constrained issuance request to OpenBao's PKI mount. It holds no
CA key of its own.

```
Device --mTLS--> [L4 passthrough] --> certbroker --AppRole--> OpenBao pki/sign
```

The security-relevant consequence: **compromising the broker does not yield a CA
key.** It yields the ability to request certificates within the bounds of the
AppRole's policy and the PKI role's constraints — which is why both are scoped
tightly (see §6).

---

## 2. Local development stack

Requirements: Docker with Compose v2, `openssl`, `curl`, `make`.

```bash
make dev-up        # generate dev certs, build the image, start OpenBao + broker
make dev-enroll    # real EST enroll + re-enroll against the running stack
make dev-logs      # follow broker logs
make dev-down      # stop everything and delete volumes
```

`make dev-up` runs, in order:

1. `deploy/gen-certs.sh` — bootstrap CA, broker server cert, one device
   bootstrap cert, into `deploy/pki/` (git-ignored).
2. `docker compose up openbao provision certbroker`.
3. `deploy/provision-openbao.sh` inside the OpenBao container — enables the
   `pki_int` mount, generates a CA, writes the `device-role` issuing role,
   enables AppRole, writes a least-privilege policy, and drops the SecretID plus
   the device CA into a shared volume.
4. A one-shot sidecar that polls `/readyz` until the broker is up.

**The dev stack is not a security demonstration.** It runs OpenBao in dev mode
(in-memory, auto-unsealed, fixed root token, plaintext HTTP) and generates
throwaway keys with a shell script. See §6 before deploying anything.

### Verifying it works

```bash
curl -s http://localhost:9090/healthz          # liveness  -> ok
curl -s http://localhost:9090/readyz           # readiness -> probes OpenBao
make dev-enroll                                # full EST round trip
```

---

## 3. Endpoints

Served under `/.well-known/est/` (optionally `/.well-known/est/{label}/`) on the
mTLS listener.

| Endpoint | Method | Client cert | Notes |
|---|---|---|---|
| `/cacerts` | GET | not required | CA chain as certs-only PKCS#7 |
| `/simpleenroll` | POST | optional, **bootstrap** anchor | initial enrollment |
| `/simplereenroll` | POST | **required, device** anchor | renewal |
| `/serverkeygen` | POST | device anchor, else bootstrap | broker-generated key |
| `/csrattrs` | GET | not required | 204 when unset |

The health listener (`:9090`) serves `/healthz` and `/readyz` over plain HTTP
and must be bound to a management interface, never exposed alongside `:8443`.

### The two trust anchors

This is the design's central distinction and the most common misconfiguration.

- `trust.bootstrap_ca_file` — gates **first** enrollment. Typically a factory or
  provisioning CA.
- `trust.device_ca_file` — gates **renewal**. This is the CA that actually
  issued the device's current certificate, i.e. the OpenBao mount.

Pointing both at the same bundle means a bootstrap credential is also a renewal
credential forever, which defeats the point of having a bootstrap phase at all.

---

## 4. Configuration

Full schema: [`internal/config/config.go`](../internal/config/config.go).
Worked example: [`deploy/config.yaml`](../deploy/config.yaml).

Secrets are **never** written in the config file — it holds either a path
(`secret_id_file`) or an env var name (`secret_id_env`). Prefer the file: a
mounted secret can be rotated in place and does not appear in `/proc`, process
listings, or crash dumps.

Config is validated at startup and the process exits non-zero on any problem.
Unknown YAML keys are rejected, so a typo fails loudly instead of silently
disabling a control.

### Knobs most likely to need tuning

| Key | Default | Raise/lower when |
|---|---|---|
| `limits.per_client_rate` / `_burst` | 1/s, 5 | A NAT'd site shares one source IP and is being limited as a unit |
| `limits.global_rate` / `_burst` | 50/s, 100 | Fleet-wide reboot storms shed legitimate traffic |
| `limits.max_concurrent` | 32 | CPU saturates on signature verification, or slots run out under normal load |
| `limits.upstream_timeout` | 20s | OpenBao is consistently slower than this |
| `policy.max_validity` | 90d | Shorter lifetimes are wanted; OpenBao's role `max_ttl` caps this independently |
| `server.max_request_bytes` | 256 KiB | Effectively never — a CSR is ~1 KiB |

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

Match keys are `cn` (glob), `serial` (exact hex), `fingerprint` (sha256 of the
cert DER). Every key set on an entry must match. **Restart to reload** —
`FileInventory.Reload()` exists but nothing currently calls it on a signal.

Keep `allowed_dns` tight. A broad glob (`cn: "*"`) turns the inventory from an
authorization gate into a rubber stamp.

### Rotate the AppRole SecretID

```bash
bao write -f -field=secret_id auth/approle/role/certbroker/secret-id > /path/to/secret-id
# restart the broker to pick it up
```

The broker reads the SecretID once at startup. It re-authenticates
automatically when its *token* expires, but only with the SecretID it already
holds — rotating the SecretID requires a restart.

### Change what a device may request

Two independent layers, both enforced:

1. **Broker** — `policy.san_constraint`, the inventory record's `allowed_dns`,
   `policy.max_validity`.
2. **OpenBao role** — `allowed_domains`, `allow_subdomains`, `max_ttl`.

Loosening only the broker will not widen issuance; OpenBao still refuses. That
is intentional (defense in depth), and it is the usual explanation for "policy
says yes but issuance fails" — check the OpenBao role.

### Rotate the broker's server TLS certificate

Replace `server.tls_cert_file` / `server.tls_key_file` and restart. The
certificate is loaded once at startup; there is no hot reload.

---

## 6. Before deploying anywhere real

The dev stack differs from a production deployment in ways that matter. Work
through this list:

- [ ] **OpenBao over TLS.** Set `openbao.address` to `https://` and
      `openbao.ca_cert_file`. Over plaintext, the AppRole SecretID and every
      issued certificate are on the wire.
- [ ] **`use_csr_sans=false` and `use_csr_common_name=false` on every PKI role
      the broker uses.** These are **not** OpenBao's defaults and they are the
      single most important role setting here. Left at their defaults (`true`),
      OpenBao merges the CSR's own subject and SANs into the issued certificate
      *alongside* the parameters the broker sends — so a device authorized for
      one name receives any other name the role's `allowed_domains` permits,
      simply by putting it in the CSR. That silently defeats the entire
      constraint policy. The broker independently verifies the returned
      certificate and refuses to release an over-broad one (§8), so a role
      misconfigured this way fails closed and logs loudly rather than leaking —
      but fix the role, do not rely on the backstop.
- [ ] **Real PKI.** The dev script generates a self-signed root *inside* the
      mount. Production should make this mount an intermediate whose CSR is
      signed by an offline root.
- [ ] **Distinct trust anchors.** Bootstrap ≠ device CA (see §3).
- [ ] **Never `-dev-insecure-allow-all`.** It authorizes every request with no
      checks. It logs a loud warning; treat that warning in production logs as
      an incident.
- [ ] **Inventory backend configured.** `backend: none` permits every device
      that clears the other gates.
- [ ] **Challenge backend for unauthenticated bootstrap.** If devices enroll
      without a bootstrap client cert, the challengePassword is the only thing
      authenticating them. Prefer single-use OTPs over a fleet-wide static
      secret.
- [ ] **Least-privilege AppRole.** The policy should grant `create`/`update` on
      `<mount>/sign/<role>` and `<mount>/issue/<role>` and `read` on
      `<mount>/ca_chain` — nothing else. See `deploy/provision-openbao.sh`.
- [ ] **Short token TTLs.** `token_ttl=20m`, `token_max_ttl=1h` in the dev
      stack; keep them short.
- [ ] **Health listener not publicly exposed.** `/readyz` reveals OpenBao
      reachability.
- [ ] **L4 passthrough, not L7.** TLS terminates in-app. An L7 proxy strips the
      client certificate and the broker loses every mTLS identity — and rate
      limiting keys on `RemoteAddr`, which behind an L7 proxy would collapse to
      the proxy's address.
- [ ] **Audit log shipped off-box.** Issuance decisions go to stdout as JSON;
      collect them.
- [ ] **Read-only root filesystem, dropped capabilities, non-root uid.** The
      compose file sets `read_only`, `cap_drop: ALL`, `no-new-privileges`, and
      the image is distroless running as 65532.

---

## 7. Observability

Structured JSON on stdout. The audit line for every enrollment decision is
`msg="enrollment decision"`:

| Field | Meaning |
|---|---|
| `op` | `simpleenroll` / `simplereenroll` / `serverkeygen` |
| `outcome` | `issued`, `deny`, `error`, `issue-error` |
| `reason` | the authorizer's rationale — why it was denied |
| `remote` | client address |
| `requested_cn` | what the CSR asked for |
| `granted_cn` | what policy actually authorized |
| `client_cn` | authenticated client cert CN, if any |
| `role` | OpenBao role used |

`requested_cn` diverging from `granted_cn` is the signal that policy constrained
a request. A sustained pattern of that from one device is worth investigating.

Rate-limit rejections log at WARN with `msg="request rate limited"` and a
`reason` of `per-client rate limit` or `global rate limit`; shed requests log
`msg="request shed: no concurrency slot"`.

There is no metrics endpoint yet — Phase 0 item 3.

---

## 8. Troubleshooting

**`/readyz` returns 503**
OpenBao is unreachable, AppRole login is failing, or the token lacks
`read` on `<mount>/ca_chain`. The response body carries the underlying error.
Check `openbao.address`, the SecretID file, and the policy.

**`secret id file "..." is empty` at startup**
The provisioning step has not run, or the file is not mounted. In compose,
confirm the `provision` service exited successfully.

**All enrollments return 403**
Work down the pipeline in order — it fails closed at the first gap:
1. Is the device in the inventory? (`reason: device not permitted by inventory`)
2. Is a challenge required with no validator configured?
3. Does any rule or `role_map.default` yield a role? (`reason: no OpenBao role for identity`)
4. Does the constraint policy reject the requested names?

The `reason` field names the stage.

**Re-enrollment returns 403 but initial enrollment works**
The client certificate does not verify against `trust.device_ca_file`, or lacks
the `clientAuth` EKU (`est.VerifyPeer` requires it explicitly). Confirm the
device CA file is the CA that actually issued that certificate.

**`requested CN ... is not part of the authenticated identity`**
`san_constraint: identity` pins issued names to the authenticated certificate; a
device may re-key but not rename itself. If the device legitimately needs a new
name, it must bootstrap again rather than renew.

**429s under normal load**
Per-client limits key on source IP. Devices behind a single NAT share a bucket —
raise `limits.per_client_rate`/`_burst`, or the whole site is limited as one
client.

**Issuance fails with an OpenBao error mentioning the common name**
The broker authorized it but the PKI role did not. Check the role's
`allowed_domains` / `allow_subdomains` / `max_ttl`.

**`SECURITY: issued certificate exceeds authorized constraints` in the logs, clients get 502**
The PKI role issued a certificate broader than what the broker authorized, and
the broker withheld it. This is a role misconfiguration, not a client problem —
almost always `use_csr_sans` / `use_csr_common_name` left at their permissive
defaults (see §6). The log line carries `authorized_cn`/`authorized_dns` versus
`issued_cn`/`issued_dns` and the serial.

The certificate **was already issued** before the check ran; revoke it:

```bash
bao write <mount>/revoke serial_number=<serial from the log>
```

Then fix the role:

```bash
bao write <mount>/roles/<role> use_csr_sans=false use_csr_common_name=false ...
```

---

## 9. CI

`make check` runs `fmt`, `vet`, and unit tests — the gate for every change.
`make test-race` and `make vuln` (govulncheck) are worth running before a
release. `make test-integration` needs a live OpenBao; see §2.
