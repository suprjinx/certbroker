# certbroker threat model

Scope: the EST enrollment broker as of Phase 4. SCEP is not implemented; §8 
records the surface it will add. Operational guidance lives in
[`runbook.md`](runbook.md).

---

## 1. What is being protected

The asset is **the authority to obtain a certificate for a given identity**. The
broker holds no CA key — OpenBao does — so the question is never "can the
attacker steal the CA?" but "can the attacker get a certificate naming something
they are not?"

A certificate for the wrong name is the whole loss condition: it lets the holder
authenticate as another device, terminate TLS for a service they do not own, or
persist in the fleet after being deprovisioned.

Secondary assets:

| Asset | Where it lives | Loss if exposed |
|---|---|---|
| AppRole SecretID | mounted file or env | Attacker can request certs directly from OpenBao, bounded by the policy and role |
| OpenBao token | broker memory | Same, until it expires (20m default) |
| Broker TLS server key | mounted file | Impersonate the broker to devices; harvest challengePasswords |
| challengePassword secrets | config env / memory store | Enroll as any device the inventory permits |
| Server-generated device keys | transient, `/serverkeygen` only | Impersonate that device |
| Audit log | stdout | Discloses fleet inventory and enrollment patterns |

---

## 2. Trust boundaries

```
                    ┌── boundary A: the public/device network
                    │
   Device ──mTLS───▶│  L4 passthrough  ──▶  certbroker
                    │                          │
                    └──────────────────────────┼── boundary B: broker → OpenBao
                                               ▼
                                            OpenBao
```

**Boundary A** is the hostile one. Everything arriving is attacker-controlled:
the CSR, the challengePassword, the client certificate, the TLS parameters, the
request body and headers. The client certificate is *evidence*, not identity,
until it verifies against a configured anchor.

The L4 passthrough is inside the trust boundary only in the sense that it does
not terminate TLS. It cannot be relied on for authentication and does not add
any — and if it were ever replaced with an L7 proxy, mTLS identity would vanish
and every source IP would collapse to the proxy's (§6, DoS).

**Boundary B** is authenticated (AppRole) and should be TLS-protected. OpenBao
is trusted to hold the CA key and enforce its role constraints, but *not* to
enforce the broker's policy — see §5.

---

## 3. Adversary model

Assumed capable of:

- **A1 — Network attacker.** Sends arbitrary traffic to the listener; observes
  and tampers with anything not protected by TLS.
- **A2 — Stolen bootstrap credential.** Holds a valid, unexpired bootstrap
  certificate and its key, extracted from a device.
- **A3 — Compromised enrolled device.** Holds a valid device certificate and
  key, and wants to broaden its identity.
- **A4 — Insider misconfiguration.** An operator with OpenBao or config access
  makes a plausible mistake. Treated as an adversary because the failure modes
  are silent and severe.

Explicitly out of scope: an attacker who already controls the broker host or
the OpenBao host; supply-chain compromise of Go or its dependencies; physical
attacks on the CA.

---

## 4. Threats: identity and authorization

### T1 — CSR subject/SAN spoofing (A1, A2, A3)

*A device requests a certificate naming something else.*

The CSR is entirely attacker-controlled. Proof-of-possession
(`csr.CheckSignature`) proves only that the requester holds the key in the CSR —
it says nothing about entitlement to the name.

**Mitigations.** `StandardConstraints` never copies the CSR's names into the
issuance request. In `identity` mode, names are re-derived from the
authenticated client certificate and every requested name must already be
covered by it; a device may re-key but not rename itself. In `allowlist` mode
they must match the inventory record. IP and URI SANs are refused outright in
both modes rather than silently dropped.

**Residual.** In `csr` mode the CSR's names are used as-is; it is documented as
dev-only. `AllowAllEcho` does the same and is gated behind
`-dev-insecure-allow-all`, which logs a warning at startup — treat that line in
production logs as an incident.

### T2 — SAN injection via the OpenBao role *(found and fixed in Phase 4)*

*The broker constrains the request correctly and OpenBao ignores it.*

OpenBao PKI roles default to `use_csr_sans=true` and
`use_csr_common_name=true`. Under those defaults the CSR's own subject and SANs
are **merged with** the parameters the broker sends rather than replaced by
them. The broker's entire constraint policy was therefore bypassable: a device
authorized for one name obtained any other name inside the role's
`allowed_domains` just by putting it in the CSR. Confirmed live against
OpenBao 2.4.1.

This is the clearest instance of A4: nothing in the broker's code was wrong, and
the failure was silent.

**Mitigations, both layers:**

1. **Prevent** — `use_csr_sans=false`, `use_csr_common_name=false` on every role
   the broker uses. Set in `deploy/provision-openbao.sh`; a checklist item in
   the runbook.
2. **Detect** — `internal/est/verify.go` re-parses every issued certificate and
   compares its CN, DNS/IP/URI SANs, and lifetime against what the authorizer
   approved. A mismatch means the certificate is withheld (502), logged at ERROR
   with the serial for revocation, and the operator is pointed at the role
   setting. Roles are externally managed and opaque to the broker, so it cannot
   repair them — it refuses to launder them.

**Residual.** The certificate is *already issued* when the check fires; only its
delivery is prevented. The serial is logged so it can be revoked, but revocation
is manual (§7, G2). A constraint the broker leaves empty is not checked, because
an empty constraint legitimately means "the role decides".

### T3 — Bootstrap credential replay (A2)

*A bootstrap certificate extracted from one device enrolls repeatedly, or
enrolls as a different device.*

**Mitigations.** The inventory gates which identities may enroll at all. In
`identity` mode the issued names are pinned to the bootstrap certificate's own
names, so a stolen credential can only re-obtain the identity it already
represents — an impersonation of that device, not an escalation.

**Residual.** A bootstrap certificate is valid until it expires and nothing
marks it consumed, so A2 can enroll that device repeatedly. The intended
control is a single-use OTP (`MemoryStore`) as the challenge backend, plus
removing the device from the inventory once enrolled. Neither is automatic.
`MemoryStore` is also process-local: it does not survive a restart and does not
work across replicas.

### T4 — Renewal used to widen identity (A3)

*A compromised device renews into a broader certificate.*

**Mitigations.** `/simplereenroll` requires a client certificate that verifies
against the **device** anchor — the bootstrap anchor is explicitly not accepted,
which is why the two are configured separately. `fromAuthenticatedIdentity` then
requires every requested name to be covered by the presenting certificate.
Verified end to end in `test/e2e` (`TestBootstrapCertCannotRenew`).

**Residual.** A compromised device renews *itself* indefinitely. Containment is
revocation plus inventory removal, both manual.

### T5 — Role escalation via unauthenticated selectors (A1, A4) — **known gap**

*An unauthenticated enrollment steers itself to a more privileged PKI role.*

`RuleSelector`'s `cn:` selector falls back to the **CSR's** common name when
there is no authenticated certificate, and `san:` always matches against the
CSR's requested dNSNames. Both are attacker-controlled at bootstrap. If role
rules map to roles of differing privilege — a wider `allowed_domains`, a longer
`max_ttl`, a different EKU set — a client with no certificate can select among
them by choosing what to put in its CSR.

**Current mitigations.** The inventory must still admit the device, and an
inventory record's `role` overrides rule selection entirely. The constraint
policy still bounds the names independently of the role.

**This is not fixed.** Recommended handling until it is:

- Prefer `ou:`, `o:`, and `serial:` selectors, which read only from an
  authenticated certificate.
- Where roles differ in privilege, set `role` per device in the inventory rather
  than relying on rules.
- Do not run with `inventory.backend: none` and multiple roles.

The principled fix is to make selectors that read unauthenticated CSR fields
opt-in, and to refuse `cn:`/`san:` rules for unauthenticated requests by
default.

### T6 — Unverifiable client certificate degrades to anonymous (A1)

For `/simpleenroll`, a presented certificate that fails to verify against the
bootstrap anchor is logged and **ignored**, and the request proceeds as
unauthenticated rather than being rejected. This is deliberate — bootstrap may
legitimately be anonymous — but it means an expired or wrong-CA device
credential silently degrades instead of producing a clear failure. Operators
debugging "why is this device being denied" should look for
`enroll: bootstrap cert not verified, ignoring` in the logs.

---

## 5. Threats: secrets

### T7 — AppRole SecretID disclosure (A1, A4)

**Mitigations.** Never stored in the config file — only referenced by path or
env var name, with the file form preferred because env vars are visible through
`/proc`, process listings, and crash dumps. Never logged: `bao.Config.SecretID`
is documented as secret and no log statement includes it. The AppRole policy
grants only `sign`/`issue` on the broker's role and `read` on `ca_chain`, so
disclosure does not yield the CA key or the ability to alter roles. Tokens are
short-lived (20m/1h).

**Residual.** A disclosed SecretID mints certificates within the role's bounds
until rotated, and rotation requires a restart (§7, G1). The dev stack talks to
OpenBao over plaintext HTTP; production must use TLS (runbook §6) or the
SecretID and every issued certificate are on the wire.

### T8 — challengePassword disclosure (A1, A4)

The challengePassword travels inside the CSR, protected only by the TLS channel.

**Mitigations.** Compared in constant time (`subtle.ConstantTimeCompare`) in
both `StaticSecret` and `MemoryStore`, so neither leaks by timing. Never logged.

**Residual.** `StaticSecret` is one secret for the entire fleet: anyone who
learns it can enroll as any device the inventory permits, and it is replayable
indefinitely. It exists for SCEP compatibility and bootstrapping; `MemoryStore`
OTPs are the better control.

### T9 — Server-generated private key exposure (A1)

`/serverkeygen` returns a private key OpenBao generated.

**Mitigations.** Delivered only over the established TLS channel. The decoded
DER is zeroed after the response is written. The key is never logged.

**Residual.** It exists in OpenBao's memory, the response buffer, and Go's heap
before the scrub; Go's GC may have copied it. Prefer device-generated keys
(`/simpleenroll`) wherever the device can generate them.

### T10 — Fail-open challenge wiring *(found and fixed in Phase 4)*

`authz.NoChallenge` accepts unconditionally, and it was wired in as the `none`
challenge backend. Because the pipeline calls the validator whenever a challenge
is *required*, an inventory record's `require_challenge: true` — or the global
`policy.require_challenge_password` — was satisfied with no secret supplied at
all. A control operators would reasonably believe was enforcing was not.

**Fixed.** The `none` backend now yields a nil validator, which the pipeline
already treats as "a required challenge cannot be satisfied" and denies.
Config validation additionally rejects `require_challenge_password: true`
alongside `challenge.backend: none` at startup, so the contradiction surfaces
immediately rather than as runtime denials. Regression tests cover both the
pipeline contract and the config rule.

---

## 6. Threats: availability

### T11 — Cryptographic DoS (A1)

Every `/simpleenroll` POST makes the broker parse attacker-supplied ASN.1 and
verify a signature *before* authorization is possible. Proof-of-possession is
unauthenticated work by definition, and it is the expensive part.

**Mitigations.** Per-source-IP and global token buckets reject before any
parsing occurs; a concurrency semaphore bounds simultaneous in-handler work and
sheds with 503 rather than queueing unboundedly. Request bodies are capped
(256 KiB) and the cap is enforced before parsing. RSA moduli are bounded
(2048–8192) and, critically, **the key size is checked before the signature is
verified**, so an oversized modulus cannot force the expensive path. Per-call
OpenBao deadlines stop a wedged upstream from pinning request goroutines and
their concurrency slots.

Rate limiting keys on `RemoteAddr` only. Forwarded headers are deliberately
ignored: they are client-supplied, and honoring them would let any caller rotate
its own limiter key and escape the limit entirely.

**Residual.** Devices behind one NAT share a bucket and can rate-limit each
other. The bucket table is bounded (65536) with eviction, so tracking cannot
itself exhaust memory, but under heavy source-address churn eviction may hand a
fresh burst to a returning attacker. A distributed attacker below the per-client
limit is caught only by the global limiter, which sheds legitimate traffic too —
availability is preserved, fairness is not.

### T12 — Connection exhaustion (A1)

**Mitigations.** `ReadHeaderTimeout` bounds the handshake and header phase
(Slowloris), `IdleTimeout` reaps quiet keep-alives, `MaxHeaderBytes` caps header
size, and read/write timeouts bound the rest. The health listener carries the
same timeouts.

**Residual.** No cap on total concurrent connections below the handler; the
concurrency limiter bounds work, not sockets. TLS handshakes themselves are
unbounded aside from `ReadHeaderTimeout`.

### T13 — Health endpoint exposure (A1)

`/readyz` probes OpenBao and returns the underlying error, disclosing upstream
reachability and some topology. It is unauthenticated by design. Bind it to a
management interface; do not expose it beside `:8443`.

---

## 7. Known gaps and accepted risks

| # | Gap | Impact | Status |
|---|---|---|---|
| G1 | SecretID rotation needs a restart | Rotation is disruptive, so it is done rarely | Accepted |
| G2 | No revocation path in the broker | T2/T4 containment is manual | Accepted; runbook documents the `bao write <mount>/revoke` command |
| G3 | Inventory reload needs a restart (`Reload()` exists, nothing calls it) | Deprovisioning a device is not immediate | Open |
| G4 | Role selection can read unauthenticated CSR fields (T5) | Role escalation at bootstrap | **Open — see T5** |
| G5 | `MemoryStore` OTPs are process-local | No OTP support across restarts or replicas | Open; needs a shared store |
| G6 | Audit log is unauthenticated stdout | An attacker with host access can forge or drop entries | Accepted; ship off-box |
| G7 | No metrics endpoint | Rate-limit and denial trends are only visible in logs | Open (Phase 0 item 3) |
| G8 | A broad inventory glob (`cn: "*"`) silently disables the gate | Inventory stops being an authorization control | Accepted; documented |
| G9 | Empty-CN client certificates | Constraints pin an empty CN, so the CN check is skipped | Open; low impact |
| G10 | No CT logging or issuance reconciliation | Mis-issuance is detected only at the moment it happens | Accepted for now |

---

## 8. SCEP (Phase 5) — surface not yet present

Recorded here so the model is not silently outgrown. See `PLAN.md` Phase 5.

- **The broker gains a private key.** SCEP requires an RA keypair to decrypt
  requests and sign responses. "No CA key on the broker" remains true, but "no
  key at rest on the broker" stops being true, and T7's blast radius grows.
- **The request signer is self-signed and authenticates nothing.** If a PKCSReq
  signer certificate were ever treated as an authenticated identity, T1's
  mitigation inverts into a rubber stamp — `fromAuthenticatedIdentity` would pin
  issued names to attacker-chosen values. The invariant to hold: populate
  `ClientCert` only after verification against a trust anchor.
- **challengePassword becomes the only bootstrap authenticator**, making T8 the
  primary risk rather than a secondary one. Single-use OTPs, not a static
  secret.
- **Replay becomes a first-class concern.** SCEP needs a transactionID and
  senderNonce cache; EST relies on TLS for freshness and needs none.
- **T11 worsens.** Every PKIOperation POST costs an unauthenticated RSA decrypt
  plus a signature verification — strictly more than EST's PoP check — on top of
  parsing far more complex attacker-controlled ASN.1 (CMS, not just PKCS#10).
- **Legacy algorithms.** Interoperability pressure toward SHA-1 and 3DES;
  default-deny with an explicit opt-in.

---

## 9. Verification

Security-relevant behavior covered by automated tests:

| Property | Test |
|---|---|
| PoP is verified; bad signatures rejected | `est.TestParseCSRBadSignature` |
| Key size checked before signature | `est.TestKeySizeCheckedBeforeSignature` |
| Issued cert cannot exceed authorized constraints | `est.TestVerifyIssued*` (9 cases) |
| A permissive role cannot leak a substituted CN | `e2e.TestPermissiveRoleCannotSubstituteCN` (real OpenBao) |
| ...and a correct role still issues | `e2e.TestStrictRoleIssuesTheAuthorizedName` |
| Bootstrap cert cannot renew | `e2e.TestBootstrapCertCannotRenew` |
| Re-enroll requires a client cert | `e2e.TestReenrollWithoutClientCertRejected` |
| SAN escalation refused | `e2e.TestSANEscalationRejected` |
| Inventory denial | `e2e.TestDeviceNotInInventoryRejected` |
| Required challenge denies with no validator | `authz.TestNoChallengeDoesNotSatisfyARequiredChallenge` |
| Contradictory challenge config fails at startup | `config.TestRequireChallengeWithoutBackendRejected` |
| OTP is single-use and expires | `authz.TestChallengeRequiredMemoryStore` |
| A wrong secret fails even when not required | `authz.TestWrongChallengeDeniedEvenWhenNotRequired` |
| Rate limits cannot be escaped via forwarded headers | `limits.TestForwardedHeadersAreIgnored` |
| Limiter state table is bounded | `limits.TestClientTableIsBounded` |
| Body cap enforced before parsing | `est.TestRequestSizeLimitIsCheckedBeforeParsing` |
| Wedged upstream does not pin goroutines | `est.TestUpstreamTimeout` |
| OpenBao enforces domains/TTL independently | `bao.TestIntegrationOutOfPolicyDomainRejected`, `bao.TestIntegrationTTLCappedByRole` |

Run everything: `make check` (unit), then `make dev-up && make test-integration`
(live OpenBao).

**Not yet verified:** no fuzzing of the CSR/ASN.1 parsers, no load testing of
the limiter under realistic fleet churn, and no external security review.
