# certbroker threat model

Scope: the enrollment broker as of Phase 5 — EST and SCEP. Sections 1–7 apply to
both; §8 covers what SCEP adds, since it drops mTLS and gives the broker a key
of its own. Operational guidance lives in [`runbook.md`](runbook.md).

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
| SCEP RA key | mounted file, SCEP only | Decrypt enrollment requests in flight and sign responses as the broker — so harvest challengePasswords and hand devices a CA chain of the attacker's choosing |
| challengePassword secrets | config env / memory store | Enroll as any device the inventory permits |
| Server-generated device keys | transient, `/serverkeygen` only | Impersonate that device |
| Audit log | stdout | Discloses fleet inventory and enrollment patterns |

---

## 2. Trust boundaries

```
                    ┌── boundary A: the public/device network
                    │
   Device ──mTLS───▶│  L4 passthrough  ──▶  certbroker
      (EST, :8443)  │                          │
                    │                          │
   Device ──────────┼──────────────────────────┤
     (SCEP, :8080)  │                          │
                    └──────────────────────────┼── boundary B: broker → OpenBao
                                               ▼
                                            OpenBao
```

**Boundary A** is the hostile one. Everything arriving is attacker-controlled:
the CSR, the challengePassword, the client certificate, the TLS parameters, the
request body and headers. The client certificate is *evidence*, not identity,
until it verifies against a configured anchor.

The SCEP listener sits on the same boundary with less protecting it. There is no
TLS, so nothing about the transport is authenticated in either direction and
anyone on the path can read and alter what goes by; all the protection is in the
CMS layer the device signs and encrypts for itself. Bind it to a network you
already trust, and treat "who is on that network" as part of the control.

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
2. **Detect** — `internal/authz/verify.go` re-parses every issued certificate and
   compares its CN, DNS/IP/URI SANs, and lifetime against what the authorizer
   approved. A mismatch means the certificate is withheld (502), logged at ERROR
   with the serial for revocation, and the operator is pointed at the role
   setting. Roles are externally managed and opaque to the broker, so it cannot
   repair them — it refuses to launder them.

**Residual.** The certificate is *already issued* when the check fires; only its
delivery is prevented. The serial is logged so it can be revoked, but revocation
is manual (§7, G2). Name checking is all-or-nothing: once a decision names any
subject, a name type it left empty permits none of that type, and only a wholly
empty decision — policy deliberately deferring to the role — skips the name
checks entirely. The TTL cap applies either way.

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

### T14 — Authorization without authentication (A1)

*An enrollment proves nothing and is authorized anyway.*

`/simpleenroll` accepts a connection with no client certificate, because a
bootstrapping device may not have one. The intended authenticator in that case
is the challengePassword. Nothing originally enforced that: with no certificate,
no challenge configured, and a file inventory carrying `allowed_dns`, the
pipeline authorized on the strength of an inventory hit alone.

That is authorization without authentication. The inventory matches on a CN the
**requester supplies**; it answers "is this name permitted?" and never "are you
that device?". Worse, the hole opened exactly when an operator did the thing the
runbook recommends — configuring an inventory — while the `none` default
happened to be safe.

**Mitigation.** Pipeline stage 5 denies when there is neither a verified client
certificate nor a validated non-empty challenge, unless
`policy.allow_unauthenticated_enrollment` is explicitly set. Open enrollment
remains supported for trusted provisioning networks, but is now a deliberate
choice logged at WARN on startup. Covered by
`authz.TestUnauthenticatedEnrollmentGate` and `make dev-estclient` step 7.

**Residual.** With the flag set, anyone who can reach the listener may enrol any
name the inventory and role permit. That is the intent of the mode; the network
boundary becomes the control.

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

The challengePassword travels inside the CSR. Under EST the TLS channel is the
only thing protecting it; under SCEP it is the CMS envelope encrypted to the RA
certificate, so anyone holding the RA key can read it (§8).

**Mitigations.** Compared in constant time (`subtle.ConstantTimeCompare`) in
both `StaticSecret` and `MemoryStore`, so neither leaks by timing. Never logged.

**Residual.** `StaticSecret` is one secret for the entire fleet: anyone who
learns it can enroll as any device the inventory permits, and it is replayable
indefinitely. `MemoryStore` OTPs are the better control, and under SCEP the
difference matters more — there the challengePassword is the *only* thing
authenticating a first enrollment, so this threat carries weight it does not
carry under EST.

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

SCEP costs more per request. A `PKIOperation` makes the broker parse a CMS
envelope — a good deal more complex than a bare PKCS#10 — then RSA-decrypt it
with the RA key and verify a signature, all before it knows who is asking.

**Mitigations.** The SCEP listener runs behind the same limiter as EST, so the
paragraphs below cover both. Per-source-IP and global token buckets reject
before any parsing occurs; a concurrency semaphore bounds simultaneous
in-handler work and sheds with 503 rather than queueing unboundedly. Request
bodies are capped (256 KiB for EST, 512 KiB for SCEP, which has to carry the
envelope) and the cap is enforced before parsing. The CMS digest algorithm is
checked against the allowlist before any signature is verified, the same
cheap-check-first ordering the key size gets. RSA moduli are bounded
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
availability is preserved, fairness is not. The two listeners share one limiter
but not one cost: the same rate buys an attacker more work through SCEP than
through EST, so size the limits for the SCEP figure when both are on.

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
| G11 | OpenBao retries are not idempotency-aware | A network error after signing makes the retry issue a second certificate — constrained, but absent from the audit log | Open; fixing it means dropping retries on POST or tracking issuance out of band |
| G12 | HTTP Basic (RFC 7030 §3.2.3) is not implemented | A client configured with only a username/password cannot enrol: the credential is not read, so the authentication gate refuses it. Fails closed, but the refusal reason will not mention the password | Mitigated by T14; implementing Basic against the challenge backend remains open |
| G13 | The SCEP replay cache lives in one process's memory | A restart, or a second replica, forgets what it has already answered, so a captured request becomes replayable again within its TTL | Open; same shared-store problem as G5 |
| G14 | No SCEP CA rollover (`GetNextCACert` is not advertised or served) | Devices cannot be handed the next CA certificate ahead of a changeover, so renewals have to be timed around it by hand | Accepted for now |
| G15 | SCEP failure responses carry a generic `badRequest` and no reason | An operator reading a device's log cannot tell why an enrollment was refused; the reason is only in the broker's audit log | Accepted — deliberate, so a prober learns nothing |

---

## 8. What SCEP adds (Phase 5)

SCEP is implemented and off by default (`scep.enabled`). It reuses the whole
authorization pipeline — the policy engine cannot tell the two protocols apart —
so §§4–6 apply unchanged. What follows is the part that is genuinely different,
and it all comes from two facts: there is no TLS, and the broker now holds a key.

**The broker holds a private key.** SCEP needs an RA keypair to decrypt requests
and sign responses. "No CA key on the broker" is still true; "no key at rest on
the broker" is not, and T7's blast radius grows to match — see the RA key row in
§1. Someone holding it can read every challengePassword in flight and sign
responses as the broker.

**A first request proves nothing about who sent it.** A `PKCSReq` is signed with
a certificate the device made for itself, which anyone can do. The handler never
puts that certificate in `Request.ClientCert`, so the policy engine treats the
request as unauthenticated and refuses to pin any issued name to it. Were that
to change, T1's mitigation would invert into a rubber stamp: the broker would
be pinning names to a value the attacker chose. `RenewalReq` is the opposite
case — its signer is the device's current certificate, verified against the
device anchor before anything else happens, which is what makes T4 hold here.

**So the challengePassword carries the whole load at bootstrap.** With no mTLS
and a signer that proves nothing, it is the only authenticator a new device has.
Config validation refuses to start SCEP with no challenge backend unless
`policy.allow_unauthenticated_enrollment` is set explicitly. T8 is therefore a
primary risk under SCEP rather than a secondary one, and a fleet-wide
`StaticSecret` is a poor fit: prefer single-use OTPs.

**Replay needs answering directly.** EST gets freshness from TLS. A SCEP message
is valid wherever and whenever it is replayed, so the broker records each
transactionID/senderNonce pair on first sight and refuses it thereafter —
checked before any issuance work, so a request that fails downstream is not
retryable either. The cache is bounded (100k entries, 15m TTL by default) and
process-local, which is G13.

**Algorithm choice is not the client's to make.** `GetCACaps` advertises SHA-256,
SHA-512 and AES and nothing weaker; content encryption is pinned to AES-256-CBC
rather than the library default of DES. SHA-1 is refused unless `allow_sha1` is
turned on deliberately, and the digest is checked against the allowlist before
any signature is verified.

**Everything else is deliberately absent.** `GetCertInitial`, `GetCert` and
`GetCRL` are refused: issuance is synchronous, so nothing is ever pending, and
each unimplemented operation is one less parser exposed to boundary A.
`GetNextCACert` is not offered either, which is G14.

---

## 9. Verification

Security-relevant behavior covered by automated tests:

| Property | Test |
|---|---|
| PoP is verified; bad signatures rejected | `est.TestParseCSRBadSignature` |
| Key size checked before signature | `est.TestKeySizeCheckedBeforeSignature` |
| Issued cert cannot exceed authorized constraints | `authz.TestVerifyIssued*` (9 cases) |
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

SCEP (§8):

| Property | Test |
|---|---|
| A self-signed `PKCSReq` signer is not an identity | `scep.TestPKCSReqSignerIsNotAuthenticated` |
| A `RenewalReq` signer is, once it verifies | `scep.TestRenewalReqSignerIsAuthenticated` |
| ...and is refused when it does not | `scep.TestRenewalReqWithUntrustedSignerRejected` |
| A replayed message is rejected | `scep.TestReplayRejected` |
| The handler will not start without a replay cache | `scep.TestNewHandlerRequiresReplayCache` |
| Denials return a failure carrying no reason | `scep.TestAuthorizationDenialReturnsFailure`, `scep.TestFailureLeaksNoReason` |
| Constraints reach the issuer, and an over-broad cert is withheld | `scep.TestConstraintsSentToIssuer`, `scep.TestVerifyIssuedWithholdsOverBroadCert` |
| No weak algorithm is advertised | `scep.TestGetCACapsOmitsWeakAlgorithms` |
| SHA-1 refused by default, allowed only on request | `cms.TestSHA1RejectedByDefault`, `cms.TestSHA1AcceptedWhenExplicitlyAllowed` |
| Digest checked before signature | `cms.TestDigestCheckedBeforeSignature` |
| "Signature intact" stays separate from "signer trusted" | `cms.TestVerifySignatureAcceptsSelfSigned`, `cms.TestVerifyChainRejectsSelfSigned` |
| Content encryption is AES, not the library's DES default | `cms.TestContentEncryptionIsAES` |
| Decryption failures are opaque | `cms.TestDecryptErrorIsOpaque` |
| Body cap, nonce and transactionID bounds enforced | `scep.TestOversizedBodyRejected`, `scep.TestShortNonceRejected`, `scep.TestOversizedTransactionIDRejected` |
| Unsupported operations and message types refused | `scep.TestUnknownOperationRejected`, `scep.TestUnsupportedMessageTypeRejected` |

Run everything: `make check` (unit), then `make dev-up && make test-integration`
(live OpenBao). `make dev-estclient` and `make dev-scepclient` additionally drive
both protocols with independent third-party clients.

**Not yet verified:** no fuzzing of the CSR, CMS or ASN.1 parsers — a larger gap
now that SCEP parses attacker-controlled CMS through a third-party library — no
load testing of the limiter under realistic fleet churn, and no external
security review.

One rule in §8 has no test behind it: config validation refuses to enable SCEP
with no challenge backend (`config.go`), but nothing pins that, so removing it
would go unnoticed. It is the startup guard for the bootstrap authenticator and
deserves the same treatment `TestRequireChallengeWithoutBackendRejected` gives
its EST counterpart.
