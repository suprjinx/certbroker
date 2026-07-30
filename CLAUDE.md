# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make check              # fmt + vet + test — what CI runs; run before proposing a change is done
make test               # unit tests only (hermetic, no network)
make test-race          # unit tests under the race detector
make build              # binary into ./bin
make vuln               # govulncheck (installs on demand)
```

Single test / single package:

```bash
go test ./internal/est/ -run TestVerifyIssuedCatchesSANInjection -v
go test ./internal/authz/ -v
```

Integration and E2E tests need a live OpenBao and are behind the `integration`
build tag, so plain `go test ./...` stays hermetic:

```bash
make dev-up             # gen dev certs, build image, start OpenBao + broker, wait for /readyz
make test-integration   # runs ./... with -tags=integration against the dev stack
make dev-enroll         # real EST enroll + re-enroll via curl/openssl
make dev-logs
make dev-down           # stops and deletes volumes
```

`make test-integration` passes `CERTBROKER_TEST_OPENBAO_ADDR` and
`CERTBROKER_TEST_OPENBAO_TOKEN`; without them those tests skip rather than fail.
To run one directly:

```bash
CERTBROKER_TEST_OPENBAO_ADDR=http://localhost:8200 \
CERTBROKER_TEST_OPENBAO_TOKEN=dev-root-token \
  go test -tags=integration -count=1 ./test/e2e/ -run TestEnrollThenReenroll -v
```

## What this is

certbroker is a **Registration Authority**, not a CA. It authenticates enrolling
devices over EST (RFC 7030), decides whether each may hold the certificate it is
asking for, and forwards a *constrained* issuance request to OpenBao's PKI mount.
It holds no CA key.

```
Device --mTLS--> [L4 passthrough] --> certbroker --AppRole--> OpenBao pki/sign
```

The loss condition is never "attacker steals the CA" — it is "attacker obtains a
certificate naming something they are not." Read `docs/threat-model.md` before
changing anything in `internal/authz` or `internal/est`.

## Architecture

Dependency direction is one-way: `cmd/certbroker` wires everything;
`internal/est` depends on `authz`, `bao`, `pkcs7`; `internal/authz`,
`internal/limits`, `internal/config`, `internal/pkcs7` depend on nothing internal.
Keep it that way — `config` in particular is a leaf and should stay one.

| Package | Role |
|---|---|
| `internal/est` | EST protocol: routing, CSR parsing/PoP, mTLS peer verification, PKCS#7 responses, post-issuance verification |
| `internal/authz` | The policy engine — identity resolution, inventory, challenge, role selection, constraint building |
| `internal/bao` | Minimal OpenBao client: AppRole auth + token lifecycle, `sign`/`issue`/`ca_chain`. Deliberately not the full SDK |
| `internal/limits` | Token-bucket rate limiting + concurrency cap, wrapped *outside* the EST handler |
| `internal/config` | YAML load + validate. Secrets are referenced by path or env var name, never inlined |
| `internal/pkcs7` | Certs-only (degenerate) SignedData encoder. Encode only; no parsing |
| `internal/baotest` | Provisions an isolated PKI mount + AppRole on a live OpenBao for integration tests |

### The authorization seam

This is the design's spine and spans several files. Protocol handlers **never**
call OpenBao with attributes taken from a CSR. They build an `authz.Request`, ask
an `Authorizer` for a `Decision`, and pass the decision's role and constraints to
the issuer. `authz.Pipeline` is the production implementation and runs seven
stages — identity → reenroll-must-auth → inventory → challenge → authenticated?
→ role → constraints — every one of which must pass.

Adding a protocol (SCEP) means building an `authz.Request` and honoring the
`Decision`; it does not mean touching the policy engine.

### Invariants

Breaking any of these is a security regression, not a style question:

- **`Request.ClientCert` is set only after verification against a trust anchor.**
  An unverifiable certificate yields `(nil, nil)` — an unauthenticated request —
  never a populated-but-untrusted identity. `resolveIdentity` keys
  `Identity.Authenticated` off this, and `StandardConstraints` pins issued names
  to it. Populate it from an unverified certificate and identity continuity
  inverts into a rubber stamp.
- **Two trust anchors stay distinct.** Bootstrap CA gates first enrollment;
  device CA gates renewal. Merging them makes a factory credential a permanent
  renewal credential.
- **Fail closed.** Nil authorizer → `DenyAll`. Nil challenge validator with a
  required challenge → deny (this is why the `none` backend wires `nil`, *not*
  `NoChallenge{}`, which accepts unconditionally). No role → deny. Unknown SAN
  mode → deny.
- **Never trust the CSR's subject/SANs.** Re-derive or constrain them from the
  authenticated identity and policy first.
- **An inventory hit is not authentication.** It matches a CN the requester
  supplied. Pipeline stage 5 requires a verified certificate or a validated
  challenge; open enrollment needs `policy.allow_unauthenticated_enrollment`.
- **Two enforcement layers.** The broker constrains what it *asks for*; the
  OpenBao role constrains what it will *grant*. Neither is the sole gate.
- **RSA key size is checked before signature verification.** PoP is
  unauthenticated work; an oversized modulus must be rejected on the cheap path.
- **Rate limiting keys on `RemoteAddr` only.** Forwarded headers are
  client-supplied and would let a caller rotate its own limiter key.

### `verifyIssued` and the `use_csr_*` trap

OpenBao PKI roles default to `use_csr_sans=true` and `use_csr_common_name=true`,
which **merge** the CSR's own names with the parameters the broker sends rather
than replacing them. Roles must set both to `false`
(`deploy/provision-openbao.sh` does). Because roles are externally managed and
opaque to the broker, `internal/est/verify.go` independently re-checks every
issued certificate against the approved decision and withholds an over-broad one.
Name checking is all-or-nothing: once a decision names any subject, a name type
it left empty permits *none* of that type.

## Design decisions

| Area | Choice |
|---|---|
| Language | Go 1.26 |
| Protocols | EST (RFC 7030) now, SCEP (RFC 8894) later |
| OpenBao auth | AppRole, short-lived tokens |
| Deployment | Container/VM behind an **L4 passthrough** proxy; TLS terminates in-app so client certs survive |
| AuthZ | mTLS cert **+** challengePassword **+** inventory allowlist **+** CSR constraint policy |
| OpenBao config | Managed **externally**. The broker never creates or modifies roles and treats role names as opaque config |
| Dependencies | Only `gopkg.in/yaml.v3`. Prefer stdlib; a third-party crypto/CMS dependency needs a deliberate decision |

## Conventions

- **Comments are at most 2 lines.** Condense rather than expand; put longer
  rationale in `docs/`.
- Comments should carry the *why* — the non-obvious hazard, the reason an
  ordering matters — not restate the code.
- Tests that pin a security property should say what breaks if the property
  fails, and be written so they fail against the pre-fix code.
- `docs/threat-model.md` numbers threats (T*) and known gaps (G*); reference
  those identifiers from code comments rather than re-explaining.

## Phase 5 — SCEP, decisions already taken

Not implemented. These were settled and should not be relitigated without cause:

- **CMS via `github.com/smallstep/pkcs7`.** The alternative is ~2k lines of
  hand-rolled ASN.1 parsing of unauthenticated attacker-controlled input.
- **The broker gains an RA keypair** (RSA — clients do RSA key transport) to
  decrypt requests and sign responses. "No CA key on the broker" still holds;
  "no key at rest" stops holding. `GetCACert` must return RA + CA chain.
- **A PKCSReq's signer certificate is self-signed and authenticates nothing.**
  It must not populate `ClientCert`. `RenewalReq` is different: its signer is the
  current device certificate, so verify it against the device anchor first.
- **challengePassword becomes the only bootstrap authenticator**, so force it on
  and prefer single-use OTPs over a fleet-wide static secret.
- SCEP needs a transactionID/senderNonce replay cache; EST relies on TLS for
  freshness and needs none.
- SCEP has no `serverkeygen` equivalent, and staying synchronous means no
  `GetCertInitial`/PENDING.

`docs/threat-model.md` §8 covers the security surface SCEP adds.
