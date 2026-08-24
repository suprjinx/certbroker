# certbroker

A certificate enrollment broker. Devices enroll over **EST** (RFC 7030) or
**SCEP** (RFC 8894); certbroker decides whether each device may hold the
certificate it is asking for, then forwards a constrained issuance request to
**OpenBao**'s PKI mount.

```
Device ──mTLS, EST─────▶ [L4 passthrough] ─┐
                                           ├─▶ certbroker ──AppRole──▶ OpenBao pki/sign
Device ──CMS/HTTP, SCEP────────────────────┘
```

## Why

For devices that support EST or SCEP, we can issue certificates from Openbao. This is essentially
glue-code until such time as the support is added to OpenBao. See these issues for status:
- [OpenBao Issue #1222](https://github.com/openbao/openbao/issues/1222)
- [OpenBao Issue #1605]( https://github.com/openbao/openbao/issues/1605)


## Design goals

- **Never trust the CSR's subject or SANs.** Names are re-derived from the
  authenticated identity and policy, never copied from the request.
- **Two distinct trust anchors.** A bootstrap CA gates first enrollment; the CA
  that issued the device's current certificate gates renewal. A factory
  credential must not be a permanent renewal credential.
- **Authorization is never authentication.** An allowlist hit on a name the
  requester supplied proves nothing about who is asking.
- **Fail closed.** Every stage denies on any gap: no authorizer, no validator
  for a required challenge, no role, no recognised policy mode.
- **Defense in depth, verified.** The OpenBao role is a second enforcement
  layer, not the only one — and the broker re-checks what it gets back.
- **OpenBao stays externally managed.** certbroker never creates or modifies
  roles; role names are opaque configuration.

## Status

Both protocols are complete and exercised end to end against a real OpenBao,
each also driven by an independent third-party client.

### EST (RFC 7030) — mTLS, `:8443`

| Endpoint | |
|---|---|
| `/cacerts` | CA chain as certs-only PKCS#7 |
| `/simpleenroll` | initial enrollment, bootstrap anchor |
| `/simplereenroll` | renewal, device anchor |
| `/serverkeygen` | broker-generated key, multipart response |
| `/csrattrs` | 204 when unset |

### SCEP (RFC 8894) — plain HTTP, `:8080`, **off by default**

| `?operation=` | |
|---|---|
| `GetCACert` | RA certificate first, then the CA chain, as certs-only CMS |
| `GetCACaps` | `POSTPKIOperation`, `Renewal`, `SHA-256`, `SHA-512`, `AES`, `SCEPStandard` |
| `PKIOperation` | `PKCSReq` enrollment and `RenewalReq` renewal |

Plain HTTP is deliberate — SCEP carries its own CMS signing and encryption — so
bind the listener to a trusted network. The advertised capabilities are
conservative: no SHA-1, no DES, and no `GetNextCACert` because there is no
rollover support. `GetCertInitial`, `GetCert`, and `GetCRL` are refused;
issuance is synchronous, so nothing is ever pending.

Go 1.26. Two dependencies: `gopkg.in/yaml.v3`, and `github.com/smallstep/pkcs7`
for CMS — the alternative was hand-rolling ASN.1 parsing of unauthenticated,
attacker-controlled input.

## Quickstart

Requires Docker with Compose v2, `openssl`, `curl`, and `make`.

```bash
make dev-up        # dev certs, build image, start OpenBao + broker, wait for /readyz
make dev-enroll    # real EST enroll + re-enroll (curl + openssl)
make dev-down      # stop and delete volumes
```

`make dev-up` generates a bootstrap CA and device certificate, starts a dev-mode
OpenBao, provisions a PKI mount with a least-privilege AppRole, and brings up the
broker. It is **not** a security demonstration: dev-mode OpenBao is in-memory,
auto-unsealed, and reachable over plaintext HTTP. Read the runbook's
"Before deploying anywhere real" checklist first.

## Tests

```bash
make check           # gofmt + go vet + unit tests — the CI gate
make test            # unit tests
make test-race       # unit tests under the race detector
make vuln            # govulncheck
```

Unit tests run standalone. Integration tests need a live OpenBao and sit behind the
`integration` build tag.

```bash
make dev-up
make test-integration    # integration + E2E against the running stack
```

Integration tests skip rather than fail when `CERTBROKER_TEST_OPENBAO_ADDR` and
`CERTBROKER_TEST_OPENBAO_TOKEN` are unset. A single test:

```bash
go test ./internal/authz/ -run TestVerifyIssuedCatchesSANInjection -v
```

### Interop

```bash
make dev-estclient     # EST,  globalsign/est container
make dev-scepclient    # SCEP, certnanny/sscep container (needs scep.enabled)
```

Each runs an independent implementation of the protocol against the stack in a
container. [globalsign/est](https://github.com/globalsign/est)'s `estclient`
walks cacerts → enroll → reenroll, then checks that a bootstrap certificate
cannot renew, an uninventoried CN is refused, and an unauthenticated request is
refused. [certnanny/sscep](https://github.com/certnanny/sscep) — a C client,
sharing no code or language with the broker — walks getcaps → getca → enroll,
asserts no weak algorithm is advertised and that an RA certificate is returned,
then checks that enrollment is refused with no challengePassword, with the wrong
one, and for an uninventoried CN.

Both distinguish a refusal from a rate-limit response, so a negative case cannot
pass for the wrong reason. [`docs/runbook.md`](docs/runbook.md) §9 covers what
each step asserts, which CNs the dev inventory permits, and the known vendor
client incompatibilities.

This exists because `deploy/enroll.sh` drives the broker with curl and openssl:
that proves the wire format but shares our assumptions about it. A different
implementation does not.

## Layout

| Path | |
|---|---|
| `cmd/certbroker` | wiring and process lifecycle |
| `internal/est` | EST protocol: routing, CSR parsing and PoP, mTLS verification, PKCS#7 |
| `internal/scep` | SCEP protocol: operation routing, CMS request parsing, signed `CertRep`, replay cache |
| `internal/cms` | CMS for SCEP over `smallstep/pkcs7` — digest allowlist, "signature intact" kept separate from "signer trusted" |
| `internal/authz` | the policy engine: identity, inventory, challenge, role selection, constraints, post-issuance checks |
| `internal/bao` | minimal OpenBao client — AppRole lifecycle plus sign/issue/ca_chain |
| `internal/limits` | rate limiting and concurrency bounds |
| `internal/config` | YAML load and validate |
| `internal/pkcs7` | certs-only SignedData encoder |
| `deploy/` | compose stack, dev PKI, OpenBao provisioning, EST and SCEP interop clients |
| `docs/` | runbook and threat model |

## Configuration

Schema: [`internal/config/config.go`](internal/config/config.go).
Worked example: [`deploy/config.yaml`](deploy/config.yaml).

Secrets are never written in the config file — it carries a file path
(`secret_id_file`, preferred) or an environment variable name. Configuration is
validated at startup and unknown keys are rejected, so a typo fails loudly
instead of silently disabling a control.

SCEP stays off until `scep.enabled` is set. Turning it on also needs
`ra_cert_file` and `ra_key_file` — `make dev-up` generates a dev pair via
`deploy/gen-certs.sh`.

## Security

[`docs/threat-model.md`](docs/threat-model.md) records the adversary model, 14
numbered threats with mitigations and residual risk, and a table of known gaps.
Read it before changing anything in `internal/authz`, `internal/est`, or
`internal/scep`. §8 covers what SCEP adds on top of EST.

Findings worth knowing up front:

- OpenBao PKI roles default to `use_csr_sans=true` and
  `use_csr_common_name=true`, which **merge** the CSR's names with the broker's
  constrained parameters instead of replacing them. Every role must set both
  false. The broker independently re-checks each issued certificate and
  withholds an over-broad one.
- An inventory allowlist is not an authenticator. Enrollment requires a verified
  client certificate or a validated challengePassword; open enrollment is
  available but must be turned on deliberately.
- **SCEP is weaker than EST for a device's first enrollment.** There is no mTLS,
  and the certificate a device signs that first request with is one it made up
  itself — anyone can do that, so the broker ignores it when deciding who is
  asking. The challengePassword is then the only thing proving anything. Give
  each device its own single-use password rather than sharing one across the
  fleet. Renewal is stronger: the device signs with the certificate it already
  has, and the broker checks that against the device CA.
- **Turning SCEP on puts a private key on the broker.** SCEP needs an RSA key of
  its own to decrypt requests and sign replies. The broker still holds no CA
  key, but it is no longer keyless.
- **SCEP needs replay protection and EST does not.** EST gets that from TLS.
  SCEP has none, so the broker remembers the transaction ID and sender nonce
  from each request and refuses a repeat — before it does any issuing work.

## Documentation

| | |
|---|---|
| [`docs/runbook.md`](docs/runbook.md) | operating: endpoints, config, routine tasks, hardening checklist, troubleshooting, client interop |
| [`docs/threat-model.md`](docs/threat-model.md) | assets, trust boundaries, threats, known gaps |
| [`CLAUDE.md`](CLAUDE.md) | orientation for Claude Code: architecture, security invariants, conventions |
