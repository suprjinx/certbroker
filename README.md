# certbroker

A certificate enrollment broker. Devices enrol over **EST** (RFC 7030);
certbroker decides whether each device may hold the certificate it is asking
for, then forwards a constrained issuance request to **OpenBao**'s PKI mount.

```
Device ──mTLS──▶ [L4 passthrough] ──▶ certbroker ──AppRole──▶ OpenBao pki/sign
```

## Why

Handing devices a direct path to a CA means the CA is the only thing deciding
what they may have — and a PKI role is a coarse instrument. It can say "names
under `example.com`, at most 90 days"; it cannot say "*this* device, holding
*this* bootstrap credential, may have *this* name, once."

certbroker is the **Registration Authority** that answers that question. It
holds no CA key, so compromising it does not yield one; it yields the ability to
request certificates within the bounds the AppRole policy and PKI role already
enforce.

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

EST is complete and exercised end to end against a real OpenBao. SCEP
(RFC 8894) is designed but not implemented — see `CLAUDE.md` for the decisions
already taken.

| Endpoint | |
|---|---|
| `/cacerts` | CA chain as certs-only PKCS#7 |
| `/simpleenroll` | initial enrollment, bootstrap anchor |
| `/simplereenroll` | renewal, device anchor |
| `/serverkeygen` | broker-generated key, multipart response |
| `/csrattrs` | 204 when unset |

Go 1.26. One dependency: `gopkg.in/yaml.v3`.

SCEP support is under development.

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
make test-race       # unit tests under the race detector
make vuln            # govulncheck
```

83 unit tests run hermetically with no network. A further 19 need a live OpenBao
and sit behind the `integration` build tag, so plain `go test ./...` stays clean:

```bash
make dev-up
make test-integration    # integration + E2E against the running stack
```

Integration tests skip rather than fail when `CERTBROKER_TEST_OPENBAO_ADDR` and
`CERTBROKER_TEST_OPENBAO_TOKEN` are unset. A single test:

```bash
go test ./internal/est/ -run TestVerifyIssuedCatchesSANInjection -v
```

### Interop

```bash
make dev-estclient
```

Runs [globalsign/est](https://github.com/globalsign/est)'s `estclient` — an
independent RFC 7030 implementation — against the stack in a container. It walks
cacerts → enroll → reenroll, then checks that a bootstrap certificate cannot
renew, an uninventoried CN is refused, and an unauthenticated request is refused.

This exists because `deploy/enroll.sh` drives the broker with curl and openssl:
that proves the wire format but shares our assumptions about it. A different
implementation does not.

## Layout

| Path | |
|---|---|
| `cmd/certbroker` | wiring and process lifecycle |
| `internal/est` | EST protocol: routing, CSR parsing and PoP, mTLS verification, PKCS#7, post-issuance checks |
| `internal/authz` | the policy engine: identity, inventory, challenge, role selection, constraints |
| `internal/bao` | minimal OpenBao client — AppRole lifecycle plus sign/issue/ca_chain |
| `internal/limits` | rate limiting and concurrency bounds |
| `internal/config` | YAML load and validate |
| `internal/pkcs7` | certs-only SignedData encoder |
| `deploy/` | compose stack, dev PKI, OpenBao provisioning, interop client |
| `docs/` | runbook and threat model |

## Configuration

Schema: [`internal/config/config.go`](internal/config/config.go).
Worked example: [`deploy/config.yaml`](deploy/config.yaml).

Secrets are never written in the config file — it carries a file path
(`secret_id_file`, preferred) or an environment variable name. Configuration is
validated at startup and unknown keys are rejected, so a typo fails loudly
instead of silently disabling a control.

## Security

[`docs/threat-model.md`](docs/threat-model.md) records the adversary model, 14
numbered threats with mitigations and residual risk, and a table of known gaps.
Read it before changing anything in `internal/authz` or `internal/est`.

Two findings from its own review are worth knowing up front:

- OpenBao PKI roles default to `use_csr_sans=true` and
  `use_csr_common_name=true`, which **merge** the CSR's names with the broker's
  constrained parameters instead of replacing them. Every role must set both
  false. The broker independently re-checks each issued certificate and
  withholds an over-broad one.
- An inventory allowlist is not an authenticator. Enrollment requires a verified
  client certificate or a validated challengePassword; open enrollment is
  available but must be turned on deliberately.

## Documentation

| | |
|---|---|
| [`docs/runbook.md`](docs/runbook.md) | operating: endpoints, config, routine tasks, hardening checklist, troubleshooting, client interop |
| [`docs/threat-model.md`](docs/threat-model.md) | assets, trust boundaries, threats, known gaps |
| [`CLAUDE.md`](CLAUDE.md) | orientation for Claude Code, including SCEP decisions already taken |
