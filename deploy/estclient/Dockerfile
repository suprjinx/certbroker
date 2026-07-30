# An independent EST client for interop testing, from globalsign/est.
#
# Deliberately NOT our own code: deploy/enroll.sh drives the broker with curl and
# openssl, which proves the wire format but shares our assumptions about it. A
# third-party RFC 7030 implementation does not.
#
# The realistic stand-in for a Cisco IOS XR/XE or FortiGate client: those images
# are licensed and only downloadable from the vendor with an entitled account,
# so they cannot be pulled in a self-contained compose stack. See the runbook.

FROM golang:1.26 AS build
RUN GOBIN=/out go install github.com/globalsign/est/cmd/estclient@latest

FROM debian:bookworm-slim
# openssl generates the device key and CSR, the way a real device would do
# internally; estclient speaks only the EST protocol.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/estclient /usr/local/bin/estclient
COPY enroll.sh /usr/local/bin/enroll.sh
RUN chmod +x /usr/local/bin/enroll.sh

ENTRYPOINT ["/usr/local/bin/enroll.sh"]
