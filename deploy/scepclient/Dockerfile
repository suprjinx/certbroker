# sscep (certnanny) — an independent C implementation of RFC 8894, standing in
# for a real network device's SCEP client.
#
# Same reasoning as deploy/estclient: a client that shares none of our code
# tests the protocol rather than our assumptions about it. Vendor images (Cisco
# XRd, FortiGate-VM) are licensed and cannot live in a self-contained stack.

FROM debian:bookworm-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         git ca-certificates build-essential autoconf automake libtool \
         pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/certnanny/sscep.git /src \
    && cd /src && ./bootstrap.sh && ./configure && make

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/sscep /usr/local/bin/sscep
COPY enroll.sh /usr/local/bin/enroll.sh
RUN chmod +x /usr/local/bin/enroll.sh

ENTRYPOINT ["/usr/local/bin/enroll.sh"]
