# syntax=docker/dockerfile:1

# --- build stage ---------------------------------------------------------
FROM golang:1.26 AS build

WORKDIR /src

# Dependencies first so the module cache survives source edits.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a fully static binary, which is what lets the runtime
# stage be distroless/static (no libc, no shell, no package manager).
# -trimpath keeps build-host paths out of the binary.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/certbroker ./cmd/certbroker

# Verify the tests pass in the same environment that produced the binary.
RUN go vet ./... && go test ./...

# --- runtime stage -------------------------------------------------------
# distroless/static: no shell, no package manager, no setuid binaries. The
# :nonroot tag runs as uid 65532 and is the reason no USER directive is needed
# beyond the explicit one below (kept for clarity and for scanners).
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/certbroker /usr/local/bin/certbroker

USER 65532:65532

# EST/mTLS listener and the health/metrics listener.
EXPOSE 8443 9090

ENTRYPOINT ["/usr/local/bin/certbroker"]
CMD ["-config", "/etc/certbroker/config.yaml"]
