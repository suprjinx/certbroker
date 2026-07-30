SHELL := /bin/bash

BINARY  := certbroker
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMPOSE := docker compose -f deploy/docker-compose.yml

# Where `make test-integration` finds the dev OpenBao. Override for another target.
BAO_ADDR  ?= http://localhost:8200
BAO_TOKEN ?= dev-root-token

.DEFAULT_GOAL := help

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | column -t -s ':'

## build: compile the broker binary into ./bin
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/certbroker

## test: run unit tests
test:
	go test ./...

## test-race: run unit tests under the race detector
test-race:
	go test -race ./...

## test-integration: run tests against the running dev stack (make dev-up first)
test-integration:
	CERTBROKER_TEST_OPENBAO_ADDR=$(BAO_ADDR) \
	CERTBROKER_TEST_OPENBAO_TOKEN=$(BAO_TOKEN) \
	go test -tags=integration -count=1 ./...

## cover: run tests and open a coverage summary
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

## vet: go vet
vet:
	go vet ./...

## fmt: gofmt -l, non-zero if anything is unformatted
fmt:
	@out=$$(gofmt -l . ); if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

## vuln: govulncheck (installs on demand)
vuln:
	@command -v govulncheck >/dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

## check: fmt + vet + test — what CI runs
check: fmt vet test

## image: build the container image
image:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) -t $(BINARY):latest .

## certs: generate dev key material into deploy/pki
certs:
	./deploy/gen-certs.sh

## dev-up: build and start the local OpenBao + broker stack
dev-up: certs
	$(COMPOSE) up --build -d openbao provision certbroker
	$(COMPOSE) run --rm healthcheck

## dev-down: stop the stack and remove its volumes
dev-down:
	$(COMPOSE) down -v

## dev-logs: follow broker logs
dev-logs:
	$(COMPOSE) logs -f certbroker

## dev-enroll: run a real EST enrollment against the running stack (curl/openssl)
dev-enroll:
	./deploy/enroll.sh

## dev-estclient: interop run against the stack using an independent EST client
dev-estclient:
	$(COMPOSE) run --rm --build -e EXPECT_OPEN estclient

## clean: remove build output and generated dev material
clean:
	rm -rf bin coverage.out deploy/pki

.PHONY: help build test test-race test-integration cover vet fmt vuln check image certs dev-up dev-down dev-logs dev-enroll dev-estclient clean
