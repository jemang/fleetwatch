GO_IMAGE := golang:1.27.1-bookworm
GO_RUN := docker run --rm -v "$(CURDIR)":/src -w /src -v fleetwatch-gomod:/go/pkg/mod -v fleetwatch-gocache:/root/.cache/go-build $(GO_IMAGE)
PKG ?= ./...
IMAGE ?= ghcr.io/jemang/fleetwatch-hub
# The version to publish: FLEETWATCH_VERSION from deploy/.env unless given on the command line.
VERSION ?= $(or $(shell sed -n 's/^FLEETWATCH_VERSION=//p' deploy/.env 2>/dev/null),0.1.0)
IMAGE_BUILD := docker buildx build -f deploy/Dockerfile.hub --build-arg VERSION=$(VERSION) \
	--secret id=signing_key,src=release/signing-key.pem -t $(IMAGE):$(VERSION) .

.PHONY: test vet tidy get build release-key image image-local
test:
	$(GO_RUN) go test -race -count=1 $(PKG)
vet:
	$(GO_RUN) go vet ./...
tidy:
	$(GO_RUN) go mod tidy
get:
	$(GO_RUN) go get $(MOD)
build:
	$(GO_RUN) sh -c 'CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/ ./cmd/...'
# Makes the release signing key once. The private key stays in release/, which
# is in no repository and no image; the public key is compiled into the binaries.
release-key:
	$(GO_RUN) go run ./cmd/fleetwatch-release keygen --key release/signing-key.pem --pub internal/release/pubkey/pubkey.pem
# Publishes the Hub image for both processor types. Needs `docker login ghcr.io`
# and a buildx builder that can push multi-platform images (docker-container driver).
image:
	$(IMAGE_BUILD) --platform linux/amd64,linux/arm64 -t $(IMAGE):latest --push
# The same image for this machine only, loaded into the local Docker.
image-local:
	$(IMAGE_BUILD) --load
