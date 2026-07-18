# Build targets for host tools and container image.
# See `make help` for usage.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
PROJECT_NAME := nfs-klldap-host
# Branch-as-version convention: a branch named like a version (leading digit,
# e.g. 0.9.96, 1.0) IS the version; anything else (main, detached) falls back
# to git describe. Mirrors build-support/version-stamp.rs (the in-app stamp).
# if/grep, not case: an unbalanced ")" would end the $(shell ...) call early.
VERSION ?= $(shell b=$$(git rev-parse --abbrev-ref HEAD 2>/dev/null); if printf '%s' "$$b" | grep -q '^[0-9]'; then printf '%s\n' "$$b"; else git describe --tags --always --dirty 2>/dev/null || echo "dev"; fi)

# Docker image
IMAGE_NAME ?= nfs-klldap-host
REGISTRY ?= ghcr.io/aelieth
FULL_IMAGE := $(REGISTRY)/$(IMAGE_NAME)

# We deliberately target x86-64-v2 baseline (not plain amd64).
# This gives better performance on modern CPUs while still being widely compatible.
# (Excludes very old pre-2009 CPUs that lack SSE4.2 / POPCNT etc.)
PLATFORMS := linux/amd64/v2,linux/arm64

# Control whether we also tag :latest (set to false for pre-releases / CI)
DOCKER_TAG_LATEST ?= true

# Rust targets for host-side tools (these run on the *host* OS, not inside the container)
AMD64_TARGET := x86_64-unknown-linux-gnu
ARM64_TARGET := aarch64-unknown-linux-gnu

# Tools
CARGO := cargo
DOCKER := docker
BUILDX := $(DOCKER) buildx

# Output
DIST_DIR := dist
BUILD_DIR := target

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
.PHONY: help
help:
	@echo "nfs-klldap-host"
	@echo ""
	@echo "  make build          native ui binary"
	@echo "  make build-cross    cross for amd64+arm64"
	@echo "  make dist           cross + dist/ artifacts"
	@echo "  make docker         local image"
	@echo "  make docker-multi   multi-arch (buildx, --push by default)"
	@echo "  make test / clippy / clean"
	@echo ""
	@echo "Variables: VERSION= IMAGE_NAME= REGISTRY= DOCKER_PUSH=false"

# -----------------------------------------------------------------------------
# Host Tools
# -----------------------------------------------------------------------------
.PHONY: build
build:
	@echo "==> Building host tools (native)..."
	$(CARGO) build --release -p nfs-klldap-ui
	@echo "Binaries:"
	@echo "  target/release/nfs-klldap-ui"

.PHONY: build-cross
build-cross:
	@echo "==> Cross-compiling host tools for $(AMD64_TARGET) and $(ARM64_TARGET)..."
	rustup target add $(AMD64_TARGET) $(ARM64_TARGET) || true
	$(CARGO) build --release --target $(AMD64_TARGET) -p nfs-klldap-ui
	$(CARGO) build --release --target $(ARM64_TARGET) -p nfs-klldap-ui
	@echo "Done."

# Produce a clean dist/ directory with architecture-suffixed binaries
.PHONY: dist
dist: build-cross
	@echo "==> Preparing distribution in $(DIST_DIR)/"
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR)
	# amd64
	cp target/$(AMD64_TARGET)/release/nfs-klldap-ui       $(DIST_DIR)/nfs-klldap-ui-amd64
	# arm64
	cp target/$(ARM64_TARGET)/release/nfs-klldap-ui       $(DIST_DIR)/nfs-klldap-ui-arm64
	# Make them executable
	chmod +x $(DIST_DIR)/nfs-klldap-ui-*
	@echo ""
	@echo "Distribution ready:"
	@ls -l $(DIST_DIR)/

# -----------------------------------------------------------------------------
# Container Image
# -----------------------------------------------------------------------------
# Runtime base is debian:13-slim (see Dockerfile). Build stages (chef/planner/builder)
# remain on fedora-minimal:${FEDORA_VERSION} (ARG, default 44) for reliable Rust
# cross-compilation and cargo-chef. Ganesha for runtime is pulled from Debian backports
# (9.x series) for closer config option parity with prior Fedora-packaged Ganesha.
.PHONY: docker
docker:
	@echo "==> Building container image for linux/amd64/v2..."
	@if [ "$(DOCKER_PUSH)" = "true" ]; then \
		$(BUILDX) build \
			$(if $(filter true,$(DOCKER_NO_CACHE)),--no-cache,) \
			--platform linux/amd64/v2 \
			--build-arg KLLDAP_VERSION=$(VERSION) \
			--tag $(FULL_IMAGE):$(VERSION) \
			$(if $(filter true,$(DOCKER_TAG_LATEST)),--tag $(FULL_IMAGE):latest,) \
			--push \
			.; \
	else \
		$(DOCKER) build \
			$(if $(filter true,$(DOCKER_NO_CACHE)),--no-cache,) \
			--build-arg KLLDAP_VERSION=$(VERSION) \
			--tag $(IMAGE_NAME):$(VERSION) \
			$(if $(filter true,$(DOCKER_TAG_LATEST)),--tag $(IMAGE_NAME):latest,) \
			.; \
	fi

.PHONY: docker-multi
docker-multi:
	@echo "==> Building multi-platform image: $(PLATFORMS)"
	$(BUILDX) build \
		--platform $(PLATFORMS) \
		--build-arg KLLDAP_VERSION=$(VERSION) \
		--tag $(FULL_IMAGE):$(VERSION) \
		$(if $(filter true,$(DOCKER_TAG_LATEST)),--tag $(FULL_IMAGE):latest,) \
		$(if $(filter false,$(DOCKER_PUSH)),--load,--push) \
		.

# -----------------------------------------------------------------------------
# Development & Quality
# -----------------------------------------------------------------------------
.PHONY: test
test:
	$(CARGO) test --workspace

.PHONY: clippy
clippy:
	$(CARGO) +nightly clippy --workspace --all-targets --all-features -- -D warnings

# Full pre-commit gate: safety-dance runs clippy + the unsafe audit, then the
# comment linter, then the workspace tests. Recipe lines already run under
# `-eu -o pipefail` (see .SHELLFLAGS), so any failure stops the chain.
.PHONY: gate
gate:
	bash scripts/safety-dance.sh
	python3 scripts/comment_lint.py
	bash scripts/check-version-pins.sh
	$(CARGO) test --workspace

.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf $(DIST_DIR)


