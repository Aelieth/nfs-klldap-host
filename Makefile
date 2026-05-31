# =============================================================================
# nfs-klldap-host — Production Build System
# =============================================================================
#
# This Makefile provides a coherent build story for:
#   - Host-side tools (run on the machine that will run the NFS container):
#       * nfs-klldap-ui  (WebUI — now runs inside the container on port 9630)
#   - The container image (multi-architecture)
#
# Supported host tool targets:
#   - Native build for your current machine
#   - Cross-compilation for linux/amd64 and linux/arm64 (glibc)
#
# Container images:
#   - Single-arch local build
#   - Multi-platform build (linux/amd64/v2 + linux/arm64) via Docker Buildx
#
# Usage examples:
#   make help
#   make build                    # native release binaries
#   make dist                     # cross-built binaries in ./dist/
#   make docker                   # local image
#   make docker-multi             # multi-arch (pushes by default)
#
# Prerequisites for cross-compilation of host tools:
#   rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
#
# For the most reliable glibc cross-compilation, consider:
#   cargo install cargo-zigbuild
#   (then set CARGO=cargo-zigbuild)
#
# =============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
PROJECT_NAME := nfs-klldap-host
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Docker image
IMAGE_NAME ?= nfs-klldap-host
REGISTRY ?= ghcr.io/aelieth
FULL_IMAGE := $(REGISTRY)/$(IMAGE_NAME)

PLATFORMS := linux/amd64/v2,linux/arm64

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
	@echo "nfs-klldap-host build system"
	@echo ""
	@echo "Host tools (run on your NFS server / management machine):"
	@echo "  make build                 Build release binaries for current host"
	@echo "  make build-cross           Cross-compile for amd64 + arm64 (requires rust targets)"
	@echo "  make dist                  Cross-compile + place nicely named binaries in $(DIST_DIR)/"
	@echo ""
	@echo "Container image:"
	@echo "  make docker                Build local image (current arch)"
	@echo "  make docker-multi          Multi-platform build (amd64/v2 + arm64) via buildx"
	@echo "                             (uses --push by default; override with DOCKER_PUSH=false)"
	@echo ""
	@echo "Development:"
	@echo "  make test                  Run tests"
	@echo "  make clippy                Strict clippy (as used in CI)"
	@echo "  make clean"
	@echo ""
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=...                Override version tag"
	@echo "  IMAGE_NAME=...             Override base image name"
	@echo "  REGISTRY=...               Override registry"
	@echo "  DOCKER_PUSH=false          Build multi-arch locally without pushing"

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
	@echo ""
	@echo "nfs-klldap-ui is now built into the container image (runs on port 9630 inside, HTTPS via axum-server)."
	@echo "It performs chown/chmod directly on bind-mounted paths (root model, no docker-exec)."

# -----------------------------------------------------------------------------
# Container Image
# -----------------------------------------------------------------------------
.PHONY: docker
docker:
	@echo "==> Building container image (local architecture)..."
	$(DOCKER) build \
		-t $(IMAGE_NAME):$(VERSION) \
		-t $(IMAGE_NAME):latest \
		.

.PHONY: docker-multi
docker-multi:
	@echo "==> Building multi-platform image: $(PLATFORMS)"
	$(BUILDX) build \
		--platform $(PLATFORMS) \
		--tag $(FULL_IMAGE):$(VERSION) \
		--tag $(FULL_IMAGE):latest \
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

.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf $(DIST_DIR)


