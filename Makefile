# =============================================================================
# nfs-klldap-host — Production Build System
# =============================================================================
#
# This Makefile provides a coherent build story for:
#   - Host-side tools (run on the machine that will run the NFS container):
#       * nfs-klldap-ui  (management web UI)
#       * nfs-perm-helper (privileged helper for chown/chmod — setuid or sudo)
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
	@echo "Installation helpers:"
	@echo "  make install-helper        Install nfs-perm-helper (with guidance for setuid/sudo)"
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
	$(CARGO) build --release -p management
	$(CARGO) build --release -p nfs-perm-helper --manifest-path management/priv-helper/Cargo.toml
	@echo "Binaries:"
	@echo "  target/release/nfs-klldap-ui"
	@echo "  management/priv-helper/target/release/nfs-perm-helper"

.PHONY: build-cross
build-cross:
	@echo "==> Cross-compiling host tools for $(AMD64_TARGET) and $(ARM64_TARGET)..."
	rustup target add $(AMD64_TARGET) $(ARM64_TARGET) || true
	$(CARGO) build --release --target $(AMD64_TARGET) -p management
	$(CARGO) build --release --target $(AMD64_TARGET) -p nfs-perm-helper --manifest-path management/priv-helper/Cargo.toml
	$(CARGO) build --release --target $(ARM64_TARGET) -p management
	$(CARGO) build --release --target $(ARM64_TARGET) -p nfs-perm-helper --manifest-path management/priv-helper/Cargo.toml
	@echo "Done."

# Produce a clean dist/ directory with architecture-suffixed binaries
.PHONY: dist
dist: build-cross
	@echo "==> Preparing distribution in $(DIST_DIR)/"
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR)
	# amd64
	cp target/$(AMD64_TARGET)/release/nfs-klldap-ui       $(DIST_DIR)/nfs-klldap-ui-amd64
	cp target/$(AMD64_TARGET)/release/nfs-perm-helper     $(DIST_DIR)/nfs-perm-helper-amd64
	# arm64
	cp target/$(ARM64_TARGET)/release/nfs-klldap-ui       $(DIST_DIR)/nfs-klldap-ui-arm64
	cp target/$(ARM64_TARGET)/release/nfs-perm-helper     $(DIST_DIR)/nfs-perm-helper-arm64
	# Make them executable
	chmod +x $(DIST_DIR)/nfs-klldap-ui-* $(DIST_DIR)/nfs-perm-helper-*
	@echo ""
	@echo "Distribution ready:"
	@ls -l $(DIST_DIR)/
	@echo ""
	@echo "On an amd64 host, copy nfs-perm-helper-amd64 → /usr/local/bin/nfs-perm-helper"
	@echo "On an arm64 host, copy nfs-perm-helper-arm64 → /usr/local/bin/nfs-perm-helper"
	@echo "(then set permissions / sudoers as documented in management/examples/sudoers.example)"

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
	$(CARGO) +nightly clippy --all-targets --all-features -- -D warnings

.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf $(DIST_DIR)

# -----------------------------------------------------------------------------
# Installation helper for the privileged binary
# -----------------------------------------------------------------------------
.PHONY: install-helper
install-helper:
	@echo "==> Installing nfs-perm-helper (you must run this as root or with sudo)"
	@echo ""
	@if [ ! -f target/release/nfs-perm-helper ] && [ ! -f target/x86_64-unknown-linux-gnu/release/nfs-perm-helper ] && [ ! -f target/aarch64-unknown-linux-gnu/release/nfs-perm-helper ]; then \
		echo "No release binary found. Run 'make build' or 'make dist' first."; \
		exit 1; \
	fi
	@echo "Copying binary to /usr/local/bin/nfs-perm-helper..."
	install -m 0755 \
		$$(find target -name nfs-perm-helper -type f | head -1) \
		/usr/local/bin/nfs-perm-helper
	@echo ""
	@echo "IMPORTANT: The helper must run with elevated privileges."
	@echo "Recommended options (choose one):"
	@echo ""
	@echo "  1. setuid root (simplest for single-user appliances):"
	@echo "       sudo chown root:root /usr/local/bin/nfs-perm-helper"
	@echo "       sudo chmod 4755 /usr/local/bin/nfs-perm-helper"
	@echo ""
	@echo "  2. sudoers rule (more auditable — see management/examples/sudoers.example):"
	@echo "       sudo visudo -f /etc/sudoers.d/nfs-mgmt"
	@echo ""
	@echo "After installation, point the management UI at the same nfs-klldap.conf"
	@echo "that the container uses."
