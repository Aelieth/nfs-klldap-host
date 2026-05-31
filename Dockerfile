# syntax=docker/dockerfile:1
# =============================================================================
# nfs-klldap-host — Multi-stage build
# =============================================================================
# Uses AlmaLinux 10-minimal for both builder and runtime (perfect glibc match).
# Builder installs Rust via rustup as non-root user + cargo-chef for caching.
# Final image is minimal + all runtime deps (Ganesha, SSSD, Kerberos, etc.).
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Base "chef" image with build dependencies + Rust
# -----------------------------------------------------------------------------
FROM quay.io/almalinuxorg/10-minimal AS chef

# Install build dependencies
#
# Notes on crypto / TLS related packages:
# - openssl-devel: Required for openldap-clients (ldapsearch LDAPS/STARTTLS probes
#   in nfs-klldap-startup) and general tooling. The Rust UI uses rustls (ring) for
#   both its own HTTPS listener (axum-server) and outbound LDAPS (ldap3 tls-rustls-ring).
# - clang + llvm: Not needed (pure-rust TLS stack for the WebUI and LDAP client).
RUN microdnf install -y --assumeyes \
        shadow-utils \
        pkgconf \
        openssl-devel \
        gcc \
        make \
        perl \
        curl \
        gzip \
        krb5-devel \
    && microdnf clean all

# Create service user early (non-root builds are cleaner)
RUN groupadd -g 1000 nfs && \
    useradd -u 1000 -g nfs -d /build -s /bin/bash nfs && \
    mkdir -p /build /output && \
    chown -R nfs:nfs /build /output

USER nfs
WORKDIR /build

# Install Rust via rustup (as the nfs user)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

# Add cargo to PATH
ENV PATH="/build/.cargo/bin:${PATH}"

# Verify
RUN rustc --version && cargo --version

# Install cargo-chef for excellent dependency caching
RUN cargo install cargo-chef --locked

# -----------------------------------------------------------------------------
# Stage 2: Planner (generate dependency recipe at workspace root)
# -----------------------------------------------------------------------------
FROM chef AS planner

WORKDIR /build

# Copy only the manifests first (canonical cargo-chef workspace pattern)
COPY --chown=nfs:nfs Cargo.toml Cargo.lock ./
COPY --chown=nfs:nfs nfs-klldap-config/Cargo.toml ./nfs-klldap-config/
COPY --chown=nfs:nfs nfs-klldap-ui/Cargo.toml ./nfs-klldap-ui/

# Prepare a single recipe from the workspace root
RUN cargo chef prepare --recipe-path recipe.json

# -----------------------------------------------------------------------------
# Stage 3: Builder (build using workspace root + -p selectors)
# -----------------------------------------------------------------------------
FROM chef AS builder

# Bring in the workspace-level recipe
COPY --from=planner --chown=nfs:nfs /build/recipe.json /build/recipe.json

WORKDIR /build

# Copy manifests (for chef cook)
COPY --chown=nfs:nfs Cargo.toml Cargo.lock ./
COPY --chown=nfs:nfs nfs-klldap-config/Cargo.toml ./nfs-klldap-config/
COPY --chown=nfs:nfs nfs-klldap-ui/Cargo.toml ./nfs-klldap-ui/

# Cook dependencies at the workspace root (canonical pattern)
RUN cargo chef cook --release --recipe-path recipe.json

# Copy full source
COPY --chown=nfs:nfs nfs-klldap-config /build/nfs-klldap-config
COPY --chown=nfs:nfs nfs-klldap-ui /build/nfs-klldap-ui

# Build binaries for the target architecture from the workspace root
RUN set -euxo pipefail && \
    case "$(uname -m)" in \
        x86_64)  TARGET="x86_64-unknown-linux-gnu" ;; \
        aarch64) TARGET="aarch64-unknown-linux-gnu" ;; \
        *)       echo "Unsupported architecture: $(uname -m)" && exit 1 ;; \
    esac && \
    echo "=== Building for target $TARGET ===" && \
    rm -rf target && \
    # Build both binaries from the config crate
    cargo build --release --target "$TARGET" \
        -p nfs-klldap-config --bin nfs-klldap-config --bin nfs-klldap-startup && \
    echo "=== nfs-klldap-config artifacts ===" && \
    ls -l target/$TARGET/release/ || true && \
    # Build the WebUI binary
    cargo build --release --target "$TARGET" -p nfs-klldap-ui --bin nfs-klldap-ui && \
    echo "=== nfs-klldap-ui artifacts ===" && \
    ls -l target/$TARGET/release/ || true && \
    # Copy artifacts
    cp "target/$TARGET/release/nfs-klldap-config" /output/ && \
    cp "target/$TARGET/release/nfs-klldap-startup" /output/ && \
    cp "target/$TARGET/release/nfs-klldap-ui" /output/ && \
    echo "=== Verifying built binaries ===" && \
    ls -l /output/ && \
    (strip /output/nfs-klldap-config /output/nfs-klldap-startup /output/nfs-klldap-ui || true)

# -----------------------------------------------------------------------------
# Stage 4: Final runtime image (AlmaLinux 10-minimal + Ganesha + SSSD + etc.)
# -----------------------------------------------------------------------------
FROM quay.io/almalinuxorg/10-minimal

LABEL maintainer="Aelieth"
LABEL description="AlmaLinux 10 NFS-Ganesha (user-space NFSv4) server with KLLDAP/SSSD POSIX UID/GID mapping. v0.6+ central TOML + in-container WebUI (HTTPS, rustls ldap3 client)."
LABEL org.opencontainers.image.source="https://github.com/aelieth/nfs-klldap-host"

# -----------------------------------------------------------------------------
# Runtime packages (Ganesha + identity + Kerberos + ops tools)
# -----------------------------------------------------------------------------
RUN microdnf install -y --assumeyes epel-release && \
    microdnf install -y --assumeyes centos-release-nfs-ganesha7 2>/dev/null || true && \
    microdnf install -y --assumeyes \
        # Ganesha (user-space NFSv4)
        nfs-ganesha \
        nfs-ganesha-vfs \
        nfs-ganesha-utils \
        nfs-ganesha-selinux \
        # Identity (LLDAP POSIX via SSSD)
        sssd \
        sssd-ldap \
        openldap-clients \
        # Kerberos client
        krb5-workstation \
        krb5-libs \
        # Templating + ops
        inotify-tools \
        procps-ng \
        iproute \
        net-tools \
        bind-utils \
        nmap-ncat \
        strace \
        less \
        nano \
        libcap \
        ca-certificates \
        sudo \
        hostname \
        # openssl: Provides the CLI + libraries used by openldap-clients (ldapsearch
        # LDAPS/StartTLS probes in the startup binary), SSSD ldap module, and general
        # debugging (openssl s_client, etc.). The Rust code itself only needs the
        # libraries at build time via openssl-devel (see builder stage).
        openssl \
    && microdnf clean all

# -----------------------------------------------------------------------------
# Directories (runtime model is root-only for all services)
# -----------------------------------------------------------------------------
RUN mkdir -p \
    /etc/ganesha \
    /etc/ganesha/exports.d \
    /var/log/ganesha \
    /etc/sssd \
    /var/lib/sss \
    /var/run/ganesha \
    /var/run/sssd \
    /var/lib/nfs-klldap/webui-certs \
    /container/scripts \
    /output

# -----------------------------------------------------------------------------
# Copy the two Rust binaries from builder
# -----------------------------------------------------------------------------
COPY --from=builder /output/ /output/
RUN cp /output/nfs-klldap-config /usr/local/bin/ && \
    cp /output/nfs-klldap-startup /usr/local/bin/ && \
    cp /output/nfs-klldap-ui /usr/local/bin/ && \
    chmod +x /usr/local/bin/nfs-klldap-config /usr/local/bin/nfs-klldap-startup /usr/local/bin/nfs-klldap-ui && \
    rm -rf /output && \
    echo "=== Installed Rust binaries ===" && \
    ls -l /usr/local/bin/nfs-klldap-*

# -----------------------------------------------------------------------------
# Copy container scripts and entrypoint
# -----------------------------------------------------------------------------
COPY container/scripts/ganesha-ctl /usr/local/bin/ganesha-ctl
COPY container/scripts/nfs-klldap-conf-watcher /usr/local/bin/nfs-klldap-conf-watcher
COPY container/healthcheck.sh /container/healthcheck.sh
RUN chmod +x /usr/local/bin/ganesha-ctl /usr/local/bin/nfs-klldap-conf-watcher /container/healthcheck.sh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# -----------------------------------------------------------------------------
# Permissions (standard root model - no gosu, no dedicated nfs user)
# -----------------------------------------------------------------------------
RUN chown root:root /etc/sssd && \
    chmod 755 /etc/sssd && \
    chmod 775 /etc/ganesha/exports.d && \
    chmod 755 /container /container/scripts

# -----------------------------------------------------------------------------
# Healthcheck & runtime
# -----------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
    CMD /container/healthcheck.sh || exit 1

EXPOSE 2049/tcp 2049/udp 111/tcp 111/udp

# Run as root (all services, including the WebUI on 9630, run as root per Red Hat conventions)
ENTRYPOINT ["/entrypoint.sh"]
