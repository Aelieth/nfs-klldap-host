# syntax=docker/dockerfile:1
# =============================================================================
# nfs-klldap-host — Multi-stage build (modeled after KLLDAP pattern)
# =============================================================================
# Uses AlmaLinux 10-minimal for both builder and runtime (perfect glibc match).
# Builder installs Rust via rustup as non-root user + cargo-chef for caching.
# Final image is minimal + all runtime deps (Ganesha, SSSD, Kerberos, etc.).
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Base "chef" image with build dependencies + Rust
# -----------------------------------------------------------------------------
FROM quay.io/almalinuxorg/10-minimal AS chef

# Install build dependencies (matching the KLLDAP pattern)
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
        clang \
        llvm \
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
# Stage 2: Planner (generate dependency recipe)
# -----------------------------------------------------------------------------
FROM chef AS planner

COPY --chown=nfs:nfs management/nfs-klldap-config /build/nfs-klldap-config
WORKDIR /build/nfs-klldap-config

RUN cargo chef prepare --recipe-path recipe.json

# -----------------------------------------------------------------------------
# Stage 3: Builder (build both binaries with caching)
# -----------------------------------------------------------------------------
FROM chef AS builder

COPY --from=planner --chown=nfs:nfs /build/nfs-klldap-config/recipe.json /build/nfs-klldap-config/recipe.json
WORKDIR /build/nfs-klldap-config

# Cook dependencies (cached layer)
RUN cargo chef cook --release --recipe-path recipe.json

# Copy full source and build both binaries
COPY --chown=nfs:nfs management/nfs-klldap-config /build/nfs-klldap-config

# Build BOTH binaries for the target architecture
RUN set -eux && \
    case "$(uname -m)" in \
        x86_64)  TARGET="x86_64-unknown-linux-gnu" ;; \
        aarch64) TARGET="aarch64-unknown-linux-gnu" ;; \
        *)       echo "Unsupported architecture: $(uname -m)" && exit 1 ;; \
    esac && \
    echo "=== Building for target $TARGET ===" && \
    rm -rf target && \
    cargo build --release \
        --bin nfs-klldap-config \
        --bin nfs-klldap-startup \
        --target "$TARGET" && \
    cp "target/$TARGET/release/nfs-klldap-config" /output/ && \
    cp "target/$TARGET/release/nfs-klldap-startup" /output/ && \
    echo "=== Verifying built binaries ===" && \
    ls -l /output/nfs-klldap-config /output/nfs-klldap-startup && \
    strip /output/nfs-klldap-config /output/nfs-klldap-startup || true

# -----------------------------------------------------------------------------
# Stage 4: Final runtime image (AlmaLinux 10-minimal + Ganesha + SSSD + etc.)
# -----------------------------------------------------------------------------
FROM quay.io/almalinuxorg/10-minimal

LABEL maintainer="Aelieth"
LABEL description="AlmaLinux 10 NFS-Ganesha (user-space NFSv4) server with KLLDAP/SSSD POSIX UID/GID mapping. v0.23+ central TOML + bundled Rust generator."
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
    && microdnf clean all

# -----------------------------------------------------------------------------
# Service user + directories
# -----------------------------------------------------------------------------
RUN groupadd -r keytab && \
    useradd -r -U -s /sbin/nologin -d /nonexistent -c "nfs-klldap service user" -G keytab nfs && \
    # Defensive: ensure sssd group exists (package usually creates it) and add the
    # unprivileged nfs user to it. This helps with SSSD responder sockets/pipes
    # that are often created with group sssd and tight perms.
    groupadd -r sssd 2>/dev/null || true && \
    usermod -aG sssd nfs 2>/dev/null || true

RUN mkdir -p \
    /etc/ganesha \
    /etc/ganesha/exports.d \
    /var/log/ganesha \
    /etc/sssd \
    /var/lib/sss \
    /var/run/ganesha \
    /var/run/sssd \
    /container/scripts \
    /output

# -----------------------------------------------------------------------------
# Copy the two Rust binaries from builder
# -----------------------------------------------------------------------------
COPY --from=builder /output/ /output/
RUN cp /output/nfs-klldap-config /usr/local/bin/ && \
    cp /output/nfs-klldap-startup /usr/local/bin/ && \
    chmod +x /usr/local/bin/nfs-klldap-config /usr/local/bin/nfs-klldap-startup && \
    rm -rf /output && \
    echo "=== Installed Rust binaries ===" && \
    ls -l /usr/local/bin/nfs-klldap-*

# -----------------------------------------------------------------------------
# Copy container scripts and entrypoint
# -----------------------------------------------------------------------------
COPY container/scripts/ganesha-ctl /usr/local/bin/ganesha-ctl
COPY container/scripts/nfs-klldap-conf-watcher /usr/local/bin/nfs-klldap-conf-watcher
COPY container/healthcheck.sh /container/healthcheck.sh
COPY container/sudoers.d/nfs /container/sudoers.d/nfs.example
RUN chmod +x /usr/local/bin/ganesha-ctl /usr/local/bin/nfs-klldap-conf-watcher /container/healthcheck.sh && \
    chmod 644 /container/sudoers.d/nfs.example || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# -----------------------------------------------------------------------------
# gosu for privilege dropping
# -----------------------------------------------------------------------------
ENV GOSU_VERSION=1.17
RUN arch="$(uname -m)" && \
    case "${arch}" in \
        x86_64)  gosuArch='amd64' ;; \
        aarch64) gosuArch='arm64' ;; \
        *)       echo >&2 "error: unsupported architecture: '${arch}'"; exit 1 ;; \
    esac && \
    curl -fsSL -o /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${gosuArch}" && \
    chmod +x /usr/local/bin/gosu && \
    gosu --version

# -----------------------------------------------------------------------------
# Permissions + capabilities
# -----------------------------------------------------------------------------
RUN chown -R nfs:nfs \
        /var/log/ganesha \
        /var/lib/sss \
        /var/run/ganesha \
        /var/run/sssd \
        /etc/ganesha \
        /etc/ganesha/exports.d \
        /container \
        /container/sudoers.d && \
    # /etc/sssd is primarily managed as root:root 0600 for the main config
    # (SSSD's access_check_file is strict about owner == 0). The generator
    # (run as root via supervisor) will create the file with correct ownership.
    # We still ensure the directory exists and is traversable.
    chown root:root /etc/sssd && \
    chmod 755 /etc/sssd && \
    # ganesha exports fragments are written by the (root) generator or watcher
    # path; make the directory writable by the nfs user so either path works
    # and ganesha (running as nfs) can read them.
    chown -R nfs:nfs /etc/ganesha/exports.d && \
    chmod 775 /etc/ganesha/exports.d && \
    chmod 755 /container /container/scripts && \
    chmod 755 /container/sudoers.d || true && \
    setcap cap_net_bind_service+ep /usr/bin/ganesha.nfsd 2>/dev/null || true

# -----------------------------------------------------------------------------
# Healthcheck & runtime
# -----------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
    CMD /container/healthcheck.sh || exit 1

EXPOSE 2049/tcp 2049/udp 111/tcp 111/udp

# Run as root so entrypoint can do setup, then drop to nfs user via gosu
ENTRYPOINT ["/entrypoint.sh"]
