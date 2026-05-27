# =============================================================================
# Stage 1: Build the tiny Rust config generator (type-safe TOML logic)
# This binary is the ONLY thing that ever parses or generates from nfs-klldap.conf.
# It has zero web / async / heavy deps — tiny attack surface + fast container builds.
# =============================================================================
FROM rust:1.82-slim AS config-builder

WORKDIR /build
# Copy only the config crate (minimal context)
COPY management/nfs-klldap-config /build/nfs-klldap-config
WORKDIR /build/nfs-klldap-config

# Build static-friendly release binary (no web features)
RUN cargo build --release --bin nfs-klldap-config \
    && strip target/release/nfs-klldap-config || true

# =============================================================================
# Stage 2: Final runtime image (AlmaLinux 10 + Ganesha + SSSD + our generator)
# =============================================================================
FROM almalinux:10

LABEL maintainer="Aelieth"
LABEL description="AlmaLinux 10 NFS-Ganesha (user-space NFSv4) server with KLLDAP/SSSD POSIX UID/GID mapping. v0.23+ central TOML + bundled Rust generator. Minimal volumes, host-only UI."
LABEL org.opencontainers.image.source="https://github.com/aelieth/nfs-klldap-host"

# -----------------------------------------------------------------------------
# Package installation - GANESHA ONLY
#
# We deliberately do NOT install the kernel NFS stack (nfs-utils, rpcbind
# daemons for kernel nfsd, etc.). This container IS the NFS server.
#
# Core:
#   nfs-ganesha + nfs-ganesha-vfs     : The user-space NFSv4 server (the whole point)
#   nfs-ganesha-utils                 : ganesha-admin + management tools (for direct control)
#   nfs-ganesha-selinux               : SELinux policy (recommended)
#
# Identity:
#   sssd + sssd-ldap                  : Talks to LLDAP, provides nss + POSIX IDs
#
# Kerberos client:
#   krb5-workstation + krb5-libs      : kinit, klist, gss support for Ganesha
#
# Misc:
#   gettext (envsubst) for template rendering
#   Debugging / ops tools
# -----------------------------------------------------------------------------
RUN dnf install -y epel-release && \
    # CentOS Storage SIG is the recommended source for modern nfs-ganesha on EL10
    dnf install -y centos-release-nfs-ganesha7 2>/dev/null || true && \
    dnf install -y \
        # === Ganesha (user-space NFSv4 server) ===
        nfs-ganesha \
        nfs-ganesha-vfs \
        nfs-ganesha-utils \
        nfs-ganesha-selinux \
        # === Identity (LLDAP POSIX via SSSD) ===
        sssd \
        sssd-ldap \
        openldap-clients \
        # === Kerberos client (for Ganesha NFS_KRB5 + GSS) ===
        krb5-workstation \
        krb5-libs \
        # === Templating + ops + self-contained export watching (no DBUS) ===
        inotify-tools \
        procps-ng \
        iproute \
        net-tools \
        bind-utils \
        strace \
        less \
        nano \
    && dnf clean all

# -----------------------------------------------------------------------------
# Directories (no more templates/ — everything is generated from nfs-klldap.conf by Rust)
# -----------------------------------------------------------------------------
RUN mkdir -p \
    /etc/ganesha \
    /etc/ganesha/exports.d \
    /var/log/ganesha \
    /etc/sssd \
    /var/lib/sss \
    /container/scripts

# -----------------------------------------------------------------------------
# Copy the Rust config generator (built in stage 1) — this is the heart of v0.23+
# -----------------------------------------------------------------------------
COPY --from=config-builder /build/nfs-klldap-config/target/release/nfs-klldap-config /usr/local/bin/nfs-klldap-config
RUN chmod +x /usr/local/bin/nfs-klldap-config

# -----------------------------------------------------------------------------
# Copy container scripts (ganesha-ctl, healthcheck, optional conf watcher)
# -----------------------------------------------------------------------------
COPY container/scripts/ganesha-ctl /usr/local/bin/ganesha-ctl
COPY container/scripts/nfs-klldap-conf-watcher /usr/local/bin/nfs-klldap-conf-watcher
COPY container/healthcheck.sh /container/healthcheck.sh
RUN chmod +x /usr/local/bin/ganesha-ctl /usr/local/bin/nfs-klldap-conf-watcher /container/healthcheck.sh

# -----------------------------------------------------------------------------
# Entrypoint (now delegates TOML work to the bundled Rust binary)
# -----------------------------------------------------------------------------
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# -----------------------------------------------------------------------------
# Healthcheck
# -----------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
    CMD /container/healthcheck.sh || exit 1

# Ports are documentation only when using host networking or explicit -p
EXPOSE 2049/tcp 2049/udp 111/tcp 111/udp

ENTRYPOINT ["/entrypoint.sh"]
