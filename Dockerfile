# syntax=docker/dockerfile:1
ARG FEDORA_VERSION=44
FROM registry.fedoraproject.org/fedora-minimal:${FEDORA_VERSION} AS chef

# Build deps for Rust (openldap-clients for ldapsearch is in runtime only; used by setup wizard probes)
RUN microdnf install -y --assumeyes \
        shadow-utils pkgconf openssl-devel gcc make perl curl gzip krb5-devel \
    && microdnf clean all

# Non-root build user
RUN groupadd -g 1000 nfs && \
    useradd -u 1000 -g nfs -d /build -s /bin/bash nfs && \
    mkdir -p /build /output && chown -R nfs:nfs /build /output

USER nfs
WORKDIR /build

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/build/.cargo/bin:${PATH}"
RUN rustc --version && cargo --version
RUN cargo install cargo-chef --locked

FROM chef AS planner
WORKDIR /build
COPY --chown=nfs:nfs Cargo.toml Cargo.lock ./
COPY --chown=nfs:nfs nfs-klldap-identity/Cargo.toml ./nfs-klldap-identity/
COPY --chown=nfs:nfs nfs-klldap-config/Cargo.toml ./nfs-klldap-config/
COPY --chown=nfs:nfs nfs-klldap-ui/Cargo.toml ./nfs-klldap-ui/
# cargo metadata (used by cargo-chef) requires every manifest target path to exist.
RUN mkdir -p nfs-klldap-identity/src \
        nfs-klldap-config/src/bin/idhelper \
        nfs-klldap-ui/src && \
    printf '%s\n' 'pub fn _chef_dummy() {}' > nfs-klldap-identity/src/lib.rs && \
    printf '%s\n' 'pub fn _chef_dummy() {}' > nfs-klldap-config/src/lib.rs && \
    printf '%s\n' 'fn main() {}' > nfs-klldap-config/src/main.rs && \
    printf '%s\n' 'fn main() {}' > nfs-klldap-config/src/bin/nfs_klldap_startup.rs && \
    printf '%s\n' 'fn main() {}' > nfs-klldap-config/src/bin/idhelper/main.rs && \
    printf '%s\n' 'fn main() {}' > nfs-klldap-ui/src/main.rs
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner --chown=nfs:nfs /build/recipe.json /build/recipe.json
WORKDIR /build
COPY --chown=nfs:nfs Cargo.toml Cargo.lock ./
COPY --chown=nfs:nfs nfs-klldap-identity/Cargo.toml ./nfs-klldap-identity/
COPY --chown=nfs:nfs nfs-klldap-config/Cargo.toml ./nfs-klldap-config/
COPY --chown=nfs:nfs nfs-klldap-ui/Cargo.toml ./nfs-klldap-ui/
RUN mkdir -p nfs-klldap-identity/src \
        nfs-klldap-config/src/bin/idhelper \
        nfs-klldap-ui/src && \
    printf '%s\n' 'pub fn _chef_dummy() {}' > nfs-klldap-identity/src/lib.rs && \
    printf '%s\n' 'pub fn _chef_dummy() {}' > nfs-klldap-config/src/lib.rs && \
    printf '%s\n' 'fn main() {}' > nfs-klldap-config/src/main.rs && \
    printf '%s\n' 'fn main() {}' > nfs-klldap-config/src/bin/nfs_klldap_startup.rs && \
    printf '%s\n' 'fn main() {}' > nfs-klldap-config/src/bin/idhelper/main.rs && \
    printf '%s\n' 'fn main() {}' > nfs-klldap-ui/src/main.rs
RUN cargo chef cook --release --recipe-path recipe.json

COPY --chown=nfs:nfs nfs-klldap-identity /build/nfs-klldap-identity
COPY --chown=nfs:nfs nfs-klldap-config /build/nfs-klldap-config
COPY --chown=nfs:nfs nfs-klldap-ui /build/nfs-klldap-ui

RUN set -euxo pipefail && \
    case "$(uname -m)" in \
        x86_64)  TARGET="x86_64-unknown-linux-gnu" ;; \
        aarch64) TARGET="aarch64-unknown-linux-gnu" ;; \
        *)       echo "Unsupported architecture: $(uname -m)" && exit 1 ;; \
    esac && \
    rm -rf target && \
    cargo build --release --target "$TARGET" -p nfs-klldap-config --bin nfs-klldap-config --bin nfs-klldap-startup --bin nfs-klldap-idhelper && \
    cargo build --release --target "$TARGET" -p nfs-klldap-ui --bin nfs-klldap-ui && \
    cp "target/$TARGET/release/nfs-klldap-config" "target/$TARGET/release/nfs-klldap-startup" "target/$TARGET/release/nfs-klldap-idhelper" "target/$TARGET/release/nfs-klldap-ui" /output/ && \
    (strip /output/nfs-klldap-config /output/nfs-klldap-startup /output/nfs-klldap-idhelper /output/nfs-klldap-ui || true)

# Runtime stage: Debian 13-slim (trixie) + Ganesha 9.6 from trixie-backports.
# ONLY config directives known to be valid for ganesha 9.6 on Debian trixie are emitted.
# Outdated keys will crash the parser at ganesha startup.
# Build remains on Fedora for rustup/cargo-chef reliability.
FROM debian:13-slim

ARG GANESHA_VERSION=9.6-1~bpo13+1

LABEL maintainer="Aelieth" \
      version="0.9.0"
LABEL org.opencontainers.image.source="https://github.com/aelieth/nfs-klldap-host"


# Runtime: Ganesha 9.6 (trixie-backports). Config is strictly limited to supported 9.6 options.
ENV DEBIAN_FRONTEND=noninteractive
# ca-certificates must be installed before adding the HTTPS backports source.
# Keep apt installs separate from nsswitch sed: a trailing "|| true" on those
# seds previously made the whole RUN succeed even when apt-get install failed.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    echo 'deb https://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/backports.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends -t trixie-backports \
        nfs-ganesha=${GANESHA_VERSION} nfs-ganesha-vfs=${GANESHA_VERSION}; \
    apt-get install -y --no-install-recommends \
        sssd sssd-ldap libnss-sss \
        krb5-user \
        dbus rpcbind \
        inotify-tools procps iproute2 netcat-openbsd \
        ldap-utils \
        libnss-wrapper libnss-extrausers \
        openssl hostname; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    # Ensure NSS integration:
    # - sss for LDAP users/groups from LLDAP
    # - extrausers after files so the idhelper can write machine principal overrides
    #   (host/..., client names) that resolve to uid 0 without hiding real SSSD users.
    sed -i 's/^\(passwd:.*\)/\1 sss/' /etc/nsswitch.conf; \
    sed -i 's/^\(group:.*\)/\1 sss/' /etc/nsswitch.conf; \
    sed -i 's/^\(shadow:.*\)/\1 sss/' /etc/nsswitch.conf || true; \
    # Insert extrausers between files and sss (idempotent best-effort).
    sed -i '/^passwd:/ s/ sss/ extrausers sss/' /etc/nsswitch.conf; \
    sed -i '/^group:/  s/ sss/ extrausers sss/' /etc/nsswitch.conf || true

RUN mkdir -p \
    /etc/ganesha /etc/ganesha/exports.d /var/log/ganesha \
    /etc/sssd /var/lib/sss /var/run/ganesha /var/run/sssd \
    /var/lib/nfs-klldap /var/run/nfs-klldap \
    /var/lib/nfs-klldap/webui-certs /container/scripts /output \
    /var/lib/extrausers \
    /run/dbus /run/rpcbind

COPY --from=builder /output/ /output/
RUN cp /output/nfs-klldap-config /usr/local/bin/ && \
    cp /output/nfs-klldap-startup /usr/local/bin/ && \
    cp /output/nfs-klldap-idhelper /usr/local/bin/ && \
    cp /output/nfs-klldap-ui /usr/local/bin/ && \
    chmod +x /usr/local/bin/nfs-klldap-config /usr/local/bin/nfs-klldap-startup /usr/local/bin/nfs-klldap-idhelper /usr/local/bin/nfs-klldap-ui && \
    rm -rf /output

COPY container/scripts/ganesha-ctl /usr/local/bin/ganesha-ctl
COPY container/scripts/nfs-klldap-conf-watcher /usr/local/bin/nfs-klldap-conf-watcher
COPY container/scripts/nfsidmap-idhelper /usr/local/bin/nfsidmap-idhelper
COPY container/healthcheck.sh /container/healthcheck.sh
COPY container/scripts/check-common.sh /container/scripts/check-common.sh
COPY scripts/verify-ganesha.sh /usr/local/bin/verify-ganesha.sh
RUN chmod +x /usr/local/bin/ganesha-ctl /usr/local/bin/nfs-klldap-conf-watcher /usr/local/bin/nfsidmap-idhelper \
        /container/healthcheck.sh /container/scripts/check-common.sh /usr/local/bin/verify-ganesha.sh && \
    # Create the literal 'nfsidmap' name (both in PATH and /usr/sbin) so that when ganesha.nfsd
    # execs "nfsidmap ..." (or absolute /usr/sbin/nfsidmap as seen in ID MAPPER "using nfsidmap" logs)
    # our shim is found first. Backup original for fallback inside the shim.
    # This ensures interception even for full-path calls in ganesha 9.6 on trixie-backports.
    [ -f /usr/sbin/nfsidmap ] && mv /usr/sbin/nfsidmap /usr/sbin/nfsidmap.system || true; \
    ln -sf /usr/local/bin/nfsidmap-idhelper /usr/local/bin/nfsidmap; \
    ln -sf /usr/local/bin/nfsidmap-idhelper /usr/sbin/nfsidmap; \
    true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN chown root:root /etc/sssd && chmod 755 /etc/sssd && \
    chmod 775 /etc/ganesha/exports.d && \
    chmod 755 /container /container/scripts

HEALTHCHECK --interval=30s --timeout=10s --start-period=150s --retries=3 \
    CMD /container/healthcheck.sh || exit 1

# NFSv4 TCP only (Enable_UDP=false); 111 kept for rpcbind compatibility tooling.
EXPOSE 2049/tcp 111/tcp 111/udp
ENTRYPOINT ["/entrypoint.sh"]
