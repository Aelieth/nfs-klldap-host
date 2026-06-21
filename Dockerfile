# syntax=docker/dockerfile:1
ARG FEDORA_VERSION=44
FROM registry.fedoraproject.org/fedora-minimal:${FEDORA_VERSION} AS chef

# Build deps for Rust (openldap-clients for ldapsearch is in runtime only; used by startup TUI probes)
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
COPY --chown=nfs:nfs nfs-klldap-config/Cargo.toml ./nfs-klldap-config/
COPY --chown=nfs:nfs nfs-klldap-ui/Cargo.toml ./nfs-klldap-ui/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner --chown=nfs:nfs /build/recipe.json /build/recipe.json
WORKDIR /build
COPY --chown=nfs:nfs Cargo.toml Cargo.lock ./
COPY --chown=nfs:nfs nfs-klldap-config/Cargo.toml ./nfs-klldap-config/
COPY --chown=nfs:nfs nfs-klldap-ui/Cargo.toml ./nfs-klldap-ui/
RUN cargo chef cook --release --recipe-path recipe.json

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

# Runtime stage: Debian 13-slim for smaller image size and Ganesha packaging stability.
# The build stages above remain on Fedora (reliable rustup + cargo-chef + cross-compilation
# for the three Rust binaries). Only the final stage base + packages change.
# Ganesha is deliberately taken from trixie-backports (9.x series) to provide configuration
# option / parser compatibility as close as possible to the Ganesha currently packaged in
# fedora-minimal:44 (targeting the 9.x line up to ~9.4 per guidance; avoids main 6.5 divergence
# and bleeding-edge custom packages).
FROM debian:13-slim

LABEL maintainer="Aelieth" \
      version="0.8.12"
LABEL org.opencontainers.image.source="https://github.com/aelieth/nfs-klldap-host"


# Runtime: Ganesha (from backports for 9.x config parity)
RUN apt-get update && \
    echo 'deb http://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/backports.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends -t trixie-backports \
        nfs-ganesha nfs-ganesha-vfs && \
    apt-get install -y --no-install-recommends \
        sssd sssd-ldap libnss-sss \
        krb5-user \
        dbus rpcbind \
        inotify-tools procps iproute2 netcat-openbsd \
        ldap-utils \
        libnss-wrapper libnss-extrausers \
        strace less nano ca-certificates openssl sudo hostname && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    # Ensure NSS integration:
    # - sss for LDAP users/groups from LLDAP
    # - extrausers after files so the idhelper can write machine principal overrides
    #   (host/..., client names) that resolve to uid 0 without hiding real SSSD users.
    sed -i 's/^\(passwd:.*\)/\1 sss/' /etc/nsswitch.conf && \
    sed -i 's/^\(group:.*\)/\1 sss/' /etc/nsswitch.conf && \
    sed -i 's/^\(shadow:.*\)/\1 sss/' /etc/nsswitch.conf || true && \
    # Insert extrausers between files and sss (idempotent best-effort).
    sed -i '/^passwd:/ s/ sss/ extrausers sss/' /etc/nsswitch.conf && \
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
RUN chmod +x /usr/local/bin/ganesha-ctl /usr/local/bin/nfs-klldap-conf-watcher /usr/local/bin/nfsidmap-idhelper /container/healthcheck.sh && \
    # Create the literal 'nfsidmap' name in the early PATH so that when ganesha.nfsd
    # execs "nfsidmap -u <principal>" (as seen in its ID MAPPER logs) our shim is found
    # first. This is required for the principal2uid interception on 9.6/trixie.
    # Symlink keeps the descriptive source filename while satisfying PATH lookup.
    ln -sf nfsidmap-idhelper /usr/local/bin/nfsidmap

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN chown root:root /etc/sssd && chmod 755 /etc/sssd && \
    chmod 775 /etc/ganesha/exports.d && \
    chmod 755 /container /container/scripts

HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
    CMD /container/healthcheck.sh || exit 1

EXPOSE 2049/tcp 2049/udp 111/tcp 111/udp
ENTRYPOINT ["/entrypoint.sh"]
