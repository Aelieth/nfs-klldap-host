# syntax=docker/dockerfile:1
ARG FEDORA_VERSION=44
FROM registry.fedoraproject.org/fedora-minimal:${FEDORA_VERSION} AS chef

# Build deps for Rust (openldap-clients for ldapsearch is in runtime only; used by setup wizard probes)
# openssl-devel + krb5-devel removed (2026 audit): we only use rustls+ring (no openssl-sys linking).
# perl + pkgconf also removed: ring ships pregenerated asm; no pkg-config crate in the tree.
#
# aws-lc-sys was dropped from the graph (2026 audit, WI-13): axum-server now uses
# tls-rustls-no-provider and the app installs the ring CryptoProvider at startup.
# That removed the cmake crate, so `make` is no longer needed — only `gcc`, which
# ring's `cc` crate invokes directly to build its C/asm.
# git-core: nfs-klldap-ui/build.rs stamps the Overview version row from the repo.
RUN microdnf install -y --assumeyes \
        shadow-utils gcc curl gzip git-core \
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
# build-support + .git ride along solely for the version stamp the crate build
# scripts include!() and derive (branch + short hash, shown by the UI Overview
# card and every --version); without .git the build falls back to
# CARGO_PKG_VERSION. --chown keeps git's dubious-ownership check quiet.
COPY --chown=nfs:nfs build-support /build/build-support
COPY --chown=nfs:nfs .git /build/.git

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

# Ganesha custom packages (refactor plan 2.1 uplift, realigned 2026-07-10).
# Rebuilds the stock Debian 9.13-1 source with MSPAC off, VFS as the only
# FSAL, and the stock POSIX-ACL backend retained (one ACL-capable binary;
# NOACL is per-export policy); produces /debs consumed by the runtime stage.
# Build it alone with: docker build --target ganesha-build .
FROM debian:13-slim AS ganesha-build
COPY container/ganesha/build-ganesha-debs.sh container/ganesha/klldap-packaging.patch /ganesha-build/
RUN chmod +x /ganesha-build/build-ganesha-debs.sh && /ganesha-build/build-ganesha-debs.sh

# Runtime stage: Debian 13-slim (trixie) + custom ACL-capable Ganesha 9.13
# debs from the ganesha-build stage (plan 2.1 uplift: same scaffold, only the
# packages swapped; NOACL shares are enforced per-export via Disable_ACL).
# ONLY config directives known to be valid for this ganesha version on Debian
# trixie are emitted. Outdated keys will crash the parser at ganesha startup.
# Build remains on Fedora for rustup/cargo-chef reliability.
FROM debian:13-slim

# Custom package version (stock 9.13-1 + klldap flag delta + the nsswitch
# getgrouplist return fix; see container/ganesha/README.md). Rollback: the
# tagged 9.6+klldap1 image (Phase 1 anchor), or stock
# nfs-ganesha=9.6-1~bpo13+1 from trixie-backports.
ARG GANESHA_VERSION=9.13-1+klldap3

# Version label rides in from make (branch-as-version; "dev" for a bare
# docker build). The binaries stamp themselves from .git independently.
ARG KLLDAP_VERSION=dev
LABEL maintainer="Aelieth" \
      version="${KLLDAP_VERSION}"
LABEL org.opencontainers.image.source="https://github.com/aelieth/nfs-klldap-host"


# Runtime: custom Ganesha (see GANESHA_VERSION). Config is strictly limited to options this version supports.
ENV DEBIAN_FRONTEND=noninteractive
ENV NSS_EXTRAUSERS_PASSWD=/var/lib/extrausers/passwd
ENV NSS_EXTRAUSERS_GROUP=/var/lib/extrausers/group
# ca-certificates must be installed before adding the HTTPS backports source.
# Keep apt installs separate from nsswitch sed: a trailing "|| true" on those
# seds previously made the whole RUN succeed even when apt-get install failed.
#
# 2026 package audit notes (see plan.md):
#   Core: nfs-ganesha* (custom Ganesha VFS), sssd* + libnss-sss (identity via LLDAP + nsswitch files+extrausers+sss),
#         libnss-wrapper + libnss-extrausers (nss_wrapper + extrausers materialization for idhelper/Ganesha),
#         krb5-user (klist/keytab for startup + ganesha-ctl), acl (getfacl/setfacl for WebUI ACL editor).
#   Daemons/helpers: dbus (dbus-daemon + dbus-send for Ganesha bus), rpcbind (best-effort, 111 compat;
#         also MOUNT/portmap registration for Navahi NFSv3 click-mount),
#         avahi-daemon (Navahi mDNS advertisement: static XMLs in /etc/avahi/services, enable-dbus=no,
#         supervised by pid-1 only while navahi_discovery = true; /run/avahi-daemon is daemon-created),
#         inotify-tools (conf-watcher), procps (pgrep/pkill in supervisor/health), iproute2 (ip/ss for bridge/net checks).
#   Probes: ldap-utils (ldapsearch in startup wizard bind/DNS checks), netcat-openbsd (nc in ldap reachability).
#   Base debian:13-slim already provides: hostname, findutils, dpkg (for dpkg-architecture), coreutils (id/getent/timeout), etc.
#   Removed as unused: openssl (no /usr/bin/openssl calls anywhere), hostname (redundant with base).
COPY --from=ganesha-build /debs/ /tmp/ganesha-debs/
# Backports stays enabled: the custom debs depend on libntirpc7.2 (>= 7.2),
# which only trixie-backports carries; -t makes apt prefer it during resolve.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    echo 'deb https://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/backports.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends -t trixie-backports \
        "/tmp/ganesha-debs/nfs-ganesha_${GANESHA_VERSION}_$(dpkg --print-architecture).deb" \
        "/tmp/ganesha-debs/nfs-ganesha-vfs_${GANESHA_VERSION}_$(dpkg --print-architecture).deb"; \
    dpkg-query -W -f='${Package} ${Version}\n' nfs-ganesha nfs-ganesha-vfs; \
    test "$(dpkg-query -W -f='${Version}' nfs-ganesha)" = "${GANESHA_VERSION}"; \
    rm -rf /tmp/ganesha-debs; \
    apt-get install -y --no-install-recommends \
        sssd sssd-ldap sssd-tools libnss-sss \
        krb5-user \
        dbus rpcbind avahi-daemon \
        inotify-tools procps iproute2 netcat-openbsd \
        ldap-utils \
        libnss-wrapper libnss-extrausers \
        acl; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    # nsswitch: files → extrausers (idhelper) → sss (LLDAP). Single-shot avoids duplicate sss.
    sed -i 's/^passwd:.*/passwd:         files extrausers sss/' /etc/nsswitch.conf; \
    sed -i 's/^group:.*/group:          files extrausers sss/' /etc/nsswitch.conf; \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf; \
    # libnss-extrausers installs to /usr/lib; glibc loads from the per-arch
    # multiarch triplet dir, so link it in (guarded: never clobber a real
    # file there, and hard-fail unless the final path resolves).
    case "$(uname -m)" in \
        x86_64)  triplet=x86_64-linux-gnu ;; \
        aarch64) triplet=aarch64-linux-gnu ;; \
        *)       echo "Unsupported architecture: $(uname -m)"; exit 1 ;; \
    esac; \
    [ -e "/usr/lib/${triplet}/libnss_extrausers.so.2" ] || \
        ln -s /usr/lib/libnss_extrausers.so.2 "/usr/lib/${triplet}/libnss_extrausers.so.2"; \
    test -e "/usr/lib/${triplet}/libnss_extrausers.so.2"

RUN mkdir -p \
    /etc/ganesha /etc/ganesha/exports.d /var/log/ganesha \
    /etc/sssd /var/lib/sss /var/run/ganesha /var/run/sssd \
    /var/lib/nfs-klldap /var/run/nfs-klldap \
    /var/lib/nfs-klldap/webui-certs /container/scripts /output \
    /var/lib/extrausers \
    /run/dbus /run/rpcbind \
    /etc/avahi/services

COPY --from=builder /output/ /output/
RUN cp /output/nfs-klldap-config /usr/local/bin/ && \
    cp /output/nfs-klldap-startup /usr/local/bin/ && \
    cp /output/nfs-klldap-idhelper /usr/local/bin/ && \
    cp /output/nfs-klldap-ui /usr/local/bin/ && \
    chmod +x /usr/local/bin/nfs-klldap-config /usr/local/bin/nfs-klldap-startup /usr/local/bin/nfs-klldap-idhelper /usr/local/bin/nfs-klldap-ui && \
    rm -rf /output
COPY container/scripts/ganesha-ctl /usr/local/bin/ganesha-ctl
COPY container/scripts/nfs-klldap-conf-watcher /usr/local/bin/nfs-klldap-conf-watcher
COPY container/healthcheck.sh /container/healthcheck.sh
COPY container/scripts/check-common.sh /container/scripts/check-common.sh
COPY container/avahi-daemon.conf /etc/avahi/avahi-daemon.conf
COPY scripts/verify-ganesha.sh /usr/local/bin/verify-ganesha.sh
RUN chmod +x /usr/local/bin/ganesha-ctl /usr/local/bin/nfs-klldap-conf-watcher \
        /container/healthcheck.sh /container/scripts/check-common.sh /usr/local/bin/verify-ganesha.sh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN chown root:root /etc/sssd && chmod 755 /etc/sssd && \
    chmod 775 /etc/ganesha/exports.d && \
    chmod 755 /container /container/scripts

HEALTHCHECK --interval=30s --timeout=10s --start-period=150s --retries=3 \
    CMD /container/healthcheck.sh || exit 1

# NFSv4 TCP only (Enable_UDP=false); 111 kept for rpcbind compatibility tooling.
# 5353/udp (mDNS) + 20048/tcp (MOUNT) serve Navahi discovery — cosmetic under
# the host networking the deploy requires; the host firewall is what matters.
EXPOSE 2049/tcp 111/tcp 111/udp 5353/udp 20048/tcp
ENTRYPOINT ["/entrypoint.sh"]
