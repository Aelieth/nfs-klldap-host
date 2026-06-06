# syntax=docker/dockerfile:1
FROM quay.io/almalinuxorg/10-minimal AS chef

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
    cargo build --release --target "$TARGET" -p nfs-klldap-config --bin nfs-klldap-config --bin nfs-klldap-startup && \
    cargo build --release --target "$TARGET" -p nfs-klldap-ui --bin nfs-klldap-ui && \
    cp "target/$TARGET/release/nfs-klldap-config" "target/$TARGET/release/nfs-klldap-startup" "target/$TARGET/release/nfs-klldap-ui" /output/ && \
    (strip /output/nfs-klldap-config /output/nfs-klldap-startup /output/nfs-klldap-ui || true)

FROM quay.io/almalinuxorg/10-minimal

LABEL maintainer="Aelieth"
LABEL org.opencontainers.image.source="https://github.com/aelieth/nfs-klldap-host"

# Runtime: Ganesha + SSSD + Kerberos + tools
RUN microdnf install -y --assumeyes epel-release && \
    microdnf install -y --assumeyes centos-release-nfs-ganesha7 2>/dev/null || true && \
    microdnf install -y --assumeyes \
        nfs-ganesha nfs-ganesha-vfs nfs-ganesha-utils nfs-ganesha-selinux \
        sssd sssd-ldap openldap-clients \
        krb5-workstation krb5-libs \
        inotify-tools procps-ng iproute nmap-ncat \
        strace less nano libcap ca-certificates sudo hostname openssl \
    && microdnf clean all

RUN mkdir -p \
    /etc/ganesha /etc/ganesha/exports.d /var/log/ganesha \
    /etc/sssd /var/lib/sss /var/run/ganesha /var/run/sssd \
    /var/lib/nfs-klldap/webui-certs /container/scripts /output

COPY --from=builder /output/ /output/
RUN cp /output/nfs-klldap-config /usr/local/bin/ && \
    cp /output/nfs-klldap-startup /usr/local/bin/ && \
    cp /output/nfs-klldap-ui /usr/local/bin/ && \
    chmod +x /usr/local/bin/nfs-klldap-config /usr/local/bin/nfs-klldap-startup /usr/local/bin/nfs-klldap-ui && \
    rm -rf /output

COPY container/scripts/ganesha-ctl /usr/local/bin/ganesha-ctl
COPY container/scripts/nfs-klldap-conf-watcher /usr/local/bin/nfs-klldap-conf-watcher
COPY container/healthcheck.sh /container/healthcheck.sh
RUN chmod +x /usr/local/bin/ganesha-ctl /usr/local/bin/nfs-klldap-conf-watcher /container/healthcheck.sh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN chown root:root /etc/sssd && chmod 755 /etc/sssd && \
    chmod 775 /etc/ganesha/exports.d && \
    chmod 755 /container /container/scripts

HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
    CMD /container/healthcheck.sh || exit 1

EXPOSE 2049/tcp 2049/udp 111/tcp 111/udp
ENTRYPOINT ["/entrypoint.sh"]
