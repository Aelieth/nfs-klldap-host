FROM almalinux:10

LABEL maintainer="Aelieth"
LABEL description="AlmaLinux 10 Kerberized NFSv4 server with SSSD/LDAP idmapping (PR1 foundation)"
LABEL org.opencontainers.image.source="https://github.com/your-org/alma_nfs-kerb"

# -----------------------------------------------------------------------------
# Package installation
# -----------------------------------------------------------------------------
# Core NFS + Kerberos
#   nfs-utils          : rpc.nfsd, exportfs, mount.nfs, rpc.mountd (even if not always used), etc.
#   krb5-workstation   : rpc.gssd, kinit, klist, ktutil
#   rpcbind            : required for NFS services
#
# Identity / LDAP (AlmaLinux 10 / EL10 supported path)
#   sssd + sssd-ldap + sssd-nfs-idmap : Primary recommendation. Provides nss and the libnfsidmap plugin
#                                       that rpc.idmapd uses for principal -> UID/GID mapping.
#   openldap-clients   : ldapsearch, useful for debugging LLDAP connectivity
#
# Debugging / ops
#   bind-utils, iproute, procps-ng, net-tools, strace, less, nano
# -----------------------------------------------------------------------------
RUN dnf install -y epel-release && \
    dnf install -y \
        # NFS + Kerberos core
        nfs-utils \
        krb5-workstation \
        rpcbind \
        krb5-libs \
        # SSSD + NFS idmapping (the supported path on AL10)
        sssd \
        sssd-ldap \
        sssd-nfs-idmap \
        openldap-clients \
        # Debugging & troubleshooting
        procps-ng \
        iproute \
        net-tools \
        bind-utils \
        strace \
        less \
        nano \
        # For envsubst templating of sssd/krb5/idmapd configs from DOMAIN env var
        gettext \
    && dnf clean all

# -----------------------------------------------------------------------------
# Directories
# -----------------------------------------------------------------------------
RUN mkdir -p \
    /var/lib/nfs \
    /etc/exports.d \
    /var/log/nfs \
    /etc/sssd \
    /container/config

# -----------------------------------------------------------------------------
# Copy default templates.
# These live in a dedicated directory so they can be cleanly bind-mounted
# separately from any final/override config files.
#
# Default location: /container/templates
# Override with:   -e TEMPLATES_DIR=/your/path
# -----------------------------------------------------------------------------
COPY container/templates/ /container/templates/

# Legacy location (still copied for transition). Prefer the templates/ dir above.
COPY container/config/ /container/config/

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# -----------------------------------------------------------------------------
# Healthcheck (lightweight)
# -----------------------------------------------------------------------------
COPY container/healthcheck.sh /container/healthcheck.sh
RUN chmod +x /container/healthcheck.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD /container/healthcheck.sh || exit 1

# Ports are documentation only when using host networking
EXPOSE 111/tcp 111/udp 2049/tcp 2049/udp

ENTRYPOINT ["/entrypoint.sh"]
