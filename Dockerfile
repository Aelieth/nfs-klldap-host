FROM almalinux:10

LABEL maintainer="Aelieth"
LABEL description="AlmaLinux 10 NFS-Ganesha (user-space NFSv4) server with LLDAP/SSSD POSIX UID/GID mapping. One-stop Kerberized NFSv4 plugin for hosts without kernel NFS."
LABEL org.opencontainers.image.source="https://github.com/your-org/alma_nfs-kerb"

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
        gettext \
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
# Directories
# -----------------------------------------------------------------------------
RUN mkdir -p \
    /etc/ganesha \
    /etc/ganesha/exports.d \
    /var/log/ganesha \
    /etc/sssd \
    /var/lib/sss \
    /container/templates \
    /container/scripts

# -----------------------------------------------------------------------------
# Copy templates (sssd, krb5, ganesha.conf, etc.)
# Bind-mount your own templates dir at runtime for customization.
# -----------------------------------------------------------------------------
COPY container/templates/ /container/templates/

# -----------------------------------------------------------------------------
# Copy ganesha-ctl wrapper (the bridge for "management tool speaks directly")
# The host-side Rust tool calls this via: docker exec <name> ganesha-ctl ...
# -----------------------------------------------------------------------------
COPY container/scripts/ganesha-ctl /usr/local/bin/ganesha-ctl
RUN chmod +x /usr/local/bin/ganesha-ctl

# -----------------------------------------------------------------------------
# Entrypoint (Ganesha only - kernel path has been removed)
# -----------------------------------------------------------------------------
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# -----------------------------------------------------------------------------
# Healthcheck
# -----------------------------------------------------------------------------
COPY container/healthcheck.sh /container/healthcheck.sh
RUN chmod +x /container/healthcheck.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
    CMD /container/healthcheck.sh || exit 1

# Ports are documentation only when using host networking or explicit -p
EXPOSE 2049/tcp 2049/udp 111/tcp 111/udp

ENTRYPOINT ["/entrypoint.sh"]
