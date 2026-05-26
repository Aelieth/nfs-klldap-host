FROM almalinux:10

LABEL maintainer="Aelieth"
LABEL description="Minimal AlmaLinux 10 NFSv4 + Kerberos server (amd64/v2 + arm64)"

# Install required packages
# nfs-utils     → nfsd, exportfs, mount.nfs, etc.
# krb5-workstation → rpc.gssd, kinit, klist, ktutil
# rpcbind       → required for NFS
# krb5-libs     → core Kerberos libraries
# procps-ng + iproute + net-tools → troubleshooting
# strace, less, nano → debugging
RUN dnf install -y epel-release && \
    dnf install -y \
        nfs-utils \
        krb5-workstation \
        rpcbind \
        krb5-libs \
        procps-ng \
        iproute \
        net-tools \
        strace \
        less \
        nano \
        bind-utils \
    && dnf clean all

# Create necessary directories
RUN mkdir -p /var/lib/nfs /etc/exports.d /var/log/nfs

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose NFS ports (documentation only - we use host networking)
EXPOSE 111/tcp 111/udp 2049/tcp 2049/udp

# Use entrypoint for proper service startup
ENTRYPOINT ["/entrypoint.sh"]
