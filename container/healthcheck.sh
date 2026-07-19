#!/bin/bash
# Docker HEALTHCHECK: ganesha.nfsd:2049, SSSD NSS pipe, WebUI:9630 (hard fail). Extra checks emit WARN only.
# In HOST_NFS mode the container is a management sidecar only; we skip the
# ganesha process + 2049 listener checks (the host NFS server provides them).
set -euo pipefail

NFS_KLLDAP_CONTAINER_ROOT="${NFS_KLLDAP_CONTAINER_ROOT:-/container}"
# shellcheck source=scripts/check-common.sh
. "${NFS_KLLDAP_CONTAINER_ROOT}/scripts/check-common.sh"

fail() {
    echo "FAIL: $*"
    exit 1
}

ok() {
    echo "OK: $*"
    exit 0
}

# Detect HOST_NFS mode (same env contract as supervisor).
HOST_NFS="${HOST_NFS:-${NFS_KLLDAP_HOST_NFS:-false}}"
case "${HOST_NFS,,}" in
    true|1|yes|on) HOST_NFS_MODE=1 ;;
    *)             HOST_NFS_MODE=0 ;;
esac

if [ "$HOST_NFS_MODE" -eq 1 ]; then
    echo "HOST_NFS mode: skipping ganesha.nfsd + 2049 checks (host provides NFS)"
else
    if ! pgrep -x ganesha.nfsd >/dev/null 2>&1; then
        fail "ganesha.nfsd process is not running"
    fi

    listening_2049=false
    if command -v ss >/dev/null 2>&1; then
        if ss -tlnp 2>/dev/null | grep -q ':2049'; then
            listening_2049=true
        fi
    else
        if timeout 2 bash -c 'echo > /dev/tcp/127.0.0.1/2049' 2>/dev/null; then
            listening_2049=true
        fi
    fi

    if [ "$listening_2049" != true ]; then
        fail "ganesha.nfsd not listening on TCP 2049"
    fi
fi

if [ ! -S /var/lib/sss/pipes/nss ]; then
    fail "SSSD NSS pipe missing — identity mapping not available"
fi

listening_9630=false
if command -v ss >/dev/null 2>&1; then
    if ss -tlnp 2>/dev/null | grep -q ':9630'; then
        listening_9630=true
    fi
else
    if timeout 2 bash -c 'echo > /dev/tcp/127.0.0.1/9630' 2>/dev/null; then
        listening_9630=true
    fi
fi

if [ "$listening_9630" != true ]; then
    fail "WebUI not listening on TCP 9630"
fi

if [ "$HOST_NFS_MODE" -ne 1 ]; then
    warn_export_fragments
    warn_navahi_discovery
fi
warn_fs_limited_shares
warn_idhelper_overrides
warn_bridge_network

if [ "$HOST_NFS_MODE" -eq 1 ]; then
    ok "HOST_NFS mode — SSSD + WebUI (9630) are healthy (host provides Ganesha/NFS)"
else
    ok "Ganesha (2049) + SSSD + WebUI (9630) are healthy"
fi