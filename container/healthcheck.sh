#!/bin/bash
# Docker HEALTHCHECK: ganesha.nfsd:2049, SSSD NSS pipe, WebUI:9630 (hard fail). Extra checks emit WARN only.
set -euo pipefail

fail() {
    echo "FAIL: $*"
    exit 1
}

ok() {
    echo "OK: $*"
    exit 0
}

# -------------------------------------------------------------------------
# 1. Ganesha process + NFS listener (the actual service we provide)
# -------------------------------------------------------------------------
if ! pgrep -x ganesha.nfsd >/dev/null 2>&1; then
    fail "ganesha.nfsd process is not running"
fi

# Prefer ss -tlnp; fall back to bash /dev/tcp when ss is absent.
# Check listening on 2049 (NFSv4)
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

# -------------------------------------------------------------------------
# 2. SSSD NSS pipe (required for POSIX uid/gid mapping from LLDAP)
# -------------------------------------------------------------------------
if [ ! -S /var/lib/sss/pipes/nss ]; then
    fail "SSSD NSS pipe missing — identity mapping not available"
fi

# -------------------------------------------------------------------------
# 3. WebUI listener on TCP 9630 (HTTPS or HTTP per TLS mode)
# -------------------------------------------------------------------------
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

# -------------------------------------------------------------------------
# Optional: warn if show-exports fails (non-fatal, e.g. early startup).
# -------------------------------------------------------------------------
if command -v /usr/local/bin/ganesha-ctl >/dev/null 2>&1; then
    if ! /usr/local/bin/ganesha-ctl show-exports >/dev/null 2>&1; then
        echo "WARN: No Ganesha exports visible yet (may be normal during startup)"
    fi
fi

# --- 4. idhelper + override files (advisory) ---
# idhelper binary + nss_passwd/extrausers files (daemon liveness not verified here).
if command -v /usr/local/bin/nfs-klldap-idhelper >/dev/null 2>&1; then
    echo "OK: nfs-klldap-idhelper present"
else
    echo "WARN: nfs-klldap-idhelper missing — Kerberos ID translation may be degraded"
fi
if [ -f /var/lib/nfs-klldap/nss_passwd ] || [ -f /var/lib/extrausers/passwd ]; then
    echo "OK: idhelper machine overrides present (wrapper or extrausers)"
else
    echo "WARN: no idhelper override files yet (may be missing if bulk-seed has not finished)"
fi

# Advisory: Docker bridge networking breaks NFSv4 client records (server_addr = 172.17.x.x).
if command -v ip >/dev/null 2>&1; then
    _BRIDGE_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '/inet / {split($4,a,"/"); print a[1]; exit}')
    if [ -n "${_BRIDGE_IP:-}" ] && [[ "$_BRIDGE_IP" == 172.17.* ]]; then
        echo "WARN: container primary IPv4 is $_BRIDGE_IP (Docker bridge 172.17.0.0/16)"
        echo "WARN: use --network=host (docker run) or network_mode: host (compose) for production NFS"
    fi
fi

ok "Ganesha (2049) + SSSD + WebUI (9630) are healthy"
