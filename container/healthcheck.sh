#!/bin/bash
# Docker HEALTHCHECK: ganesha.nfsd + 2049 + SSSD NSS + WebUI 9630. See container/README.md.
#
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

# Check listening on 2049 (NFSv4)
listening_2049=false
if command -v ss >/dev/null 2>&1; then
    if ss -tlnp 2>/dev/null | grep -q ':2049'; then
        listening_2049=true
    fi
elif command -v netstat >/dev/null 2>&1; then
    if netstat -tlnp 2>/dev/null | grep -q ':2049'; then
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
# 3. WebUI HTTPS listener on 9630 (in-container management)
# -------------------------------------------------------------------------
listening_9630=false
if command -v ss >/dev/null 2>&1; then
    if ss -tlnp 2>/dev/null | grep -q ':9630'; then
        listening_9630=true
    fi
elif command -v netstat >/dev/null 2>&1; then
    if netstat -tlnp 2>/dev/null | grep -q ':9630'; then
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
# Optional: quick sanity that we have at least one export configured.
# This is best-effort and does not fail the healthcheck.
# -------------------------------------------------------------------------
if command -v /usr/local/bin/ganesha-ctl >/dev/null 2>&1; then
    if ! /usr/local/bin/ganesha-ctl show-exports >/dev/null 2>&1; then
        echo "WARN: No Ganesha exports visible yet (may be normal during startup)"
    fi
fi

ok "Ganesha (2049) + SSSD + WebUI (9630) are healthy"
