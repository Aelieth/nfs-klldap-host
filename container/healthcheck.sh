#!/bin/bash
# Docker HEALTHCHECK: ganesha.nfsd:2049, SSSD NSS pipe, WebUI:9630 (hard fail). Extra checks emit WARN only.
set -euo pipefail

# shellcheck source=scripts/check-common.sh
. /container/scripts/check-common.sh

fail() {
    echo "FAIL: $*"
    exit 1
}

ok() {
    echo "OK: $*"
    exit 0
}

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

warn_export_fragments
warn_idhelper_overrides
warn_bridge_network

ok "Ganesha (2049) + SSSD + WebUI (9630) are healthy"