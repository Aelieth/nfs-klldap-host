#!/bin/bash
#
# Lightweight healthcheck for the Ganesha-based NFS container.
#
# Success criteria (all must pass):
#   - ganesha.nfsd process is running
#   - Ganesha is listening on TCP 2049 (NFSv4)
#   - At least one export is registered (via ganesha-ctl or simple port check)
#
# This is intentionally simple. Deeper checks (active clients, Kerberos ticket
# validation against LLDAP, export content, etc.) belong in external monitoring.
#
set -euo pipefail

# 1. Is the Ganesha process alive?
if ! pgrep -x ganesha.nfsd >/dev/null 2>&1; then
    echo "FAIL: ganesha.nfsd is not running"
    exit 1
fi

# 2. Is it listening on the NFS port (2049)?
# Use ss if available, fall back to netstat, then a simple timeout connect.
if command -v ss >/dev/null 2>&1; then
    if ! ss -tlnp 2>/dev/null | grep -q ':2049'; then
        echo "FAIL: ganesha.nfsd not listening on TCP 2049"
        exit 1
    fi
elif command -v netstat >/dev/null 2>&1; then
    if ! netstat -tlnp 2>/dev/null | grep -q ':2049'; then
        echo "FAIL: ganesha.nfsd not listening on TCP 2049"
        exit 1
    fi
else
    # Last resort: try a non-blocking connect with timeout
    if ! timeout 2 bash -c 'echo > /dev/tcp/127.0.0.1/2049' 2>/dev/null; then
        echo "FAIL: cannot connect to TCP 2049 (ganesha.nfsd not listening?)"
        exit 1
    fi
fi

# 3. Quick check that the management interface is at least responsive
# (ganesha-ctl show-exports will fail if DBUS/Ganesha is broken)
if command -v /usr/local/bin/ganesha-ctl >/dev/null 2>&1; then
    if ! /usr/local/bin/ganesha-ctl show-exports >/dev/null 2>&1; then
        # Not fatal for basic health — Ganesha may just have no exports yet.
        # We only warn.
        echo "WARN: ganesha-ctl show-exports failed (DBUS or no exports yet?)"
    fi
fi

echo "OK: NFS-Ganesha is healthy (process + port 2049)"
exit 0
