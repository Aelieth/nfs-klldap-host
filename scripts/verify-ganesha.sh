#!/bin/bash
#
# verify-ganesha.sh
#
# Simple validation script for the Ganesha + LLDAP NFSv4 setup.
#
# Run this inside the running container (or on the host with docker exec).
#
# Usage:
#   ./verify-ganesha.sh
#

set -euo pipefail

echo "=== NFS-Ganesha + LLDAP Verification ==="
echo

echo "[1] Healthcheck..."
if /container/healthcheck.sh; then
    echo "  OK: healthcheck passed"
else
    echo "  FAIL: healthcheck failed"
fi

echo
echo "[2] SSSD / LLDAP resolution..."
if getent passwd root >/dev/null 2>&1; then
    echo "  OK: getent works (SSSD responding)"
else
    echo "  WARN: getent root failed"
fi

echo
echo "[3] Ganesha management interface..."
if command -v ganesha-ctl >/dev/null 2>&1; then
    if ganesha-ctl show-exports >/dev/null 2>&1; then
        echo "  OK: ganesha-ctl show-exports succeeded"
    else
        echo "  WARN: ganesha-ctl show-exports returned non-zero (no exports yet?)"
    fi
else
    echo "  WARN: ganesha-ctl not found in PATH"
fi

echo
echo "[4] Current exports (raw)..."
ganesha-ctl show-exports 2>/dev/null | head -30 || echo "  (could not retrieve)"

echo
echo "[5] Keytab (if present)..."
if [ -f /etc/krb5.keytab ]; then
    klist -k /etc/krb5.keytab 2>/dev/null | head -8 || echo "  klist failed or no tickets"
else
    echo "  No keytab at /etc/krb5.keytab"
fi

echo
echo "=== Verification complete ==="
echo
echo "Next steps if things look wrong:"
echo "  - Check container logs for sssd and ganesha.nfsd"
echo "  - Run: ganesha-ctl show-exports"
echo "  - Verify users have posixAccount + uidNumber/gidNumber in LLDAP"
echo "  - Confirm host filesystem ownership matches those numeric IDs"
