#!/bin/bash
#
# verify-idmap.sh
#
# Simple validation script for LLDAP + SSSD + Kerberized NFSv4 idmapping.
#
# Run this inside the running container (or on the host with docker exec).
#
# Usage:
#   ./verify-idmap.sh [username]
#
# Example:
#   ./verify-idmap.sh alice
#

set -euo pipefail

USER="${1:-}"

echo "=== NFSv4 + LLDAP ID Mapping Verification ==="
echo

echo "[1] Checking SSSD status..."
if ! pgrep -x sssd >/dev/null; then
    echo "  WARNING: sssd does not appear to be running"
else
    echo "  sssd is running"
fi

echo
echo "[2] Testing nsswitch / SSSD resolution..."
if [ -n "$USER" ]; then
    echo "  Looking up user: $USER"
    if getent passwd "$USER" >/dev/null 2>&1; then
        echo "  SUCCESS: $(getent passwd "$USER")"
    else
        echo "  FAILURE: getent could not find $USER"
        echo "  Check LLDAP POSIX attributes and sssd.conf"
    fi

    echo
    echo "  id output:"
    id "$USER" 2>&1 || echo "  id command failed for $USER"
else
    echo "  (No username supplied — skipping specific user lookup)"
    echo "  Example: $0 alice"
fi

echo
echo "[3] Checking rpc.idmapd..."
if pgrep -x rpc.idmapd >/dev/null; then
    echo "  rpc.idmapd is running"
    echo "  For live debugging run:  rpc.idmapd -f -vvv  (in another shell)"
else
    echo "  WARNING: rpc.idmapd does not appear to be running"
fi

echo
echo "[4] Current NFS exports:"
exportfs -s 2>/dev/null || echo "  exportfs failed or no exports"

echo
echo "[5] Quick Kerberos keytab check (if present):"
if [ -f /etc/krb5.keytab ]; then
    klist -k /etc/krb5.keytab 2>/dev/null | head -5 || echo "  klist failed"
else
    echo "  No keytab found at /etc/krb5.keytab"
fi

echo
echo "=== Verification complete ==="
echo
echo "Next steps if things look wrong:"
echo "  - Check container logs for sssd and rpc.gssd"
echo "  - Run: rpc.idmapd -f -vvv"
echo "  - Verify the user has posixAccount + uidNumber/gidNumber in LLDAP"
echo "  - Confirm host filesystem ownership matches those numeric IDs"
