#!/bin/bash
# verify-ganesha.sh — post-deploy checks; run inside container (or docker exec).
# Usage: ./verify-ganesha.sh

set -euo pipefail

echo "=== NFS-Ganesha + LLDAP Verification ==="
echo

# --- [1] Healthcheck (non-fatal; later steps still run) ---
echo "[1] Healthcheck..."
if /container/healthcheck.sh; then
    echo "  OK: healthcheck passed"
else
    echo "  FAIL: healthcheck failed (continuing with remaining checks)"
fi

echo
# --- [2] SSSD / LLDAP resolution ---
echo "[2] SSSD / LLDAP resolution..."
if getent passwd root >/dev/null 2>&1; then
    echo "  OK: getent works (SSSD responding)"
else
    echo "  WARN: getent root failed"
fi

echo
# --- [3] Ganesha management interface ---
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
# --- [4] Current exports (raw) ---
echo "[4] Current exports (raw)..."
ganesha-ctl show-exports 2>/dev/null | head -30 || echo "  (could not retrieve)"

echo
# --- [5] Keytab (if present) ---
echo "[5] Keytab (if present)..."
if [ -f /etc/krb5.keytab ]; then
    klist -k /etc/krb5.keytab 2>/dev/null | head -8 || echo "  klist failed or no tickets"
else
    echo "  No keytab at /etc/krb5.keytab"
fi

echo
# --- [6] idhelper ---
echo "[6] Kerberos idhelper (machine vs user principal translator)..."
if command -v /usr/local/bin/nfs-klldap-idhelper >/dev/null 2>&1; then
    /usr/local/bin/nfs-klldap-idhelper explain || true
    /usr/local/bin/nfs-klldap-idhelper check || true
    echo "  idhelper override files (nss_passwd for Ganesha LD_PRELOAD; supplemental extrausers):"
    ls -l /var/lib/extrausers/passwd /var/lib/extrausers/group /var/lib/nfs-klldap/nss_passwd /var/lib/nfs-klldap/nss_group 2>/dev/null || echo "  (not materialized yet; bulk-seed may still be running)"
else
    echo "  WARN: nfs-klldap-idhelper not present (mount stability for Kerberos clients may be impacted)"
fi

echo
# --- [7] Principal mapping + export policy ---
echo "[7] Principal mapping + export policy (id-map-test, fragment grep, shim paths)..."
ganesha-ctl id-map-test testuser1 2>/dev/null || echo "  id-map-test not available or failed (non-fatal during early verify)"
if ls /etc/ganesha/exports.d/*.conf >/dev/null 2>&1; then
    if grep -q 'Read_Access_Check_Policy' /etc/ganesha/exports.d/*.conf 2>/dev/null; then
        echo "  WARN: Read_Access_Check_Policy present — trixie-backports Ganesha 9.6 rejects this key (regenerate config)"
    else
        echo "  OK: Read_Access_Check_Policy omitted (ganesha 9.6 trixie default pre applies)"
    fi
fi
# Idmap* directives in ganesha.conf are intentionally omitted; mapping uses idhelper + idmapd.conf.
if [ -e /usr/local/bin/nfsidmap ] || [ -e /usr/sbin/nfsidmap ] || [ -L /usr/sbin/nfsidmap ]; then
    echo "  OK: 'nfsidmap' (shim/symlink) visible in /usr/local/bin and/or /usr/sbin for principal2uid"
else
    echo "  WARN: no 'nfsidmap' shim visible; interception may fail for Ganesha nfsidmap calls"
fi

if ! grep -qi 'idmapconf\|idmapd.conf\|UseGetpwnam\|Idmapping' /etc/ganesha/ganesha.conf 2>/dev/null; then
    echo "  OK: no Idmap* keys in ganesha.conf (safe for 9.6 trixie-backports)"
else
    echo "  WARN: unexpected idmap keys found in ganesha.conf"
fi

if [ -f /var/lib/nfs-klldap/.bulk_seed_done ]; then
    _bulk_n=$(cat /var/lib/nfs-klldap/.bulk_seed_done 2>/dev/null | tr -d '[:space:]')
    echo "  OK: idhelper bulk-seed marker present (${_bulk_n} users)"
else
    echo "  WARN: bulk-seed marker missing (principal2uid may WARN on first user compound)"
fi
if getent passwd testuser1 >/dev/null 2>&1 || grep -q '^testuser1:' /var/lib/extrausers/passwd /var/lib/nfs-klldap/nss_passwd 2>/dev/null; then
    echo "  OK: user short name materialization visible"
fi
_REALM=$(awk '/default_realm/ {print $3; exit}' /etc/krb5.conf 2>/dev/null || echo "")
if [ -n "$_REALM" ] && grep -q '^testuser1:' /var/lib/nfs-klldap/nss_passwd 2>/dev/null; then
    echo "  OK: testuser1 short name in nss_passwd (libnfsidmap strips principal to this for getpwnam)"
fi
if grep -q '^root:' /var/lib/extrausers/passwd /var/lib/nfs-klldap/nss_passwd 2>/dev/null; then
    echo "  OK: root (uid 0 for machines) present in materialized files"
fi

echo
# --- [8] Network mode check ---
echo "[8] Network mode check..."
if command -v ip >/dev/null 2>&1; then
    _BRIDGE_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '/inet / {split($4,a,"/"); print a[1]; exit}')
    if [ -n "${_BRIDGE_IP:-}" ] && [[ "$_BRIDGE_IP" == 172.17.* ]]; then
        echo "  WARN: container primary IPv4 is $_BRIDGE_IP (Docker bridge 172.17.0.0/16)"
        echo "        NFSv4 + Kerberos expect host-reachable addresses."
        echo "        Use --network=host (docker run) or network_mode: host (compose)."
    else
        echo "  OK: primary IPv4 is not in default Docker bridge range (${_BRIDGE_IP:-unknown})"
    fi
else
    echo "  WARN: ip command not available — skipping bridge network check"
fi

echo
echo "=== Verification complete ==="
echo
echo "Next steps: see docs/run/README.md — ganesha-ctl show-exports, id-check, id-map-test."