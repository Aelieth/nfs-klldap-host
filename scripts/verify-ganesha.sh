#!/bin/bash
# verify-ganesha.sh — post-deploy diagnostics; run inside container (or docker exec).
# Usage: verify-ganesha.sh
set -euo pipefail

# shellcheck source=../container/scripts/check-common.sh
if [ -f /container/scripts/check-common.sh ]; then
    # shellcheck source=/container/scripts/check-common.sh
    . /container/scripts/check-common.sh
else
    # Dev checkout: resolve relative to this script.
    _DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=../container/scripts/check-common.sh
    . "${_DIR}/../container/scripts/check-common.sh"
fi

echo "=== NFS-Ganesha + LLDAP Verification ==="
echo

echo "[1] Healthcheck (liveness)..."
if /container/healthcheck.sh; then
    echo "  OK: healthcheck passed"
else
    echo "  FAIL: healthcheck failed (continuing with extended checks)"
fi

echo
echo "[2] SSSD / LLDAP resolution..."
if getent passwd root >/dev/null 2>&1; then
    echo "  OK: getent works (SSSD responding)"
else
    echo "  WARN: getent root failed"
fi

echo
echo "[3] Export fragments (on-disk, from nfs-klldap.conf)..."
if command -v ganesha-ctl >/dev/null 2>&1; then
    ganesha-ctl show-fragments 2>/dev/null | head -40 || echo "  (could not list fragments)"
else
    echo "  WARN: ganesha-ctl not found in PATH"
fi

echo
echo "[4] Keytab (if present)..."
if [ -f /etc/krb5.keytab ]; then
    klist -k /etc/krb5.keytab 2>/dev/null | head -8 || echo "  klist failed or no tickets"
else
    echo "  No keytab at /etc/krb5.keytab"
fi

echo
echo "[5] Kerberos idhelper..."
if command -v /usr/local/bin/nfs-klldap-idhelper >/dev/null 2>&1; then
    /usr/local/bin/nfs-klldap-idhelper explain || true
    /usr/local/bin/nfs-klldap-idhelper check || true
    echo "  Materialized override files:"
    ls -l /var/lib/extrausers/passwd /var/lib/extrausers/group \
        /var/lib/nfs-klldap/nss_passwd /var/lib/nfs-klldap/nss_group 2>/dev/null \
        || echo "  (not materialized yet; bulk-seed may still be running)"
else
    echo "  WARN: nfs-klldap-idhelper not present"
fi

echo
echo "[6] Principal mapping + Ganesha 9.6 policy..."
ganesha-ctl id-map-test testuser1 2>/dev/null || echo "  id-map-test not available or failed (non-fatal)"
if ls /etc/ganesha/exports.d/*.conf >/dev/null 2>&1; then
    if grep -q 'Read_Access_Check_Policy' /etc/ganesha/exports.d/*.conf 2>/dev/null; then
        echo "  NOTE: Read_Access_Check_Policy present (expected for limited/noacl FS with post policy)"
    else
        echo "  OK: Read_Access_Check_Policy omitted in fragments (9.6 default pre)"
    fi
fi
if [ -e /usr/local/bin/nfsidmap ] || [ -e /usr/sbin/nfsidmap ] || [ -L /usr/sbin/nfsidmap ]; then
    echo "  OK: nfsidmap shim visible (fallback path; principal2uid uses in-process libnfsidmap)"
else
    echo "  WARN: no nfsidmap shim visible"
fi
if ! grep -qi 'idmapconf\|idmapd.conf\|Idmapping' /etc/ganesha/ganesha.conf 2>/dev/null; then
    echo "  OK: no Idmap* keys in ganesha.conf"
else
    echo "  WARN: unexpected idmap keys in ganesha.conf"
fi
if [ -f /var/lib/nfs-klldap/.bulk_seed_done ]; then
    _bulk_n=$(cat /var/lib/nfs-klldap/.bulk_seed_done 2>/dev/null | tr -d '[:space:]')
    echo "  OK: idhelper bulk-seed marker present (${_bulk_n} users)"
else
    echo "  WARN: bulk-seed marker missing"
fi
if getent passwd testuser1 >/dev/null 2>&1 || grep -q '^testuser1:' /var/lib/extrausers/passwd /var/lib/nfs-klldap/nss_passwd 2>/dev/null; then
    echo "  OK: testuser1 visible via getent or materialized files"
fi
if grep -q '^root:' /var/lib/extrausers/passwd /var/lib/nfs-klldap/nss_passwd 2>/dev/null; then
    echo "  OK: root (uid 0) present in materialized files"
fi
if [ -f /etc/ganesha/ganesha.conf ]; then
    if grep -q 'UseGetpwnam = true' /etc/ganesha/ganesha.conf 2>/dev/null; then
        echo "  OK: UseGetpwnam=true (uid2grp_allocate_by_uid path for Manage_Gids on Ganesha 9.6)"
    elif grep -q 'UseGetpwnam = false' /etc/ganesha/ganesha.conf 2>/dev/null; then
        GANESHA_BIN="$(command -v ganesha.nfsd 2>/dev/null || true)"
        if [ -n "$GANESHA_BIN" ] && strings "$GANESHA_BIN" 2>/dev/null | grep -qi mspac; then
            echo "  WARN: UseGetpwnam=false with _MSPAC_SUPPORT ganesha.nfsd — user TGT managed groups will hit Unsupported code path"
        else
            echo "  NOTE: UseGetpwnam=false (principal2grp path; verify ganesha build)"
        fi
    fi
fi

echo
echo "[7] Network mode..."
warn_bridge_network

echo
echo "=== Verification complete ==="
echo "See docs/run/README.md — ganesha-ctl show-fragments, id-check, id-map-test."