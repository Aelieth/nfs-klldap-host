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
        if grep -q 'Read_Access_Check_Policy = pre;' /etc/ganesha/exports.d/*.conf 2>/dev/null; then
            echo "  OK: Read_Access_Check_Policy = pre; present in NOACL fragment(s) as required"
        else
            echo "  NOTE: Read_Access_Check_Policy present but not = pre (unquoted) (check for post or unexpected)"
        fi
    else
        echo "  OK: Read_Access_Check_Policy omitted in fragments (9.6 default pre for ACL-capable)"
    fi
fi
if ! grep -qi 'idmapconf\|idmapd.conf\|Idmapping' /etc/ganesha/ganesha.conf 2>/dev/null; then
    echo "  OK: no Idmap* keys in ganesha.conf"
else
    echo "  WARN: unexpected idmap keys in ganesha.conf"
fi
if grep -q '^root:x:0:0:root:/root:/bin/sh$' /var/lib/nfs-klldap/nss_passwd /var/lib/extrausers/passwd 2>/dev/null; then
    echo "  OK: idhelper nss root entry present (idempotent full snapshot; marker removed)"
else
    echo "  WARN: nss root entry missing (getgrouplist root may fail)"
fi
if getent passwd testuser1 >/dev/null 2>&1 || grep -q '^testuser1:' /var/lib/extrausers/passwd /var/lib/nfs-klldap/nss_passwd 2>/dev/null; then
    echo "  OK: testuser1 visible via getent or materialized files"
fi
if grep -q '^root:' /var/lib/extrausers/passwd /var/lib/nfs-klldap/nss_passwd 2>/dev/null; then
    echo "  OK: root (uid 0) present in materialized files"
fi
if [ -f /etc/ganesha/ganesha.conf ]; then
    if grep -q 'UseGetpwnam = true' /etc/ganesha/ganesha.conf 2>/dev/null; then
        echo "  OK: UseGetpwnam=true (getpwuid_r + getgrouplist via nss_wrapper; Manage_Gids=false skips AUTH_SYS only)"
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
echo "[7] ACL capability of serve paths (Ganesha 9.6 VFS FSAL)..."
# Whether the packaged Ganesha VFS can serve NFSv4 ACLs depends on BOTH the build and the
# backing filesystem. These are best-effort server-side signals; the authoritative check is
# a krb5p mount + nfs4_getfacl from a client (see scripts/fedora-krb5p-client-validate.sh).
_acl_probe_path() {
    p="$1"
    if [ ! -d "$p" ]; then
        echo "    $p: (not present in container)"
        return
    fi
    if getfacl -c -- "$p" >/dev/null 2>&1; then
        echo "    $p: POSIX ACLs readable (getfacl ok)"
    else
        echo "    $p: POSIX ACLs NOT supported here — ACL exports will return NFS4ERR_NOTSUPP; keep NOACL or stage onto an ACL-capable tree"
    fi
}
if ls /etc/ganesha/exports.d/*.conf >/dev/null 2>&1; then
    for f in /etc/ganesha/exports.d/*.conf; do
        path="$(awk -F'=' '/^[[:space:]]*Path[[:space:]]*=/{gsub(/[; ]/,"",$2);print $2;exit}' "$f")"
        mode="ACL"; grep -q 'Disable_ACL = true;' "$f" && mode="NOACL"
        echo "  $(basename "$f"): Path=${path:-?} [$mode]"
        [ -n "${path:-}" ] && _acl_probe_path "$path"
    done
fi
# Packaged Ganesha VFS FSAL build: does it reference ACL symbols at all?
VFS_SO="$(ls /usr/lib/*/ganesha/libfsalvfs.so* /usr/lib/ganesha/libfsalvfs.so* 2>/dev/null | head -1 || true)"
if [ -n "$VFS_SO" ]; then
    if strings "$VFS_SO" 2>/dev/null | grep -qiE 'nfs4_acl|posix_acl|richacl'; then
        echo "  NOTE: $VFS_SO references ACL symbols (build may support ACLs; confirm end-to-end)"
    else
        echo "  WARN: $VFS_SO shows no ACL symbols — NFSv4 ACL ops may be unsupported in this build"
    fi
fi
# The failure this guards against: ACL-path NFS4ERR_NOTSUPP already in ganesha.log.
if [ -f /var/log/ganesha.log ] && grep -q 'Permission check for ACL.*Operation not supported' /var/log/ganesha.log 2>/dev/null; then
    echo "  FAIL: ganesha.log shows ACL-path NFS4ERR_NOTSUPP — set enable_acl=false (NOACL) or stage/rebuild for ACLs"
fi

echo
echo "[8] Network mode..."
warn_bridge_network

echo
echo "=== Verification complete ==="
echo "See docs/run/README.md — ganesha-ctl show-fragments, id-check, id-map-test."
echo "ACL end-to-end: mount krb5p + nfs4_getfacl from a client (scripts/fedora-krb5p-client-validate.sh)."