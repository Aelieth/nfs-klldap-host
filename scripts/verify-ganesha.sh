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
echo "[6] Principal mapping + Ganesha policy..."
ganesha-ctl id-map-test testuser1 2>/dev/null || echo "  id-map-test not available or failed (non-fatal)"
if ls /etc/ganesha/exports.d/*.conf >/dev/null 2>&1; then
    if grep -q 'Read_Access_Check_Policy' /etc/ganesha/exports.d/*.conf 2>/dev/null; then
        if grep -q 'Read_Access_Check_Policy = pre;' /etc/ganesha/exports.d/*.conf 2>/dev/null; then
            echo "  OK: Read_Access_Check_Policy = pre; present in NOACL fragment(s) as required"
        else
            echo "  NOTE: Read_Access_Check_Policy present but not = pre (unquoted) (check for post or unexpected)"
        fi
    else
        echo "  OK: Read_Access_Check_Policy omitted in fragments (default pre for ACL-capable)"
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
    # 1.4 hardening: machine host/ keytabs must not be root on exports.
    rkp="$(grep -o 'Root_Kerberos_Principal = [^;]*' /etc/ganesha/ganesha.conf 2>/dev/null | head -1)"
    case "${rkp:-}" in
        '')
            echo "  WARN: Root_Kerberos_Principal missing from ganesha.conf — Ganesha default is 'all' (every enrolled machine keytab is root)" ;;
        *all*|*host*)
            echo "  WARN: ${rkp} — includes host/all; enrolled client machine keytabs can act as root on exports" ;;
        *)
            echo "  OK: ${rkp} (machine host/ principals map to anonymous, not root)" ;;
    esac
    # 1.4 runtime shaping: recovery state must survive container recreation.
    recov_root="$(grep -o 'RecoveryRoot = [^;]*' /etc/ganesha/ganesha.conf 2>/dev/null | awk -F'= ' '{print $2}' | head -1)"
    recov_root="${recov_root:-/var/lib/nfs/ganesha}"
    if awk -v p="$recov_root" '$5 == p {found=1} END {exit !found}' /proc/self/mountinfo 2>/dev/null; then
        echo "  OK: RecoveryRoot ${recov_root} is volume-backed (grace/reclaim survives container recreate)"
    else
        echo "  WARN: RecoveryRoot ${recov_root} is NOT a mount — client recovery state dies with the container (add the ganesha-recovery bind in nfs-klldap-host.yaml)"
    fi
    # Debug LOG block currency: pre-2026-07 images set SESSIONS/CLIENTID
    # FULL_DEBUG but not IDMAPPER, leaving uid2grp failures undiagnosable
    # in captures.
    if grep -q 'Default_Log_Level = DEBUG' /etc/ganesha/ganesha.conf 2>/dev/null; then
        if grep -q 'IDMAPPER = FULL_DEBUG' /etc/ganesha/ganesha.conf 2>/dev/null; then
            echo "  OK: debug LOG block includes IDMAPPER = FULL_DEBUG (uid2grp root causes visible)"
        else
            echo "  WARN: debug LOG block lacks IDMAPPER = FULL_DEBUG — stale generated config; redeploy current image so captures show uid2grp/idmapper root causes"
        fi
    fi
    if grep -q 'UseGetpwnam = true' /etc/ganesha/ganesha.conf 2>/dev/null; then
        echo "  OK: UseGetpwnam=true (getpwuid_r + getgrouplist via nss_wrapper; Manage_Gids defaults true, non-default false skips AUTH_SYS managed gids only)"
    elif grep -q 'UseGetpwnam = false' /etc/ganesha/ganesha.conf 2>/dev/null; then
        GANESHA_BIN="$(command -v ganesha.nfsd 2>/dev/null || true)"
        # grep -a, not strings(1): binutils is not in the image. The probed
        # string only exists in _MSPAC_SUPPORT builds (uid2grp.c stub).
        if [ -n "$GANESHA_BIN" ] && grep -qa 'Unsupported code path for principal' "$GANESHA_BIN" 2>/dev/null; then
            echo "  WARN: UseGetpwnam=false with _MSPAC_SUPPORT ganesha.nfsd — user TGT managed groups will hit Unsupported code path"
        else
            echo "  NOTE: UseGetpwnam=false (principal2grp path compiled in; klldap build)"
        fi
    fi
fi
# Live group-resolution health (1.5 gate: zero failed group-fetch messages).
# Under RPCSEC_GSS the rpc-cred fallback carries no unix groups, so these
# failures silently strip every supplementary group from the user.
if [ -f /var/log/ganesha.log ]; then
    mg_count="$(grep -cE 'Attempt to fetch managed' /var/log/ganesha.log 2>/dev/null || true)"
    if [ "${mg_count:-0}" -gt 0 ]; then
        mg_uids="$(grep -E 'Attempt to fetch managed' /var/log/ganesha.log | grep -oE 'uid[:=] ?[0-9]+' | grep -oE '[0-9]+' | sort -un | tr '\n' ' ')"
        echo "  FAIL: ${mg_count} managed-groups fetch failure(s) in ganesha.log for uid(s): ${mg_uids:-unknown} — run ganesha-ctl id-uid <uid> to replicate uid2grp under the live daemon env"
    else
        echo "  OK: no managed-groups fetch failures in ganesha.log"
    fi
fi

echo
echo "[7] ACL capability of serve paths (Ganesha VFS FSAL)..."
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
# Packaged Ganesha VFS FSAL build: does it carry an ACL backend at all?
# (grep -a, not strings(1): binutils is not in the image. nfs4_acl_release_entry
# and the system.posix_acl_access xattr-filter string exist in ALL builds; only
# the POSIX-ACL backend entry points / debug store mark an ACL-capable FSAL.)
VFS_SO="$(ls /usr/lib/*/ganesha/libfsalvfs.so* /usr/lib/ganesha/libfsalvfs.so* 2>/dev/null | head -1 || true)"
if [ -n "$VFS_SO" ]; then
    if grep -qaE 'acl_(get|set)_(fd|file)|acl_from_text|acl_to_any_text|vfs_acl_init' "$VFS_SO" 2>/dev/null; then
        echo "  OK: $VFS_SO carries the POSIX-ACL backend (Phase 2 single ACL-capable binary; NOACL is per-export policy)"
    else
        echo "  NOTE: $VFS_SO has no ACL backend — Phase 1 NOACL build is serving (ACL exports would return NFS4ERR_NOTSUPP)"
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