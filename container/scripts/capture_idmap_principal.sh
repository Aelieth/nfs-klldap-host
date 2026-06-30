#!/bin/bash
# capture_idmap_principal.sh — append-only non-interactive probe for idmap principal path.
# Usage: KRB5CCNAME=/tmp/krb5cc_$$ KRB5_KTNAME=/etc/krb5.keytab ./container/scripts/capture_idmap_principal.sh
# Appends to ${CAPTURE_LOG:-/var/log/idmap_principal_probe.log} using tee -a .
set -euo pipefail

LOG="${CAPTURE_LOG:-/var/log/idmap_principal_probe.log}"
MNT="${CAPTURE_MNT:-/mnt/nfs-test}"
SHARE="${CAPTURE_SHARE:-/users}"
PRINC="${CAPTURE_PRINC:-testuser1}"

mkdir -p "$(dirname "$LOG")" "${MNT}" 2>/dev/null || true

{
    echo "=== capture_idmap_principal $(date -Iseconds) ==="
    echo "principal=${PRINC} share=${SHARE}"
    echo "klist (before):"; klist 2>/dev/null || echo "(no ticket)"
    # non-interactive: prefer keytab or existing ccache; kinit -k if needed
    if ! klist -s 2>/dev/null; then
        kinit -k "${PRINC}@$(hostname -d 2>/dev/null || echo EXAMPLE.COM)" 2>&1 | cat || true
    fi
    echo "klist (after):"; klist 2>/dev/null || true

    echo "mount probe (non-interactive, background safe):"
    # use -o sec=krb5p,soft,timeo to avoid hang; mount may be noop if already
    mount -t nfs -o sec=krb5p,soft,vers=4.2 "${HOST:-127.0.0.1}:${SHARE}" "${MNT}" 2>&1 | tee -a "$LOG" || true

    echo "ls probe:"; (cd "${MNT}" && ls -l . 2>&1 | head -5) || true

    # umount best effort
    umount -l "${MNT}" 2>/dev/null || true

    echo "grep for uid2grp_allocate_by_uid and Unsupported code path:"
    if [ -f /var/log/ganesha.log ]; then
        grep -E 'uid2grp_allocate_by_uid|getgrouplist for uname|"Unsupported code path"' /var/log/ganesha.log | tail -10 | tee -a "$LOG" || true
    else
        echo "(no ganesha.log yet)"
    fi
    echo "=== end capture ==="
} 2>&1 | tee -a "$LOG"

echo "capture complete; log appended to $LOG"
