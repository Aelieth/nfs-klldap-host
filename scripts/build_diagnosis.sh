#!/bin/bash
# build_diagnosis.sh — drives capture patterns + collects evidence (append-only, tee -a).
# Usage: SCRATCH=/path ./scripts/build_diagnosis.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-goal-diagnosis}"
mkdir -p "$SCRATCH"

LOG="$SCRATCH/build_diagnosis.log"
echo "=== build_diagnosis $(date -Iseconds) ===" | tee -a "$LOG"

# feed the idmap principal capture (non-int kinit+mount+ls + greps)
CAP_SCRIPT="$ROOT/container/scripts/capture_idmap_principal.sh"
if [ -x "$CAP_SCRIPT" ]; then
    CAPTURE_LOG="$SCRATCH/idmap_principal_probe.log" CAPTURE_MNT="$SCRATCH/mnt" \
        bash "$CAP_SCRIPT" 2>&1 | tee -a "$LOG" || true
else
    echo "WARN: no capture_idmap_principal.sh" | tee -a "$LOG"
fi

# also capture idhelper + ganesha-ctl + generated artifacts if present
if command -v nfs-klldap-idhelper >/dev/null 2>&1 || [ -x /usr/local/bin/nfs-klldap-idhelper ]; then
    ( /usr/local/bin/nfs-klldap-idhelper resolve 'probe@REALM' --json 2>/dev/null || true ) | tee -a "$SCRATCH/idhelper-probe.log" || true
fi
if command -v ganesha-ctl >/dev/null 2>&1 || [ -x /usr/local/bin/ganesha-ctl ]; then
    /usr/local/bin/ganesha-ctl id-resolve 'probeuser@REALM' 2>/dev/null | tee -a "$SCRATCH/ganesha-ctl-probe.log" || true
fi

# copy any fresh generated idmapd/exports
for f in /etc/ganesha/exports.d/*.conf /etc/idmapd.conf /var/log/ganesha.log; do
    [ -f "$f" ] && cp -f "$f" "$SCRATCH/$(basename "$f").$(date +%s)" 2>/dev/null || true
done

echo "diagnosis artifacts in $SCRATCH" | tee -a "$LOG"
echo "=== build_diagnosis end ===" | tee -a "$LOG"
