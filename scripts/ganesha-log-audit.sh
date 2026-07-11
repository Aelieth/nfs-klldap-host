#!/bin/bash
# ganesha-log-audit.sh — audit a Ganesha log capture against the refactor
# plan 1.5 log-audit gate. Works on any saved capture (e.g. logs.txt) or a
# live /var/log/ganesha.log; read-only, safe to run repeatedly.
#
# Usage: ganesha-log-audit.sh <ganesha-log-file>
# Exit:  0 all gate criteria pass, 1 at least one FAIL, 2 usage error.
set -euo pipefail

LOG="${1:-}"
if [ -z "$LOG" ] || [ ! -f "$LOG" ]; then
    echo "Usage: $0 <ganesha-log-file>" >&2
    exit 2
fi

PASS=0; FAIL=0; WARN=0
ok()   { echo "  OK: $*";   PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
note() { echo "  WARN: $*"; WARN=$((WARN+1)); }

# grep -c exits 1 on zero matches under pipefail; wrap it.
count() { grep -cE "$1" "$LOG" 2>/dev/null || true; }

echo "=== Ganesha log audit: $LOG ==="
echo "  lines: $(wc -l < "$LOG")"
first_ts="$(head -1 "$LOG" | grep -oE '^[0-9/]+ [0-9:]+' || true)"
last_ts="$(tail -1 "$LOG" | grep -oE '^[0-9/]+ [0-9:]+' || true)"
[ -n "$first_ts" ] && echo "  window: $first_ts .. $last_ts"

echo
echo "[1] Severity sweep (FATAL/MAJ/CRIT must be zero)..."
crit=$(count ':(FATAL|MAJ|CRIT) :')
if [ "$crit" -eq 0 ]; then
    ok "no FATAL/MAJ/CRIT lines"
else
    bad "$crit FATAL/MAJ/CRIT line(s):"
    grep -E ':(FATAL|MAJ|CRIT) :' "$LOG" | head -5 | sed 's/^/    /'
fi
# Known-benign startup notices (unconditional on this stack): DS DomainName
# precedence info, IO_FLUSHER under the reduced cap set, btrfs subvol probe.
# Config-defect warns (grace<lease, manage_gids_expiration routing) are NOT
# whitelisted — fixed in 0.9.81, they must fail loudly if they reappear.
EXPECTED_WARN_RE='Using domainname from DIRECTORY_SERVICES|PR_SET_IO_FLUSHER due to EPERM|btrfs filesystem .* may have unsupported subvols'
warns=$(count ':WARN :')
unexpected=$(grep -E ':WARN :' "$LOG" 2>/dev/null | grep -cvE "$EXPECTED_WARN_RE" || true)
if [ "$warns" -eq 0 ]; then
    ok "no WARN lines"
elif [ "$unexpected" -eq 0 ]; then
    ok "$warns WARN line(s), all expected startup notices"
else
    note "$unexpected unexpected WARN line(s) (of $warns total):"
    grep -E ':WARN :' "$LOG" | grep -vE "$EXPECTED_WARN_RE" | head -5 | sed 's/^/    /'
fi

echo
echo "[2] Group resolution (1.5 gate: zero failed group-fetch messages)..."
mg=$(count 'Attempt to fetch managed')
if [ "$mg" -eq 0 ]; then
    ok "no managed-groups fetch failures"
else
    uids="$(grep -E 'Attempt to fetch managed' "$LOG" | grep -oE 'uid[:=] ?[0-9]+' | grep -oE '[0-9]+' | sort -un | tr '\n' ' ')"
    bad "$mg managed-groups failure line(s) for uid(s): ${uids:-unknown}"
    echo "    Under RPCSEC_GSS the rpc-cred fallback carries no groups: these"
    echo "    users operate with uid+primary gid only (supplementary groups lost)."
    echo "    Diagnose in-container: ganesha-ctl id-uid <uid>"
fi
ggl=$(count 'my_getgrouplist_alloc.*(failed|WARN)')
if [ "$ggl" -eq 0 ]; then
    ok "no getgrouplist allocation failures"
else
    bad "$ggl my_getgrouplist_alloc failure line(s)"
fi
unmapped=$(count 'Could not map principal')
if [ "$unmapped" -eq 0 ]; then
    ok "no unmapped principals"
else
    bad "$unmapped 'Could not map principal' line(s):"
    grep -E 'Could not map principal' "$LOG" | head -3 | sed 's/^/    /'
fi
mspac=$(count 'Unsupported code path for principal')
if [ "$mspac" -eq 0 ]; then
    ok "no MSPAC stub hits (custom build path or unexercised)"
else
    bad "$mspac 'Unsupported code path' line(s) — stock _MSPAC_SUPPORT binary is serving"
fi

echo
echo "[3] Capture diagnosability (components present in this capture)..."
comps="$(grep -oE ':[A-Z][A-Z_ 0-9]+ :(F_DBG|M_DBG|DEBUG|INFO|EVENT|WARN|CRIT|MAJ|FATAL) :' "$LOG" \
    | sed -E 's/^:(.*) :[A-Z_]+ :$/\1/' | sort -u | tr '\n' ' ')"
echo "  components seen: ${comps:-none}"
if grep -qE ':ID MAPPER :' "$LOG"; then
    ok "ID MAPPER lines present (uid2grp/idmapper root causes visible)"
else
    note "no ID MAPPER lines — capture cannot show uid2grp root causes; redeploy with current GANESHA_DEBUG=TRUE LOG block (IDMAPPER=FULL_DEBUG) and re-capture unfiltered"
fi
# 9.6 tags GSS lines ":RPCSEC GSS :"; 9.13 dropped that component and logs
# GSS cred flow under DISP (nfs_creds.c/gss_extra.c function names match).
if grep -qiE 'rpcsec|gss' "$LOG"; then
    ok "GSS-related lines present (context/cred flow visible)"
else
    note "no GSS-related lines — GSS context/cred flow not visible in this capture"
fi

echo
echo "[4] NFSv4 operation errors..."
errs="$(grep -oE 'NFS4ERR_[A-Z0-9_]+' "$LOG" | sort | uniq -c | sort -rn || true)"
if [ -z "$errs" ]; then
    ok "no NFS4ERR_* statuses in capture"
else
    note "NFS4ERR statuses seen (some are normal client probing):"
    echo "$errs" | sed 's/^/    /'
fi

echo
echo "[5] Client/session summary..."
clients="$(grep -oE 'Linux NFSv4\.[0-9]+ [A-Za-z0-9._-]+' "$LOG" | sort -u || true)"
if [ -n "$clients" ]; then
    echo "$clients" | sed 's/^/  client: /'
else
    echo "  (no client id strings in capture)"
fi
xprt=$(count ':XPRT :(WARN|EVENT) :.*(error|fail|dead)')
if [ "$xprt" -eq 0 ]; then
    ok "no transport errors"
else
    note "$xprt transport error line(s)"
fi

echo
echo "=== Audit summary: $PASS ok, $WARN warn, $FAIL fail ==="
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL (1.5 log-audit gate not met)"
    exit 1
fi
echo "RESULT: PASS"
exit 0
