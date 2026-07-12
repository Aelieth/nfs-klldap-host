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
# On a restart-spanning capture the OLD daemon logs a DBUS CRIT while
# releasing its bus name — the container's D-Bus connection is already torn
# down, so the name-release fails. Cosmetic shutdown-ordering, expected on
# every container stop; excluded here (a real bus-name CRIT at RUNTIME would
# not carry "Connection is closed").
CRIT_BENIGN_RE='gsh_dbus_pkgshutdown :DBUS :CRIT :err releasing name .*Connection is closed'
crit=$(grep -E ':(FATAL|MAJ|CRIT) :' "$LOG" 2>/dev/null | grep -cvE "$CRIT_BENIGN_RE" || true)
if [ "$crit" -eq 0 ]; then
    ok "no FATAL/MAJ/CRIT lines (excluding benign DBUS shutdown name-release)"
else
    bad "$crit FATAL/MAJ/CRIT line(s):"
    grep -E ':(FATAL|MAJ|CRIT) :' "$LOG" | grep -vE "$CRIT_BENIGN_RE" | head -5 | sed 's/^/    /'
fi
# Known-benign startup notices (unconditional on this stack): DS DomainName
# precedence info, the "Using idmapped_*_time_validity ... instead of" pair
# (9.13 nfs_init.c warns on BOTH the set and unset branch of these params —
# TODO-marked transitional notices; no config is warning-free), IO_FLUSHER
# under the reduced cap set, and the btrfs subvol probe. NOT whitelisted:
# grace<lease and the unset-branch "Use idmapped_*_time_validity under
# DIRECTORY_SERVICES" (either reappearing means the generator regressed).
# Also benign: pwentname2id "input name: <n> must contain a domain" — a
# client SETATTR carrying a numeric owner/group string, which is exactly
# what Only_Numeric_Owners=true yields on the wire; the mapper warns then
# resolves it numerically and the op succeeds.
EXPECTED_WARN_RE='Using domainname from DIRECTORY_SERVICES|Using idmapped_(user|group)_time_validity from DIRECTORY_SERVICES|PR_SET_IO_FLUSHER due to EPERM|btrfs filesystem .* may have unsupported subvols|pwentname2id :ID MAPPER :WARN :The input name: [0-9]+ must contain a domain'
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
# Client machine creds (host/...) mapping to anonymous is the DESIGNED
# root-squash path (Root_Kerberos_Principal excludes host since 1.4);
# only unmapped USER principals are identity failures.
unmapped_user=$(grep -E 'Could not map principal' "$LOG" 2>/dev/null | grep -cvE 'principal (host|nfs|root)/' || true)
unmapped_machine=$(grep -E 'Could not map principal' "$LOG" 2>/dev/null | grep -cE 'principal (host|nfs|root)/' || true)
if [ "$unmapped_user" -eq 0 ]; then
    ok "no unmapped user principals ($unmapped_machine machine-principal lines = expected anonymous squash)"
else
    bad "$unmapped_user unmapped USER principal line(s):"
    grep -E 'Could not map principal' "$LOG" | grep -vE 'principal (host|nfs|root)/' | head -3 | sed 's/^/    /'
fi
mspac=$(count 'Unsupported code path for principal')
if [ "$mspac" -eq 0 ]; then
    ok "no MSPAC stub hits (custom build path or unexercised)"
else
    bad "$mspac 'Unsupported code path' line(s) — stock _MSPAC_SUPPORT binary is serving"
fi
# Export squash: no_root_squash lets a machine keytab write as a privileged
# identity (2026-07-11 stress test). Default is root_squash since 0.9.81;
# any no_root_squash export in the startup config is a finding unless it was
# a deliberate per-share opt-out.
if grep -qE 'export_commit_common.*created' "$LOG"; then
    nrs=$(grep -E 'export_commit_common.*created' "$LOG" | grep -c 'no_root_squash' || true)
    if [ "$nrs" -eq 0 ]; then
        ok "all exports created with root_squash"
    else
        bad "$nrs export(s) created with no_root_squash — a machine keytab can write as root there:"
        grep -E 'export_commit_common.*created' "$LOG" | grep 'no_root_squash' \
            | grep -oE 'pseudo \(/[^)]*\)' | sort -u | sed 's/^/    /'
    fi
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
echo "[4b] ACL serving health (0.9.90 ACL line)..."
# With ACL/auto shares live, the POSIX-ACL backend failing to serve an ACL
# from the backing filesystem is a real defect (share misconfigured onto a
# non-ACL filesystem, or the staging pattern missing) — the generate-time
# write probe should have caught it, so a capture hit means probe and
# reality disagree.
acl_notsupp=$(count 'Permission check for ACL.*(not supported|NOTSUPP)')
if [ "$acl_notsupp" -eq 0 ]; then
    ok "no POSIX-ACL NOTSUPP serving failures"
else
    bad "$acl_notsupp ACL-NOTSUPP line(s) — an ACL export cannot serve its filesystem:"
    grep -iE 'Permission check for ACL' "$LOG" | head -3 | sed 's/^/    /'
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
