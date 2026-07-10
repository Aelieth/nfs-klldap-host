#!/bin/bash
# ganesha-export-reload-smoke.sh — refactor-plan 1.4 live export management gate.
# Proves the custom +klldap1 ganesha.nfsd handles the supervisor's fast path
# (SIGHUP → reread_exports) for all three operations WITHOUT a restart:
#   add    — new fragment + %include appears in the live export set
#   update — same Export_Id/Path with a changed Pseudo is remounted in place
#   remove — deleted fragment is pruned (prune_defunct_exports)
# Ground truth is DBus ShowExports on the live daemon, not just log lines.
#
# Runs INSIDE the image; the export root must be a bind-mounted real
# filesystem (overlayfs/--tmpfs cannot provide FSAL_VFS file handles).
# From the repo root:
#
#   mkdir -p .smoke-exportroot
#   docker run --rm --entrypoint bash \
#     --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH \
#     -v "$PWD/.smoke-exportroot:/srv/smoke" \
#     -v "$PWD/scripts/ganesha-export-reload-smoke.sh:/smoke.sh:ro" \
#     <image> /smoke.sh
#
# Companion of scripts/ganesha-startup-smoke.sh (plan 1.3 startup gate).
set -u

pass=0; fail=0
ok()  { echo "PASS: $*"; pass=$((pass+1)); }
bad() { echo "FAIL: $*"; fail=$((fail+1)); }

LOG=/tmp/ganesha-reload-smoke.log
CONF_DIR=/tmp/reload-smoke
EXPORTS_D="$CONF_DIR/exports.d"
CONF="$CONF_DIR/ganesha.conf"

mkdir -p "$EXPORTS_D" /srv/smoke/alpha /srv/smoke/bravo /var/lib/nfs/ganesha /run/dbus /run/rpcbind
dbus-daemon --system --fork 2>/dev/null || echo "    (dbus start failed; ShowExports checks will fail)"
rpcbind 2>/dev/null || echo "    (rpcbind start failed; non-fatal for v4-only)"
# Local keytab: NFS_KRB5 Active_krb5 defaults to true even without the block,
# so gss_principal_init CRITs without acquirable nfs/ accept creds (no KDC needed).
cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = SMOKE.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    SMOKE.TEST = { kdc = 127.0.0.1 }
EOF
printf 'addent -password -p nfs/%s@SMOKE.TEST -k 1 -e aes256-cts-hmac-sha1-96\nsmokepw\nwkt /etc/krb5.keytab\nq\n' "$(hostname)" | ktutil >/dev/null 2>&1

write_main_conf() { # args: fragment basenames to %include
    {
        cat <<'EOF'
NFS_CORE_PARAM {
    Protocols = 4;
    Enable_NLM = false;
    Enable_RQUOTA = false;
    Enable_UDP = false;
    Allow_Set_Io_Flusher_Fail = true;
}
NFSv4 {
    Graceless = true;
}
EOF
        for f in "$@"; do
            echo "%include $EXPORTS_D/$f"
        done
    } > "$CONF"
}

write_fragment() { # args: basename export_id path pseudo
    cat > "$EXPORTS_D/$1" <<EOF
EXPORT {
    Export_Id = $2;
    Path = $3;
    Pseudo = $4;
    Access_Type = RW;
    Squash = None;
    SecType = sys;
    Protocols = 4;
    Disable_ACL = true;
    FSAL { Name = VFS; }
}
EOF
}

show_exports() {
    dbus-send --system --print-reply --dest=org.ganesha.nfsd \
        /org/ganesha/nfsd/ExportMgr org.ganesha.nfsd.exportmgr.ShowExports 2>/dev/null
}

# Wait until the log contains N "Reread exports complete" markers.
wait_for_reread() {
    local want="$1" i n
    for i in $(seq 1 20); do
        n="$(grep -c 'Reread exports complete' "$LOG" 2>/dev/null || true)"
        [ "${n:-0}" -ge "$want" ] && return 0
        sleep 1
    done
    return 1
}

echo "== [1] start with export /alpha =="
write_fragment 10-alpha.conf 1 /srv/smoke/alpha /alpha
write_main_conf 10-alpha.conf
ganesha.nfsd -F -f "$CONF" -L "$LOG" -N NIV_INFO &
GPID=$!
up=""
for i in $(seq 1 30); do
    if ss -tln 2>/dev/null | grep -q ':2049'; then up=1; break; fi
    kill -0 "$GPID" 2>/dev/null || break
    sleep 1
done
if [ -n "$up" ]; then ok "ganesha.nfsd up on 2049 (pid $GPID)"; else bad "2049 never came up"; fi
# ShowExports structs carry the export Path (not the Pseudo); pseudo changes
# are asserted via the log_all_exports "pseudo (...)" lines after each reread.
exports_now="$(show_exports)"
if echo "$exports_now" | grep -q '"/srv/smoke/alpha"'; then
    ok "ShowExports lists export 1 (/srv/smoke/alpha)"
else
    bad "ShowExports missing /srv/smoke/alpha:"; echo "$exports_now" | head -20
fi

echo "== [2] ADD export 2 via SIGHUP (no restart) =="
write_fragment 20-bravo.conf 2 /srv/smoke/bravo /bravo
write_main_conf 10-alpha.conf 20-bravo.conf
kill -HUP "$GPID"
if wait_for_reread 1; then ok "reread_exports ran after SIGHUP"; else bad "no 'Reread exports complete' after add"; fi
exports_now="$(show_exports)"
if echo "$exports_now" | grep -q '"/srv/smoke/bravo"'; then
    ok "ShowExports gained export 2 (live add, same pid $GPID)"
else
    bad "live add failed — /srv/smoke/bravo absent:"; echo "$exports_now" | head -20
fi

echo "== [3] UPDATE export 2 Pseudo /bravo → /bravo2 via SIGHUP =="
write_fragment 20-bravo.conf 2 /srv/smoke/bravo /bravo2
kill -HUP "$GPID"
if wait_for_reread 2; then ok "second reread complete"; else bad "no second reread after update"; fi
exports_now="$(show_exports)"
if grep -q 'pseudo (/bravo2)' "$LOG" && echo "$exports_now" | grep -q '"/srv/smoke/bravo"'; then
    ok "export 2 updated in place (log shows pseudo (/bravo2); path still exported)"
else
    bad "live update failed (no pseudo (/bravo2) in log or export gone):"
    grep -o 'pseudo ([^)]*)' "$LOG" | sort -u | head -6
fi

echo "== [4] REMOVE export 2 via SIGHUP (prune_defunct_exports) =="
rm -f "$EXPORTS_D/20-bravo.conf"
write_main_conf 10-alpha.conf
kill -HUP "$GPID"
if wait_for_reread 3; then ok "third reread complete"; else bad "no third reread after remove"; fi
exports_now="$(show_exports)"
if echo "$exports_now" | grep -q '"/srv/smoke/bravo"'; then
    bad "live remove failed — /srv/smoke/bravo still exported:"; echo "$exports_now" | head -20
else
    ok "export 2 pruned from live export set"
fi
if echo "$exports_now" | grep -q '"/srv/smoke/alpha"'; then
    ok "export 1 survived all three reload cycles"
else
    bad "export 1 lost during reloads"
fi
if kill -0 "$GPID" 2>/dev/null; then
    ok "daemon never restarted (pid $GPID alive throughout)"
else
    bad "daemon died during reload cycles"
fi

echo "== [5] log audit =="
if grep -qiE ':CRIT :|:FATAL :' "$LOG"; then
    bad "CRIT/FATAL during reload cycles:"
    grep -iE ':CRIT :|:FATAL :' "$LOG" | head -8
else
    ok "no CRIT/FATAL across add/update/remove"
fi

kill "$GPID" 2>/dev/null; wait "$GPID" 2>/dev/null

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
