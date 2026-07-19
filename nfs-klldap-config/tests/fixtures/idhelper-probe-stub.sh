#!/bin/sh
# Probe stub: answers grps/resolve/daemon without hanging (used by supervisor integration tests).
# Emits short pw_name + @ principal passwd rows and short+@ group member fields (Ganesha uid2grp path).
mkdir -p /var/lib/nfs-klldap /var/lib/extrausers /var/run/nfs-klldap
PW="${NSS_PASSWD:-/var/lib/nfs-klldap/nss_passwd}"
GR="${NSS_GROUP:-/var/lib/nfs-klldap/nss_group}"
EPW="${NSS_EXTRAUSERS_PASSWD:-/var/lib/extrausers/passwd}"
EGR="${NSS_EXTRAUSERS_GROUP:-/var/lib/extrausers/group}"
mkdir -p "$(dirname "$PW")" "$(dirname "$GR")" "$(dirname "$EPW")" "$(dirname "$EGR")"
# Never clobber caller-supplied nss_wrapper fixtures (tests pre-seed short+@ rows).
if [ -n "${NSS_PASSWD:-}" ] && [ -s "$PW" ]; then
  grep -q '^root:' "$PW" 2>/dev/null || echo 'root:x:0:0:root:/root:/bin/sh' >> "$PW"
  grep -q '^root:x:0:' "$GR" 2>/dev/null || echo 'root:x:0:root,daemon,bin' >> "$GR"
else
  echo 'root:x:0:0:root:/root:/bin/sh' > "$PW"
  echo 'root:x:0:root,daemon,bin' > "$GR"
fi
cp -f "$PW" "$EPW" 2>/dev/null || true
cp -f "$GR" "$EGR" 2>/dev/null || true
echo probe > /var/lib/nfs-klldap/.bulk_seed_done || true

emit_user_nss() {
  principal="$1"
  short="${principal%%@*}"
  grep -q "^${short}:" "$PW" 2>/dev/null || echo "${short}:x:3788:3002:u:/nonexistent:/usr/sbin/nologin" >> "$PW"
  grep -q "^${principal}:" "$PW" 2>/dev/null || echo "${principal}:x:3788:3002:u:/nonexistent:/usr/sbin/nologin" >> "$PW"
  grep -q '^root:x:0:' "$GR" 2>/dev/null || echo 'root:x:0:root,daemon,bin' >> "$GR"
  for spec in "staff:x:3002:${short},${principal}" "writers:x:3005:${short},${principal}" "aux:x:3007:${short},${principal}"; do
    gname="${spec%%:*}"
    grep -q "^${gname}:x:" "$GR" 2>/dev/null || echo "$spec" >> "$GR"
  done
  cp -f "$PW" "$EPW" 2>/dev/null || true
  cp -f "$GR" "$EGR" 2>/dev/null || true
}

emit_machine_nss() {
  principal="$2"
  short="${principal#host/}"
  short="${short%%@*}"
  grep -q "^${short}:" "$PW" 2>/dev/null || echo "${short}:x:0:0:host:/nonexistent:/usr/sbin/nologin" >> "$PW"
  grep -q "^${principal}:" "$PW" 2>/dev/null || echo "${principal}:x:0:0:host:/nonexistent:/usr/sbin/nologin" >> "$PW"
  grep -q '^root:x:0:' "$GR" 2>/dev/null || echo 'root:x:0:root,daemon,bin' >> "$GR"
  cp -f "$PW" "$EPW" 2>/dev/null || true
  cp -f "$GR" "$EGR" 2>/dev/null || true
}

case "$1" in
  daemon)
    # Seed root nss row where the supervisor waits (NSS_PASSWD), then idle.
    # Without this, restart_idhelper_and_wait_bulk spins for the full timeout.
    mkdir -p "$(dirname "$PW")" "$(dirname "$GR")" 2>/dev/null || true
    if ! grep -q '^root:x:0:0:root:/root:/bin/sh' "$PW" 2>/dev/null; then
      echo 'root:x:0:0:root:/root:/bin/sh' >> "$PW"
    fi
    # Keep the process as this shell (not exec'd to sleep) so pkill by binary
    # path and process_is_live(pid) stay aligned under the supervisor.
    trap 'exit 0' TERM HUP
    while :; do sleep 60 & wait $! || true; done
    ;;
  grps)
    case "$2" in
      host/*) emit_machine_nss grps "$2" ;;
      *@*) emit_user_nss "$2" ;;
    esac
    case "$2" in
      host/*) echo "OK 0"; exit 0 ;;
      *) echo "OK 3002|3007|3005"; exit 0 ;;
    esac ;;
  resolve)
    case "$2" in
      host/*) echo "$2 -> name=stub uid=0 gid=0 kind=machine source=stub"; exit 0 ;;
      *) echo "$2 -> name=stub uid=3788 gid=3002 kind=user source=stub"; exit 0 ;;
    esac ;;
  check) echo "realm: TEST"; exit 0 ;;
esac
echo "unknown command: $1" >&2
exit 1