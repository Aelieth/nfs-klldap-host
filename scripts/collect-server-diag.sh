#!/bin/bash
# collect-server-diag.sh — server half of every NFS/krb5/ACL triage; the
# counterpart of setup-script/collect-client-diag.sh. Run on the docker host.
# Captures what the 2026-07-14 blue-lt analysis had to guess at: idhelper
# write timing, exact NSS store contents/inodes, and the container's own view
# of a user's groups.
# Usage: ./collect-server-diag.sh [container] [test-user] [output-parent-dir]
set -uo pipefail

CONTAINER="${1:-nfs-klldap-host}"
TEST_USER="${2:-testuser1}"
PARENT="${3:-/tmp}"
OUT="${PARENT}/nfs-diag-$(hostname -s)-server-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

run() {
  local label="$1"; shift
  { echo "### $*"; "$@" 2>&1; } > "${OUT}/${label}.txt" || true
}

dexec() { docker exec "$CONTAINER" "$@"; }

run 00-versions       bash -c "docker inspect --format '{{.Config.Image}} started={{.State.StartedAt}} health={{if .State.Health}}{{.State.Health.Status}}{{end}}' '$CONTAINER'; docker exec '$CONTAINER' dpkg-query -W 'nfs-ganesha*' 'libntirpc*' 2>/dev/null"
run 01-container-ps   docker ps --filter "name=$CONTAINER" --format '{{.Names}}  {{.Status}}  {{.Ports}}'

# Supervisor + idhelper stderr: materialize/observer/rebulk lines carry the
# write timeline the NSS-race analysis needs.
run 02-docker-logs    bash -c "docker logs --tail 2000 --timestamps '$CONTAINER' 2>&1 | tail -2000"
run 03-idhelper-lines bash -c "docker logs --timestamps '$CONTAINER' 2>&1 | grep -E 'idhelper|materialize|rebulk|observed|fast-heal' | tail -300"

run 04-ganesha-log    dexec sh -c 'tail -5000 /var/log/ganesha.log 2>/dev/null'
run 05-ganesha-warns  dexec sh -c "grep -E ':(MAJ|CRIT|WARN|EVENT|FATAL) :' /var/log/ganesha.log 2>/dev/null | tail -200"
run 06-ganesha-conf   dexec sh -c 'ls -l /etc/ganesha/ 2>/dev/null; for f in /etc/ganesha/*.conf /etc/ganesha/exports.d/*.conf; do [ -f "$f" ] || continue; echo "--- $f"; sed -e "s/\(password\|authtok\|bindpw\)[^;]*/\1 = REDACTED/Ig" "$f"; done'

# NSS stores: full contents + inode/mtime. Inode changes between two captures
# = a materialize rewrite happened in between (steady state should be none).
run 07-nss-stat       dexec sh -c 'stat -c "%n ino=%i size=%s mtime=%y" /var/lib/nfs-klldap/nss_passwd /var/lib/nfs-klldap/nss_group /var/lib/extrausers/passwd /var/lib/extrausers/group 2>/dev/null'
run 08-nss-passwd     dexec sh -c 'cat /var/lib/nfs-klldap/nss_passwd 2>/dev/null'
run 09-nss-group      dexec sh -c 'cat /var/lib/nfs-klldap/nss_group 2>/dev/null'
run 10-extrausers     dexec sh -c 'echo "--- passwd"; cat /var/lib/extrausers/passwd 2>/dev/null; echo "--- group"; cat /var/lib/extrausers/group 2>/dev/null'
run 11-idmap-cache    dexec sh -c 'stat -c "%n ino=%i size=%s mtime=%y" /var/lib/nfs-klldap/idmap.cache 2>/dev/null; sha256sum /var/lib/nfs-klldap/idmap.cache 2>/dev/null; head -100 /var/lib/nfs-klldap/idmap.cache 2>/dev/null'

# The container's own answer for the test user — plain NSS and under the same
# nss_wrapper env ganesha runs with. Counts here must match the client `id`.
run 12-getent-user    dexec sh -c "getent passwd '$TEST_USER' 2>/dev/null; id -G '$TEST_USER' 2>/dev/null; id '$TEST_USER' 2>/dev/null"
run 13-wrapped-groups dexec sh -c "so=\$(ls /usr/lib/*/libnss_wrapper.so /usr/lib/libnss_wrapper.so 2>/dev/null | head -1); [ -n \"\$so\" ] || { echo 'no libnss_wrapper.so'; exit 0; }; LD_PRELOAD=\$so NSS_WRAPPER_PASSWD=/var/lib/nfs-klldap/nss_passwd NSS_WRAPPER_GROUP=/var/lib/nfs-klldap/nss_group id -G '$TEST_USER' 2>&1; LD_PRELOAD=\$so NSS_WRAPPER_PASSWD=/var/lib/nfs-klldap/nss_passwd NSS_WRAPPER_GROUP=/var/lib/nfs-klldap/nss_group getent passwd '$TEST_USER' 2>&1"

run 14-mountinfo      dexec sh -c 'grep -E "/export" /proc/self/mountinfo 2>/dev/null'
run 15-export-acls    dexec sh -c 'find /export -maxdepth 2 \( -type d -o -type f \) -print0 2>/dev/null | xargs -0 -r getfacl -p 2>/dev/null | head -500'
run 16-share-manifest bash -c 'curl -fsSk --max-time 10 https://localhost:9630/client-manifest.json 2>&1'

tar -C "$(dirname "$OUT")" -czf "${OUT}.tar.gz" "$(basename "$OUT")"
echo "Diag bundle: ${OUT}.tar.gz"
