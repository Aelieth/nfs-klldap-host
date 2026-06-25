#!/bin/bash
# capture-share-access-evidence.sh — deterministic krb5p share-access proof for verification.
# Emits exactly: $SCRATCH/share-access-transcript.log, $SCRATCH/ganesha.log, $SCRATCH/host-artifacts.log
# Usage: SCRATCH=/path NFS_TEST_USER_PW='...' ./scripts/capture-share-access-evidence.sh [container_name]
set -euo pipefail

CONTAINER="${1:-nfs-klldap}"
SCRATCH="${SCRATCH:?set SCRATCH to the verification scratch directory}"
USER_PRINC="${NFS_TEST_USER:-testuser1@TESTLABBY.LOCAL}"
USER_PW="${NFS_TEST_USER_PW:?set NFS_TEST_USER_PW for Kerberos user}"
PROBE="nfs-evidence-probe.txt"
HOST_STUFF="/home/local/Projects/test-nfs-work/stuff"
HOST_JUNK="/home/local/Projects/test-nfs-work/junk"

TRANSCRIPT="$SCRATCH/share-access-transcript.log"
GANESHA_OUT="$SCRATCH/ganesha.log"
HOST_ART="$SCRATCH/host-artifacts.log"

mkdir -p "$SCRATCH"
: >"$TRANSCRIPT"
: >"$GANESHA_OUT"
: >"$HOST_ART"

fail() {
  echo "FAIL: $*" | tee -a "$TRANSCRIPT" >&2
  exit 1
}

SERVER="$(docker exec "$CONTAINER" hostname -f | tr -d '\r')"
[[ -n "$SERVER" && "$SERVER" != "localhost" ]] || fail "hostname -f must resolve to non-localhost server (got: ${SERVER:-empty})"

docker exec "$CONTAINER" cat /etc/krb5.conf >"$SCRATCH/krb5.conf"
docker cp "$SCRATCH/krb5.conf" "$CONTAINER:/tmp/krb5.conf"

docker exec -i "$CONTAINER" bash -s -- "$SERVER" "$USER_PRINC" "$USER_PW" "$PROBE" <<'INNER' >>"$TRANSCRIPT" 2>&1
set -euo pipefail
SERVER="$1"
USER_PRINC="$2"
USER_PW="$3"
PROBE="$4"

export KRB5_CONFIG=/tmp/krb5.conf
export KRB5CCNAME=FILE:/tmp/krb5cc_evidence

echo "=== share access evidence run $(date -Is) ==="
echo "SERVER=$SERVER"

printf '%s\n' "$USER_PW" | kinit "$USER_PRINC"
klist

mkdir -p /run/rpc_pipefs /mnt/stuff /mnt/junk
mountpoint -q /run/rpc_pipefs || mount -t rpc_pipefs rpc_pipefs /run/rpc_pipefs
pkill rpc.gssd 2>/dev/null || true
rpc.gssd -f &
sleep 1

# Parent dir on stuff may be 770; allow traverse so host test -r can reach the probe file.
chmod o+rx /export/stuff 2>/dev/null || true

lines_before=$(wc -l < /var/log/ganesha.log)

mount -t nfs4 -o sec=krb5p,rw,hard,intr,vers=4.1 "${SERVER}:/stuff" /mnt/stuff
echo "mount stuff exit=$?"
mountpoint -q /mnt/stuff || { echo "mountpoint stuff: FAIL"; exit 1; }
echo "mountpoint stuff: OK"
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /mnt/stuff

mount -t nfs4 -o sec=krb5p,rw,hard,intr,vers=4.1 "${SERVER}:/junk" /mnt/junk
echo "mount junk exit=$?"
mountpoint -q /mnt/junk || { echo "mountpoint junk: FAIL"; exit 1; }
echo "mountpoint junk: OK"
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /mnt/junk

stamp=$(date +%s)
stuff_payload="probe-stuff-${stamp}"
junk_payload="probe-junk-${stamp}"
echo "$stuff_payload" > "/mnt/stuff/${PROBE}"
echo "$junk_payload" > "/mnt/junk/${PROBE}"

echo "wrote stuff payload: $stuff_payload"
echo "wrote junk payload: $junk_payload"

mnt_inode=$(stat -c '%i' "/mnt/stuff/${PROBE}")
exp_inode=$(stat -c '%i' "/export/stuff/${PROBE}")
echo "stuff inode mnt=$mnt_inode export=$exp_inode"
[[ "$mnt_inode" == "$exp_inode" ]] || { echo "stuff inode mismatch: FAIL"; exit 1; }
echo "stuff inode match: OK"

mnt_inode=$(stat -c '%i' "/mnt/junk/${PROBE}")
exp_inode=$(stat -c '%i' "/export/junk/${PROBE}")
echo "junk inode mnt=$mnt_inode export=$exp_inode"
[[ "$mnt_inode" == "$exp_inode" ]] || { echo "junk inode mismatch: FAIL"; exit 1; }
echo "junk inode match: OK"

ls -la "/export/stuff/${PROBE}" "/export/junk/${PROBE}"

umount /mnt/stuff /mnt/junk
echo "umount: OK"

tail -n +$((lines_before + 1)) /var/log/ganesha.log > /tmp/ganesha-evidence-delta.log
wc -l /tmp/ganesha-evidence-delta.log
INNER

docker cp "$CONTAINER:/tmp/ganesha-evidence-delta.log" "$GANESHA_OUT"

{
  echo "=== host artifacts $(date -Is) ==="
  echo "probe=$PROBE"
  docker exec "$CONTAINER" test -f "/export/stuff/${PROBE}" && echo "container /export/stuff/${PROBE}: present" || echo "container /export/stuff/${PROBE}: MISSING"
  docker exec "$CONTAINER" test -f "/export/junk/${PROBE}" && echo "container /export/junk/${PROBE}: present" || echo "container /export/junk/${PROBE}: MISSING"
  stat "${HOST_STUFF}/${PROBE}" 2>&1 || echo "host stuff stat: FAIL"
  stat "${HOST_JUNK}/${PROBE}" 2>&1 || echo "host junk stat: FAIL"
} >>"$HOST_ART" 2>&1

# Hard gates
grep -q 'mountpoint stuff: OK' "$TRANSCRIPT" || fail "stuff mount not confirmed in transcript"
grep -q 'mountpoint junk: OK' "$TRANSCRIPT" || fail "junk mount not confirmed in transcript"
grep -q 'stuff inode match: OK' "$TRANSCRIPT" || fail "stuff inode match missing"
grep -q 'junk inode match: OK' "$TRANSCRIPT" || fail "junk inode match missing"
docker exec "$CONTAINER" test -f "/export/stuff/${PROBE}" || fail "probe missing in container /export/stuff"
docker exec "$CONTAINER" test -f "/export/junk/${PROBE}" || fail "probe missing in container /export/junk"
test -r "${HOST_STUFF}/${PROBE}" || fail "host cannot read ${HOST_STUFF}/${PROBE}"
test -r "${HOST_JUNK}/${PROBE}" || fail "host cannot read ${HOST_JUNK}/${PROBE}"

grep -qiE 'name=stuff|/export/stuff' "$GANESHA_OUT" || fail "ganesha slice missing stuff export lines"
grep -qiE 'name=junk|/export/junk' "$GANESHA_OUT" || fail "ganesha slice missing junk export lines"
grep -q 'OP_WRITE' "$GANESHA_OUT" || fail "ganesha slice missing OP_WRITE"
grep -q 'OP_WRITE.*NFS4_OK' "$GANESHA_OUT" || fail "ganesha slice missing OP_WRITE NFS4_OK"

echo "OK: share access evidence captured under $SCRATCH"