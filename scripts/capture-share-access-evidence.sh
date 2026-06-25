#!/bin/bash
# capture-share-access-evidence.sh — krb5p NFSv4 share-access proof (external client + LLDAP uid).
# Emits: $SCRATCH/share-access-transcript.log, $SCRATCH/ganesha.log, $SCRATCH/host-artifacts.log
# Usage: SCRATCH=/path NFS_TEST_USER_PW='...' ./scripts/capture-share-access-evidence.sh [server_container]
set -euo pipefail

CONTAINER="${1:-nfs-klldap}"
SCRATCH="${SCRATCH:?set SCRATCH to the verification scratch directory}"
USER_PRINC="${NFS_TEST_USER:-testuser1@TESTLABBY.LOCAL}"
USER_PW="${NFS_TEST_USER_PW:?set NFS_TEST_USER_PW for Kerberos user}"
HOST_STUFF="${NFS_TEST_HOST_STUFF:-/home/local/Projects/test-nfs-work/stuff}"
HOST_JUNK="${NFS_TEST_HOST_JUNK:-/home/local/Projects/test-nfs-work/junk}"
CLIENT_IMAGE="${NFS_TEST_CLIENT_IMAGE:-fedora:42}"
EXPECTED_UID="${NFS_TEST_EXPECTED_UID:-3001}"
EXPECTED_GID="${NFS_TEST_EXPECTED_GID:-3005}"

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

# Host agent shells may run in a nested user namespace (stat shows 65534/nobody).
# Read bind-mount ownership from the init user namespace instead.
host_stat_init_ns() {
  local host_path="$1" fmt="$2"
  docker run --rm --pid=host --userns=host \
    -v "$(dirname "$host_path"):/mnt:ro" \
    "$CLIENT_IMAGE" stat -c "$fmt" "/mnt/$(basename "$host_path")"
}

SERVER_FQDN="$(docker exec "$CONTAINER" hostname -f | tr -d '\r')"
[[ -n "$SERVER_FQDN" && "$SERVER_FQDN" != "localhost" ]] || fail "hostname -f must be non-localhost (got: ${SERVER_FQDN:-empty})"

docker exec "$CONTAINER" cat /etc/krb5.conf >"$SCRATCH/krb5.conf"

RUN_ID="$(date +%s)"
PROBE="nfs-evidence-${RUN_ID}.txt"
STUFF_PAYLOAD="stuff-${RUN_ID}"
JUNK_PAYLOAD="junk-${RUN_ID}"

echo "=== evidence run ${RUN_ID} $(date -Is) ===" | tee -a "$TRANSCRIPT"
echo "SERVER_FQDN=$SERVER_FQDN PROBE=$PROBE" | tee -a "$TRANSCRIPT"

lines_before="$(docker exec "$CONTAINER" bash -c 'wc -l < /var/log/ganesha.log')"
echo "ganesha_lines_before=$lines_before" | tee -a "$TRANSCRIPT"

# Writable export roots for krb5p user creates; transcript records mode for audit.
docker exec "$CONTAINER" bash -c "chmod 1777 /export/stuff /export/junk && ls -ld /export/stuff /export/junk" >>"$TRANSCRIPT" 2>&1

# External NFS client (not loopback inside server) so rpc.gssd presents testuser1@ for I/O.
docker run --rm -i --network=host --privileged \
  -v "$SCRATCH/krb5.conf:/etc/krb5.conf:ro" \
  -v "$SCRATCH:/scratch" \
  "$CLIENT_IMAGE" bash -s -- "$SERVER_FQDN" "$USER_PRINC" "$USER_PW" "$PROBE" "$STUFF_PAYLOAD" "$JUNK_PAYLOAD" <<'CLIENT' >>"$TRANSCRIPT" 2>&1
set -euo pipefail
SERVER_FQDN="$1"
USER_PRINC="$2"
USER_PW="$3"
PROBE="$4"
STUFF_PAYLOAD="$5"
JUNK_PAYLOAD="$6"

dnf install -y -q nfs-utils krb5-workstation >/dev/null
groupadd -g 3005 testgrp 2>/dev/null || true
useradd -u 3001 -g 3005 testuser1 2>/dev/null || true
export KRB5_CONFIG=/etc/krb5.conf
export KRB5CCNAME=FILE:/scratch/krb5cc_evidence
printf '%s\n' "$USER_PW" | kinit "$USER_PRINC"
chown testuser1:testgrp /scratch/krb5cc_evidence
chmod 600 /scratch/krb5cc_evidence
klist

printf '[general]\npipefs-directory=/run/rpc_pipefs\n[gssd]\nuse-machine-creds=0\n' >/etc/nfs.conf
mkdir -p /run/rpc_pipefs /mnt/stuff /mnt/junk
mount -t rpc_pipefs rpc_pipefs /run/rpc_pipefs
rpc.gssd -f -n &
sleep 2

mount -t nfs4 -o sec=krb5p,rw,hard,intr,vers=4.1 "${SERVER_FQDN}:/stuff" /mnt/stuff
echo "mount stuff exit=$?"
mountpoint -q /mnt/stuff || { echo "mountpoint stuff: FAIL"; exit 1; }
echo "mountpoint stuff: OK"
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /mnt/stuff

mount -t nfs4 -o sec=krb5p,rw,hard,intr,vers=4.1 "${SERVER_FQDN}:/junk" /mnt/junk
echo "mount junk exit=$?"
mountpoint -q /mnt/junk || { echo "mountpoint junk: FAIL"; exit 1; }
echo "mountpoint junk: OK"
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /mnt/junk

runuser -u testuser1 -g testgrp -- env KRB5CCNAME=FILE:/scratch/krb5cc_evidence KRB5_CONFIG=/etc/krb5.conf \
  bash -c "echo ${STUFF_PAYLOAD} > /mnt/stuff/${PROBE}"
runuser -u testuser1 -g testgrp -- env KRB5CCNAME=FILE:/scratch/krb5cc_evidence KRB5_CONFIG=/etc/krb5.conf \
  bash -c "echo ${JUNK_PAYLOAD} > /mnt/junk/${PROBE}"
echo "wrote stuff payload: ${STUFF_PAYLOAD}"
echo "wrote junk payload: ${JUNK_PAYLOAD}"

mnt_inode=$(stat -c '%i' "/mnt/stuff/${PROBE}")
echo "stuff mnt_inode=${mnt_inode}"
mnt_inode=$(stat -c '%i' "/mnt/junk/${PROBE}")
echo "junk mnt_inode=${mnt_inode}"

umount /mnt/stuff /mnt/junk
echo "umount: OK"
CLIENT

docker exec "$CONTAINER" bash -c "tail -n +$((lines_before + 1)) /var/log/ganesha.log" >"$GANESHA_OUT"

RUN_TS="$(date -Is)"
{
  echo "=== host artifacts ${RUN_TS} run_id=${RUN_ID} ==="
  echo "probe=${PROBE}"
  docker exec "$CONTAINER" stat -c 'container stuff: %u %g %i %n' "/export/stuff/${PROBE}"
  docker exec "$CONTAINER" stat -c 'container junk: %u %g %i %n' "/export/junk/${PROBE}"
  host_stat_init_ns "${HOST_STUFF}/${PROBE}" 'host init-ns stuff: %u %g %i %n' || echo "host init-ns stuff stat: FAIL"
  host_stat_init_ns "${HOST_JUNK}/${PROBE}" 'host init-ns junk: %u %g %i %n' || echo "host init-ns junk stat: FAIL"
  stat -c 'agent-shell stuff: %u %g (nested userns view)' "${HOST_STUFF}/${PROBE}" 2>&1 || true
  stat -c 'agent-shell junk: %u %g (nested userns view)' "${HOST_JUNK}/${PROBE}" 2>&1 || true
  echo "stuff_content=$(cat "${HOST_STUFF}/${PROBE}")"
  echo "junk_content=$(cat "${HOST_JUNK}/${PROBE}")"
} >>"$HOST_ART" 2>&1

# Hard gates
grep -q 'mountpoint stuff: OK' "$TRANSCRIPT" || fail "stuff mount not confirmed"
grep -q 'mountpoint junk: OK' "$TRANSCRIPT" || fail "junk mount not confirmed"
grep -q "wrote stuff payload: ${STUFF_PAYLOAD}" "$TRANSCRIPT" || fail "stuff payload missing from transcript"
grep -q "wrote junk payload: ${JUNK_PAYLOAD}" "$TRANSCRIPT" || fail "junk payload missing from transcript"

docker exec "$CONTAINER" test -f "/export/stuff/${PROBE}" || fail "probe missing in /export/stuff"
docker exec "$CONTAINER" test -f "/export/junk/${PROBE}" || fail "probe missing in /export/junk"

stuff_uid="$(docker exec "$CONTAINER" stat -c '%u' "/export/stuff/${PROBE}")"
junk_uid="$(docker exec "$CONTAINER" stat -c '%u' "/export/junk/${PROBE}")"
[[ "$stuff_uid" == "$EXPECTED_UID" ]] || fail "stuff uid ${stuff_uid} != expected ${EXPECTED_UID}"
[[ "$junk_uid" == "$EXPECTED_UID" ]] || fail "junk uid ${junk_uid} != expected ${EXPECTED_UID}"

host_stuff_uid="$(host_stat_init_ns "${HOST_STUFF}/${PROBE}" '%u')"
host_junk_uid="$(host_stat_init_ns "${HOST_JUNK}/${PROBE}" '%u')"
[[ "$host_stuff_uid" == "$EXPECTED_UID" ]] || fail "host init-ns stuff uid ${host_stuff_uid} != expected ${EXPECTED_UID}"
[[ "$host_junk_uid" == "$EXPECTED_UID" ]] || fail "host init-ns junk uid ${host_junk_uid} != expected ${EXPECTED_UID}"

test -r "${HOST_STUFF}/${PROBE}" || fail "host cannot read stuff probe"
test -r "${HOST_JUNK}/${PROBE}" || fail "host cannot read junk probe"
grep -q "^stuff_content=${STUFF_PAYLOAD}$" "$HOST_ART" || fail "host stuff content mismatch"
grep -q "^junk_content=${JUNK_PAYLOAD}$" "$HOST_ART" || fail "host junk content mismatch"

grep -qF "$PROBE" "$GANESHA_OUT" || fail "ganesha slice missing probe filename"
grep -qF "name=${PROBE}" "$GANESHA_OUT" || fail "ganesha slice missing OP_LOOKUP for probe filename"
grep -qiE 'Get uid for testuser1@|testuser1@TESTLABBY\.LOCAL' "$GANESHA_OUT" || fail "ganesha slice missing testuser1 uid resolution"
grep -qiE 'name=stuff|/export/stuff' "$GANESHA_OUT" || fail "ganesha slice missing stuff export"
grep -qiE 'name=junk|/export/junk' "$GANESHA_OUT" || fail "ganesha slice missing junk export"
grep -q 'OP_WRITE' "$GANESHA_OUT" || fail "ganesha slice missing OP_WRITE"
grep -q 'OP_WRITE.*NFS4_OK' "$GANESHA_OUT" || fail "ganesha slice missing OP_WRITE NFS4_OK"

echo "OK: share access evidence captured under $SCRATCH (probe=${PROBE}, uid=${EXPECTED_UID})"