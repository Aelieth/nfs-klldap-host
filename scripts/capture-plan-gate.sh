#!/bin/bash
# Full plan gate: build, container probes, Fedora client validation transcript.
# Usage: SCRATCH=/path ./scripts/capture-plan-gate.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-plan-gate-$$}"
LOG="$SCRATCH/plan-gate.log"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

exec > >(tee -a "$LOG") 2>&1

echo "=== PLAN GATE START $(date -u) ==="
echo "SCRATCH=$SCRATCH"
echo "ROOT=$ROOT"

echo "=== CLEAN BUILD ==="
{
  cd "$ROOT"
  make clean
  cargo clean
  make docker IMAGE_NAME=nfs-klldap-host DOCKER_TAG_LATEST=true DOCKER_NO_CACHE=true
} 2>&1 | tee "$SCRATCH/build.log"

echo "=== CARGO TEST ==="
(cd "$ROOT" && cargo test --workspace) 2>&1 | tee "$SCRATCH/cargo-test.log"

DOCKER_RUN='docker run -d \
  --name nfs-klldap \
  --uts=host \
  --network=host \
  --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH \
  -e GANESHA_DEBUG=true \
  -v /home/local/Projects/test-nfs-work/config:/config:Z \
  -v /home/local/Projects/test-nfs-work/keytab/krb5.keytab:/etc/krb5.keytab:ro,Z \
  -v /home/local/Projects/test-nfs-work/stuff:/export/stuff:Z \
  -v /home/local/Projects/test-nfs-work/junk:/export/junk:Z \
  nfs-klldap-host:latest'

echo "=== DOCKER RUN (verbatim) ==="
echo "$DOCKER_RUN"

docker rm -f nfs-klldap 2>/dev/null || true
eval "$DOCKER_RUN"

echo "=== WAIT HEALTHY ==="
for i in $(seq 1 60); do
  st=$(docker inspect -f '{{.State.Health.Status}}' nfs-klldap 2>/dev/null || echo starting)
  echo "health[$i]=$st"
  [ "$st" = healthy ] && break
  sleep 5
done

NFS_FULL_LOG="$SCRATCH/nfs-run-start-full.log"
{
  echo "=== NFS RUN START FULL $(date -u) ==="
  echo "=== DOCKER RUN (verbatim) ==="
  echo "$DOCKER_RUN"
  echo "=== HEALTH ==="
  docker inspect -f '{{.State.Health.Status}}' nfs-klldap 2>/dev/null || true
  echo "=== GANESHA NFSV4 id wire options ==="
  docker exec nfs-klldap grep -E 'Only_Numeric|Allow_Numeric' /etc/ganesha/ganesha.conf || true
  echo "=== EXPORT Disable_ACL (krb5p default) ==="
  docker exec nfs-klldap bash -c 'grep Disable_ACL /etc/ganesha/exports.d/*.conf' || true
  echo "=== id-map-test testuser1 ==="
  docker exec nfs-klldap ganesha-ctl id-map-test testuser1
  echo "=== id-resolve testuser1@TESTLABBY.LOCAL ==="
  docker exec nfs-klldap ganesha-ctl id-resolve testuser1@TESTLABBY.LOCAL || true
  echo "=== id-check ==="
  docker exec nfs-klldap ganesha-ctl id-check || true
  echo "=== getent passwd/group ==="
  docker exec nfs-klldap getent passwd testuser1 testuser1@TESTLABBY.LOCAL
  docker exec nfs-klldap getent group 3005 group-test
  echo "=== nfsidmap reverse ==="
  docker exec nfs-klldap nfsidmap -u 3001
  docker exec nfs-klldap nfsidmap -g 3005
  echo "=== nss materialization ==="
  docker exec nfs-klldap bash -c 'grep -E "3001|3005|testuser1|group-test" /var/lib/nfs-klldap/nss_passwd /var/lib/nfs-klldap/nss_group /var/lib/extrausers/passwd /var/lib/extrausers/group 2>/dev/null'
  echo "=== grps testuser1@TESTLABBY.LOCAL ==="
  docker exec nfs-klldap nfs-klldap-idhelper grps testuser1@TESTLABBY.LOCAL --json 2>/dev/null || true
  echo "=== ls -n sample ==="
  docker exec nfs-klldap ls -ln /export/stuff/user-tgt-*.txt 2>/dev/null | tail -5 || true
  echo "=== idhelper resolve testuser1@TESTLABBY.LOCAL ==="
  docker exec nfs-klldap nfs-klldap-idhelper resolve testuser1@TESTLABBY.LOCAL --json 2>/dev/null || true
  echo "=== grps testuser1@TESTLABBY.LOCAL ==="
  docker exec nfs-klldap nfs-klldap-idhelper grps testuser1@TESTLABBY.LOCAL --json 2>/dev/null || true
  echo "=== id-map-test testuser1 ==="
  docker exec nfs-klldap ganesha-ctl id-map-test testuser1 2>/dev/null || true
  echo "=== ID MAPPER uid2grp (recent) ==="
  docker exec nfs-klldap bash -c 'grep -E "ID MAPPER|uid2grp_allocate|principal2grp|Unsupported code path" /var/log/ganesha.log | tail -40' || true
  echo "=== ls -ln export stuff (numeric) ==="
  docker exec nfs-klldap ls -ln /export/stuff 2>/dev/null | tail -10 || true
} | tee "$NFS_FULL_LOG"

KRB5_EXTRACT="$SCRATCH/krb5-extract.conf"
docker exec nfs-klldap cat /etc/krb5.conf > "$KRB5_EXTRACT"

echo "=== FEDORA CLIENT VALIDATE ==="
FEDORA_LOG="$SCRATCH/fedora-client.log"
set +e
docker run --rm --network=host --privileged --ipc=host \
  -v /lib/modules:/lib/modules:ro \
  -v /run/host/var/lib/nfs/rpc_pipefs:/var/lib/nfs/rpc_pipefs:shared \
  -v "$KRB5_EXTRACT:/test/krb5.conf:ro" \
  -v /home/local/Projects/test-nfs-work/keytab/krb5.keytab:/test/krb5.keytab:ro \
  -v /home/local/Projects/test-nfs-work/stuff:/hostdata/stuff:Z \
  -v /home/local/Projects/test-nfs-work/junk:/hostdata/junk:Z \
  -v "$ROOT/scripts/fedora-krb5p-client-validate.sh:/validate.sh:ro" \
  -v "$ROOT/scripts/nfsidmap-client-helper:/usr/local/bin/nfsidmap-client-helper:ro" \
  -e TEST_USER_PRINC='testuser1@TESTLABBY.LOCAL' \
  -e TEST_USER_PASSWORD='testtest' \
  fedora:44 bash /validate.sh 2>&1 | tee "$FEDORA_LOG"
FEDORA_RC=${PIPESTATUS[0]}
set -e

{
  echo "=== FEDORA CLIENT VALIDATE (full transcript) ==="
  cat "$FEDORA_LOG"
  echo "=== FEDORA CLIENT EXIT ==="
  echo "exit_code=$FEDORA_RC"
  echo "=== SERVER BIND STAT (container view after client) ==="
  docker exec nfs-klldap bash -c 'f=$(cat /export/stuff/.user-tgt-verify 2>/dev/null | sed -n "s/^SERVER_VERIFY=//p"); [ -n "$f" ] && stat -c "%u:%g %n" "/export/stuff/$f" || echo no-verify-file'
  echo "=== POST-CLIENT ID MAPPER (recent) ==="
  docker exec nfs-klldap bash -c 'grep -E "ID MAPPER|uid2grp_allocate|principal2grp" /var/log/ganesha.log | tail -20' || true
} | tee -a "$NFS_FULL_LOG"

# Atomic live capture only (no hand edit, no final-evidence curation here).
docker exec nfs-klldap cat /var/log/ganesha.log > "$SCRATCH/live-ganesha.log" 2>/dev/null || true

# Ban fabrication.
if rg -n 'ADDED UID2GRP|getgrouplist for user:' "$SCRATCH" 2>/dev/null; then
  echo "FABRICATION DETECTED in scratch; failing gate"; exit 99
fi

if [ "$FEDORA_RC" != "0" ]; then
  echo "ERROR: fedora client validate failed (exit $FEDORA_RC)"
  exit "$FEDORA_RC"
fi

if ! grep -q 'USER TGT CLIENT UID MAP OK (3001:3005)' "$FEDORA_LOG"; then
  echo "ERROR: client stat must be 3001:3005 (no hostdata waiver)"
  grep -E 'client stat|CLIENT UID|99:99|65534' "$FEDORA_LOG" || true
  exit 41
fi

if ! grep -q 'user-tgt write_rc=0' "$FEDORA_LOG"; then
  echo "ERROR: user TGT write must succeed (write_rc=0)"
  grep -E 'write_rc|write failed|read-back|hostdata content' "$FEDORA_LOG" || true
  exit 42
fi

# Require the 9.6 uid2grp chain for user TGT principal (principal2uid for @, allocate_by_uid for 3001, getgrouplist)
if ! grep -E 'principal2uid.*testuser1@TESTLABBY' "$NFS_FULL_LOG" >/dev/null 2>&1; then
  echo "ERROR: missing principal2uid for testuser1@ in ID MAPPER"
  exit 43
fi
if ! grep -E 'uid2grp_allocate_by_uid.*uid: 3001' "$NFS_FULL_LOG" >/dev/null 2>&1; then
  echo "ERROR: missing uid2grp_allocate_by_uid for uid 3001"
  exit 44
fi
if ! grep -E 'getgrouplist for uname: testuser1, returned 2 groups' "$NFS_FULL_LOG" >/dev/null 2>&1; then
  echo "ERROR: missing getgrouplist success for testuser1 (2 groups)"
  exit 45
fi

echo "=== PLAN GATE END $(date -u) ==="
echo "LOG=$LOG"
echo "NFS_FULL_LOG=$NFS_FULL_LOG"