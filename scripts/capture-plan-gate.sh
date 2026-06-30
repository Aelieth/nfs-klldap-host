#!/bin/bash
# Full plan gate: build, chain preflight, Fedora client validation transcript.
# Usage: SCRATCH=/path ./scripts/capture-plan-gate.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-plan-gate-$$}"
LOG="$SCRATCH/plan-gate.log"
KEYTAB_PATH="${KEYTAB_PATH:-}"
NFS_FULL_LOG="$SCRATCH/nfs-run-start-full.log"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
# Prefer a live nfs keytab (/tmp/nfs.keytab) over the repo placeholder (DUMMYKEYTABDATA).
if [ -z "$KEYTAB_PATH" ]; then
  if [ -s /tmp/nfs.keytab ] && ! grep -q DUMMYKEYTABDATA /tmp/nfs.keytab 2>/dev/null; then
    KEYTAB_PATH=/tmp/nfs.keytab
  else
    KEYTAB_PATH=/home/local/Projects/test-nfs-work/keytab/krb5.keytab
  fi
fi
echo "KEYTAB_PATH=$KEYTAB_PATH"
# DUMMYKEYTABDATA placeholder cannot kinit; prefer a generated nfs keytab when lldap-kerb is up.
if [ ! -s "$KEYTAB_PATH" ] || grep -q DUMMYKEYTABDATA "$KEYTAB_PATH" 2>/dev/null; then
  if docker inspect lldap-kerb >/dev/null 2>&1; then
    docker exec lldap-kerb kadmin.local -q "ktadd -k /tmp/nfs-gate.keytab nfs/aurora@TESTLABBY.LOCAL nfs/aurora.testlabby.local@TESTLABBY.LOCAL" >/dev/null 2>&1 || true
    docker cp lldap-kerb:/tmp/nfs-gate.keytab "$SCRATCH/nfs-gate.keytab" 2>/dev/null || true
    if [ -s "$SCRATCH/nfs-gate.keytab" ]; then
      KEYTAB_PATH="$SCRATCH/nfs-gate.keytab"
      echo "Using generated KEYTAB_PATH=$KEYTAB_PATH (placeholder keytab unusable)"
    fi
  fi
fi

exec > >(tee -a "$LOG") 2>&1

echo "=== PLAN GATE START $(date -u) ==="
echo "SCRATCH=$SCRATCH"
echo "ROOT=$ROOT"

echo "=== BUILD (GATE_SKIP_BUILD=${GATE_SKIP_BUILD:-0}) ==="
{
  cd "$ROOT"
  if [ "${GATE_SKIP_BUILD:-0}" = "1" ]; then
    make docker IMAGE_NAME=nfs-klldap-host DOCKER_TAG_LATEST=true
  else
    make clean
    cargo clean
    make docker IMAGE_NAME=nfs-klldap-host DOCKER_TAG_LATEST=true DOCKER_NO_CACHE=true
  fi
} 2>&1 | tee "$SCRATCH/build.log"

echo "=== CARGO TEST ==="
(cd "$ROOT" && cargo test --workspace -- --test-threads=1) 2>&1 | tee "$SCRATCH/cargo-test.log"

DOCKER_RUN="docker run -d \
  --name nfs-klldap \
  --uts=host \
  --network=host \
  --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH \
  -e GANESHA_DEBUG=true \
  -v /home/local/Projects/test-nfs-work/config:/config:Z \
  -v ${KEYTAB_PATH}:/etc/krb5.keytab:ro,Z \
  -v /home/local/Projects/test-nfs-work/stuff:/export/stuff:Z \
  -v /home/local/Projects/test-nfs-work/junk:/export/junk:Z \
  nfs-klldap-host:latest"

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

: > "$NFS_FULL_LOG"
{
  echo "=== NFS RUN START FULL $(date -u) ==="
  echo "=== DOCKER RUN (verbatim) ==="
  echo "$DOCKER_RUN"
  echo "=== HEALTH ==="
  docker inspect -f '{{.State.Health.Status}}' nfs-klldap 2>/dev/null || true
} | tee -a "$NFS_FULL_LOG"

SCRATCH="$SCRATCH" NFS_FULL_LOG="$NFS_FULL_LOG" "$ROOT/scripts/ganesha-chain-preflight.sh"

KRB5_EXTRACT="$SCRATCH/krb5-extract.conf"
docker exec nfs-klldap cat /etc/krb5.conf > "$KRB5_EXTRACT"

echo "=== FEDORA CLIENT VALIDATE ==="
if docker inspect lldap-kerb >/dev/null 2>&1; then
  kerb_st=$(docker inspect -f '{{.State.Health.Status}}' lldap-kerb 2>/dev/null || echo unknown)
  echo "lldap-kerb health=$kerb_st"
  if [ "$kerb_st" != healthy ]; then
    echo "ERROR: lldap-kerb must be healthy for user TGT kinit"
    exit 48
  fi
fi
FEDORA_LOG="$SCRATCH/fedora-client.log"
set +e
docker run --rm --network=host --privileged --ipc=host \
  -v /lib/modules:/lib/modules:ro \
  -v /run/host/var/lib/nfs/rpc_pipefs:/var/lib/nfs/rpc_pipefs:shared \
  -v "$KRB5_EXTRACT:/test/krb5.conf:ro" \
  -v ${KEYTAB_PATH}:/test/krb5.keytab:ro \
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
  echo "=== POST-CLIENT ganesha-ctl id-resolve (uid2grp chain in ganesha.log) ==="
  docker exec nfs-klldap ganesha-ctl id-resolve testuser1@TESTLABBY.LOCAL || true
  echo "=== POST-CLIENT ID MAPPER (recent) ==="
  docker exec nfs-klldap bash -c 'grep -E "ID MAPPER|uid2grp_allocate|principal2uid|getgrouplist|Unsupported code path" /var/log/ganesha.log | tail -30' || true
} | tee -a "$NFS_FULL_LOG"

docker exec nfs-klldap cat /var/log/ganesha.log > "$SCRATCH/live-ganesha.log" 2>/dev/null || true

if rg -n 'ADDED UID2GRP|getgrouplist for user:' "$SCRATCH" 2>/dev/null; then
  echo "FABRICATION DETECTED in scratch; failing gate"; exit 99
fi

# --- Preflight markers (verification plan step 2, pre-mount) ---
if ! grep -q 'PREFLIGHT_OK: UseGetpwnam=true' "$NFS_FULL_LOG"; then
  echo "ERROR: missing PREFLIGHT_OK: UseGetpwnam=true"
  exit 50
fi
if ! grep -q 'CHAIN_PREFLIGHT_OK' "$NFS_FULL_LOG"; then
  echo "ERROR: missing CHAIN_PREFLIGHT_OK"
  exit 51
fi
if ! [ -s "$SCRATCH/ganesha.conf" ]; then
  echo "ERROR: missing ganesha.conf snapshot in SCRATCH"
  exit 52
fi
if ! grep -q 'UseGetpwnam = true' "$SCRATCH/ganesha.conf"; then
  echo "ERROR: ganesha.conf snapshot missing UseGetpwnam = true"
  exit 53
fi
if ! grep -q 'GETGROUPLIST_SHIM_OK' "$NFS_FULL_LOG"; then
  echo "ERROR: missing GETGROUPLIST_SHIM_OK in preflight"
  exit 54
fi
if grep -q 'ganesha-log:no-uid2grp' "$NFS_FULL_LOG"; then
  echo "ERROR: preflight must not emit ganesha-log:no-uid2grp (uid2grp is post-client)"
  exit 55
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

# POST-CLIENT uid2grp chain (Ganesha 9.6 UseGetpwnam=true path)
if ! grep -E 'principal2uid.*testuser1@TESTLABBY' "$NFS_FULL_LOG" >/dev/null 2>&1; then
  echo "ERROR: missing POST-CLIENT principal2uid for testuser1@"
  exit 43
fi
if ! grep -E 'uid2grp_allocate_by_uid.*uid: 3001' "$NFS_FULL_LOG" >/dev/null 2>&1; then
  echo "ERROR: missing POST-CLIENT uid2grp_allocate_by_uid for uid 3001"
  exit 44
fi
if ! grep -E 'getgrouplist for uname: testuser1, returned 2 groups' "$NFS_FULL_LOG" >/dev/null 2>&1; then
  echo "ERROR: missing POST-CLIENT getgrouplist success for testuser1 (2 groups)"
  exit 45
fi
if grep -E 'Unsupported code path for principal testuser1@' "$NFS_FULL_LOG" >/dev/null 2>&1; then
  echo "ERROR: Unsupported code path for user TGT principal"
  exit 46
fi

echo "=== PLAN GATE END $(date -u) ==="
echo "LOG=$LOG"
echo "NFS_FULL_LOG=$NFS_FULL_LOG"
echo "GANESHA_CONF=$SCRATCH/ganesha.conf"