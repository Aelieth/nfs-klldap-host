#!/bin/bash
# Full plan gate: build, container probes, Fedora client validation transcript.
# Usage: SCRATCH=/path ./scripts/capture-plan-gate.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-plan-gate-$$}"
LOG="$SCRATCH/plan-gate.log"
mkdir -p "$SCRATCH"

exec > >(tee -a "$LOG") 2>&1

echo "=== PLAN GATE START $(date -u) ==="
echo "SCRATCH=$SCRATCH"
echo "ROOT=$ROOT"

echo "=== CARGO TEST ==="
(cd "$ROOT" && cargo test --workspace)

echo "=== DOCKER BUILD ==="
(cd "$ROOT" && make docker IMAGE_NAME=nfs-klldap-host DOCKER_TAG_LATEST=true)

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

echo "=== IN-CONTAINER IDHELPER / NSS STRESS ==="
docker exec nfs-klldap ganesha-ctl id-map-test testuser2
docker exec nfs-klldap ganesha-ctl id-resolve testuser2@TESTLABBY.LOCAL || true
docker exec nfs-klldap getent passwd testuser2@TESTLABBY.LOCAL
docker exec nfs-klldap getent group 3005
docker exec nfs-klldap bash -c 'grep 3005 /var/lib/nfs-klldap/nss_group /var/lib/extrausers/group'

KRB5_EXTRACT="$SCRATCH/krb5.conf"
docker exec nfs-klldap cat /etc/krb5.conf > "$KRB5_EXTRACT"

echo "=== FEDORA CLIENT VALIDATE ==="
FEDORA_LOG="$SCRATCH/fedora-client.log"
docker run --rm --network=host --privileged --ipc=host \
  -v "$KRB5_EXTRACT:/test/krb5.conf:ro" \
  -v /home/local/Projects/test-nfs-work/keytab/krb5.keytab:/test/krb5.keytab:ro \
  -v /home/local/Projects/test-nfs-work/stuff:/hostdata/stuff:Z \
  -v /home/local/Projects/test-nfs-work/junk:/hostdata/junk:Z \
  -v "$ROOT/scripts/fedora-krb5p-client-validate.sh:/validate.sh:ro" \
  -e TEST_USER_PRINC='testuser2@TESTLABBY.LOCAL' \
  -e TEST_USER_PASSWORD='testtest' \
  fedora:44 bash /validate.sh 2>&1 | tee "$FEDORA_LOG"

echo "=== SERVER BIND STAT (authoritative container view) ==="
docker exec nfs-klldap bash -c 'f=$(cat /export/stuff/.user-tgt-verify 2>/dev/null | sed -n "s/^SERVER_VERIFY=//p"); [ -n "$f" ] && stat -c "%u:%g %n" "/export/stuff/$f" || echo no-verify-file'

echo "=== PLAN GATE END $(date -u) ==="
echo "LOG=$LOG"