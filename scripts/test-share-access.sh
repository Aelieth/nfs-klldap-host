#!/bin/bash
# test-share-access.sh — krb5p NFSv4 client access to stuff/junk exports inside nfs-klldap.
# Requires: running nfs-klldap container, KLLDAP/KDC, testuser1@REALM credentials.
# Usage: NFS_TEST_USER_PW='...' ./scripts/test-share-access.sh [container_name]
set -euo pipefail

CONTAINER="${1:-nfs-klldap}"
SCRATCH="${NFS_TEST_SCRATCH:-/tmp/nfs-klldap-share-access-$$}"
SERVER="${NFS_TEST_SERVER:-aurora.testlabby.local}"
USER_PRINC="${NFS_TEST_USER:-testuser1@TESTLABBY.LOCAL}"
USER_PW="${NFS_TEST_USER_PW:?set NFS_TEST_USER_PW for Kerberos user}"

mkdir -p "$SCRATCH"

docker exec "$CONTAINER" cat /etc/krb5.conf >"$SCRATCH/krb5.conf"
docker cp "$SCRATCH/krb5.conf" "$CONTAINER:/tmp/krb5.conf"

docker exec "$CONTAINER" bash -c "
set -euo pipefail
export KRB5_CONFIG=/tmp/krb5.conf
export KRB5CCNAME=FILE:/tmp/krb5cc_sharetest
printf '%s\n' '$USER_PW' | kinit '$USER_PRINC'
mkdir -p /run/rpc_pipefs /mnt/stuff /mnt/junk
mountpoint -q /run/rpc_pipefs || mount -t rpc_pipefs rpc_pipefs /run/rpc_pipefs
pkill rpc.gssd 2>/dev/null || true
rpc.gssd -f &
sleep 1
lines_before=\$(wc -l < /var/log/ganesha.log)
mount -t nfs4 -o sec=krb5p,rw,hard,intr,vers=4.1 $SERVER:/stuff /mnt/stuff
mount -t nfs4 -o sec=krb5p,rw,hard,intr,vers=4.1 $SERVER:/junk /mnt/junk
stamp=\$(date +%s)
echo nfs-sharetest-stuff-\$stamp > /mnt/stuff/nfs-sharetest.txt
echo nfs-sharetest-junk-\$stamp > /mnt/junk/nfs-sharetest.txt
cat /mnt/stuff/nfs-sharetest.txt
cat /mnt/junk/nfs-sharetest.txt
umount /mnt/stuff /mnt/junk
ganesha_slice=/tmp/ganesha-sharetest-slice.log
tail -n +\$((lines_before + 1)) /var/log/ganesha.log > \"\$ganesha_slice\"
grep -iE 'name=stuff|/export/stuff' \"\$ganesha_slice\" | head -15 || true
grep -iE 'name=junk|/export/junk' \"\$ganesha_slice\" | head -15 || true
" 2>&1 | tee "$SCRATCH/share-access.log"

if ! grep -q 'nfs-sharetest-stuff-' "$SCRATCH/share-access.log"; then
  echo "FAIL: stuff share write missing from transcript" >&2
  exit 1
fi
if ! grep -q 'nfs-sharetest-junk-' "$SCRATCH/share-access.log"; then
  echo "FAIL: junk share write missing from transcript" >&2
  exit 1
fi
if ! grep -qE 'name=stuff|/export/stuff' "$SCRATCH/share-access.log"; then
  echo "FAIL: ganesha stuff export lines missing" >&2
  exit 1
fi
if ! grep -qE 'name=junk|/export/junk' "$SCRATCH/share-access.log"; then
  echo "FAIL: ganesha junk export lines missing" >&2
  exit 1
fi

echo "OK: share access test passed (log: $SCRATCH/share-access.log)"