#!/bin/bash
# Strict Fedora 44 krb5p client validation script.
# Must be run inside fedora:44 with proper volumes.
# Exits non-zero on any failure of mount or visibility.
set -euo pipefail

echo "=== FEDORA KRB5P VALIDATE START $(date -u) ==="

dnf install -y --quiet nfs-utils krb5-workstation rpcbind

# Expect volumes:
#   /test/krb5.conf   (working krb5.conf from server)
#   /test/krb5.keytab (the nfs keytab)
#   /hostdata/stuff   (host /.../stuff)
#   /hostdata/junk    (host /.../junk)

if [ ! -f /test/krb5.conf ] || [ ! -f /test/krb5.keytab ]; then
  echo "ERROR: missing /test/krb5.conf or /test/krb5.keytab"
  exit 10
fi

cp /test/krb5.conf /etc/krb5.conf
cp /test/krb5.keytab /etc/krb5.keytab
chmod 600 /etc/krb5.keytab

cat /etc/krb5.conf

# Prepare rpc pipefs for gssd (required in container)
mkdir -p /var/lib/nfs/rpc_pipefs
mount -t rpc_pipefs rpc_pipefs /var/lib/nfs/rpc_pipefs 2>/dev/null || true

rpcbind || true
rpc.gssd -f &
GSSD_PID=$!
sleep 2

# kinit machine principal from the keytab (exact principal must exist in keytab)
PRINC="nfs/aurora.testlabby.local@TESTLABBY.LOCAL"
KRB5CCNAME=/tmp/ccm kinit -k -t /etc/krb5.keytab -c /tmp/ccm "$PRINC" 2>&1
export KRB5CCNAME=/tmp/ccm
klist -c "$KRB5CCNAME"

mkdir -p /mnt/stuff /mnt/junk

echo "=== ATTEMPTING KRB5P MOUNTS ==="
set +e
mount -t nfs4 -o vers=4.2,sec=krb5p aurora.testlabby.local:/stuff /mnt/stuff
M1=$?
mount -t nfs4 -o vers=4.2,sec=krb5p aurora.testlabby.local:/junk /mnt/junk
M2=$?
set -e

echo "M1=$M1 M2=$M2"

mount | grep -E '/mnt/(stuff|junk)' || true

if [ "$M1" != "0" ] || [ "$M2" != "0" ]; then
  echo "MOUNT FAILED (M1=$M1 M2=$M2)"
  kill "$GSSD_PID" 2>/dev/null || true
  exit 32
fi

echo "=== MOUNTS SUCCEEDED - RUNNING CYCLES ==="

for i in 1 2 3; do
  echo "cycle $i"
  echo "fedora-krb5p-real-$i" > /mnt/stuff/fed-krb5p-$i.txt
  cat /mnt/stuff/fed-krb5p-$i.txt
  echo "fedora-krb5p-real-$i" > /mnt/junk/fed-krb5p-$i.txt
  cat /mnt/junk/fed-krb5p-$i.txt
done

sync
sleep 1

echo "=== HOST BIND VISIBILITY CHECK (cycle files + marker) ==="
cycle_ok=true
for i in 1 2 3; do
  if ! ls /hostdata/stuff/fed-krb5p-$i.txt >/dev/null 2>&1; then
    echo "MISSING cycle file on host: stuff/fed-krb5p-$i.txt"
    cycle_ok=false
  fi
  if ! ls /hostdata/junk/fed-krb5p-$i.txt >/dev/null 2>&1; then
    echo "MISSING cycle file on host: junk/fed-krb5p-$i.txt"
    cycle_ok=false
  fi
done
# marker for good measure
echo "krb5p-success-$$" > /mnt/stuff/krb5p-success-marker.txt
sync
if ls /hostdata/stuff/krb5p-success-marker.txt >/dev/null 2>&1; then
  : # marker visible
else
  echo "MISSING marker on host"
  cycle_ok=false
fi

if $cycle_ok; then
  echo "CYCLE_FILES_VISIBLE ON HOST BIND - SUCCESS"
  echo "VISIBLE ON HOST BIND - SUCCESS"
else
  echo "NOT ALL CYCLE FILES VISIBLE ON HOST BIND"
  ls -l /hostdata/stuff/fed-krb5p-*.txt /hostdata/junk/fed-krb5p-*.txt 2>/dev/null || true
  kill "$GSSD_PID" 2>/dev/null || true
  exit 33
fi

# now safe to clean
for i in 1 2 3; do
  rm -f /mnt/stuff/fed-krb5p-$i.txt /mnt/junk/fed-krb5p-$i.txt
done
rm -f /mnt/stuff/krb5p-success-marker.txt

umount /mnt/stuff /mnt/junk 2>/dev/null || true
kill "$GSSD_PID" 2>/dev/null || true

# Optional user TGT phase (requires Kerberos-synced user on KDC, e.g. testuser2 after LLDAP password sync).
if [ -n "${TEST_USER_PRINC:-}" ] && [ -n "${TEST_USER_PASSWORD:-}" ]; then
  echo "=== USER TGT PHASE (${TEST_USER_PRINC}) ==="
  cat > /etc/nfs.conf <<'NFSCONF'
[general]
pipefs-directory=/var/lib/nfs/rpc_pipefs
[gssd]
use-machine-creds=0
NFSCONF
  export KRB5CCNAME=FILE:/tmp/ccuser
  printf '%s\n' "$TEST_USER_PASSWORD" | kinit -c /tmp/ccuser "$TEST_USER_PRINC" 2>&1
  mount -t nfs4 -o vers=4.2,sec=krb5p aurora.testlabby.local:/stuff /mnt/stuff
  echo "user-tgt-$(date +%s)" > "/mnt/stuff/user-tgt-${TEST_USER_PRINC%%@*}.txt"
  sync
  uid=$(stat -c %u "/mnt/stuff/user-tgt-${TEST_USER_PRINC%%@*}.txt")
  gid=$(stat -c %g "/mnt/stuff/user-tgt-${TEST_USER_PRINC%%@*}.txt")
  echo "user-tgt uid:gid = ${uid}:${gid}"
  test "$uid" != "65534" -a "$gid" != "65534" || exit 41
  umount /mnt/stuff
fi

echo "=== FEDORA KRB5P VALIDATE END $(date -u) ==="
