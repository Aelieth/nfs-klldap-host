#!/bin/bash
# Strict Fedora 44 krb5p client validation script.
# Run inside fedora:44 with --network=host --privileged --ipc=host.
set -euo pipefail

echo "=== FEDORA KRB5P VALIDATE START $(date -u) ==="

dnf install -y --quiet nfs-utils krb5-workstation rpcbind keyutils dbus kmod

if [ ! -f /test/krb5.conf ] || [ ! -f /test/krb5.keytab ]; then
  echo "ERROR: missing /test/krb5.conf or /test/krb5.keytab"
  exit 10
fi

cp /test/krb5.conf /etc/krb5.conf
cp /test/krb5.keytab /etc/krb5.keytab
chmod 600 /etc/krb5.keytab

modprobe nfs 2>/dev/null || true

mkdir -p /var/lib/nfs/rpc_pipefs
# Host bind mount of rpc_pipefs (see capture-plan-gate.sh) is required for gssd/idmap in Docker.
if ! mountpoint -q /var/lib/nfs/rpc_pipefs 2>/dev/null; then
  mount -t rpc_pipefs rpc_pipefs /var/lib/nfs/rpc_pipefs 2>/dev/null || true
fi

rpcbind || true
rpc.gssd -f &
GSSD_PID=$!
sleep 2

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
echo "krb5p-success-$$" > /mnt/stuff/krb5p-success-marker.txt
sync
if ! ls /hostdata/stuff/krb5p-success-marker.txt >/dev/null 2>&1; then
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

for i in 1 2 3; do
  rm -f /mnt/stuff/fed-krb5p-$i.txt /mnt/junk/fed-krb5p-$i.txt
done
rm -f /mnt/stuff/krb5p-success-marker.txt

umount /mnt/stuff /mnt/junk 2>/dev/null || true
kill "$GSSD_PID" 2>/dev/null || true

if [ -n "${TEST_USER_PRINC:-}" ] && [ -n "${TEST_USER_PASSWORD:-}" ]; then
  echo "=== USER TGT PHASE (${TEST_USER_PRINC}) ==="
  realm="${TEST_USER_PRINC#*@}"
  short="${TEST_USER_PRINC%%@*}"
  case "${short}" in
    testuser1) exp_uid=3001 ;;
    testuser2) exp_uid=3002 ;;
    *) exp_uid=3002 ;;
  esac
  exp_gid=3005

  cat > /etc/nsswitch.conf <<EOF
passwd: files
group: files
EOF
  grep -q "^group-test:" /etc/group || groupadd -g "${exp_gid}" group-test 2>/dev/null || echo "group-test:x:${exp_gid}:${short}" >> /etc/group
  if ! getent passwd "${short}" >/dev/null 2>&1; then
    useradd -u "${exp_uid}" -g "${exp_gid}" -M -s /sbin/nologin "${short}" 2>/dev/null \
      || echo "${short}:x:${exp_uid}:${exp_gid}:user TGT test:/tmp:/sbin/nologin" >> /etc/passwd
  fi
  grep -q "^${short}@${realm}:" /etc/passwd || echo "${short}@${realm}:x:${exp_uid}:${exp_gid}:user TGT test:/tmp:/sbin/nologin" >> /etc/passwd
  grep -q "^group-test:" /etc/group || echo "group-test:x:${exp_gid}:${short}" >> /etc/group
  usermod -aG group-test "${short}" 2>/dev/null || true

  cat > /etc/idmapd.conf <<EOF
[General]
Domain = ${realm}
Local-Realms = ${realm}
[Mapping]
Nobody-User = nobody
Nobody-Group = nobody
[Translation]
Method = nsswitch
GSS-Methods = nsswitch
EOF
  cat > /etc/nfs.conf <<'NFSCONF'
[general]
pipefs-directory=/var/lib/nfs/rpc_pipefs
nfs4-disable-idmapping=0
[gssd]
use-machine-creds=0
use-gss-proxy=0
NFSCONF
  echo 0 > /sys/module/nfs/parameters/nfs4_disable_idmapping 2>/dev/null || true

  getent passwd "${short}" >/dev/null || { echo "ERROR: client passwd stub missing for ${short}"; exit 41; }
  getent passwd "${TEST_USER_PRINC}" >/dev/null || { echo "ERROR: client passwd stub missing for ${TEST_USER_PRINC}"; exit 41; }
  getent group group-test >/dev/null || { echo "ERROR: client group stub missing for gid ${exp_gid}"; exit 41; }

  if [ -x /usr/local/bin/nfsidmap-client-helper ]; then
    cat > /etc/request-key.d/id_resolver.conf <<'RKCONF'
create id_resolver * * /usr/local/bin/nfsidmap-client-helper %k %d
negate id_resolver * * /bin/keyctl negate %k 0 %c
RKCONF
  fi

  dbus-daemon --system --fork 2>/dev/null || true
  export KRB5CCNAME=FILE:/tmp/ccuser
  printf '%s\n' "$TEST_USER_PASSWORD" | kinit -c /tmp/ccuser "$TEST_USER_PRINC" 2>&1
  klist -c /tmp/ccuser
  rpc.idmapd -f &
  IDMAP_PID=$!
  rpc.gssd -f &
  GSSD_USER_PID=$!
  sleep 2

  mount -t nfs4 -o vers=4.2,sec=krb5p aurora.testlabby.local:/stuff /mnt/stuff
  marker="user-tgt-${short}-$(date +%s)"
  out="/mnt/stuff/${marker}.txt"
  rm -f "$out"
  set +e
  printf '%s\n' "$marker" | tee "$out" >/dev/null
  write_rc=$?
  set -e
  sync
  if [ "$write_rc" != "0" ]; then
    echo "ERROR: user TGT write failed on $out (write_rc=${write_rc})"
    ls -ln "$out" 2>/dev/null || true
    exit 41
  fi
  if [ ! -e "$out" ]; then
    echo "ERROR: user TGT file missing after write: $out"
    exit 41
  fi
  read_back="$(cat "$out" 2>/dev/null || true)"
  if [ "$read_back" != "$marker" ]; then
    echo "ERROR: user TGT client read-back '${read_back}' != '${marker}'"
    exit 41
  fi
  uid=$(stat -c %u "$out")
  gid=$(stat -c %g "$out")
  echo "user-tgt write_rc=${write_rc}"
  echo "user-tgt client stat uid:gid = ${uid}:${gid}"
  base="${marker}.txt"
  echo "SERVER_VERIFY=${base}" > /hostdata/stuff/.user-tgt-verify
  srv_uid=""; srv_gid=""
  if [ -f "/hostdata/stuff/${base}" ]; then
    srv_uid=$(stat -c %u "/hostdata/stuff/${base}")
    srv_gid=$(stat -c %g "/hostdata/stuff/${base}")
    host_back="$(cat "/hostdata/stuff/${base}" 2>/dev/null || true)"
    echo "user-tgt hostdata bind stat uid:gid = ${srv_uid}:${srv_gid}"
    if [ "$host_back" != "$marker" ]; then
      echo "ERROR: hostdata content '${host_back}' != '${marker}'"
      exit 41
    fi
  else
    echo "ERROR: hostdata bind missing ${base}"
    exit 41
  fi
  if [ "$srv_uid" = "$exp_uid" ] && [ "$srv_gid" = "$exp_gid" ]; then
    echo "USER TGT HOSTDATA UID MAP OK (${srv_uid}:${srv_gid})"
  else
    echo "ERROR: hostdata bind stat ${srv_uid:-?}:${srv_gid:-?} expected ${exp_uid}:${exp_gid} for ${TEST_USER_PRINC}"
    exit 41
  fi
  if [ "$uid" = "$exp_uid" ] && [ "$gid" = "$exp_gid" ]; then
    echo "USER TGT CLIENT UID MAP OK (${uid}:${gid})"
  else
    echo "ERROR: client stat ${uid}:${gid} expected ${exp_uid}:${exp_gid} (hostdata ${srv_uid}:${srv_gid})"
    exit 41
  fi
  umount /mnt/stuff
  kill "$GSSD_USER_PID" "$IDMAP_PID" 2>/dev/null || true
  echo "USER TGT PHASE OK (kinit + krb5p mount + write)"
fi

echo "=== FEDORA KRB5P VALIDATE END $(date -u) ==="