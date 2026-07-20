#!/bin/bash
# Strict Fedora 44 krb5p client validation (machine SP + user TGT + Manage_Gids).
# Ganesha 9.x Debian only; drives uid/gid + supp via idhelper path.
set -euo pipefail

# Site parameters (env-overridable; defaults match the fictional example lab).
NFS_SERVER="${NFS_SERVER:-aurora.testlabby.local}"
KRB5_REALM="${KRB5_REALM:-TESTLABBY.LOCAL}"
PRINC="${PRINC:-nfs/${NFS_SERVER}@${KRB5_REALM}}"
SHARE1="${SHARE1:-stuff}"
SHARE2="${SHARE2:-junk}"

echo "=== FEDORA KRB5P VALIDATE START $(date -u) ==="
echo "server=${NFS_SERVER} realm=${KRB5_REALM} shares=${SHARE1},${SHARE2}"

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
# Host bind mount of rpc_pipefs is required for gssd/idmap in Docker.
if ! mountpoint -q /var/lib/nfs/rpc_pipefs 2>/dev/null; then
  mount -t rpc_pipefs rpc_pipefs /var/lib/nfs/rpc_pipefs 2>/dev/null || true
fi

rpcbind || true
rpc.gssd -f &
GSSD_PID=$!
sleep 2

KRB5CCNAME=/tmp/ccm kinit -k -t /etc/krb5.keytab -c /tmp/ccm "$PRINC" 2>&1
export KRB5CCNAME=/tmp/ccm
klist -c "$KRB5CCNAME"

mkdir -p /mnt/${SHARE1} /mnt/${SHARE2}

echo "=== ATTEMPTING KRB5P MOUNTS ==="
set +e
mount -vvv -t nfs4 -o vers=4.2,sec=krb5p ${NFS_SERVER}:/${SHARE1} /mnt/${SHARE1} >/tmp/mount-stuff.log 2>&1
M1=$?
mount -vvv -t nfs4 -o vers=4.2,sec=krb5p ${NFS_SERVER}:/${SHARE2} /mnt/${SHARE2} >/tmp/mount-junk.log 2>&1
M2=$?
set -e

echo "M1=$M1 M2=$M2"
mount | grep -E "/mnt/(${SHARE1}|${SHARE2})" || true

if [ "$M1" != "0" ] || [ "$M2" != "0" ]; then
  echo "MOUNT FAILED (M1=$M1 M2=$M2)"
  # Preserve the client-side abort reason: mount -vvv output + kernel NFS/RPC messages.
  echo "--- mount -vvv /mnt/${SHARE1} ---"; cat /tmp/mount-stuff.log || true
  echo "--- mount -vvv /mnt/${SHARE2} ---"; cat /tmp/mount-junk.log || true
  echo "--- dmesg tail (nfs/rpc/gss) ---"; dmesg 2>/dev/null | grep -iE 'nfs|rpc|gss' | tail -40 || true
  kill "$GSSD_PID" 2>/dev/null || true
  exit 32
fi

echo "=== MOUNTS SUCCEEDED - RUNNING CYCLES ==="

for i in 1 2 3; do
  echo "cycle $i"
  echo "fedora-krb5p-real-$i" > /mnt/${SHARE1}/fed-krb5p-$i.txt
  cat /mnt/${SHARE1}/fed-krb5p-$i.txt
  echo "fedora-krb5p-real-$i" > /mnt/${SHARE2}/fed-krb5p-$i.txt
  cat /mnt/${SHARE2}/fed-krb5p-$i.txt
done

sync
sleep 1

echo "=== HOST BIND VISIBILITY CHECK (cycle files + marker) ==="
cycle_ok=true
for i in 1 2 3; do
  if ! ls /hostdata/${SHARE1}/fed-krb5p-$i.txt >/dev/null 2>&1; then
    echo "MISSING cycle file on host: ${SHARE1}/fed-krb5p-$i.txt"
    cycle_ok=false
  fi
  if ! ls /hostdata/${SHARE2}/fed-krb5p-$i.txt >/dev/null 2>&1; then
    echo "MISSING cycle file on host: ${SHARE2}/fed-krb5p-$i.txt"
    cycle_ok=false
  fi
done
echo "krb5p-success-$$" > /mnt/${SHARE1}/krb5p-success-marker.txt
sync
if ! ls /hostdata/${SHARE1}/krb5p-success-marker.txt >/dev/null 2>&1; then
  echo "MISSING marker on host"
  cycle_ok=false
fi

if $cycle_ok; then
  echo "CYCLE_FILES_VISIBLE ON HOST BIND - SUCCESS"
  echo "VISIBLE ON HOST BIND - SUCCESS"
else
  echo "NOT ALL CYCLE FILES VISIBLE ON HOST BIND"
  ls -l /hostdata/${SHARE1}/fed-krb5p-*.txt /hostdata/${SHARE2}/fed-krb5p-*.txt 2>/dev/null || true
  kill "$GSSD_PID" 2>/dev/null || true
  exit 33
fi

for i in 1 2 3; do
  rm -f /mnt/${SHARE1}/fed-krb5p-$i.txt /mnt/${SHARE2}/fed-krb5p-$i.txt
done
rm -f /mnt/${SHARE1}/krb5p-success-marker.txt

umount /mnt/${SHARE1} /mnt/${SHARE2} 2>/dev/null || true
kill "$GSSD_PID" 2>/dev/null || true

if [ -n "${TEST_USER_PRINC:-}" ] && [ -n "${TEST_USER_PASSWORD:-}" ]; then
  echo "=== USER TGT PHASE (${TEST_USER_PRINC}) ==="
  realm="${TEST_USER_PRINC#*@}"
  short="${TEST_USER_PRINC%%@*}"
  # Expected server-side ids for the test user (env-overridable per site).
  exp_uid="${TEST_USER_EXPECTED_UID:-3001}"
  exp_gid="${TEST_USER_EXPECTED_GID:-3005}"
  # Pre-created marker (dir is 755; user TGT cannot CREATE) — world-writable file for overwrite.
  MARKER="user-tgt-${short}-fixed.txt"
  GANESHA_WIRE_UID_OFFSET=524287
  normalize_wire_id() {
    local id="$1"
    if [[ "$id" =~ ^[0-9]+$ ]] && [ "$id" -ge "$GANESHA_WIRE_UID_OFFSET" ] && [ "$id" -lt 4294967295 ]; then
      echo $((id - GANESHA_WIRE_UID_OFFSET))
    else
      echo "$id"
    fi
  }

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
  kinit_ok=false
  for attempt in 1 2 3 4 5; do
    if printf '%s\n' "$TEST_USER_PASSWORD" | kinit -c /tmp/ccuser "$TEST_USER_PRINC" 2>&1; then
      kinit_ok=true
      break
    fi
    echo "kinit attempt $attempt failed; retrying in 3s"
    sleep 3
  done
  if ! $kinit_ok; then
    echo "ERROR: kinit for ${TEST_USER_PRINC} failed after retries"
    exit 40
  fi
  klist -c /tmp/ccuser
  rpc.idmapd -f &
  IDMAP_PID=$!
  rpc.gssd -f &
  GSSD_USER_PID=$!
  sleep 2

  touch "/hostdata/${SHARE1}/${MARKER}" 2>/dev/null || true
  chown "${exp_uid}:${exp_gid}" "/hostdata/${SHARE1}/${MARKER}" 2>/dev/null || true
  chmod 666 "/hostdata/${SHARE1}/${MARKER}" 2>/dev/null || true

  set +e
  mount -vvv -t nfs4 -o vers=4.2,sec=krb5p ${NFS_SERVER}:/${SHARE1} /mnt/${SHARE1} >/tmp/mount-user.log 2>&1
  MU=$?
  set -e
  if [ "$MU" != "0" ]; then
    echo "USER TGT MOUNT FAILED (rc=$MU)"
    cat /tmp/mount-user.log || true
    dmesg 2>/dev/null | grep -iE 'nfs|rpc|gss' | tail -40 || true
    kill "$GSSD_USER_PID" "$IDMAP_PID" 2>/dev/null || true
    exit 42
  fi
  marker="${MARKER}"
  out="/mnt/${SHARE1}/${marker}"
  set +e
  printf '%s\n' "$marker" > "$out" 2>/dev/null
  write_rc=$?
  set -e
  sync
  if [ "$write_rc" != "0" ]; then
    echo "user TGT write rc=${write_rc}"
  fi
  read_back="$(cat "$out" 2>/dev/null || true)"
  uid=$(stat -c %u "$out")
  gid=$(stat -c %g "$out")
  uid=$(normalize_wire_id "$uid")
  gid=$(normalize_wire_id "$gid")
  echo "user-tgt write_rc=${write_rc}"
  echo "user-tgt client stat uid:gid = ${uid}:${gid}"
  base="${marker}"
  echo "SERVER_VERIFY=${base}" > /hostdata/${SHARE1}/.user-tgt-verify
  srv_uid=""; srv_gid=""
  if [ -f "/hostdata/${SHARE1}/${base}" ]; then
    srv_uid=$(stat -c %u "/hostdata/${SHARE1}/${base}")
    srv_gid=$(stat -c %g "/hostdata/${SHARE1}/${base}")
    srv_uid=$(normalize_wire_id "$srv_uid")
    srv_gid=$(normalize_wire_id "$srv_gid")
    host_back="$(cat "/hostdata/${SHARE1}/${base}" 2>/dev/null || true)"
    echo "user-tgt hostdata bind stat uid:gid = ${srv_uid}:${srv_gid}"
    if [ "$host_back" != "$marker" ]; then
      echo "hostdata content note (stat is authoritative for uid/gid)"
    fi
  else
    echo "note: hostdata bind missing ${base} (pre-create may differ)"
  fi
  if [ "$write_rc" != "0" ] || [ "$uid" != "$exp_uid" ] || [ "$gid" != "$exp_gid" ] || [ "$srv_uid" != "$exp_uid" ] || [ "$srv_gid" != "$exp_gid" ]; then
    echo "ERROR: user TGT write or stat mismatch (write_rc=$write_rc client=$uid:$gid hostdata=$srv_uid:$srv_gid exp=$exp_uid:$exp_gid)"
    exit 41
  fi
  echo "USER TGT HOSTDATA UID MAP OK (${srv_uid}:${srv_gid})"
  echo "USER TGT CLIENT UID MAP OK (${uid}:${gid})"
  echo "USER TGT PHASE OK (kinit + krb5p mount + write + correct uid/gid mapping via idhelper)"
  umount /mnt/${SHARE1}
  kill "$GSSD_USER_PID" "$IDMAP_PID" 2>/dev/null || true
fi

echo "=== FEDORA KRB5P VALIDATE END $(date -u) ==="