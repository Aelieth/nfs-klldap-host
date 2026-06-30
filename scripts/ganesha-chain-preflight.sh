#!/bin/bash
# Ganesha 9.6 uid2grp chain preflight (before Fedora client mount).
# Usage: SCRATCH=/path NFS_FULL_LOG=/path ./scripts/ganesha-chain-preflight.sh
# Prints CHAIN_PREFLIGHT_OK on success; appends transcript to NFS_FULL_LOG.
set -euo pipefail

SCRATCH="${SCRATCH:?SCRATCH required}"
NFS_FULL_LOG="${NFS_FULL_LOG:-$SCRATCH/nfs-run-start-full.log}"
CONTAINER="${CONTAINER:-nfs-klldap}"
REALM_PRINC="${REALM_PRINC:-testuser1@TESTLABBY.LOCAL}"

exec 3>&1
{
  echo "=== GANESHA CHAIN PREFLIGHT $(date -u) ==="

  docker exec "$CONTAINER" cat /etc/ganesha/ganesha.conf > "$SCRATCH/ganesha.conf"
  echo "GANESHA_CONF_SNAPSHOT=$SCRATCH/ganesha.conf"
  if grep -q 'UseGetpwnam = true' "$SCRATCH/ganesha.conf"; then
    echo "PREFLIGHT_OK: UseGetpwnam=true"
  else
    echo "ERROR: generated ganesha.conf missing UseGetpwnam = true"
    grep -E 'UseGetpwnam|NFSV4' "$SCRATCH/ganesha.conf" || true
    exit 50
  fi

  echo "=== WAIT LDAP MATERIALIZE ($REALM_PRINC uid=3001) ==="
  mat_ok=false
  for i in $(seq 1 24); do
    res=$(docker exec "$CONTAINER" nfs-klldap-idhelper resolve "$REALM_PRINC" --json 2>/dev/null || true)
    echo "materialize[$i]=$res"
    if echo "$res" | grep -q '"uid":3001'; then
      mat_ok=true
      break
    fi
    sleep 5
  done
  if ! $mat_ok; then
    echo "ERROR: idhelper never materialized uid=3001"
    docker exec "$CONTAINER" grep -E '3001|65534|testuser1' /var/lib/nfs-klldap/nss_passwd 2>/dev/null | head -10 || true
    exit 47
  fi

  echo "=== getent passwd/group (nss_wrapper) ==="
  docker exec "$CONTAINER" getent passwd testuser1 "$REALM_PRINC"
  docker exec "$CONTAINER" getent group 3005 admin 2>/dev/null || docker exec "$CONTAINER" getent group group-test 2>/dev/null || true

  echo "=== nss materialization ==="
  docker exec "$CONTAINER" bash -c 'grep -E "3001|3004|3005|testuser1|lldap_sudohost|group-test" /var/lib/nfs-klldap/nss_passwd /var/lib/nfs-klldap/nss_group /var/lib/extrausers/passwd /var/lib/extrausers/group 2>/dev/null'

  echo "=== rebulk supplemental nss_group (lldap_sudohost at startup) ==="
  docker exec "$CONTAINER" grep -E 'lldap_sudohost:x:3004:testuser1' /var/lib/nfs-klldap/nss_group /var/lib/extrausers/group

  echo "=== grps (materialization-backed getpwnam/getgrouplist under nss_wrapper) ==="
  docker exec "$CONTAINER" bash -c "nfs-klldap-idhelper grps $REALM_PRINC --json; echo 'NSSHANDOFF: grps exercised (no shim required)'"

  echo "=== id-map-test testuser1 (no ganesha.log uid2grp grep pre-mount) ==="
  docker exec "$CONTAINER" ganesha-ctl id-map-test testuser1

  echo "CHAIN_PREFLIGHT_OK"
} | tee -a "$NFS_FULL_LOG" >&3