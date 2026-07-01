#!/bin/sh
# Probe stub: answers grps/resolve/daemon without hanging (used by supervisor integration tests).
mkdir -p /var/lib/nfs-klldap /var/run/nfs-klldap
echo 'root:x:0:0:root:/root:/bin/sh' > /var/lib/nfs-klldap/nss_passwd || true
echo probe > /var/lib/nfs-klldap/.bulk_seed_done || true
echo 'root:x:0:0:root:/root:/bin/sh' > /var/lib/nfs-klldap/nss_passwd
case "$1" in
  daemon) exec sleep 3600 ;;
  grps)
    # Pipeline tempdir: materialize nss entries Ganesha getent reads (idmap_log_contract path).
    if [ -n "${NSS_PASSWD:-}" ] && [ -n "${NSS_GROUP:-}" ]; then
      case "$2" in
        host/*)
          short="${2#host/}"; short="${short%@*}"
          echo "${short}:x:0:0:host:/nonexistent:/usr/sbin/nologin" >> "$NSS_PASSWD"
          echo "$2:x:0:0:host:/nonexistent:/usr/sbin/nologin" >> "$NSS_PASSWD"
          grep -q '^root:x:0:' "$NSS_GROUP" 2>/dev/null || echo 'root:x:0:' >> "$NSS_GROUP"
          ;;
        *@*)
          echo "$2:x:3788:3002:u:/nonexistent:/usr/sbin/nologin" >> "$NSS_PASSWD"
          grep -q '^root:x:0:' "$NSS_GROUP" 2>/dev/null || echo 'root:x:0:' >> "$NSS_GROUP"
          echo "staff:x:3002:$2" >> "$NSS_GROUP"
          echo "aux:x:3007:$2" >> "$NSS_GROUP"
          ;;
      esac
    fi
    case "$2" in
      host/*) echo "OK 0"; exit 0 ;;
      *) echo "OK 3002|3007|3005"; exit 0 ;;
    esac ;;
  resolve)
    case "$2" in
      host/*) echo "$2 -> name=stub uid=0 gid=0 kind=machine source=stub"; exit 0 ;;
      *) echo "$2 -> name=stub uid=3788 gid=3002 kind=user source=stub"; exit 0 ;;
    esac ;;
  check) echo "realm: TEST"; exit 0 ;;
esac
echo "unknown command: $1" >&2
exit 1