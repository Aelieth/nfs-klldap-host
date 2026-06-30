#!/bin/bash
# Verify ganesha getgrouplist shim: Ganesha 9.6 sizing + fill passes (ret==0 on fill).
set -euo pipefail

SO=/usr/lib/x86_64-linux-gnu/libnss_wrapper.so
SHIM=/usr/local/lib/libganesha_getgrouplist_shim.so
NP="${NSS_WRAPPER_PASSWD:-/var/lib/nfs-klldap/nss_passwd}"
NG="${NSS_WRAPPER_GROUP:-/var/lib/nfs-klldap/nss_group}"
EG="${NSS_EXTRAUSERS_GROUP:-/var/lib/extrausers/group}"
TEST_BIN=/usr/local/bin/test_getgrouplist_shim

[ -f "$SHIM" ] || { echo "missing $SHIM"; exit 1; }
[ -f "$NP" ] || { echo "missing $NP"; exit 1; }
[ -f "$NG" ] || { echo "missing $NG"; exit 1; }
[ -x "$TEST_BIN" ] || { echo "missing $TEST_BIN (image build must compile shim probe)"; exit 1; }

export LD_PRELOAD="$SHIM:$SO"
export NSS_WRAPPER_PASSWD="$NP"
export NSS_WRAPPER_GROUP="$NG"
export NSS_EXTRAUSERS_GROUP="$EG"

out="$("$TEST_BIN")"
echo "$out"

# Sizing pass: groups=NULL ngroups=0 → ret==-1, ngroups>=2 (Ganesha 9.6 my_getgrouplist_alloc)
echo "$out" | grep -qE 'size ret=-1 ng=[2-9]' || { echo "shim size-query must return -1 with ng>=2"; exit 1; }

# Fill pass: ret==0, ng>=2, primary 3005 + supplemental 3004
echo "$out" | grep -qE 'fill ret=0 ng=[2-9]' || { echo "shim fill must return 0 with >=2 groups"; exit 1; }
echo "$out" | grep -q ' 3005' || { echo "missing primary gid 3005"; exit 1; }
echo "$out" | grep -q ' 3004' || { echo "missing supplemental gid 3004 (lldap_sudohost)"; exit 1; }
echo "GETGROUPLIST_SHIM_OK"