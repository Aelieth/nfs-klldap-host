#!/bin/bash
# Host-side shim contract test against fixture nss files (cargo test / CI).
# Usage: FIXTURE_DIR=/path/to/fixtures ROOT=/repo ./scripts/test-getgrouplist-shim-fixture.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="${FIXTURE_DIR:?FIXTURE_DIR required}"
BUILD_DIR="${BUILD_DIR:-$FIXTURE_DIR/.shim-build}"

mkdir -p "$BUILD_DIR"
SHIM_SO="$BUILD_DIR/libganesha_getgrouplist_shim.so"
PROBE="$BUILD_DIR/test_getgrouplist_shim"

if [ ! -f "$SHIM_SO" ]; then
  command -v gcc >/dev/null || { echo "gcc required to build shim"; exit 1; }
  gcc -shared -fPIC -O2 -o "$SHIM_SO" "$ROOT/container/getgrouplist_ganesha_shim.c" -ldl
fi
if [ ! -x "$PROBE" ]; then
  gcc -o "$PROBE" "$ROOT/container/test_getgrouplist_shim.c"
fi

SO=""
for cand in /usr/lib/x86_64-linux-gnu/libnss_wrapper.so /usr/lib64/libnss_wrapper.so; do
  [ -f "$cand" ] && SO="$cand" && break
done

export LD_PRELOAD="$SHIM_SO${SO:+:$SO}"
export NSS_WRAPPER_PASSWD="$FIXTURE_DIR/nss_passwd"
export NSS_WRAPPER_GROUP="$FIXTURE_DIR/nss_group"
export NSS_EXTRAUSERS_GROUP="$FIXTURE_DIR/extrausers_group"

out="$("$PROBE")"
echo "$out"
echo "$out" | grep -qE 'size ret=-1 ng=[2-9]'
echo "$out" | grep -qE 'fill ret=0 ng=[2-9]'
echo "$out" | grep -q ' 3004'
echo "$out" | grep -q ' 3005'
echo "GETGROUPLIST_SHIM_FIXTURE_OK"