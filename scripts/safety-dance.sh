#!/usr/bin/env bash
# Clippy + first-party unsafe audit (safety-dance). Dependency geiger noise is ignored.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

echo "==> clippy (-D warnings)"
make clippy

echo "==> deny(unsafe_code) on ui/config/identity (supervisor.rs is sole allow)"
grep -q '#!\[deny(unsafe_code' nfs-klldap-ui/src/main.rs
grep -q '#!\[deny(unsafe_code' nfs-klldap-config/src/lib.rs
grep -q '#!\[deny(unsafe_code' nfs-klldap-identity/src/lib.rs
grep -q '#!\[allow(unsafe_code)\]' nfs-klldap-config/src/supervisor.rs

echo "==> first-party geiger (unsafe fn count must be 0)"
for crate in nfs-klldap-ui nfs-klldap-config nfs-klldap-identity; do
  line=$(cd "$crate" && cargo geiger --all-features 2>/dev/null | grep -E "^[0-9]+/[0-9]+.*${crate} " | head -1 || true)
  if [ -z "$line" ]; then
    line=$(cd "$crate" && cargo geiger --all-features 2>/dev/null | grep -E "^[0-9]+/[0-9]+" | head -1)
  fi
  unsafe=${line%%/*}
  if [ "$unsafe" != "0" ]; then
    echo "FAIL: $crate reports unsafe functions: $line" >&2
    exit 1
  fi
  echo "OK: $crate $line"
done

echo "==> safety-dance passed"