#!/usr/bin/env bash
# Clippy + first-party unsafe audit (safety-dance). Dependency geiger noise goes to sidecar.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
SCRATCH="${SAFETY_DANCE_SCRATCH:-/tmp/grok-goal-fdb12523156d/implementer}"
mkdir -p "$SCRATCH"

echo "==> clippy (-D warnings)"
make clippy

echo "==> deny(unsafe_code) on ui/config/identity (supervisor.rs is sole allow)"
grep -q '#!\[deny(unsafe_code' nfs-klldap-ui/src/main.rs
grep -q '#!\[deny(unsafe_code' nfs-klldap-config/src/lib.rs
grep -q '#!\[deny(unsafe_code' nfs-klldap-identity/src/lib.rs
grep -q '#!\[allow(unsafe_code)\]' nfs-klldap-config/src/supervisor.rs

echo "==> first-party geiger (unsafe fn count must be 0; dep noise in sidecar)"
for crate in nfs-klldap-ui nfs-klldap-config nfs-klldap-identity; do
  sidecar="$SCRATCH/geiger-${crate}-stderr.log"
  stdout="$SCRATCH/geiger-${crate}-stdout.log"
  (cd "$crate" && cargo geiger --all-features >"$stdout" 2>"$sidecar") || true
  line=$(grep -h -E "^[0-9]+/[0-9]+.*${crate} " "$stdout" "$sidecar" 2>/dev/null | head -1 || true)
  if [ -z "$line" ]; then
    line=$(grep -h -E "^0/[0-9]+[[:space:]]+.*${crate} " "$stdout" 2>/dev/null | head -1 || true)
  fi
  if [ -z "$line" ]; then
    echo "FAIL: could not parse geiger summary for $crate (see $stdout / $sidecar)" >&2
    exit 1
  fi
  unsafe=${line%%/*}
  if [ "$unsafe" != "0" ]; then
    echo "FAIL: $crate reports unsafe functions: $line" >&2
    exit 1
  fi
  echo "OK: $crate $line"
done

echo "==> safety-dance passed"