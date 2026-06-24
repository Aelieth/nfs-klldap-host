#!/usr/bin/env bash
# Clippy + deny(unsafe_code) + first-party unsafe-fn grep audit.
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

echo "==> first-party unsafe fn (grep count must be 0 outside supervisor.rs)"
count_unsafe() {
  local dir="$1" exclude="${2:-}"
  if [ -n "$exclude" ]; then
    { grep -r 'unsafe fn' "$dir" --include='*.rs' 2>/dev/null || true; } \
      | { grep -v "$exclude" || true; } | wc -l
  else
    { grep -r 'unsafe fn' "$dir" --include='*.rs' 2>/dev/null || true; } | wc -l
  fi
}

for crate in nfs-klldap-ui nfs-klldap-identity; do
  count=$(count_unsafe "$crate/src" | tr -d ' ')
  if [ "${count:-0}" != "0" ]; then
    echo "FAIL: $crate has $count unsafe fn" >&2
    exit 1
  fi
  echo "OK: $crate unsafe fn count=0"
done

count=$(count_unsafe nfs-klldap-config/src supervisor.rs | tr -d ' ')
sup=$({ grep -c 'unsafe fn' nfs-klldap-config/src/supervisor.rs 2>/dev/null || true; })
sup=${sup:-0}
if [ "${count:-0}" != "0" ]; then
  echo "FAIL: nfs-klldap-config has $count unsafe fn outside supervisor.rs" >&2
  exit 1
fi
echo "OK: nfs-klldap-config unsafe fn outside supervisor.rs=0 (supervisor.rs=$sup allowed)"

echo "==> safety-dance passed"