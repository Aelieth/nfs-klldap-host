#!/usr/bin/env bash
# Clippy + deny(unsafe_code) + zero first-party unsafe audit.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

echo "==> clippy (-D warnings)"
make clippy

echo "==> deny(unsafe_code) on all workspace crates"
for crate in nfs-klldap-ui nfs-klldap-config nfs-klldap-identity; do
  grep -q '#!\[deny(unsafe_code' "$crate/src/main.rs" 2>/dev/null \
    || grep -q '#!\[deny(unsafe_code' "$crate/src/lib.rs"
done

echo "==> zero allow(unsafe_code) in first-party sources"
if grep -r '#!\[allow(unsafe_code)\]' nfs-klldap-config/src nfs-klldap-ui/src nfs-klldap-identity/src --include='*.rs' 2>/dev/null; then
  echo "FAIL: allow(unsafe_code) found" >&2
  exit 1
fi
echo "OK: no allow(unsafe_code)"

echo "==> zero unsafe blocks/fns in first-party sources"
if grep -rE '\bunsafe\b' nfs-klldap-config/src nfs-klldap-ui/src nfs-klldap-identity/src --include='*.rs' 2>/dev/null; then
  echo "FAIL: unsafe found in first-party sources" >&2
  exit 1
fi
echo "OK: zero unsafe"

echo "==> zero direct libc usage in first-party sources"
if grep -r 'libc::' nfs-klldap-config/src nfs-klldap-ui/src nfs-klldap-identity/src --include='*.rs' 2>/dev/null; then
  echo "FAIL: libc:: found in first-party sources" >&2
  exit 1
fi
echo "OK: zero libc::"

echo "==> safety-dance passed"