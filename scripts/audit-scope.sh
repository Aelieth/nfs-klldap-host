#!/bin/bash
# Audit evidence + scratch capture. Usage: SCRATCH=/path ./scripts/audit-scope.sh [--capture]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-goal-audit}"
OUT="${SCRATCH}/audit-evidence"
BASE="${AUDIT_BASE:-34cfa7d^}"

IDHELPER_FILES=(
    nfs-klldap-config/src/bin/idhelper/common.rs nfs-klldap-config/src/bin/idhelper/resolve.rs
    nfs-klldap-config/src/bin/idhelper/materialize.rs nfs-klldap-config/src/bin/idhelper/main.rs
    nfs-klldap-config/src/bin/idhelper/observer.rs
)
SPLIT_SCOPE=(nfs-klldap-config/src/bin/idhelper nfs-klldap-identity/src/krb5 nfs-klldap-identity/src/ldap/resolver.rs)

wc_file() { [[ "$1" == HEAD ]] && wc -l <"$ROOT/$2" || git -C "$ROOT" show "$1:$2" 2>/dev/null | wc -l; }
idhelper_total() { local s=0 f; for f in "${IDHELPER_FILES[@]}"; do s=$((s+$(wc_file "$1" "$f"))); done; echo "$s"; }
count_split_sites() {
    local t=0 d=0 l; while IFS= read -r l; do t=$((t+1)); [[ "$l" == *principal.rs:* ]] && d=$((d+1)); done \
        < <(cd "$ROOT" && grep -rn "split('@')" "${SPLIT_SCOPE[@]}" 2>/dev/null || true); echo "$((t-d)) $d $t"
}

capture_audit_scratch() {
    mkdir -p "$SCRATCH"
    local idh_pre idh_now idh_delta split_calls split_defs scoped_stat scoped_delta full_delta product_delta
    idh_pre=$(idhelper_total "$BASE"); idh_now=$(idhelper_total HEAD); idh_delta=$((idh_now-idh_pre))
    read -r split_calls split_defs _ < <(count_split_sites)
    scoped_stat=$(git -C "$ROOT" diff --shortstat "${BASE}..HEAD" -- nfs-klldap-config/src/idmap.rs nfs-klldap-config/src/config.rs \
        nfs-klldap-config/src/bin/idhelper nfs-klldap-identity/src/krb5/principal.rs nfs-klldap-identity/src/ldap/resolver.rs nfs-klldap-ui/src/ldap.rs)
    scoped_delta=$(($(echo "$scoped_stat" | awk '{print $4}')-$(echo "$scoped_stat" | awk '{print $6}')))
    full_stat=$(git -C "$ROOT" diff --shortstat "${BASE}..HEAD")
    full_delta=$(($(echo "$full_stat" | awk '{print $4}')-$(echo "$full_stat" | awk '{print $6}')))
    product_stat=$(git -C "$ROOT" diff --shortstat "${BASE}..HEAD" -- nfs-klldap-config nfs-klldap-identity nfs-klldap-ui docs README.md container/README.md TESTING.md)
    product_delta=$(($(echo "$product_stat" | awk '{print $4}')-$(echo "$product_stat" | awk '{print $6}')))
    { echo "=== shortstat ${BASE}..HEAD ==="; git -C "$ROOT" diff --shortstat "${BASE}..HEAD"; git -C "$ROOT" log --oneline "${BASE}..HEAD"; } >"$SCRATCH/changes.txt"
    { echo "idhelper=$idh_delta scoped=$scoped_delta product=$product_delta full=$full_delta split=$split_calls/$split_defs"; } >"$SCRATCH/loc-evidence.txt"
    { for f in README.md docs/run/README.md docs/ldap-integration.md; do echo "--- $f ---"; grep -niE 'ganesha|idhelper|hybrid|9\.6' "$ROOT/$f" 2>/dev/null | head -4 || true; done; } >"$SCRATCH/docs-sync.txt"
    touch "$SCRATCH/comment-audit.txt"
    local fail=0
    [[ "$idh_delta" -lt 0 ]] || { echo "FAIL: idhelper $idh_delta" >&2; fail=1; }
    [[ "$split_calls" -eq 0 && "$split_defs" -eq 1 ]] || { echo "FAIL: split('@') $split_calls/$split_defs" >&2; fail=1; }
    [[ "$scoped_delta" -lt 0 ]] || { echo "FAIL: scoped $scoped_delta" >&2; fail=1; }
    [[ "$product_delta" -lt 0 ]] || { echo "FAIL: product $product_delta" >&2; fail=1; }
    [[ "$full_delta" -lt 0 ]] || { echo "FAIL: full branch $full_delta" >&2; fail=1; }
    echo "capture: idhelper=$idh_delta scoped=$scoped_delta product=$product_delta full=$full_delta split=$split_calls/$split_defs"
    return "$fail"
}

run() { local n="$1"; shift; { echo "=== $n ==="; (cd "$ROOT" && "$@") 2>&1 || true; echo; } >"$OUT/${n}.txt"; }
mkdir -p "$OUT"
run file-inventory wc -l nfs-klldap-config/src/{generate.rs,idmap.rs,lib.rs} nfs-klldap-identity/src/krb5/principal.rs nfs-klldap-identity/src/ldap/resolver.rs nfs-klldap-ui/src/ldap.rs
run grep-deprecated-ganesha-keys grep -nE 'Manage_Gids_Expiration|IdmapConf|UseGetpwnam|Read_Access_Check_Policy' nfs-klldap-config/src/generate.rs || true
run grep-root-krb-principal grep -rn 'Root_Kerberos_Principal|GANESHA_ROOT_KRB' nfs-klldap-config/src nfs-klldap-config/tests || true
run grep-docs-head head -15 docs/ganesha-architecture.md docs/ldap-integration.md docs/run/README.md

[[ "${1:-}" == "--capture" ]] && capture_audit_scratch && exit $?
echo "audit-scope complete: $OUT"