#!/bin/bash
# Audit evidence + optional scratch capture. Usage: SCRATCH=/path ./scripts/audit-scope.sh [--capture]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-goal-audit}"
OUT="${SCRATCH}/audit-evidence"
BASE="${AUDIT_BASE:-34cfa7d^}"

IDHELPER_FILES=(
    nfs-klldap-config/src/bin/idhelper/common.rs
    nfs-klldap-config/src/bin/idhelper/resolve.rs
    nfs-klldap-config/src/bin/idhelper/materialize.rs
    nfs-klldap-config/src/bin/idhelper/main.rs
    nfs-klldap-config/src/bin/idhelper/observer.rs
)
SPLIT_SCOPE=(
    nfs-klldap-config/src/bin/idhelper
    nfs-klldap-identity/src/krb5
    nfs-klldap-identity/src/ldap/resolver.rs
)

wc_file() {
    local rev="$1" path="$2"
    if [[ "$rev" == "HEAD" ]]; then
        wc -l <"$ROOT/$path"
    else
        git -C "$ROOT" show "${rev}:${path}" 2>/dev/null | wc -l
    fi
}

idhelper_total() {
    local rev="$1" sum=0 n
    for f in "${IDHELPER_FILES[@]}"; do
        sum=$((sum + $(wc_file "$rev" "$f")))
    done
    echo "$sum"
}

count_split_sites() {
    local total=0 def=0 line
    while IFS= read -r line; do
        total=$((total + 1))
        [[ "$line" == *nfs-klldap-identity/src/krb5/principal.rs:* ]] && def=$((def + 1))
    done < <(cd "$ROOT" && grep -rn "split('@')" "${SPLIT_SCOPE[@]}" 2>/dev/null || true)
    echo "$((total - def)) $def $total"
}

capture_audit_scratch() {
    mkdir -p "$SCRATCH"
    local idh_pre idh_now idh_delta split_calls split_defs split_total scoped_stat scoped_ins scoped_del scoped_delta
    local full_ins full_del full_delta product_ins product_del product_delta
    idh_pre=$(idhelper_total "$BASE")
    idh_now=$(idhelper_total HEAD)
    idh_delta=$((idh_now - idh_pre))
    read -r split_calls split_defs split_total < <(count_split_sites)
    scoped_stat=$(git -C "$ROOT" diff --shortstat "${BASE}..HEAD" -- \
        nfs-klldap-config/src/idmap.rs nfs-klldap-config/src/config.rs nfs-klldap-config/src/bin/idhelper \
        nfs-klldap-identity/src/krb5/principal.rs nfs-klldap-identity/src/ldap/resolver.rs nfs-klldap-ui/src/ldap.rs)
    scoped_ins=$(echo "$scoped_stat" | awk '{print $4}'); scoped_ins=${scoped_ins:-0}
    scoped_del=$(echo "$scoped_stat" | awk '{print $6}'); scoped_del=${scoped_del:-0}
    scoped_delta=$((scoped_ins - scoped_del))
    full_stat=$(git -C "$ROOT" diff --shortstat "${BASE}..HEAD")
    full_ins=$(echo "$full_stat" | awk '{print $4}'); full_ins=${full_ins:-0}
    full_del=$(echo "$full_stat" | awk '{print $6}'); full_del=${full_del:-0}
    full_delta=$((full_ins - full_del))
    product_stat=$(git -C "$ROOT" diff --shortstat "${BASE}..HEAD" -- \
        nfs-klldap-config nfs-klldap-identity nfs-klldap-ui docs README.md container/README.md TESTING.md)
    product_ins=$(echo "$product_stat" | awk '{print $4}'); product_ins=${product_ins:-0}
    product_del=$(echo "$product_stat" | awk '{print $6}'); product_del=${product_del:-0}
    product_delta=$((product_ins - product_del))

    {
        echo "=== git diff --shortstat ${BASE}..HEAD ==="; git -C "$ROOT" diff --shortstat "${BASE}..HEAD"
        echo; echo "=== commits ==="; git -C "$ROOT" log --oneline "${BASE}..HEAD"
    } >"$SCRATCH/changes.txt"

    {
        echo "=== idhelper delta: $idh_delta scoped: $scoped_delta product: $product_delta full: $full_delta ==="
        echo "split calls=$split_calls defs=$split_defs total=$split_total"
        git -C "$ROOT" diff --shortstat "${BASE}..HEAD" -- \
            nfs-klldap-config/src/idmap.rs nfs-klldap-config/src/config.rs nfs-klldap-config/src/bin/idhelper \
            nfs-klldap-identity/src/krb5/principal.rs nfs-klldap-identity/src/ldap/resolver.rs nfs-klldap-ui/src/ldap.rs
    } >"$SCRATCH/loc-evidence.txt"

    {
        for f in nfs-klldap-config/src/generate.rs nfs-klldap-config/src/bin/idhelper/resolve.rs \
            nfs-klldap-identity/src/krb5/principal.rs nfs-klldap-config/src/supervisor.rs; do
            echo "--- $f ---"; grep -n -E '^(//|//!|# )' "$ROOT/$f" 2>/dev/null || true
        done
    } >"$SCRATCH/comment-audit.txt"

    {
        for f in README.md docs/run/README.md docs/ldap-integration.md docs/ganesha-architecture.md container/README.md; do
            echo "--- $f ---"
            grep -n -iE 'ganesha|idhelper|Root_Kerberos|hybrid|9\.6' "$ROOT/$f" 2>/dev/null | head -6 || true
        done
    } >"$SCRATCH/docs-sync.txt"

    local fail=0
    [[ "$idh_delta" -lt 0 ]] || { echo "FAIL: idhelper delta $idh_delta" >&2; fail=1; }
    [[ "$split_calls" -eq 0 ]] || { echo "FAIL: split('@') calls $split_calls" >&2; fail=1; }
    [[ "$split_defs" -eq 1 ]] || { echo "FAIL: split('@') defs $split_defs" >&2; fail=1; }
    [[ "$scoped_delta" -lt 0 ]] || { echo "FAIL: scoped delta $scoped_delta" >&2; fail=1; }
    [[ "$product_delta" -lt 0 ]] || { echo "FAIL: product code delta $product_delta" >&2; fail=1; }
    echo "capture: idhelper=$idh_delta scoped=$scoped_delta product=$product_delta full=$full_delta split=$split_calls/$split_defs"
    return "$fail"
}

run() {
    local name="$1"; shift
    { echo "=== $name ==="; echo "cmd: $*"; echo "---"; (cd "$ROOT" && "$@") 2>&1 || true; echo; } >"$OUT/${name}.txt"
}

mkdir -p "$OUT"
run file-inventory bash -c 'wc -l nfs-klldap-config/src/{generate.rs,idmap.rs,lib.rs} nfs-klldap-identity/src/krb5/principal.rs nfs-klldap-identity/src/ldap/resolver.rs nfs-klldap-ui/src/ldap.rs 2>/dev/null'
run grep-deprecated-ganesha-keys grep -n -E 'Manage_Gids_Expiration|IdmapConf|UseGetpwnam|Read_Access_Check_Policy' nfs-klldap-config/src/generate.rs || true
run grep-root-krb-principal grep -rn 'Root_Kerberos_Principal|GANESHA_ROOT_KRB' nfs-klldap-config/src nfs-klldap-config/tests || true
run grep-docs-head head -20 docs/ganesha-architecture.md docs/ldap-integration.md docs/run/README.md

if [[ "${1:-}" == "--capture" ]]; then
    capture_audit_scratch
    exit $?
fi

echo "audit-scope complete: $OUT"