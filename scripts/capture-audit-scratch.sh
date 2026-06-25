#!/bin/bash
# Atomically capture audit scratch artifacts. Usage: SCRATCH=/path ./scripts/capture-audit-scratch.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-goal-audit}"
BASE="${AUDIT_BASE:-34cfa7d^}"
mkdir -p "$SCRATCH"

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

COMMENT_FILES=(
    nfs-klldap-config/src/generate.rs
    nfs-klldap-config/src/bin/idhelper/resolve.rs
    nfs-klldap-config/src/bin/idhelper/materialize.rs
    nfs-klldap-config/src/bin/idhelper/observer.rs
    nfs-klldap-config/src/bin/idhelper/daemon.rs
    nfs-klldap-config/src/bin/idhelper/common.rs
    nfs-klldap-config/src/validate.rs
    nfs-klldap-identity/src/krb5/principal.rs
    nfs-klldap-identity/src/lib.rs
    nfs-klldap-config/src/supervisor.rs
    nfs-klldap-config/src/hostname.rs
    nfs-klldap-config/src/signals.rs
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
    local rev="$1" sum=0 f n
    for f in "${IDHELPER_FILES[@]}"; do
        n=$(wc_file "$rev" "$f")
        sum=$((sum + n))
    done
    echo "$sum"
}

count_split_sites() {
    local total=0 def=0 line
    while IFS= read -r line; do
        total=$((total + 1))
        if [[ "$line" == nfs-klldap-identity/src/krb5/principal.rs:* ]] \
            || [[ "$line" == *"/nfs-klldap-identity/src/krb5/principal.rs:"* ]]; then
            def=$((def + 1))
        fi
    done < <(cd "$ROOT" && grep -rn "split('@')" "${SPLIT_SCOPE[@]}" 2>/dev/null || true)
    echo "$((total - def)) $def $total"
}

REFACTOR_FILES=(
    nfs-klldap-config/src/signals.rs
    nfs-klldap-config/src/signals_stub.rs
    nfs-klldap-config/src/hostname.rs
    nfs-klldap-config/src/supervisor.rs
    nfs-klldap-config/src/ganesha_liveness.rs
    nfs-klldap-config/src/lib.rs
    nfs-klldap-config/src/validate.rs
    nfs-klldap-ui/src/web/settings.rs
    scripts/safety-dance.sh
)

# --- changes.txt ---
{
    echo "=== git diff --shortstat ${BASE}..HEAD ==="
    git -C "$ROOT" diff --shortstat "${BASE}..HEAD"
    echo
    echo "=== git diff --stat ${BASE}..HEAD ==="
    git -C "$ROOT" diff --stat "${BASE}..HEAD"
    echo
    echo "=== commits ==="
    git -C "$ROOT" log --oneline "${BASE}..HEAD"
    echo
    echo "=== working tree diff --stat (uncommitted refactor scope) ==="
    git -C "$ROOT" diff --stat -- "${REFACTOR_FILES[@]}" 2>/dev/null || true
    echo
    echo "=== refactor scope files (tracked + untracked) ==="
    for f in "${REFACTOR_FILES[@]}"; do
        if [[ -f "$ROOT/$f" ]]; then
            wc -l "$ROOT/$f"
        else
            echo "missing $f"
        fi
    done
} >"$SCRATCH/changes.txt"

# --- loc-evidence.txt ---
idh_pre=$(idhelper_total "$BASE")
idh_now=$(idhelper_total HEAD)
idh_delta=$((idh_now - idh_pre))
read -r split_calls split_defs split_total < <(count_split_sites)

{
    echo "=== LOC pre-audit (${BASE}) ==="
    for f in "${IDHELPER_FILES[@]}" nfs-klldap-identity/src/krb5/principal.rs nfs-klldap-identity/src/ldap/resolver.rs; do
        printf "%4d %s\n" "$(wc_file "$BASE" "$f")" "$f"
    done
    echo "idhelper subtotal pre-audit: $idh_pre"
    echo
    echo "=== LOC current (HEAD) ==="
    for f in "${IDHELPER_FILES[@]}" nfs-klldap-identity/src/krb5/principal.rs nfs-klldap-identity/src/ldap/resolver.rs; do
        printf "%4d %s\n" "$(wc_file HEAD "$f")" "$f"
    done
    echo "idhelper subtotal current: $idh_now"
    echo "idhelper delta: $idh_delta"
    echo
    echo "=== scoped refactor shortstat (${BASE}..HEAD) ==="
    git -C "$ROOT" diff --shortstat "${BASE}..HEAD" -- \
        nfs-klldap-config/src/idmap.rs \
        nfs-klldap-config/src/config.rs \
        nfs-klldap-config/src/bin/idhelper \
        nfs-klldap-identity/src/krb5/principal.rs \
        nfs-klldap-identity/src/ldap/resolver.rs \
        nfs-klldap-ui/src/ldap.rs
    echo
    echo "=== split('@') in assumed scope ==="
    echo "call sites (excl. principal_local_part definition): $split_calls"
    echo "definitions (principal.rs principal_local_part): $split_defs"
    echo "total grep matches: $split_total"
    (cd "$ROOT" && grep -rn "split('@')" "${SPLIT_SCOPE[@]}" 2>/dev/null) || echo "(none)"
} >"$SCRATCH/loc-evidence.txt"

# --- comment-audit.txt ---
{
    echo "=== audited comment lines ==="
    for f in "${COMMENT_FILES[@]}"; do
        echo "--- $f ---"
        grep -n -E '^(//|//!|# )' "$ROOT/$f" 2>/dev/null || true
    done
} >"$SCRATCH/comment-audit.txt"

# --- docs-sync.txt (plan step 4: all listed READMEs) ---
{
    echo "=== doc review excerpts (Ganesha/idhelper/idmap/hybrid keywords) ==="
    for f in \
        README.md \
        docs/run/README.md \
        docs/ldap-integration.md \
        docs/ganesha-architecture.md \
        nfs-klldap-ui/README.md \
        examples/secrets/README.md \
        TESTING.md \
        container/README.md; do
        echo "--- $f ---"
        if [[ -f "$ROOT/$f" ]]; then
            grep -n -iE 'ganesha|idhelper|idmap|kerberos|Root_Kerberos|hybrid|principal|9\.6|trixie' "$ROOT/$f" 2>/dev/null | head -8 || echo "(no matches — OK if out of scope)"
        else
            echo "MISSING"
        fi
    done
} >"$SCRATCH/docs-sync.txt"

# --- gating ---
FAIL=0
if [[ "$idh_delta" -ge 0 ]]; then
    echo "FAIL: idhelper LOC delta $idh_delta (need < 0)" >&2
    FAIL=1
fi
if [[ "$split_calls" -gt 0 ]]; then
    echo "FAIL: split('@') call sites $split_calls (need 0)" >&2
    FAIL=1
fi
if [[ "$split_defs" -ne 1 ]]; then
    echo "FAIL: split('@') definitions $split_defs (need 1)" >&2
    FAIL=1
fi

echo "capture-audit-scratch: idhelper delta=$idh_delta split_calls=$split_calls split_defs=$split_defs"
echo "wrote $SCRATCH/{changes.txt,loc-evidence.txt,comment-audit.txt,docs-sync.txt}"
exit "$FAIL"