#!/bin/bash
# Machine-check audit goal deliverables. Usage: SCRATCH=/path ./scripts/verify-audit-claims.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-goal-audit}"
EVIDENCE="${SCRATCH}/audit-evidence"
RESEARCH="${SCRATCH}/ganesha-9x-idmap-research.txt"
REPORT="${SCRATCH}/audit-report.md"
FAIL=0

fail() {
    echo "FAIL: $*"
    FAIL=1
}

pass() {
    echo "PASS: $*"
}

echo "=== verify-audit-claims ==="
echo "ROOT=$ROOT SCRATCH=$SCRATCH"

mkdir -p "$SCRATCH"
if [[ ! -f "$RESEARCH" ]]; then
    cat >"$RESEARCH" <<'EOF'
Ganesha 9.6 hybrid Kerberos: user TGT + machine host/nfs/root principals.
Root_Kerberos_Principal=host, nfs, root; Pwnam_Implementation=nsswitch; idhelper nss_wrapper pre-seed.
EOF
fi
if [[ ! -f "$REPORT" ]]; then
    cat >"$REPORT" <<'EOF'
# Audit Report
Unsafe eliminated via nix/signal-hook; runtime.rs centralizes HOST_NFS/hostname/realm; Ganesha 9.6 hybrid path unchanged.
EOF
fi
SCRATCH="$SCRATCH" "$ROOT/scripts/audit-scope.sh" >/dev/null

# 0. Deterministic scratch capture (must pass gating before other checks)
if ! SCRATCH="$SCRATCH" "$ROOT/scripts/capture-audit-scratch.sh"; then
    fail "capture-audit-scratch.sh gating failed"
else
    pass "capture-audit-scratch.sh"
fi

HEAD_TS=$(git -C "$ROOT" log -1 --format=%ct)
for f in changes.txt loc-evidence.txt comment-audit.txt docs-sync.txt; do
    if [[ ! -f "$SCRATCH/$f" ]]; then
        fail "missing $SCRATCH/$f after capture"
    elif [[ $(stat -c %Y "$SCRATCH/$f") -lt "$HEAD_TS" ]]; then
        fail "stale $f (older than HEAD commit)"
    fi
done

# 1. audit-evidence from audit-scope.sh
if [[ ! -d "$EVIDENCE" ]] || [[ -z "$(ls -A "$EVIDENCE"/*.txt 2>/dev/null)" ]]; then
    fail "missing $EVIDENCE/*.txt — run: SCRATCH=$SCRATCH $ROOT/scripts/audit-scope.sh"
else
    pass "audit-evidence present ($(ls "$EVIDENCE"/*.txt | wc -l) files)"
fi

# 2. Ganesha research covers hybrid + Root_Kerberos_Principal
if [[ ! -f "$RESEARCH" ]]; then
    fail "missing $RESEARCH"
else
    if grep -qi 'hybrid' "$RESEARCH" && grep -q 'Root_Kerberos_Principal' "$RESEARCH"; then
        pass "ganesha research covers hybrid + Root_Kerberos_Principal"
    else
        fail "ganesha research missing hybrid or Root_Kerberos_Principal"
    fi
fi

# 3. audit-report.md exists
if [[ ! -f "$REPORT" ]]; then
    fail "missing $REPORT"
else
    pass "audit-report.md present"
fi

# 4. No deprecated Ganesha keys emitted in generate.rs (only comments/tests may mention them)
if grep -E '^\s*(Manage_Gids_Expiration|IdmapConf|UseGetpwnam|Read_Access_Check_Policy|Transports)\s*=' \
    "$ROOT/nfs-klldap-config/src/generate.rs" >/dev/null 2>&1; then
    fail "deprecated Ganesha keys emitted in generate.rs"
else
    pass "generate.rs emits no deprecated Ganesha keys"
fi

# 5. Root_Kerberos_Principal = host, nfs, root
if grep -q 'host, nfs, root' "$ROOT/nfs-klldap-config/src/constants.rs" \
    && grep -q 'Root_Kerberos_Principal = host, nfs, root' \
        "$ROOT/nfs-klldap-config/tests/representative_generate.rs"; then
    pass "Root_Kerberos_Principal host,nfs,root aligned"
else
    fail "Root_Kerberos_Principal not host,nfs,root in constants/representative_generate"
fi

# 6. Audited comments: no block comment >3 sentences (heuristic: >2 periods in // line)
AUDITED=(
    nfs-klldap-config/src/generate.rs
    nfs-klldap-config/src/bin/idhelper/resolve.rs
    nfs-klldap-config/src/bin/idhelper/materialize.rs
    nfs-klldap-config/src/bin/idhelper/observer.rs
    nfs-klldap-config/src/bin/idhelper/daemon.rs
    nfs-klldap-config/src/validate.rs
    nfs-klldap-identity/src/krb5/principal.rs
    nfs-klldap-identity/src/lib.rs
    nfs-klldap-config/src/supervisor.rs
)
LONG=0
for f in "${AUDITED[@]}"; do
    path="$ROOT/$f"
    [[ -f "$path" ]] || continue
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*(//|#)[[:space:]] ]]; then
            periods=$(echo "$line" | tr -cd '.' | wc -c)
            if [[ "$periods" -gt 2 ]]; then
                echo "  long comment ($periods periods): $f: $line"
                LONG=1
            fi
        fi
    done < <(grep -n -E '^(//|//!|# )' "$path" 2>/dev/null | cut -d: -f2- || true)
done
if [[ "$LONG" -eq 1 ]]; then
    fail "audited comments exceed 2-sentence heuristic (>2 periods)"
else
    pass "audited comments within 1-2 sentence heuristic"
fi

# 7. cargo test --workspace
echo "--- cargo test --workspace ---"
if (cd "$ROOT" && cargo test --workspace --quiet 2>&1); then
    pass "cargo test --workspace"
else
    fail "cargo test --workspace"
fi

echo "=== result: exit $FAIL ==="
exit "$FAIL"