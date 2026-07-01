#!/bin/bash
# Run verification plan steps 1–5 with fixed scratch tee paths.
# Usage: SCRATCH=/path ./scripts/run-plan-verification.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-goal-25c1e2ddb1b5/implementer}"
mkdir -p "$SCRATCH"

echo "=== PLAN VERIFICATION START $(date -u) ==="
echo "ROOT=$ROOT SCRATCH=$SCRATCH"

cd "$ROOT"

echo "=== step 1: cargo test --workspace ==="
cargo test --workspace 2>&1 | tee "$SCRATCH/cargo-test-workspace.log"

echo "=== step 2: named idmap contract suites ==="
echo "# Plan step 2 lists six suite filters; cargo accepts one TESTNAME per invocation."
{
  cargo test -p nfs-klldap-config --test ganesha_96_identity_audit -- --nocapture
  cargo test -p nfs-klldap-config --test limited_fs_generate -- --nocapture
  cargo test -p nfs-klldap-config --lib ganesha_readiness -- --nocapture
  cargo test -p nfs-klldap-config --lib ganesha_identity_pipeline -- --nocapture
  cargo test -p nfs-klldap-config --lib ganesha_nss_contract -- --nocapture
  cargo test -p nfs-klldap-config --bin nfs-klldap-idhelper idmap_log_contract -- --nocapture
} 2>&1 | tee "$SCRATCH/cargo-test-idmap-contracts.log"

echo "=== step 3: supervisor_readiness_transcript ==="
cargo test -p nfs-klldap-config --test supervisor_readiness_transcript -- --nocapture 2>&1 \
  | tee "$SCRATCH/supervisor-readiness.log"

echo "=== step 4: resolve fail-closed (plan: cargo test -p nfs-klldap-config resolve -- --nocapture) ==="
cargo test -p nfs-klldap-config resolve -- --nocapture 2>&1 \
  | tee "$SCRATCH/fail-closed-resolve.log"

echo "=== step 5: verify-audit-claims ==="
bash "$ROOT/scripts/verify-audit-claims.sh" 2>&1 | tee "$SCRATCH/verify-audit-claims.log"

echo "=== PLAN VERIFICATION COMPLETE $(date -u) ==="