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

echo "=== step 2: plan_step2_named_idmap_contracts ==="
cargo test -p nfs-klldap-config plan_step2_named_idmap_contracts -- --nocapture 2>&1 \
  | tee "$SCRATCH/cargo-test-idmap-contracts.log"

echo "=== step 3: supervisor_readiness_transcript ==="
cargo test -p nfs-klldap-config --test supervisor_readiness_transcript -- --nocapture 2>&1 \
  | tee "$SCRATCH/supervisor-readiness.log"

echo "=== step 4: resolve_fail_closed evidence ==="
cargo test -p nfs-klldap-config resolve_fail_closed -- --nocapture 2>&1 \
  | tee "$SCRATCH/fail-closed-resolve.log"

echo "=== step 5: verify-audit-claims ==="
bash "$ROOT/scripts/verify-audit-claims.sh" 2>&1 | tee "$SCRATCH/verify-audit-claims.log"

echo "=== PLAN VERIFICATION COMPLETE $(date -u) ==="