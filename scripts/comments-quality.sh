#!/usr/bin/env bash
# Thin wrapper around scripts/comment_lint.py (single source of truth).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
scratch="${SCRATCH:-/tmp/grok-goal-comments-audit}"
mkdir -p "$scratch"
out="$scratch/comments-audit.txt"
python3 scripts/comment_lint.py >"$out" 2>&1
cat "$out"
echo "comments-quality: wrote $out"