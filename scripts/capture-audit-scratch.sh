#!/bin/bash
# Usage: SCRATCH=/path ./scripts/capture-audit-scratch.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec env SCRATCH="${SCRATCH:-/tmp/grok-goal-audit}" "$ROOT/scripts/audit-scope.sh" --capture