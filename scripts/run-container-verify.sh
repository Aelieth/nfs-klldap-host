#!/bin/bash
# run-container-verify.sh — in-container verification commands for SCRATCH/container-verify.log
# Usage: SCRATCH=/path ./scripts/run-container-verify.sh [container_name]
set -euo pipefail

CONTAINER="${1:-nfs-klldap}"
SCRATCH="${SCRATCH:?set SCRATCH}"
OUT="$SCRATCH/container-verify.log"

{
  echo "=== healthcheck $(date -Is) ==="
  docker exec "$CONTAINER" /container/healthcheck.sh
  echo "healthcheck exit=$?"
  echo "=== verify-ganesha ==="
  docker exec "$CONTAINER" verify-ganesha.sh
  echo "verify-ganesha exit=$?"
  echo "=== ganesha-ctl show-fragments ==="
  docker exec "$CONTAINER" ganesha-ctl show-fragments
  echo "=== ganesha-ctl id-check ==="
  docker exec "$CONTAINER" ganesha-ctl id-check
  echo "=== ganesha-ctl fs-warnings ==="
  docker exec "$CONTAINER" ganesha-ctl fs-warnings
} >"$OUT" 2>&1

echo "OK: container verification log: $OUT"