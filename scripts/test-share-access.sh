#!/bin/bash
# test-share-access.sh — thin wrapper around capture-share-access-evidence.sh
# Usage: NFS_TEST_USER_PW='...' ./scripts/test-share-access.sh [container_name]
set -euo pipefail

CONTAINER="${1:-nfs-klldap}"
SCRATCH="${NFS_TEST_SCRATCH:-/tmp/nfs-klldap-share-access-$$}"
export SCRATCH
export NFS_TEST_USER_PW="${NFS_TEST_USER_PW:?set NFS_TEST_USER_PW for Kerberos user}"

exec "$(dirname "$0")/capture-share-access-evidence.sh" "$CONTAINER"