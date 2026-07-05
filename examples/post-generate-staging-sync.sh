#!/bin/sh
# Example post-generate hook: sync host data tree into container_path staging (idempotent rsync).
# Configure in nfs-klldap.conf:
#   [ganesha]
#   post_generate_hook = "/config/post-generate-staging-sync.sh"
# Or set NFS_KLLDAP_POST_GENERATE_HOOK to this script path.
#
# Environment (set per share by nfs-klldap-config):
#   SHARE_NAME, HOST_PATH, CONTAINER_PATH, SERVE_PATH, GANESHA_PATH, EXPORT_PATH
set -eu

SRC="${CONTAINER_PATH:?CONTAINER_PATH required}"
DST="${GANESHA_PATH:-${SERVE_PATH:?SERVE_PATH or GANESHA_PATH required}}"

if [ "$SRC" = "$DST" ]; then
    echo "post-generate-staging-sync: skip share=${SHARE_NAME:-?} (source equals destination)"
    exit 0
fi

mkdir -p "$DST"
# Trailing slashes matter for rsync directory merge semantics.
rsync -a --delete "${SRC%/}/" "${DST%/}/"
echo "post-generate-staging-sync: share=${SHARE_NAME:-?} synced ${SRC} -> ${DST}"
exit 0