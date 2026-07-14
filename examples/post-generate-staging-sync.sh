#!/bin/sh
# Example post-generate hook: stage a share's data onto its ACL-capable serve tree
# (idempotent rsync). Use when a share sets `enable_acl = true` but its real data lives on
# a filesystem that cannot store POSIX ACLs — the packaged Ganesha VFS FSAL cannot serve those.
#
# Configure in nfs-klldap.conf:
#   [ganesha]
#   post_generate_hook = "/config/post-generate-staging-sync.sh"
#   [[shares]]
#   name          = "users"
#   host_path     = "/media/nvme-raid/users"     # host-side data (WebUI/chown)
#   source_path   = "/export/nvme-raid/users"    # where that data is bind-mounted (SOURCE)
#   container_path = "/export/staging/users"      # ACL-capable serve tree (Ganesha Path=)
#   enable_acl    = true
# Or set NFS_KLLDAP_POST_GENERATE_HOOK to this script path.
#
# Environment (set per share by nfs-klldap-config):
#   SHARE_NAME, HOST_PATH, SOURCE_PATH, SERVE_PATH (== CONTAINER_PATH), PSEUDO_PATH
# SOURCE_PATH defaults to SERVE_PATH when `source_path` is unset (no staging => no-op).
set -eu

SRC="${SOURCE_PATH:?SOURCE_PATH required}"
DST="${SERVE_PATH:?SERVE_PATH required}"

if [ "$SRC" = "$DST" ]; then
    echo "post-generate-staging-sync: skip share=${SHARE_NAME:-?} (source == serve; no staging)"
    exit 0
fi

mkdir -p "$DST"
# -A/-X preserve POSIX ACLs + xattrs so the served copy keeps ACL entries.
# Trailing slashes matter for rsync directory merge semantics.
rsync -aAX --delete "${SRC%/}/" "${DST%/}/"
echo "post-generate-staging-sync: share=${SHARE_NAME:-?} staged ${SRC} -> ${DST}"
exit 0