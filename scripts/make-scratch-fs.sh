#!/bin/bash
# make-scratch-fs.sh — loopback-image scratch filesystems for the 2.6 ACL
# gate's per-fstype legs (ext4 required by the gate; xfs/btrfs optional
# extras; vfat deliberately included as the negative write-probe demo — it
# cannot store POSIX ACLs, so a share on it must classify Incapable).
# Run AS ROOT on the deploy host. Creates the image + mount UNDER /var/data
# so the container's /var/data -> /export bind carries it.
#
# Usage: ./make-scratch-fs.sh <ext4|xfs|btrfs|vfat> [size]      (default 2G)
#        ./make-scratch-fs.sh --teardown <ext4|xfs|btrfs|vfat>
set -euo pipefail

BASE="/var/data"

usage() { sed -n '2,10{s/^# \{0,1\}//;p}' "$0"; exit 1; }

[[ $# -ge 1 ]] || usage
MODE="make"
if [[ "$1" == "--teardown" ]]; then
    MODE="teardown"; shift
    [[ $# -ge 1 ]] || usage
fi
FSTYPE="$1"
SIZE="${2:-2G}"
case "$FSTYPE" in ext4|xfs|btrfs|vfat) ;; *) echo "Unsupported fstype: $FSTYPE"; usage ;; esac

# Everything this script touches stays under $BASE — the bind-mounted tree.
NAME="scratch-${FSTYPE}"
IMG="${BASE}/${NAME}.img"
MNT="${BASE}/${NAME}"
case "$IMG" in "$BASE"/*) ;; *) echo "refusing path outside ${BASE}: $IMG"; exit 1 ;; esac

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root (mkfs + mount)." ; exit 1
fi

if [[ "$MODE" == "teardown" ]]; then
    if mountpoint -q "$MNT"; then umount "$MNT"; fi
    rmdir "$MNT" 2>/dev/null || true
    rm -f "$IMG"
    echo "Torn down ${MNT} + ${IMG}."
    echo "Remove the share in the WebUI too, then:  docker restart nfs-klldap-host"
    exit 0
fi

if mountpoint -q "$MNT"; then
    echo "${MNT} is already mounted — teardown first or use it as-is."
    exit 1
fi

command -v "mkfs.${FSTYPE}" >/dev/null || { echo "mkfs.${FSTYPE} not installed on this host"; exit 1; }

truncate -s "$SIZE" "$IMG"
mkfs."$FSTYPE" $( [[ "$FSTYPE" == "vfat" ]] || echo -q ) "$IMG" >/dev/null
mkdir -p "$MNT"
mount -o loop "$IMG" "$MNT"
# The gate's fixtures are created by aclprep as root; group-writability comes
# from the fixture script, not the mount root. vfat has no POSIX perms at all.
[[ "$FSTYPE" == "vfat" ]] || chmod 755 "$MNT"

echo "Mounted ${SIZE} ${FSTYPE} image at ${MNT} (backing file ${IMG})."
findmnt -no SOURCE,FSTYPE,OPTIONS "$MNT"
cat <<EOF

NEXT STEPS — the parts the mount alone does NOT cover:

1. Make it visible in the container. The compose bind /var/data -> /export is
   rprivate: a mount created AFTER container start does not propagate. From
   the HOST run:
       docker restart nfs-klldap-host
   (The WebUI Admin restart / SIGUSR1 recycle happens INSIDE the container's
   mount namespace and will NOT pick this up.)
   This mount also does not survive a host reboot — re-run this script (or
   add an fstab loop entry) before re-testing after one.

2. SELinux: the compose ':Z' relabel ran at container CREATE, not restart.
   If the container gets EACCES/denials under this tree:
       chcon -R -t container_file_t ${MNT}

3. Add the share in the WebUI (System Settings -> shares): serve path
   /export/${NAME} — leave enable_acl unset (auto). Expected classification:
     ext4/xfs/btrfs -> write-probe proves Capable -> class acl (auto)
     vfat           -> Incapable -> class noacl, ACL editor gated off
   Then Apply, and confirm the class at:  <webui>/client-manifest.json

4. Client side: mount the new share (it now appears in the manifest; the
   client kit picks it up on a re-run, or mount by hand), then retarget the
   harness config block in setup-script/stress-test.sh:
       ACL_SHARE="/var/mnt/${NAME}"           (or wherever it is mounted)
       ACL_FIXTURE="\${ACL_SHARE}/aclgate"
       SERVER_FIXTURE_PATH="/export/${NAME}/aclgate"
       ACL_SHARE_NAME="${NAME}"
   and re-run:  ./stress-test.sh aclprep aclmatrix aclperf
   (add aclwire on the audit client; the identity/propagation rows are
   filesystem-independent and do not need a per-fstype re-run).
EOF
