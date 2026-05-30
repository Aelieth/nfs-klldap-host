#!/bin/bash
#
# fix-keytab-perms.sh
#
# Convenience helper to make a Kerberos keytab readable by the
# nfs-klldap-host container when it runs as the non-root "nfs" user.
#
# The container image creates a system group called "keytab" and adds
# its runtime user to that group. This script inspects the image for
# the numeric GID of that group and applies the correct ownership + mode
# on the *host* copy of the keytab.
#
# Usage:
#   ./scripts/fix-keytab-perms.sh /path/to/your/krb5.keytab
#
# Or with a custom image:
#   IMAGE=ghcr.io/aelieth/nfs-klldap-host:v0.5 ./scripts/fix-keytab-perms.sh ./secrets/krb5.keytab
#
# After running this, you can mount the keytab read-only and the
# container will be able to read it without running as root.
#
set -euo pipefail

KEYTAB="${1:-}"
IMAGE="${IMAGE:-ghcr.io/aelieth/nfs-klldap-host:latest}"

if [[ -z "$KEYTAB" ]]; then
    echo "Usage: $0 /path/to/krb5.keytab"
    echo "       IMAGE=your-image:tag $0 /path/to/krb5.keytab"
    exit 1
fi

if [[ ! -f "$KEYTAB" ]]; then
    echo "Error: $KEYTAB does not exist or is not a regular file"
    exit 1
fi

echo "Inspecting image '$IMAGE' for the 'keytab' group GID..."
GID=$(docker run --rm --entrypoint getent "$IMAGE" keytab 2>/dev/null | cut -d: -f3 || true)

if [[ -z "$GID" || "$GID" == "0" ]]; then
    echo "Error: Could not determine a usable GID for the 'keytab' group from the image."
    echo "       You may need to run the container at least once so the group is created,"
    echo "       or inspect it manually with:"
    echo "         docker run --rm --entrypoint getent $IMAGE keytab"
    exit 1
fi

echo "Found keytab group GID: $GID"
echo "Applying permissions to $KEYTAB ..."

# We need root on the host to change the group of the keytab file.
if ! sudo -n true 2>/dev/null; then
    echo "This script needs sudo to change group ownership of the keytab."
fi

sudo chgrp "$GID" "$KEYTAB"
sudo chmod g+r "$KEYTAB"

echo "Done. $KEYTAB is now group-readable by GID $GID."
echo
echo "You can mount it with:"
echo "  -v $(realpath "$KEYTAB"):/etc/krb5.keytab:ro"
echo
echo "Recommended: also add the group inside the container in docker-compose:"
echo "    group_add:"
echo "      - \"$GID\""
