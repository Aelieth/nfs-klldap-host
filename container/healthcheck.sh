#!/bin/bash
#
# Lightweight healthcheck for the Kerberized NFS container.
#
# Success criteria (all must pass):
#   - rpcbind is responsive
#   - At least one NFS service is registered
#   - exportfs can list exports without error
#
# This is intentionally simple. More sophisticated checks (active mounts,
# Kerberos ticket validation against LLDAP, etc.) belong in external monitoring.
#
set -euo pipefail

# Check that rpcbind can at least answer
if ! rpcinfo -p localhost >/dev/null 2>&1; then
    echo "FAIL: rpcbind not responding"
    exit 1
fi

# Check that NFSv4 is at least registered (port 2049)
if ! rpcinfo -p localhost | grep -q 'nfs.*2049'; then
    echo "FAIL: NFS service not registered on expected ports"
    exit 1
fi

# Check that exports can be read (this exercises idmapd indirectly in some cases)
if ! exportfs -s >/dev/null 2>&1; then
    echo "FAIL: exportfs -s failed"
    exit 1
fi

echo "OK: NFS services healthy"
exit 0
