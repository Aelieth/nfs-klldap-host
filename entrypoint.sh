#!/bin/bash
set -e

echo "=== Starting Kerberized NFS Server ==="

# Start rpcbind
echo "[+] Starting rpcbind..."
rpcbind -w

# Start rpc.gssd (Kerberos)
echo "[+] Starting rpc.gssd..."
rpc.gssd -f &

# Apply exports
echo "[+] Applying exports..."
exportfs -ra

# Start nfsd (NFSv4 only for security)
echo "[+] Starting nfsd..."
rpc.nfsd -N 4 -V 4

echo "[+] NFS server is ready."
echo "    Keytab: /etc/krb5.keytab"
echo "    Exports: /etc/exports"

# Keep container alive
tail -f /dev/null
