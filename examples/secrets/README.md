# Keytab for the NFS Service Principal

The container expects the Kerberos keytab at:

    /etc/krb5.keytab

This keytab **must** contain the NFS service principal for the container's hostname:

    nfs/<hostname>@REALM

Example principal:

    nfs/nfs-server-01.example.com@EXAMPLE.COM

## How to obtain the keytab

1. On your KDC (or using a tool like `ipa-getkeytab`, `ktutil`, or your Kerberos admin interface), extract the keytab for the NFS principal.

2. Copy it to the host and set strict permissions:

   ```bash
   chmod 600 /path/to/krb5.keytab
   chown root:root /path/to/krb5.keytab
   ```

3. Bind-mount it read-only into the container:

   ```yaml
   - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
   ```

## Important

- The strongly recommended way to run is with `--uts=host` (or `uts: host` in compose). This lets the container see the real host hostname. The `nfs-klldap-startup` TUI will then automatically compute and display the correct principal using the `-nfs` insertion (e.g. `host.example.com` → `nfs/host-nfs.example.com@REALM`).
- You can still override with `--hostname` (or compose `hostname:`) if you want a completely different name inside the container. This takes precedence.
- Never commit the real keytab to git. This directory contains only an example.
- For automated renewal later, the keytab can be refreshed in place and the container sent SIGHUP (or restarted).

## Example mount in docker-compose

See the main `examples/docker-compose.yml`.
