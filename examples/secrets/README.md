# Kerberos keytab for nfs-klldap-host

Mount at `/etc/krb5.keytab:ro` (0600, root:root on the host).

With `--uts=host` (or compose `uts: host`), the container hostname should match the Docker host. Include NFS service principals for the short hostname and FQDN when they differ, for example:

- `nfs/myhost@REALM`
- `nfs/myhost.example.com@REALM`

The startup TUI and WebUI verify alignment with the two-tier hostname check (`hostname` vs `/proc/sys/kernel/hostname`).

Never commit real keytabs.