# Kerberos keytab for nfs-klldap-host

Mount at `/etc/krb5.keytab:ro` (0600, root:root on the host).

Run the container with **host networking** (`--network=host` or compose `network_mode: host`) so Ganesha CLIENT records use host-reachable addresses, not Docker bridge `172.17.x.x`. Also use `--uts=host` (or compose `uts: host`) so the container hostname matches the Docker host. Include NFS service principals for the short hostname and FQDN when they differ, for example:

- `nfs/myhost@REALM`
- `nfs/myhost.example.com@REALM`

The WebUI setup wizard and System Settings verify alignment with the two-tier hostname check (`hostname` vs `/proc/sys/kernel/hostname`).

Never commit real keytabs.