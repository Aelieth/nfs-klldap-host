# Running

All services run as root inside the container. Recommended: `--uts=host`, keytab with NFS service principals matching the host hostname, bind mounts for config + data.

See root README for the docker run example.

## docker-compose

See [examples/docker-compose.yml](../../examples/docker-compose.yml). The example uses `uts: host`. The three volumes (data, config, keytab) are normally sufficient. No extra capabilities are required for chown/chmod when running as root.

## Realm & ldap_uri Hardening

- `kerberos.realm` is mandatory after first init (or `NFS_REALM` env). No silent EXAMPLE.COM.
- `ldap_uri` host must be a DNS name (literal IPs are rejected at validation).
- Port must be in `ldap_uri` (not only `[sssd] port`, which is derived for reference).
- Forward + reverse DNS are required for Kerberos NFS.

## WebUI (9630)

HTTPS (axum-server + rustls). Self-signed certs unless `WEBUI_TLS_CERT` / `WEBUI_TLS_KEY` are set.

- Edit `nfs-klldap.conf` (raw or structured form).
- Reload NFS client after changing bind credentials.
- Login: `localhost` (`webui-password` sidecar) or LLDAP members of `webui_admin_group` (default `lldap_admin`).

## Keytab

Mount a 0600 root-owned keytab at `/etc/krb5.keytab:ro` (`:Z` on SELinux). No host-side permission scripts are required for the root-in-container model.

With `--uts=host`, the container hostname should match the Docker host. Create principals for the short name and FQDN when they differ:

```bash
# On the KDC (example host aurora.example.com, realm EXAMPLE.COM):
addprinc -randkey nfs/aurora@EXAMPLE.COM
addprinc -randkey nfs/aurora.example.com@EXAMPLE.COM
ktadd -k /tmp/keytab nfs/aurora@EXAMPLE.COM nfs/aurora.example.com@EXAMPLE.COM
```

The startup TUI and WebUI System Settings page compare `hostname` with `/proc/sys/kernel/hostname` and check the mounted keytab.

## Troubleshooting at Start

Watch `docker logs`. `nfs-klldap-startup` prints step-by-step requirements (persistent `/config`, DNS `ldap_uri`, bind test, shares) and SSSD-oriented hints at step 3.

Force reload from host: `docker kill -s HUP <name>`.

Do not set compose `user:` unless you have a specific reason — pid 1 must manage 0600 files and daemons as root.