# Running the Container (Practical)

All services run as root inside the container (standard for sssd/kerberos appliances). The WebUI (9630) and generator also run as root so they can write `sssd.conf` with correct ownership and perform direct chown/chmod on bind mounts.

## Recommended docker run

```bash
docker run -d \
  --name nfs \
  --uts=host \
  -p 2049:2049 -p 2049:2049/udp -p 9630:9630 \
  -v /host/config:/config \
  -v /media/data:/export \
  -v /secure/krb5.keytab:/etc/krb5.keytab:ro \
  ghcr.io/aelieth/nfs-klldap-host:latest
```

**Capabilities note**: The WebUI performs `chown`/`chmod` directly as root on bind-mounted host paths via the `privileged` module (see `nfs-klldap-ui/src/privileged.rs`). Safe std APIs are used; no `--cap-add CHOWN/FOWNER/DAC_*` are required under the documented root model. `NET_BIND_SERVICE` is only relevant if you later drop root privileges.

`--uts=host` lets the container see the real Docker host hostname → TUI prints the exact `nfs/<host>-nfs@REALM` principal you need.

## docker-compose

See [examples/docker-compose.yml](../examples/docker-compose.yml). The example uses `uts: host`. The three volumes (data, config, keytab) are the only ones normally required. Capabilities are not needed for the FFI-based chown/chmod path when running as root.

## Realm & ldap_uri Hardening

- `kerberos.realm` is mandatory after first init (or `NFS_REALM` env). No silent EXAMPLE.COM.
- `ldap_uri` host must be a DNS name (literal IPs are rejected at validation with a clear error).
- Forward + reverse DNS required for the NFS service principal.

## WebUI (9630)

HTTPS (axum-server + rustls). Self-signed certs are generated automatically (rcgen) unless `WEBUI_TLS_CERT`/`WEBUI_TLS_KEY` are supplied.

- Edit `nfs-klldap.conf` (raw or structured form).
- "Reload NFS client" after changing bind credentials.
- Login: "localhost" (sidecar file) or LLDAP members of `webui_admin_group`.

## Keytab

Standard 0600 root-owned keytab at `/etc/krb5.keytab:ro` (with `:Z` on SELinux). No special groups or host-side scripts required.

On the KDC:
```bash
addprinc -randkey nfs/host.example.com@REALM
addprinc -randkey nfs/host-nfs.example.com@REALM   # when using --uts=host
ktadd -k /tmp/keytab ...
```

## Troubleshooting at Start

Watch `docker logs`. The `nfs-klldap-startup` TUI prints step-by-step requirements and rich diagnostics (DNS, bind, reachable paths, keytab, writable runtime dirs).

Force reload from host: `docker kill -s HUP <name>`.

Do not use `--user` (or compose `user:`) unless you have a specific reason — the root pid-1 supervisor is required for 0600 files and daemon management.
