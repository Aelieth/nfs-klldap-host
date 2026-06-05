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

HTTPS by default (axum-server + rustls, self-signed or via `WEBUI_TLS_CERT` / `WEBUI_TLS_KEY`).

- Edit `nfs-klldap.conf` (raw or structured form).
- Reload NFS client after changing bind credentials.
- Login: `localhost` (`webui-password` sidecar) or LLDAP members of `webui_admin_group` (default `lldap_admin`).

### TLS mode and reverse proxy support

The WebUI always serves on `WEBUI_BIND` (default `0.0.0.0:9630`).

- **Default (TLS enabled)**: internal TLS is terminated by the WebUI. Session cookies are emitted with the `Secure` flag. Self-signed certs are generated into a stable container path unless you provide `WEBUI_TLS_CERT` + `WEBUI_TLS_KEY`.
- **Reverse proxy mode (`WEBUI_TLS=off`)**: disables internal TLS and the cert ensure logic entirely; a plain HTTP server is started (`axum::serve` + `TcpListener`). Use this when a front proxy (Caddy, Nginx, Traefik, ...) terminates TLS and forwards to the container. The proxy **must** set `X-Forwarded-Proto: https` (and preferably `X-Forwarded-Host`) on requests that arrived over HTTPS; the WebUI reads these (via a lightweight middleware layer) so that `AppState::is_https()` returns true and session cookies still get `Secure` (plus `HttpOnly`, `SameSite=Lax`, `Path=/`, 12h Max-Age). Without the header the cookies will be non-Secure (appropriate for a direct HTTP client).

The legacy `WEBUI_COOKIE_SECURE=false` override is still honored when present (forces non-Secure regardless of TLS/headers) for setups that were already using the workaround.

Login, first-run setup, redirects, logout, and all session validation are identical in both modes. The large in-tree auth flow tests cover the cookie emission paths for both direct-TLS and proxied cases.

#### Recommended proxy snippets

Caddy (headers are set automatically):

```
yourhost.example.com {
    reverse_proxy 127.0.0.1:9630
}
```

Nginx:

```
location / {
    proxy_pass http://127.0.0.1:9630;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    # add other standard proxy headers as needed
}
```

Set the env in your container / compose:

```
WEBUI_TLS=off
# WEBUI_BIND=0.0.0.0:9630   # (optional, default is fine)
```

Start-up logs will clearly state `TLS: disabled (reverse proxy mode)` vs `TLS: enabled (self-signed or custom)`.

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

Watch `docker logs`. `nfs-klldap-startup` prints step-by-step requirements (persistent `/config`, DNS `ldap_uri`, bind test) and SSSD-oriented hints at step 3.

Force reload from host: `docker kill -s HUP <name>`.

Do not set compose `user:` unless you have a specific reason — pid 1 must manage 0600 files and daemons as root.