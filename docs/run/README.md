# Running

All services run as root inside the container. Recommended: `--uts=host`, keytab with NFS service principals matching the host hostname, bind mounts for config + data.

See root README for the docker run example.

## docker-compose

See [examples/docker-compose.yml](../../examples/docker-compose.yml). The example uses `uts: host`. The three volumes (data, config, keytab) are normally sufficient. No extra capabilities are required for chown/chmod when running as root.

## Realm & ldap_uri Hardening

- `kerberos.realm` is mandatory after first init (or `NFS_KLLDAP_KERBEROS_REALM` env). No silent EXAMPLE.COM.
- `ldap_uri` host must be a DNS name (literal IPs are rejected at validation).
- Port must be in `ldap_uri` (not only `[sssd] port`, which is derived for reference).
- Forward + reverse DNS are required for Kerberos NFS.

## WebUI (9630)

HTTPS by default (axum-server + rustls, self-signed or via `NFS_KLLDAP_WEBUI_TLS_CERT` / `NFS_KLLDAP_WEBUI_TLS_KEY`).

- Edit `nfs-klldap.conf` (raw or structured form).
- Reload NFS client after changing bind credentials.
- Login: `localhost` (`webui-password` sidecar) or LLDAP members of `webui_admin_group` (default `lldap_admin`).

### TLS mode and reverse proxy support

The WebUI always serves on `NFS_KLLDAP_WEBUI_BIND` (default `0.0.0.0:9630`).

- **Default (TLS enabled)**: internal TLS is terminated by the WebUI. Session cookies are emitted with the `Secure` flag. Self-signed certs are generated into a stable container path unless you provide `NFS_KLLDAP_WEBUI_TLS_CERT` + `NFS_KLLDAP_WEBUI_TLS_KEY`.
- **Reverse proxy mode (`NFS_KLLDAP_WEBUI_TLS=off`)**: disables internal TLS and the cert ensure logic entirely; a plain HTTP server is started (`axum::serve` + `TcpListener`). Use this when a front proxy (Caddy, Nginx, Traefik, ...) terminates TLS and forwards to the container. The proxy **must** set `X-Forwarded-Proto: https` (and preferably `X-Forwarded-Host`) on requests that arrived over HTTPS; the WebUI reads these (via a lightweight middleware layer) so that `AppState::is_https()` returns true and session cookies still get `Secure` (plus `HttpOnly`, `SameSite=Lax`, `Path=/`, 12h Max-Age). Without the header the cookies will be non-Secure (appropriate for a direct HTTP client).

The `NFS_KLLDAP_WEBUI_COOKIE_SECURE=false` override is honored when present (forces non-Secure regardless of TLS/headers).

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
NFS_KLLDAP_WEBUI_TLS=off
# NFS_KLLDAP_WEBUI_BIND=0.0.0.0:9630   # (optional, default is fine)
```

Or set in `nfs-klldap.conf` (single source of truth; env still wins at runtime):

```
[webui]
tls = false
# tls_cert = "/config/webui.crt"
# tls_key = "/config/webui.key"
```

Start-up logs will clearly state `TLS: disabled (reverse proxy mode)` vs `TLS: enabled (self-signed or custom)`.

## Environment variable overrides (core nfs-klldap.conf options)

Core `nfs-klldap.conf` options (not every advanced `[sssd]` field) plus select runtime options can be supplied or overridden via environment variables at container start (`docker -e` or compose `environment:`). Environment variables always win over file values. This enables secrets injection, 12-factor deploys, and minimal TOML files.

| Variable                                   | Default                          | Example                                      | Description |
|--------------------------------------------|----------------------------------|----------------------------------------------|-------------|
| `NFS_CONFIG`                               | `/config/nfs-klldap.conf`        | `/config/nfs-klldap.conf`                    | Path to the central `nfs-klldap.conf` (single source of truth TOML). Override if you mount the config volume to a different container path. |
| `NFS_KLLDAP_LDAP_URI`                      | *(required)*                     | `ldaps://kllap.example.com:6360`             | LDAP(S) server URI. **Must** include port and use a resolvable DNS hostname (IPs are rejected for Kerberos reasons). |
| `NFS_KLLDAP_SSSD_LDAP_DEFAULT_BIND_DN`     | *(required)*                     | `uid=admin,ou=people,dc=example,dc=com`      | Full bind DN (or identity) used by SSSD for LDAP lookups. |
| `NFS_KLLDAP_SSSD_LDAP_DEFAULT_AUTHTOK`     | *(required)*                     | `strong-secret`                              | Bind password / authentication token for the above DN. |
| `NFS_KLLDAP_LLDAP_USER`                    | *(compat alias)*                 | `uid=admin,ou=people,dc=example,dc=com`      | Alias that also sets the bind DN. Honored by the WebUI for live directory queries (in addition to generate/TUI). |
| `NFS_KLLDAP_LLDAP_PW`                      | *(compat alias)*                 | `strong-secret`                              | Alias that also sets the bind password. |
| `NFS_KLLDAP_KERBEROS_REALM`                | *(derived from `ldap_uri` host)* | `EXAMPLE.COM`                                | Kerberos realm. Overrides automatic derivation from the LDAP URI hostname. |
| `NFS_KLLDAP_SERVER_HOSTNAME`               | *(container hostname)*           | `myhost.example.com`                         | Optional override for the hostname used when matching keytab `nfs/<host>` principals. Strongly prefer `docker run --uts=host`. |
| `NFS_KLLDAP_STORAGE_CONTAINER_ROOT`        | `/export`                        | `/export`                                    | Container mount point for exported data. Must match the target of your `-v /host/data:/export` (or compose equivalent). |
| `NFS_KLLDAP_GANESHA_DEFAULT_SECURITY`      | `krb5p`                          | `krb5p`                                      | Default Ganesha security type for exports: `krb5p` (recommended), `krb5i`, or `krb5`. Can be overridden per `[[shares]]`. |
| `NFS_KLLDAP_MANAGEMENT_WEBUI_ADMIN_GROUP`  | `lldap_admin`                    | `lldap_admin`                                | Name of the LLDAP group whose members are granted WebUI admin rights (alongside the localhost `webui-password` sidecar). |
| `NFS_KLLDAP_SSSD_KLLLDAP_IGNORED_ATTRIBUTES` | `true`                         | `true`                                       | Boolean (accepts `true`/`1`/`yes`/`on`). When enabled (default), the generator emits KLLDAP-specific `ignored_*_attributes` blocks into `sssd.conf`. |
| `NFS_KLLDAP_SSSD_LDAP_TLS_REQCERT`         | *(none / derived)*               | `never`                                      | Value for SSSD `ldap_tls_reqcert` (commonly `never` when using self-signed/internal CAs). |
| `NFS_KLLDAP_SSSD_LDAP_TLS_CACERT`          | *(none)*                         | `/config/ca.pem`                             | Absolute path inside the container to a CA certificate file for verifying the LDAP server. |
| `NFS_KLLDAP_SSSD_LDAP_ID_USE_START_TLS`    | `false`                          | `true`                                       | Boolean. When true, emits `ldap_id_use_start_tls = true` (only valid with plain `ldap://` URIs, not `ldaps://`). |
| `NFS_KLLDAP_WEBUI_TLS`                     | *(TLS enabled)*                  | `off`                                        | Set to `off` / `false` / `0` / `no` (case-insensitive) to disable the WebUI's internal TLS server (plain HTTP for reverse-proxy frontends). |
| `NFS_KLLDAP_WEBUI_TLS_CERT`                | *(self-signed in container)*     | `/config/webui.crt`                          | Custom cert PEM path for the WebUI. Takes precedence over `[webui] tls_cert` in the TOML. |
| `NFS_KLLDAP_WEBUI_TLS_KEY`                 | *(self-signed in container)*     | `/config/webui.key`                          | Custom key PEM path (recommend 0600). Precedence same as cert. |
| `NFS_KLLDAP_WEBUI_BIND`                    | `0.0.0.0:9630`                   | `127.0.0.1:9630`                             | Listen address and port for the WebUI (both TLS and plain-http modes). |

### Additional / operational environment variables

These are less commonly needed:

| Variable                     | Default   | Example | Description |
|------------------------------|-----------|---------|-------------|
| `LOG_FORMAT`                 | `text`    | `json`  | Container stdout log format: `text` (default) or `json`. |
| `SSSD_DEBUG_LEVEL`           | *(unset)* | `4`     | When set, passed as `-d $SSSD_DEBUG_LEVEL` to the `sssd` daemon for increased verbosity. |
| `WATCHER_DEBOUNCE_SECONDS`   | `2`       | `1`     | Seconds to sleep after detecting a config file change (via inotify) before signaling the supervisor for reload. |

A small number of path/binary overrides (`SSSD_CONF`, `GANESHA_CONF`, `CONFIG_BIN`, `HEALTHCHECK`, etc.) and `NFS_KLLDAP_CONF` exist primarily for testing, CI, and image development. Typical users set `NFS_CONFIG` (which also drives `NFS_KLLDAP_CONF` for the WebUI) instead.

After load/validate, `NfsKlldapConfig` reflects the effective (env-applied) values for generate, TUI, and UI.

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
