# Running

All services run as root inside the container. Recommended: `--uts=host`, keytab with NFS service principals matching the host hostname, bind mounts for config + data.

See root README for the docker run example.

## docker-compose

See [examples/docker-compose.yml](../../examples/docker-compose.yml). The example uses `uts: host` + `network_mode: host`. The three volumes (data, config, keytab) are normally sufficient. `cap_add: [SYS_ADMIN, DAC_READ_SEARCH]` is included in the example and strongly recommended for reliable Ganesha VFS + WebUI recursive operations on host bind mounts (see the dedicated section below).

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
| `GANESHA_DEBUG`              | *(unset)* | `TRUE`  | When set exactly to `TRUE`, the generator emits a `LOG { Default_Log_Level = DEBUG; Components { IDMAPPER/FSAL/NFS4 = FULL_DEBUG; } }` block into `ganesha.conf`. For deep Ganesha troubleshooting only. |
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

## Running Ganesha in Docker against the host filesystem (capabilities, dbus, rpcbind, pitfalls)

This project exports real directories from the Docker *host* via Ganesha VFS inside the container. The WebUI also performs direct recursive `chown`/`chmod` on those trees (as root, under an allow-list from `[[shares]].host_path`). The following is the distilled guidance after review of Ganesha container patterns, Fedora packaging, Ganesha core config man pages, and practical bind-mount/UID realities.

### Core contract (unchanged but worth repeating)
- `host_path` values in `nfs-klldap.conf` (and the UI) are **absolute paths on the Docker host** (unchanged by this layout).
- Inside the container the data for a share is visible at the *internal* location derived from `storage.container_root` + (tail of the share's `host_path` after its first directory component). The first dir component of `host_path` acts as the implicit per-share bind root (e.g. host `/media/NVME-RAID/nvme` → internal `/export/NVME-RAID/nvme`). `export_path` (editable in the Shares section; defaults to `/<name>`) is used *only* for the client-visible Pseudo path and can be a short/friendly name independently of the internal layout.
- Translation (host_path → real container path for chown/chmod/readdir) happens only at the syscall boundary (`FsManager` + `privileged.rs`).
- **Numeric UID/GID identity must be identical** on the host and inside the container for the bind-mounted trees. Do **not** use `--userns-remap`, rootless podman user namespaces, or subuid/gid shifts. The on-disk owners written by the WebUI (and seen by NFS clients) are the raw numbers from LLDAP `uidNumber`/`gidNumber`.

### Recommended container flags
```yaml
# (or equivalent docker run flags)
network_mode: host
uts: host
cap_add:
  - SYS_ADMIN
  - DAC_READ_SEARCH
volumes:
  - /media/:/export:rw                # single (or multiple) root-level bind(s) of host parent dir(s). First dir component of each share's host_path is the implicit per-share bind root; the tail is the subpath under /export. export_path only controls the external Pseudo (can be short).
  - ./config:/config:rw
  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
```

- `uts: host` — makes the container see the real hostname so that the keytab principals (`nfs/<short>@REALM` and `nfs/<fqdn>@REALM`) match what clients and Kerberos expect. This has always been the documented recommendation.
- `SYS_ADMIN` — provides the broad capabilities Ganesha VFS containers commonly need for certain namespace, mount, and process-control operations when exporting host paths. Many community Ganesha images (e.g. patterns derived from janeczku/nfs-ganesha and similar) document this cap.
- `DAC_READ_SEARCH` — allows bypassing normal directory traversal permission checks. This is important for:
  - The WebUI's `WalkDir`-based recursive permission scanner (it must be able to descend trees that have mixed ownership and restrictive perms on intermediate directories).
  - Ganesha VFS itself when it walks or stats content under the exported paths on behalf of NFS clients.
  Community reports and provisioner code frequently list this exact pair for "Ganesha or NFS-provisioner on bind-mounted host trees."

`--privileged` works but is overkill and not recommended. The two caps above are the minimal practical set for this workload.

### dbus-daemon and rpcbind (new in the image)
- Ganesha (the packaged build used in this image, whether from Fedora or the Debian backports 9.x channel) expects a D-Bus system bus (typically `/run/dbus/system_bus_socket`). The image installs `dbus` (providing dbus-daemon) and the entrypoint launches `dbus-daemon --system --nofork &` early, before `ganesha.nfsd`.
- `rpcbind` is also installed and started (best-effort). For pure NFSv4 (`Protocols = 4`) it is not strictly required, but:
  - Some tooling, `showmount`, older clients, or status scripts still reference the portmapper.
  - The user request explicitly asked for it "for good measure."
- The supervisor and `ganesha-ctl` management path remain "DBUS-free" (we use export fragments on disk + SIGHUP to pid 1 + pkill/respawn). The bus is present for Ganesha's internal/monitoring use.

In the container you should see the socket and processes:
```
/run/dbus/system_bus_socket
dbus-daemon ...
rpcbind (may daemonize)
ganesha.nfsd ...
```

### NFS_CORE_PARAM and the generated ganesha.conf
The generator emits a minimal, proven-safe block for the Ganesha build in this image (see `write_ganesha_main` in nfs-klldap-config). Only options accepted by the parser in this build are emitted.

```
NFS_CORE_PARAM {
    Protocols = 4;
    Enable_UDP = false;
    Allow_Set_Io_Flusher_Fail = true;
}
```

- `Protocols = 4` restricts to NFSv4 (no NFSv3 negotiation).
- `Enable_UDP = false` disables UDP listeners.
- `Allow_Set_Io_Flusher_Fail = true` is a Linux/container compatibility tunable.
- Other options (Transports, Bind_addr, Mountd_Port/NLM_Port/Rquota_Port, Enable_NLM, Enable_RQUOTA, etc.) are omitted because they are rejected by the parser in the packaged Ganesha build.
- Explicit per-share `%include` lines are emitted for the fragments under `/etc/ganesha/exports.d/` (no glob).

Each generated per-share EXPORT block (in `exports.d/NN-name.conf`) includes a minimal `CLIENT { Clients = *; Access_Type = RW|RO; Principals = "host/*@REALM"; }` block (using the share's `rw` setting and the Kerberos realm). This is the mechanism that applies the access type selected in the WebUI and supports hybrid user TGT + client machine keytab authentication. The generated CLIENT is intentionally minimal (full wildcard). SecType stays at the EXPORT level. Additional CLIENT blocks for specific nets can be added manually if needed (they are overwritten on next regeneration from the TOML source of truth).

### SELinux, volume labeling, and other host notes
- On enforcing SELinux hosts (e.g. Atomic Fedora), bind-mounted data volumes often still need the `:Z` (or `:z`) suffix so that the content is labeled appropriately for container use (`container_file_t` etc.). The image itself no longer includes a Fedora SELinux subpackage (runtime is Debian-based).
- If you see denials related to dbus, rpc, or file labeling, the two caps + relabeling resolve the large majority of cases. Full `--privileged` is a last resort.
- `read_ahead_kb` on the host block devices that back your shares remains a host-side tuning knob (outside the container) for sequential read workloads.

### Common failure modes and fixes
- "No such file or directory" when mounting a VFS export, or Ganesha failing to traverse the tree → missing `SYS_ADMIN`/`DAC_READ_SEARCH` or the bind mount not actually visible at the expected internal Path (container_root + tail of host_path after its first dir component) inside the container. (export_path is only for the Pseudo; check that the first dir of the share's host_path matches the bind source you mounted.)
- WebUI "apply" fails with permission errors on subdirectories → numeric UIDs don't match across the host/container boundary, or the DAC cap is absent.
- Ganesha fails to start with dbus/socket errors → the entrypoint dbus launch didn't produce `/run/dbus/system_bus_socket` in time (rare; the readiness loop helps), or the package was not present in an old image.
- Kerberos principal / hostname mismatches → missing `--uts=host` (or `uts: host` in compose) and/or keytab principals that don't match the name the container sees.
- UDP clients or legacy `showmount` tools complain → we disable UDP by default in CORE_PARAM and ship rpcbind anyway; open the ports you actually need.

### Security model recap (WebUI FS changes)
All owner/group/mode mutations still go exclusively through `FsManager` (allow-list from configured `host_path` entries, WalkDir with `follow_links(false)`, never descend symlinks for mutation, refuse uid/gid 0 and set*id bits). The caps are additive for traversal and Ganesha VFS reliability; they do not relax the allow-list or symlink policy. See `nfs-klldap-ui/src/fs.rs`, `privileged.rs`, and `ui/docs/security.md`.

This combination (bind mounts + root inside + the two caps + `--uts=host` + explicit CORE_PARAM + dbus in the image) is the practical, supportable way to run this Ganesha-based appliance while giving the WebUI safe direct control over the host's exported trees.
