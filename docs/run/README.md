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

## First-run setup (WebUI wizard)

On a fresh container the supervisor starts the WebUI immediately and polls until setup is complete.

1. **https://\<host\>:9630/setup/1** — verify a persistent `/config` bind mount.
2. **/setup/2** — set `ldap_uri` (DNS name); **Test Settings**, then **Save and Continue**.
3. **/setup/3** — set `[sssd]` bind DN/password; **Test Settings**, then **Save and Continue**.
4. **Restarting page** — same service recycle as System Settings **Restart and apply**; polls `/restart-status` until SSSD/Ganesha/WebUI are ready, then **/login** to create the localhost admin password (`webui-password` sidecar).

**Pre-configured bypass:** mount a valid `nfs-klldap.conf` and `/etc/krb5.keytab` before start — steps 1–3 are skipped; go directly to `/login`.

### Setup wizard troubleshooting

The **Test Log** on each setup page mirrors the old terminal TUI probes. Common failures:

- **DNS failure (step 2):** check hostname spelling and DNS records on the Docker host; try `getent hosts <host>` from the host; container may need `--network=host` or `--dns=...`.
- **Port unreachable (step 2):** confirm port in `ldap_uri` (ldaps usually 636, ldap usually 389); check firewall/SELinux; try `nc -zv <host> <port>` from the Docker host.
- **Bind failed / error 49 (step 3):** verify `ldap_default_bind_dn` and password match LLDAP exactly (no trailing spaces).
- **TLS / contact errors (step 3):** wrong port or self-signed cert — add `ldap_tls_reqcert = "never"` under `[sssd]` for internal LLDAP/KLLDAP certs.

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

`NFS_KLLDAP_WEBUI_BIND` (default `0.0.0.0:9630`) is a runtime-only setting read by `nfs-klldap-ui`; it is not validated by the TOML config crate.

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
| `NFS_KLLDAP_LLDAP_USER`                    | *(compat alias)*                 | `uid=admin,ou=people,dc=example,dc=com`      | Alias that also sets the bind DN. Honored by the WebUI for live directory queries (in addition to generate/setup). |
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
| `HOST_NFS` (or `NFS_KLLDAP_HOST_NFS`) | `false` | `true` | When truthy, runs the container as a management sidecar only. Ganesha fragments are still generated and written to host-visible paths (mount the host's `/etc/ganesha`); the container does not start or manage the NFS server. See the dedicated "HOST_NFS mode" section below for compose, keytab, UI, and ZimaOS notes. |
| `NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS` | `600` | `0` | Seconds between idhelper LDAP→nss_passwd syncs (`0` disables periodic rebulk). |
| `NFS_KLLDAP_WEBUI_COOKIE_SECURE` | *(derived)* | `false` | Force non-Secure session cookies regardless of TLS mode or `X-Forwarded-Proto`. |

A small number of path/binary overrides (`SSSD_CONF`, `GANESHA_CONF`, `CONFIG_BIN`, `HEALTHCHECK`, etc.) and `NFS_KLLDAP_CONF` exist primarily for testing, CI, and image development. Typical users set `NFS_CONFIG` (which also drives `NFS_KLLDAP_CONF` for the WebUI) instead.

After load/validate, `NfsKlldapConfig` reflects the effective (env-applied) values for generate, setup wizard, and UI.

### HOST_NFS mode (host-managed NFS server)

Set `HOST_NFS=true` (or `NFS_KLLDAP_HOST_NFS=true`) to run the container as a **management sidecar**:

- The container still fully owns `nfs-klldap.conf`, the WebUI (9630), share editing, recursive chown/chmod on your `host_path` trees, SSSD (for numeric uid/gid resolution from LLDAP), and generation of `krb5.conf` + Ganesha export fragments.
- It does **not** start or manage `ganesha.nfsd` (or bounce it on HUP).
- Ganesha config fragments are written to the normal container paths (`/etc/ganesha/ganesha.conf` and `/etc/ganesha/exports.d/*.conf`). The operator bind-mounts the *host's* Ganesha config tree so the host daemon picks them up:
  ```yaml
  volumes:
    - /etc/ganesha:/etc/ganesha:rw          # host Ganesha reads our fragments
    - /media/SSD-01:/export:rw
    - ./config:/config:rw
    - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
  environment:
    - HOST_NFS=true
  ```
- Healthcheck, entrypoint logs, and the UI adapt automatically (no 2049 expectation inside the container; restart button becomes "Apply to host NFS").
- The same keytab (with `nfs/<short>@REALM` + `nfs/<fqdn>@REALM`) must be available to the **host** Ganesha process (usual location `/etc/krb5.keytab` on the host). The container mount satisfies the container's krb5 client needs and the UI/startup banners continue to advertise the required principals.
- `--uts=host` + the two caps (`SYS_ADMIN`, `DAC_READ_SEARCH`) + numeric UID identity contract remain exactly as documented for normal operation.
- WebUI share management, permission tree, and raw/structured TOML editing stay fully functional. Only server-daemon controls are muted/grayed with explanatory notes.

This mode is the recommended integration shape for appliance OSes such as ZimaOS (and similar CasaOS-derived or minimal NAS hosts). ZimaOS primarily documents kernel NFS via direct `/etc/exports` edits, but many deployments (or custom images) run Ganesha on the host and consume standard `/etc/ganesha/exports.d` fragments. The sidecar writes the exact fragments the host Ganesha expects while the container continues to provide the friendly WebUI + identity + permission layer.

In the UI you will see a prominent banner on System Settings and adjusted language on the share list page and restart flow. The on-disk `nfs-klldap.conf` may also declare the mode persistently:

```toml
[host]
host_nfs = true
```

Env always wins (you can force normal mode with `HOST_NFS=false` even if the file says true).

Example healthcheck behavior in this mode: only SSSD NSS pipe + WebUI 9630 are asserted; ganesha process + 2049 listener checks are skipped.

## Keytab

Mount a 0600 root-owned keytab at `/etc/krb5.keytab:ro` (`:Z` on SELinux). No host-side permission scripts are required for the root-in-container model.

With `--uts=host`, the container hostname should match the Docker host. Create principals for the short name and FQDN when they differ:

```bash
# On the KDC (example host aurora.example.com, realm EXAMPLE.COM):
addprinc -randkey nfs/aurora@EXAMPLE.COM
addprinc -randkey nfs/aurora.example.com@EXAMPLE.COM
ktadd -k /tmp/keytab nfs/aurora@EXAMPLE.COM nfs/aurora.example.com@EXAMPLE.COM
```

The WebUI setup wizard and System Settings page compare `hostname` with `/proc/sys/kernel/hostname` and check the mounted keytab.

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

- `network_mode: host` / `--network=host` — **required for production NFS + Kerberos.** Default Docker bridge networking assigns the container a `172.17.0.0/16` address; Ganesha stores this as `server_addr` in NFSv4 CLIENT records, which breaks client reconnects and complicates identity when clients mount from external hosts. Port mapping (`-p 2049:2049`) does **not** substitute for host networking.
- `uts: host` — makes the container see the real hostname so that the keytab principals (`nfs/<short>@REALM` and `nfs/<fqdn>@REALM`) match what clients and Kerberos expect. This has always been the documented recommendation.
- `SYS_ADMIN` — provides the broad capabilities Ganesha VFS containers commonly need for certain namespace, mount, and process-control operations when exporting host paths. Many community Ganesha images (e.g. patterns derived from janeczku/nfs-ganesha and similar) document this cap.
- `DAC_READ_SEARCH` — allows bypassing normal directory traversal permission checks. This is important for:
  - The WebUI's `WalkDir`-based recursive permission scanner (it must be able to descend trees that have mixed ownership and restrictive perms on intermediate directories).
  - Ganesha VFS itself when it walks or stats content under the exported paths on behalf of NFS clients.
  Community reports and provisioner code frequently list this exact pair for "Ganesha or NFS-provisioner on bind-mounted host trees."

`--privileged` works but is overkill and not recommended. The two caps above are the minimal practical set for this workload.

### dbus-daemon and rpcbind
- Ganesha 9.6 (Debian trixie-backports) expects a D-Bus system bus (`/run/dbus/system_bus_socket`). The entrypoint launches `dbus-daemon --system --nofork &` before `ganesha.nfsd`.
- `rpcbind` is installed and started (best-effort). For pure NFSv4 (`Protocols = 4`) it is not strictly required; some tooling and status scripts still reference the portmapper.
- The supervisor and `ganesha-ctl` management path remain "DBUS-free" (export fragments on disk + SIGHUP to pid 1 for full recycle). The bus is present for Ganesha's internal/monitoring use.

In the container you should see the socket and processes:
```
/run/dbus/system_bus_socket
dbus-daemon ...
rpcbind (may daemonize)
ganesha.nfsd ...
```

### Generated ganesha.conf and exports

The generator writes a minimal `ganesha.conf` plus one fragment per share under `/etc/ganesha/exports.d/`.

Example top-level configuration emitted (exact form for ganesha 9.6 on Debian trixie / trixie-backports; only these options are used to avoid parser crashes):

```
NFS_CORE_PARAM {
    Protocols = 4;
    Bind_addr = 0.0.0.0;
    NFS_Port = 2049;
    Enable_UDP = false;
    Enable_RQUOTA = false;
    Enable_NLM = false;
    Allow_Set_Io_Flusher_Fail = true;
}

DIRECTORY_SERVICES {
    DomainName = EXAMPLE.COM;
    Pwnam_Implementation = nsswitch;
    Root_Kerberos_Principal = host, nfs;
    idmapped_user_time_validity = 600;
    idmapped_group_time_validity = 600;
}

NFS_KRB5 {
    PrincipalName = "nfs";
    KeytabPath = "/etc/krb5.keytab";
    Active_krb5 = TRUE;
}

NFSV4 {
    Allow_Numeric_Owners = false;
    RecoveryBackend = fs;
    Lease_Lifetime = 20;
    Grace_Period = 20;
}

EXPORT_DEFAULTS {
    SecType = krb5p;
    Protocols = 4;
}

LOG {
    Default_Log_Level = INFO;
    Components {
        CLIENTID = EVENT;
        SESSIONS = EVENT;
        IDMAPPER = EVENT;
        XPRT = EVENT;
    }
}
```

Key points:
- `Protocols = 4` (also in EXPORT_DEFAULTS and per-share CLIENT blocks) for strict NFSv4.
- `Enable_UDP = false` (NFSv4-only; verified on trixie-backports Ganesha 9.6).
- `idmapped_user_time_validity` / `idmapped_group_time_validity` in `DIRECTORY_SERVICES` (not deprecated `Manage_Gids_Expiration` in `NFS_CORE_PARAM`).
- `DomainName` is uppercase `effective_realm()` (matches `/etc/idmapd.conf` Domain).
- Kerberos configuration via NFS_KRB5 and a minimal Root_Kerberos_Principal (host, nfs).
- Explicit `%include` lines (one per share fragment) for deterministic loading.
- `Read_Access_Check_Policy` omitted everywhere (trixie Ganesha 9.6 rejects it; built-in default `pre` applies).
- Only the options above + safe NFSV4/EXPORT_DEFAULTS are emitted. Idmap* keys are deliberately not present in ganesha.conf (use the idhelper + shim + /etc/idmapd.conf + nss materialization instead; see man nfsidmap / idmapd.conf). Other legacy options are omitted because they are not accepted by the ganesha 9.6 parser on trixie-backports.

Each per-share fragment contains an EXPORT with Path (internal), Pseudo (client-visible), SecType, Squash, optional PrefRead/PrefWrite, a CLIENT block for access control, and the VFS FSAL. Additional CLIENT blocks can be appended manually (they will be lost on regeneration).

See also the reference shape in `examples/ganesha-exports.d/10-example.conf`.

### SELinux, volume labeling, and other host notes
- On enforcing SELinux hosts (e.g. Atomic Fedora), bind-mounted data volumes often still need the `:Z` (or `:z`) suffix so that the content is labeled appropriately for container use (`container_file_t` etc.). The image itself no longer includes a Fedora SELinux subpackage (runtime is Debian-based).
- If you see denials related to dbus, rpc, or file labeling, the two caps + relabeling resolve the large majority of cases. Full `--privileged` is a last resort.
- `read_ahead_kb` on the host block devices that back your shares remains a host-side tuning knob (outside the container) for sequential read workloads.

### Common failure modes and fixes
- "No such file or directory" when mounting a VFS export, or Ganesha failing to traverse the tree → missing `SYS_ADMIN`/`DAC_READ_SEARCH` or the bind mount not actually visible at the expected internal Path (container_root + tail of host_path after its first dir component) inside the container. (export_path is only for the Pseudo; check that the first dir of the share's host_path matches the bind source you mounted.)
- WebUI "apply" fails with permission errors on subdirectories → numeric UIDs don't match across the host/container boundary, or the DAC cap is absent.
- Ganesha fails to start with dbus/socket errors → the entrypoint dbus launch didn't produce `/run/dbus/system_bus_socket` in time (rare; the readiness loop helps), or the package was not present in an old image.
- Kerberos principal / hostname mismatches → missing `--uts=host` (or `uts: host` in compose) and/or keytab principals that don't match the name the container sees.
- Ganesha CLIENT records show `server_addr = 172.17.x.x` while clients connect from external addresses → container is on Docker bridge networking instead of host mode. Restart with `network_mode: host` / `--network=host`. `verify-ganesha.sh` and `nfs-klldap-startup check` warn when the container primary IPv4 is in `172.17.0.0/16`.
- UDP clients or legacy `showmount` tools complain → `Enable_UDP = false` in `NFS_CORE_PARAM` (NFSv4 TCP only); rpcbind is still present for compatibility; open the ports you actually need.
- Mounts repeatedly fail / get torn down with Fedora Immutable clients (host keytab + user TGT) → the `nfs-klldap-idhelper` daemon must be running (started automatically after SSSD). Ganesha uses nss_wrapper preload by default (`USE_NSS_WRAPPER=1`); set `USE_NSS_WRAPPER=0` to rely on extrausers alone. Use `ganesha-ctl id-check`, `ganesha-ctl id-resolve '<principal>'`, and inspect `/var/lib/nfs-klldap/nss_passwd` to verify. See [docs/ldap-integration.md](../ldap-integration.md).

### Security model recap (WebUI FS changes)
All owner/group/mode mutations still go exclusively through `FsManager` (allow-list from configured `host_path` entries, WalkDir with `follow_links(false)`, never descend symlinks for mutation, refuse uid/gid 0 and set*id bits). The caps are additive for traversal and Ganesha VFS reliability; they do not relax the allow-list or symlink policy. See `nfs-klldap-ui/src/fs.rs`, `privileged.rs`, and [nfs-klldap-ui/docs/security.md](../../nfs-klldap-ui/docs/security.md).

This combination (bind mounts + root inside + the two caps + `--uts=host` + explicit CORE_PARAM + dbus in the image) is the practical, supportable way to run this Ganesha-based appliance while giving the WebUI safe direct control over the host's exported trees.

### Verification

```bash
/container/healthcheck.sh
verify-ganesha.sh            # in-container Ganesha/export + network checks (/usr/local/bin/)
ganesha-ctl show-fragments
getent passwd <user>
```
