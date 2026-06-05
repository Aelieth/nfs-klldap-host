# nfs-klldap-host

AlmaLinux 10 container providing a complete Kerberized NFSv4 server (NFS-Ganesha) with KLLDAP-backed POSIX UID/GID mapping via SSSD.

Designed for hosts without (or that prefer not to use) kernel NFS modules.

## Architecture

```
nfs-klldap.conf (TOML, edited by WebUI or hand)
        │
        ▼
nfs-klldap-config (validate + derive + generate)
        │
        ├── /etc/sssd/sssd.conf   (root:root 0600)
        ├── /etc/krb5.conf
        └── /etc/ganesha/exports.d/*.conf
        │
        ▼ (inotify / SIGHUP)
entrypoint (pid 1) → restart/reload daemons
        │
        └── nfs-klldap-ui (9630, HTTPS, root) ──direct──> chown/chmod on bind-mounted host_path trees
```

One TOML (`nfs-klldap.conf`) drives generation of sssd.conf, krb5.conf, and Ganesha exports. The WebUI (9630) edits it and applies direct chown/chmod on bind mounts inside the container. Use `--uts=host` and a keytab with `nfs/<hostname>@REALM` principals matching the container hostname (short + FQDN strongly suggested).

## Quick Start

```bash
docker run -d \
  --name nfs-klldap \
  --uts=host \
  -p 2049:2049/tcp -p 2049:2049/udp \
  -p 9630:9630/tcp \
  -v /path/to/config:/config \
  -v /media/data:/export \
  -v /secure/krb5.keytab:/etc/krb5.keytab:ro \
  ghcr.io/aelieth/nfs-klldap-host:latest
```

First run writes a default `nfs-klldap.conf`. 
A console guided TUI will do basic diagnostics via a loop and look for 3 key, important working options in the nfs-klldap.conf
1. Mount point for config to persist
2. ldap_uri
3. sssd - ldap_default_bind_dn and ldap_default_authtok

Edit nfs-klldap.conf in container or via mounted directory. The watcher + entrypoint handle regeneration and reload.


See [docs/run/README.md](docs/run/README.md) for compose examples and TLS notes.

## Configuration

Sample generated `nfs-klldap.conf`:

```toml
ldap_uri = "ldaps://kllap.example.com:6360"                     # LLDAP default secure port. 3890 for LLDAP unencrypted

[storage]
container_root = "/export"                                      # Where your Ganesha NFS shares mount at. Match docker -v ...:/export

[management]
# webui_admin_group = "lldap_admin"                             # Default - Edit to change group for WebUI admins

[server]
# hostname = "myhost.example.com"                               # Default - Optional override for keytab only. Recommended: docker run --uts=host

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "strong-secret"
# ldap_user_search_base = "ou=people,dc=example,dc=com"         # Default - Edit this if your base user OU differs
# ldap_group_search_base = "ou=groups,dc=example,dc=com"        # Default - Edit this if your base user OU differs 
kllldap_ignored_attributes = true                               # KLLDAP specific - improves lookup time, prevents attribute spam

[kerberos]
# realm = "EXAMPLE.COM"                                         # Default - auto-derived from ldap_uri host, edit to override

[ganesha]
default_security = "krb5p"                                      # securtiy, krb5p (default) | krb5i | krb5

[webui]
# WEBUI_TLS = false                                             # commented (tls on by default). Set tls=false (or WEBUI_TLS=off env) for reverse proxy.
# tls_cert = "/config/webui.crt"
# tls_key = "/config/webui.key"

# [[shares]]                                                    # shares section sample, shares can be added / edited via system settings
# name = "movies"
# host_path = "/home/user/nfs-data/movies"
# export_path = "/movies"                                       # optional; if absent, generator derives "/" + name
# security = "krb5p"                                            # optional per-share override (krb5p|krb5i|krb5); default from [ganesha]
# rw = true                                                     # default RW; set false for RO
```

# [[shares]] sections are optional for first-run (add via WebUI System Settings or edit here; use "Restart and apply" or let the watcher trigger a service bounce to activate).

The generator derives ports, search bases, sssd.conf, krb5.conf, and Ganesha fragments. `kllldap_ignored_attributes = true` (default) emits recommended server-side ignore lists.

Per-share Ganesha options (in [[shares]]) include `sync`, `cache_profile` (see below), and the advanced/raw `pref_read` / `pref_write` (bytes). The recommended way is the **Cache Profile** dropdown in the WebUI (stored as e.g. `cache_profile = "Read - Heavy"` under the share). The generator always resolves the profile (or falls back to explicit pref_* for power users) when (re)writing Ganesha EXPORT fragments. See the table below and the WebUI shares editor. Raw TOML always supports any valid Ganesha EXPORT key as fallback.

### Cache Profiles (Shares tuning)
In **System Settings → Shares** the former "PrefRd" numeric input is now a **Cache Profile** dropdown with five curated options. The chosen profile name is written into the `[[shares]]` table (e.g. `cache_profile = "Read - Heavy"`) and becomes the source of truth for that share.

On every `generate` (container start, config watcher, "Restart and apply", or explicit HUP) the following are *rewritten* from the profiles in `nfs-klldap.conf`:
- Ganesha `EXPORT` blocks (`PrefRead` + `PrefWrite` values for the share's export).
- Ganesha I/O sizing via the Cache Profile dropdown (see below).

| Tuning Profile | Ganesha pref_read | Ganesha pref_write | Best For |
|----------------|-------------------|--------------------|----------|
| Default        | 1 MiB (1048576)   | 1 MiB (1048576)    | General purpose, maximum compatibility, set-and-forget |
| Read - Basic   | 4 MiB (4194304)   | 4 MiB (4194304)    | Light-to-moderate read workloads, file shares |
| Read - Heavy   | 16 MiB (16777216) | 8 MiB (8388608)    | 4K movies, large ISOs, mostly sequential media |
| Mixed Use      | 4 MiB (4194304)   | 4 MiB (4194304)    | Everyday shares with both reads and writes |
| Write - Heavy  | 2 MiB (2097152)   | 16 MiB (16777216)  | Backups, large uploads, write-intensive workloads |

Legacy `pref_read = N;` (and `pref_write`) values in raw TOML are still honored by the generator when no `cache_profile` key is present on the share (useful for one-off custom sizes). Saving shares via the WebUI structured editor will convert a legacy numeric to the nearest profile name on next load and will write the `cache_profile` key (cleaning the numeric on save).

Note: to optimize performance for sequential workloads, set read_ahead_kb on the host block devices backing the shares (outside the container).

## Environment Variables

Environment variables are availble to those that prefer them, but not necessary to run nfs-klldap-host as walking through the TUI or a pre-configured nfs-klldap.conf maybe used. 

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
| `NFS_REALM`                                | *(legacy alias)*                 | `EXAMPLE.COM`                                | Legacy alias for realm (still supported). |
| `REALM`                                    | *(legacy)*                       | `EXAMPLE.COM`                                | Older legacy alias for realm. |
| `NFS_KLLDAP_SERVER_HOSTNAME`               | *(container hostname)*           | `myhost.example.com`                         | Optional override for the hostname used when matching keytab `nfs/<host>` principals. Strongly prefer `docker run --uts=host`. |
| `NFS_KLLDAP_STORAGE_CONTAINER_ROOT`        | `/export`                        | `/export`                                    | Container mount point for exported data. Must match the target of your `-v /host/data:/export` (or compose equivalent). |
| `NFS_KLLDAP_GANESHA_DEFAULT_SECURITY`      | `krb5p`                          | `krb5p`                                      | Default Ganesha security type for exports: `krb5p` (recommended), `krb5i`, or `krb5`. Can be overridden per `[[shares]]`. |
| `NFS_KLLDAP_MANAGEMENT_WEBUI_ADMIN_GROUP`  | `lldap_admin`                    | `lldap_admin`                                | Name of the LLDAP group whose members are granted WebUI admin rights (alongside the localhost `webui-password` sidecar). |
| `NFS_KLLDAP_SSSD_KLLLDAP_IGNORED_ATTRIBUTES` | `true`                         | `true`                                       | Boolean (accepts `true`/`1`/`yes`/`on`). When enabled (default), the generator emits KLLDAP-specific `ignored_*_attributes` blocks into `sssd.conf`. |
| `NFS_KLLDAP_SSSD_LDAP_TLS_REQCERT`         | *(none / derived)*               | `never`                                      | Value for SSSD `ldap_tls_reqcert` (commonly `never` when using self-signed/internal CAs). |
| `NFS_KLLDAP_SSSD_LDAP_TLS_CACERT`          | *(none)*                         | `/config/ca.pem`                             | Absolute path inside the container to a CA certificate file for verifying the LDAP server. |
| `NFS_KLLDAP_SSSD_LDAP_ID_USE_START_TLS`    | `false`                          | `true`                                       | Boolean. When true, emits `ldap_id_use_start_tls = true` (only valid with plain `ldap://` URIs, not `ldaps://`). |
| `WEBUI_TLS`                                | *(TLS enabled)*                  | `off`                                        | Set to `off` / `false` / `0` / `no` (case-insensitive) to disable the WebUI's internal TLS server (plain HTTP for reverse-proxy frontends). |
| `WEBUI_TLS_CERT`                           | *(self-signed in container)*     | `/config/webui.crt`                          | Custom cert PEM path for the WebUI. Takes precedence over `[webui] tls_cert` in the TOML. |
| `WEBUI_TLS_KEY`                            | *(self-signed in container)*     | `/config/webui.key`                          | Custom key PEM path (recommend 0600). Precedence same as cert. |
| `NFS_KLLDAP_WEBUI_TLS` / `_CERT` / `_KEY`  | *(prefixed aliases)*             | `off`                                        | `NFS_KLLDAP_WEBUI_*` variants of the three `WEBUI_TLS*` variables (consistent naming with the rest of the `NFS_KLLDAP_*` set). |
| `WEBUI_BIND`                               | `0.0.0.0:9630`                   | `127.0.0.1:9630`                             | Listen address and port for the WebUI (both TLS and plain-http modes). |

### Additional / operational environment variables

These are less commonly needed:

| Variable                     | Default   | Example | Description |
|------------------------------|-----------|---------|-------------|
| `LOG_FORMAT`                 | `text`    | `json`  | Container stdout log format: `text` (default) or `json`. |
| `SSSD_DEBUG_LEVEL`           | *(unset)* | `4`     | When set, passed as `-d $SSSD_DEBUG_LEVEL` to the `sssd` daemon for increased verbosity. |
| `WATCHER_DEBOUNCE_SECONDS`   | `2`       | `1`     | Seconds to sleep after detecting a config file change (via inotify) before signaling the supervisor for reload. |

A small number of path/binary overrides (`SSSD_CONF`, `GANESHA_CONF`, `CONFIG_BIN`, `HEALTHCHECK`, etc.) and `NFS_KLLDAP_CONF` exist primarily for testing, CI, and image development. Typical users set `NFS_CONFIG` (which also drives `NFS_KLLDAP_CONF` for the WebUI) instead.

See [docs/run/README.md](docs/run/README.md) for reverse-proxy setup, `WEBUI_TLS=off` behavior, and compose examples.

## WebUI (9630)

- `/` — Live FS tree browser (under shares) + KLLDAP user/group search + direct recursive chown/chmod.
- `/settings` — Raw + structured TOML editor + current LLDAP bind identity + "Reload NFS client" + "Clear identity cache" (10 min user/group + 2 min search cache; stats shown).

Auth: "localhost" (sidecar `webui-password` file next to config, SHA-256 hash) or any LLDAP user in `webui_admin_group` (default `lldap_admin`).

### Security Contracts for Directory Permission Changes

All owner/group/mode changes performed by the WebUI go through `FsManager` + `privileged` (inside the container as root) on bind-mounted `host_path` trees.

- **Symlink policy**: The recursive engine (WalkDir) **never recurses into symlinks** (`follow_links(false)` + `filter_entry`). `chown`/`chmod` calls follow symlinks for the entries that are mutated (standard std behavior, matching historical `chown(2)`). Symlink inodes themselves are skipped by default. This prevents accidental escape from the declared `host_path` trees (a previous risk with the old `Path::is_dir()` recursion).
- **UID/GID are numeric only on disk**: The engine and WebUI always write raw `u32` values (sourced from LLDAP `uidNumber`/`gidNumber` or direct numeric entry in the editor). Friendly names are resolved only for display.
- **Bind-mount UID namespace assumption**: The container must run as real root with the data directories bind-mounted such that the numeric UIDs written *inside* the container are exactly the IDs visible on the Docker host filesystem. `--userns-remap`, rootless podman user namespaces, or subuid/gid shifts will cause the on-disk owners to be wrong from the host/NFS client perspective.

These contracts are also documented in source comments in `nfs-klldap-ui/src/fs.rs` and `privileged.rs`.

## Prerequisites

- Kerberos time sync.
- `--uts=host` (recommended) so the container sees the real Docker host hostname (`hostname` must match `/proc/sys/kernel/hostname`).
- Keytab (0600) with `nfs/<short-hostname>@REALM` and `nfs/<fqdn>@REALM` when they differ.
- `ldap_uri` host must resolve (DNS, not IP). Forward + reverse DNS required for the NFS principal.
- Bind-mounted data directories on attached/media storage (numeric uid/gid must match KLLDAP posixAccount/posixGroup).

## Verification

Inside container:
```bash
getent passwd alice && id alice && klist -k /etc/krb5.keytab && ganesha-ctl show-exports
```

From client:
```bash
kinit alice && mount -t nfs4 -o sec=krb5p server:/data /mnt && ls -l /mnt
```

## Project Layout (workspace)

- `nfs-klldap-config/` — lib + `nfs-klldap-config` (generate) + `nfs-klldap-startup` (TUI)
- `nfs-klldap-ui/` — Axum WebUI (9630)
- `entrypoint.sh` — thin pid-1 supervisor
- `container/` — healthcheck + ganesha-ctl + conf-watcher (inotify → SIGHUP)

## License

MIT — see LICENSE.
