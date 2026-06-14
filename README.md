# nfs-klldap-host

Companion app for [KLLDAP](https://github.com/Aelieth/lldap-with-kerberos), this docker container helps to host and manage NFS shares with POSIX attributes sync'ed with real name resolution to users and groups across the LDAP protocol for simple management and visualization. Lightweight, flexible, and agile enough to host multiple shares, be deployable across a small network, and allow easy remote management via secure connections with KLLDAP.

Debian 13-slim runtime (Rust build stages remain on Fedora minimal) providing a complete Kerberized NFSv4 server (NFS-Ganesha) with KLLDAP-backed POSIX UID/GID mapping via SSSD. The multi-stage build keeps the three Rust compilation stages on Fedora for reliable cargo-chef + cross-compilation while the final runtime uses Debian 13-slim (with Ganesha from backports for configuration compatibility) for smaller size and packaging stability.

<img
  src="https://raw.githubusercontent.com/Aelieth/nfs-klldap-host/refs/heads/main/screenshot.png"
  alt="Screenshot of the nfs shares"
  width="50%"
/>

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
  --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH \
  -p 2049:2049/tcp -p 2049:2049/udp \
  -p 9630:9630/tcp \
  -v /path/to/config:/config \
  -v /media/:/export \
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
container_root = "/export"                                      # Anchor for Ganesha paths + UI container translation.
# No explicit host_root key. The first directory component of each share's host_path
# (e.g. "media" from "/media/NVME-RAID/nvme") is the implicit per-share bind root.
# The remainder of the host_path becomes the subpath under container_root.
# This lets the editable "Export Path" (in [[shares]] or the Shares editor) be used
# purely for the external/client Pseudo name while the internal stays correct.

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
default_security = "krb5p"                                      # security, krb5p (default) | krb5i | krb5

[webui]
# webui_tls = false                                             # commented (tls on by default). Set tls=false (or NFS_KLLDAP_WEBUI_TLS=off env) for reverse proxy.
# tls_cert = "/config/webui.crt"
# tls_key = "/config/webui.key"

# [[shares]]                                                    # shares section sample, shares can be added / edited via system settings
# name = "movies"
# host_path = "/home/user/nfs-data/movies"
# export_path = "/movies"                                       # optional; the *external* client Pseudo (short/friendly name OK). The internal container dir (Ganesha Path + permission tree) is auto-derived from host_path (its first dir component is the implicit bind root) + container_root. Derives to /<name> when absent.
# security = "krb5p"                                            # optional per-share override (krb5p|krb5i|krb5); default from [ganesha]
# rw = true                                                     # default RW; set false for RO
```

## [[shares]] sections are optional for first-run.

The generator derives ports, search bases, sssd.conf, krb5.conf, and Ganesha fragments. `kllldap_ignored_attributes = true` (default) emits recommended server-side ignore lists.

Per-share Ganesha options (in [[shares]]) include `cache_profile` (see below) and the advanced/raw `pref_read` / `pref_write` (bytes). The recommended way is the **Cache Profile** dropdown in the WebUI (stored as e.g. `cache_profile = "Read - Heavy"` under the share). The generator always resolves the profile (or falls back to explicit pref_* for power users) when (re)writing Ganesha EXPORT fragments. See the table below and the WebUI shares editor. Raw TOML always supports any valid Ganesha EXPORT key as fallback.

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

Environment variables are available to those that prefer them, but not necessary to run nfs-klldap-host (walk through the TUI or use a pre-configured nfs-klldap.conf). 

Not every advanced `[sssd]` option is exposed via env. The core options (LDAP URI + binds, realm, hostname, storage root, Ganesha default security, WebUI admin group, KLLDAP ignored attributes, SSSD TLS fields, and `[webui]`) can be supplied or overridden using `NFS_KLLDAP_*` variables (only prefixed forms are available). Environment variables always win and allow omitting the corresponding keys from `nfs-klldap.conf` in many cases.

Example in compose:

```
environment:
  NFS_KLLDAP_LDAP_URI: ldaps://kllap.example.com:6360
  NFS_KLLDAP_SSSD_LDAP_DEFAULT_BIND_DN: uid=admin,ou=people,dc=example,dc=com
  NFS_KLLDAP_SSSD_LDAP_DEFAULT_AUTHTOK: "..."
  NFS_KLLDAP_KERBEROS_REALM: EXAMPLE.COM
  NFS_KLLDAP_WEBUI_TLS: "off"
```

See [docs/run/README.md](docs/run/README.md) for environment variables and reverse-proxy setup, `NFS_KLLDAP_WEBUI_TLS=off` behavior, and compose examples.

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


## Project Layout (workspace)

- `nfs-klldap-config/` — lib + `nfs-klldap-config` (generate) + `nfs-klldap-startup` (TUI)
- `nfs-klldap-ui/` — Axum WebUI (9630)
- `entrypoint.sh` — thin pid-1 supervisor
- `container/` — healthcheck + ganesha-ctl + conf-watcher (inotify → SIGHUP)

The container image uses a split-stage strategy (build on Fedora minimal for the Rust binaries; runtime on Debian 13-slim) — see the Dockerfile for the exact comment and package choices.

## License

MIT — see LICENSE.
