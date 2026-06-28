# nfs-klldap-host

**Branch 0.9.x** — WebUI setup wizard at `/setup` (HTTPS :9630); first-run configuration is browser-based.

Companion app for [KLLDAP](https://github.com/Aelieth/lldap-with-kerberos), this docker container helps to host and manage NFS shares with POSIX attributes sync'ed with real name resolution to users and groups across the LDAP protocol for simple management and visualization. Lightweight, flexible, and agile enough to host multiple shares, be deployable across a small network, and allow easy remote management via secure connections with KLLDAP.

Debian 13-slim runtime (Rust build stages remain on Fedora minimal) providing a complete Kerberized NFSv4 server (NFS-Ganesha) with KLLDAP-backed POSIX UID/GID mapping via SSSD. The multi-stage build keeps the three Rust compilation stages on Fedora for reliable cargo-chef + cross-compilation while the final runtime uses Debian 13-slim (with Ganesha from backports for configuration compatibility) for smaller size and packaging stability.

<img
  src="https://raw.githubusercontent.com/Aelieth/nfs-klldap-host/refs/heads/main/screenshot.png"
  alt="Screenshot of the nfs shares"
  width="50%"
/>

## Documentation

- [Running & deployment](docs/run/README.md)
- [LDAP / SSSD / Kerberos integration](docs/ldap-integration.md)
- [Ganesha architecture & contracts](docs/ganesha-architecture.md)
- [WebUI security model](nfs-klldap-ui/docs/security.md)
- [Testing](TESTING.md)

## Architecture

```
nfs-klldap.conf (TOML, edited by WebUI or hand)
        │
        ▼
nfs-klldap-config (validate + derive + generate)
        │
        ├── /etc/sssd/sssd.conf   (root:root 0600)
        ├── /etc/krb5.conf
        ├── /etc/idmapd.conf      (Domain + Local-Realms + Method + GSS-Methods derived from nfs-klldap.conf + [sssd])
        ├── /etc/nfs.conf         (rpc.gssd use-machine-creds=0 for krb5p user creds)
        └── /etc/ganesha/exports.d/*.conf
        │
        ▼ (inotify / SIGHUP)
entrypoint → nfs-klldap-startup supervise (pid 1) → restart/reload daemons
        │
        └── nfs-klldap-ui (9630, HTTPS) ──direct──> chown/chmod on bind-mounted host_path trees
```

One TOML (`nfs-klldap.conf`) drives generation of sssd.conf, krb5.conf, /etc/idmapd.conf (standardized NFSv4 Domain + Local-Realms + GSS-Methods for idhelper/shim/clients + Kerberos realm handling), and Ganesha exports. The WebUI (9630) edits it and applies direct chown/chmod on bind mounts inside the container. Use `--uts=host` and a keytab with `nfs/<hostname>@REALM` principals matching the container hostname (short + FQDN strongly suggested).

See [docs/ganesha-architecture.md](docs/ganesha-architecture.md) for the `host_path` / `export_path` / bind-mount contract table.

## Quick Start

**Recommended:** use [examples/docker-compose.yml](examples/docker-compose.yml) with `network_mode: host` and `uts: host` so NFS and Kerberos see the real host identity. Port mapping in a bridged `docker run` can work for lab use but host networking is the supported production pattern.

```bash
docker compose -f examples/docker-compose.yml up -d
```

**Alternative** (`docker run` with host networking — required for NFS + Kerberos):

```bash
docker run -d \
  --name nfs-klldap \
  --network=host \
  --uts=host \
  --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH \
  -v /path/to/config:/config \
  -v /media/:/export \
  -v /secure/krb5.keytab:/etc/krb5.keytab:ro \
  ghcr.io/aelieth/nfs-klldap-host:latest
```

First run writes a default `nfs-klldap.conf` and starts the WebUI immediately. Open **https://<host>:9630/setup** for the 3-step wizard:

1. Persistent `/config` bind mount (writable volume check)
2. `ldap_uri` — **Test Settings**, then **Save and Continue** (DNS/TCP reachability)
3. `[sssd]` bind DN + password — **Test Settings**, then **Save and Continue** (`ldapsearch` bind)

Each step shows a **Test Log** with command output and troubleshooting hints when a probe fails.

After step 3, the same **Restart and apply** flow runs (restarting page polling `/restart-status` until SSSD, Kerberos, and NFS services are up), then redirects to `/login` to set the localhost admin password.

**Pre-configured deploy:** mount a complete `nfs-klldap.conf` plus `/etc/krb5.keytab` at startup — the wizard is skipped and you go straight to `/login` (or the main UI if the password sidecar already exists).

See [docs/run/README.md](docs/run/README.md) for compose examples, env vars, TLS/proxy notes, and troubleshooting.

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
# ldap_user_search_base = "ou=people,dc=example,dc=com"         # Optional - defaults to dc=<realm> (Subtree)
# ldap_group_search_base = "ou=people,dc=example,dc=com"        # Optional - defaults to dc=<realm> (Subtree)
kllldap_ignored_attributes = true                               # KLLDAP specific - improves lookup time, prevents attribute spam

[kerberos]
# realm = "EXAMPLE.COM"                                         # Default - auto-derived from ldap_uri host, edit to override

[ganesha]
default_security = "krb5p"                                      # security, krb5p (default) | krb5i | krb5

[webui]
# tls = false                                                   # commented (tls on by default). Set tls=false (or NFS_KLLDAP_WEBUI_TLS=off env) for reverse proxy.
# tls_cert = "/config/webui.crt"
# tls_key = "/config/webui.key"

# [[shares]]                                                    # shares section sample, shares can be added / edited via system settings
# name = "movies"
# host_path = "/home/user/nfs-data/movies"
# export_path = "/movies"                                       # optional; the *external* client Pseudo (short/friendly name OK). The internal container dir (Ganesha Path + permission tree) is auto-derived from host_path (its first dir component is the implicit bind root) + container_root. Derives to /<name> when absent.
# security = "krb5p"                                            # optional per-share override (krb5p|krb5i|krb5); default from [ganesha]
# rw = true                                                     # default RW; set false for RO
# enable_acl = false                                            # optional; set false (or omit for auto) to emit Disable_ACL = true on limited FS
# manage_gids = true                                            # optional; default true (false auto on limited FS) for krb5* uid2grp
# ganesha_path = "/export/staging/movies"                       # optional; Ganesha EXPORT Path= + probe target (staging)
```

## [[shares]] sections are optional for first-run.

The generator derives ports, search bases, sssd.conf, krb5.conf, /etc/idmapd.conf (following [sssd] + realm), and Ganesha fragments. `kllldap_ignored_attributes = true` (default) emits recommended server-side ignore lists.

Per-share Ganesha options include `cache_profile` (recommended), `enable_acl`, `manage_gids`, `ganesha_path` (staging override), and raw `pref_read` / `pref_write`. The generator probes each share's **serve path** (`ganesha_path` when set, else the derived container path) and auto-applies conservative settings on limited filesystems (btrfs+noacl, vfat, ntfs): `Disable_ACL = true; Manage_Gids = false; Read_Access_Check_Policy = "post";` plus the comment block “posix-only conservative mode for noacl btrfs (ZimaOS)”. Capable volumes use full native behavior. The system adapts automatically. A lightweight check runs after generate/validate/startup to warn if idhelper cannot resolve sample user@ and host/ principals for the exports. Optional `[ganesha] post_generate_hook` (or `NFS_KLLDAP_POST_GENERATE_HOOK`) runs after every generate — see `examples/post-generate-staging-sync.sh`. Use `nfs-klldap-config fs-warnings` or `ganesha-ctl fs-warnings` for limited-FS diagnostics. The WebUI **Cache Profile** dropdown writes e.g. `cache_profile = "Read - Heavy"`; the generator resolves it on every regen. Unrecognized `[[shares]]` keys are ignored and surfaced as warnings.

### Cache Profiles (Shares tuning)

**System Settings → Shares** uses a **Cache Profile** dropdown (five options). The chosen name is the source of truth for that share's `PrefRead`/`PrefWrite` emission.

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

Environment variables are available to those that prefer them, but not necessary to run nfs-klldap-host (use the WebUI setup wizard or a pre-configured nfs-klldap.conf + keytab).

Not every advanced `[sssd]` option is exposed via env. The core options (LDAP URI + binds, realm, hostname, storage root, Ganesha default security, WebUI admin group, KLLDAP ignored attributes, SSSD TLS fields, and `[webui]`) can be supplied or overridden using `NFS_KLLDAP_*` variables (only prefixed forms are available). Environment variables always win and allow omitting the corresponding keys from `nfs-klldap.conf` in many cases.

A new top-level switch `HOST_NFS=true` (or `NFS_KLLDAP_HOST_NFS=true`) runs the container as a management sidecar for a *host* NFS server (Ganesha at `/etc/ganesha`). Shares, Kerberos config, and the WebUI permission tools continue to work normally; the container does not start ganesha.nfsd. See docs/run/README.md for compose volumes, keytab sharing, UI gray-out behavior, and ZimaOS-style appliance notes.

Example in compose:

```
environment:
  NFS_KLLDAP_LDAP_URI: ldaps://kllap.example.com:6360
  NFS_KLLDAP_SSSD_LDAP_DEFAULT_BIND_DN: uid=admin,ou=people,dc=example,dc=com
  NFS_KLLDAP_SSSD_LDAP_DEFAULT_AUTHTOK: "..."
  NFS_KLLDAP_KERBEROS_REALM: EXAMPLE.COM
  NFS_KLLDAP_WEBUI_TLS: "off"
```

See [docs/run/README.md](docs/run/README.md) for the full env var table, reverse-proxy setup, and compose examples.

## WebUI (9630)

- `/setup/1` … `/setup/3` — First-run wizard (volume, ldap_uri, bind creds); each step has a **Test Log** with probe output and fix suggestions; steps 2–3 use **Test Settings** then **Save and Continue**.
- `/login` — localhost password (first run) or LLDAP admin login.
- `/` — Live FS tree browser (under shares) + KLLDAP user/group search + direct recursive chown/chmod.
- `/settings` — Raw + structured TOML editor + current LLDAP bind identity + "Reload NFS client" + "Clear identity cache" (10 min user/group + 2 min search cache; stats shown).

Auth: "localhost" (sidecar `webui-password` file next to config, SHA-256 hash) or any LLDAP user in `webui_admin_group` (default `lldap_admin`).

### Security Contracts for Directory Permission Changes

All owner/group/mode changes performed by the WebUI go through `FsManager` + `privileged` (inside the container as root) on bind-mounted `host_path` trees.

- **Symlink policy**: The recursive engine (WalkDir) **never recurses into symlinks** (`follow_links(false)` + `filter_entry`). `chown`/`chmod` calls follow symlinks for the entries that are mutated (standard std behavior, matching historical `chown(2)`). Symlink inodes themselves are skipped by default. This prevents accidental escape from the declared `host_path` trees (a previous risk with the old `Path::is_dir()` recursion).
- **UID/GID are numeric only on disk**: The engine and WebUI always write raw `u32` values (sourced from LLDAP `uidNumber`/`gidNumber` or direct numeric entry in the editor). Friendly names are resolved only for display.
- **Bind-mount UID namespace assumption**: The container must run as real root with the data directories bind-mounted such that the numeric UIDs written *inside* the container are exactly the IDs visible on the Docker host filesystem. `--userns-remap`, rootless podman user namespaces, or subuid/gid shifts will cause the on-disk owners to be wrong from the host/NFS client perspective.

See [nfs-klldap-ui/docs/security.md](nfs-klldap-ui/docs/security.md) for the full security model.

## Prerequisites

- Kerberos time sync.
- `--uts=host` (recommended) so the container sees the real Docker host hostname (`hostname` must match `/proc/sys/kernel/hostname`).
- Keytab (0600) with `nfs/<short-hostname>@REALM` and `nfs/<fqdn>@REALM` when they differ.
- `ldap_uri` host must resolve (DNS, not IP). Forward + reverse DNS required for the NFS principal.
- Bind-mounted data directories on attached/media storage (numeric uid/gid must match KLLDAP posixAccount/posixGroup).

## Project Layout (workspace)

- `nfs-klldap-identity/` — shared LDAP/Kerberos/NSS primitives (`IdLdapResolver`, POSIX mapping, hostname/keytab helpers)
- `nfs-klldap-config/` — lib (`startup` step machine + probes) + `nfs-klldap-config` (generate) + `nfs-klldap-startup` (supervise/check) + `nfs-klldap-idhelper` (daemon + CLI)
- `nfs-klldap-ui/` — Axum WebUI (9630) including `/setup` wizard
- `entrypoint.sh` — exec wrapper → `nfs-klldap-startup supervise`
- `container/` — healthcheck, conf-watcher, ganesha-ctl helper scripts

## Identity & Kerberos (idhelper)

`nfs-klldap-idhelper` classifies machine (host/nfs/root) vs user principals, resolves uid/gid via getent + LDAP, materializes to nss_wrapper/extrausers. Ganesha 9.x principal2uid uses libnfsidmap + nss_wrapper; nfsidmap shim for fallback.

Inside the container:

```bash
nfs-klldap-idhelper resolve 'alice@REALM' --json
nfs-klldap-idhelper classify 'host/myfedora@REALM'
ganesha-ctl id-resolve 'user@REALM'
ganesha-ctl id-check
```

See [docs/ldap-integration.md](docs/ldap-integration.md) for SSSD/POSIX requirements, TLS behavior, idhelper architecture, and verification commands.

## Kerberos user principal idmap
Supported: full `user@REALM` and `host/hostname@REALM` via idhelper GRPS/resolve (POSIX groups for users; nobody-equivalent 65534 for host principals) + nss/extrausers. Numeric reverse rejected for stable getpwuid. Ganesha uses Only_Numeric + Allow_Numeric. Default krb5p: Manage_Gids=true (limited FS forces false), UseGetpwnam=false so uid2grp_allocate_by_principal + idhelper. Use ganesha-ctl id-resolve.

Ganesha 9.6 omits `Read_Access_Check_Policy` by default (pre). For limited/noacl filesystems the generator emits `Read_Access_Check_Policy = "post";` (plus the posix-only comment). The idhelper now handles full `user@REALM` and `host/hostname@REALM` forms via GRPS for supplemental groups. It syncs LDAP users into `nss_passwd` at startup and every 10 minutes (pruning deletions, refreshing uid/gid). Set `NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS=0` to disable periodic sync; the log observer still resolves new principals between syncs. A post-generate/startup check warns if sample principals cannot be resolved.

The container image uses a split-stage strategy (build on Fedora minimal for the Rust binaries; runtime on Debian 13-slim) — see the Dockerfile for package choices.

## Development & testing

```bash
make test
# or: cargo test --workspace
```

See [TESTING.md](TESTING.md) for coverage map and patterns.

## License

MIT — see LICENSE.
