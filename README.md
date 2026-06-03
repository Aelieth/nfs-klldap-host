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

One TOML (`nfs-klldap.conf`) drives generation of sssd.conf, krb5.conf, and Ganesha exports. The WebUI (9630) edits it and applies direct chown/chmod on bind mounts inside the container. Use `--uts=host` and a keytab with `nfs/<hostname>@REALM` principals matching the container hostname (short + FQDN when they differ).

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

First run writes a default `nfs-klldap.conf`. Edit it (or use the WebUI at https://host:9630). The watcher + entrypoint handle regeneration and reload.



See [docs/run/README.md](docs/run/README.md) for compose examples and TLS notes.

## Configuration

Minimal `nfs-klldap.conf`:

```toml
ldap_uri = "ldaps://kllap.example.com:6360"

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "strong-secret"

[kerberos]
realm = "EXAMPLE.COM"        # or rely on auto-derivation from ldap_uri host

[[shares]]
name = "data"
host_path = "/media/data"
# security = "krb5p"         # per-share override (krb5p|krb5i|krb5); falls back to [ganesha] default_security
# rw = true                  # default; false for read-only
# export_path = "/data"      # optional; defaults to /<name> if omitted
# # root_squash checkbox in UI sets squash = "root_squash" (default is no_root_squash, key omitted)
# # sync defaults to true (Sync=true in export); key omitted when default
```

The generator derives ports, search bases, sssd.conf, krb5.conf, and Ganesha fragments. `kllldap_ignored_attributes = true` (default) emits recommended server-side ignore lists.

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

## Build & Test

```bash
cargo build --workspace
make docker          # or make docker-multi
cargo test --workspace
make clippy
```

See [TESTING.md](TESTING.md).

## Project Layout (workspace)

- `nfs-klldap-config/` — lib + `nfs-klldap-config` (generate) + `nfs-klldap-startup` (TUI)
- `nfs-klldap-ui/` — Axum WebUI (9630)
- `entrypoint.sh` — thin pid-1 supervisor
- `container/` — healthcheck + ganesha-ctl + conf-watcher (inotify → SIGHUP)

## License

MIT — see LICENSE.
