# Ganesha Architecture & Bind-Mount Contract

**0.9.x / Ganesha 9.6 (Debian trixie-backports):** id mapping uses `DIRECTORY_SERVICES` (`DomainName`, `Pwnam_Implementation=nsswitch`, `Root_Kerberos_Principal=host, nfs, root`, `idmapped_*_time_validity=600`) plus `nfs-klldap-idhelper` for hybrid machine/user Kerberos principals.

Single TOML (nfs-klldap.conf) is source of truth. nfs-klldap-config validates+derives+generates sssd/krb5/ganesha fragments. nfs-klldap-startup supervise (pid1) + watcher (SIGHUP) + ganesha-ctl handle reloads/bounces. nfs-klldap-ui (9630 HTTPS) edits TOML + direct chown/chmod (root, on allowed host_path trees). Ganesha VFS + SSSD (from LLDAP POSIX) serve NFSv4 krb5. No host kernel NFS.

## Key Contracts

| Contract                  | Rule |
|---------------------------|------|
| `host_path` vs container  | UI + allow-list + ownership use the host-visible absolute path (unchanged). The internal container location (Ganesha Path + FsManager translations) is derived as `storage.container_root` + (tail of share `host_path` after its first directory component). `export_path` (defaults to `/<name>`) controls *only* the client-visible Pseudo path. First dir component of `host_path` acts as the implicit per-share bind root. A single (or multiple) root bind(s) (host parent(s) → /export) is the stable pattern. Translation only at the syscall boundary (`FsManager`). |
| Hostname                  | `get_consistent_hostname()` (hostname(1) == /proc/sys/kernel/hostname). Mismatch → loud diagnostic. `--uts=host` is the normal way to get the real name. |
| Realm                     | Strictly required. No silent EXAMPLE.COM. Auto-derived from ldap_uri host or NFS_KLLDAP_KERBEROS_REALM. |
| ldap_uri                  | DNS hostname only (IP rejected). Forward+reverse DNS required. Keytab: `nfs/<short>@REALM` and `nfs/<fqdn>@REALM` when they differ (`--uts=host`). |
| Execution                 | Everything (Ganesha, SSSD, WebUI, generator) runs as root inside the container. |
| Reload                    | Watcher → SIGHUP to pid 1 → generator + permission fixup + supervisor bounces Ganesha/SSSD/WebUI in place (no full container death). Container ships a system bus for Ganesha; management itself uses fragments + HUP. |

## Volumes (typical)

```yaml
volumes:
  - /media/:/export:rw                # Recommended: single (or multiple) root-level bind(s) of host parent dir(s). First dir of each share's host_path is the implicit bind root; tail becomes subpath under container_root. export_path is only for the client Pseudo (can be short).
  - ./config:/config:rw               # nfs-klldap.conf (single source)
  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
```

See container/healthcheck.sh for service checks. See TESTING.md for test coverage.

## ACL and filesystem compatibility

At validate/generate time nfs-klldap-config probes `/proc/self/mountinfo` for each share's **serve path** (`ganesha_path` when set, otherwise the derived container path from `host_path`). Normal filesystems (ext4, xfs, btrfs with ACL) need no extra configuration. Limited filesystems (btrfs+noacl, vfat/fat, ntfs) automatically get `Disable_ACL = true` and `Manage_Gids = false` in the Ganesha 9.6 EXPORT block plus a single WARN — basic file access works without client error 524.

**Staging pattern:** set `ganesha_path` to an ACL-capable tree (e.g. ext4 under `/export/staging/...`) while keeping `host_path` for WebUI chown and validation. Use `[ganesha] post_generate_hook` (see `examples/post-generate-staging-sync.sh`) to sync data into the staging path after each generate.

| Filesystem | Typical behavior |
|------------|------------------|
| ext4, xfs | Full NFSv4.2 ACL features (default) |
| btrfs + `acl` | Full features |
| btrfs + `noacl` | Auto limited mode |
| vfat/fat, ntfs | Auto limited mode |

Explicit `disable_acl` / `manage_gids` in nfs-klldap.conf override probe defaults.
