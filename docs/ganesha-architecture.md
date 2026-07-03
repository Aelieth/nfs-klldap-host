# Ganesha Architecture & Bind-Mount Contract

Ganesha 9.6: DIRECTORY_SERVICES + idhelper (proactive+reactive, cache) authoritative for uid0+supp groups in nss/extrausers; UseGetpwnam + nss_wrapper getgrouplist.

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

At validate/generate time nfs-klldap-config probes `/proc/self/mountinfo` for each share's **serve path** (`ganesha_path` when set, otherwise the derived container path from `host_path`). The generator maintains two distinct supported mainline paths:

- ACL-capable (ext4, xfs, btrfs+acl, or explicit `enable_acl=true`): full native NFSv4 ACL behavior.
- NOACL/limited (btrfs+noacl, vfat/fat, ntfs, or explicit `enable_acl=false`): 0.9.40-style simple disk/share settings (`Disable_ACL = true; Manage_Gids = false;` emitted before SecType; no `Read_Access_Check_Policy`, no per-export Enable_NLM/Enable_RQUOTA/POSIX marker). Auto-detect via fstype+noacl mountopt (overrides allowed).

Limited filesystems automatically use the NOACL path — basic file reads and connectivity work for noacl clients (per 0.9.40). Identity resolution (UID/GID/groups via 0.9.65 nss/idhelper/UseGetpwnam) is shared by both paths.

**Ganesha 9.6 ACL-path limitation (not a regression fix):** On direct noacl, some OP_ACCESS/GETATTR may still surface NFS4ERR_NOTSUPP under ACL masks in ganesha.log for certain clients. Use `ganesha_path` staging + post-generate hook to an ACL-capable tree when full-feature `ls` / extended ACLs are required on the share. Staging remains supported.

Preflight identity uses `ganesha_identity_pipeline` (tempdir materialize + nss contract) plus runtime nss materialize, socket GRPS, `ganesha-ctl id-resolve`, and ganesha.log uid2grp tags — the same nss_wrapper getent path Ganesha uses at request time per `idmap_log_contract`.

**Staging pattern:** set `ganesha_path` to an ACL-capable tree (e.g. ext4 under `/export/staging/...`) while keeping `host_path` for WebUI chown and validation. Use `[ganesha] post_generate_hook` (see `examples/post-generate-staging-sync.sh`) to sync data into the staging path after each generate.

| Filesystem | Typical behavior |
|------------|------------------|
| ext4, xfs | Full NFSv4.2 ACL features (default; ACL path) |
| btrfs + `acl` | Full features (ACL path) |
| btrfs + `noacl` | NOACL path (0.9.40-style: Disable_ACL + Manage_Gids=false); basics work; may need staging for some clients |
| vfat/fat, ntfs | NOACL path (auto) |

Explicit `enable_acl` / `manage_gids` in nfs-klldap.conf override probe defaults. On limited filesystems (detected via mountinfo or ganesha_path), NOACL settings applied automatically; capable default to full native. The two paths coexist. Diagnose with `ganesha_log_contract`: ACL-path NOTSUPP vs identity-path NOTSUPP.
