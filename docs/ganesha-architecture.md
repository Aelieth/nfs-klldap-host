# Ganesha Architecture & Bind-Mount Contract

Ganesha 9.6: DIRECTORY_SERVICES + idhelper (proactive+reactive, cache) authoritative for uid0+supp groups in nss/extrausers; UseGetpwnam + nss_wrapper getgrouplist.

Single TOML (nfs-klldap.conf) is source of truth. nfs-klldap-config validates+derives+generates sssd/krb5/ganesha fragments. nfs-klldap-startup supervise (pid1) + watcher (SIGHUP) + ganesha-ctl handle reloads/bounces. nfs-klldap-ui (9630 HTTPS) edits TOML + direct chown/chmod (root, on allowed host_path trees). Ganesha VFS + SSSD (from LLDAP POSIX) serve NFSv4 krb5. No host kernel NFS.

## Key Contracts

| Contract                  | Rule |
|---------------------------|------|
| `host_path` vs container  | UI + allow-list + ownership use the host-visible absolute path (unchanged). The *effective* internal container/serve location for Ganesha EXPORT `Path=` , fs probes, *and* WebUI permission tree / `get_dir_meta` (owner/group/mode display) / ACLs / chown+chmod applies is `serve_path_for(share)`: `ganesha_path` when set (explicit override for staging or non-standard bind depths), otherwise the derived container path. The default derivation (no `ganesha_path`) is `storage.container_root` + (tail of share `host_path` after its first directory component) — the first dir component of `host_path` is the implicit per-share bind root. `pseudo_path` (defaults to `/<name>`) controls *only* the client-visible Pseudo path. A single (or multiple) root bind(s) (host parent(s) → /export) is the stable pattern. For example, bind `/var/data:/export` + `host_path = "/var/data/nvme-raid/users"` + `ganesha_path = "/export/nvme-raid/users"` makes WebUI and Ganesha see the data at `/export/nvme-raid/users` (without `ganesha_path` the heuristic would wrongly target `/export/data/nvme-raid/users`). Translation only at the syscall boundary (`FsManager`). |
| Hostname                  | `get_consistent_hostname()` (hostname(1) == /proc/sys/kernel/hostname). Mismatch → loud diagnostic. `--uts=host` is the normal way to get the real name. |
| Realm                     | Strictly required. No silent EXAMPLE.COM. Auto-derived from ldap_uri host or NFS_KLLDAP_KERBEROS_REALM. |
| ldap_uri                  | DNS hostname only (IP rejected). Forward+reverse DNS required. Keytab: `nfs/<short>@REALM` and `nfs/<fqdn>@REALM` when they differ (`--uts=host`). |
| Execution                 | Everything (Ganesha, SSSD, WebUI, generator) runs as root inside the container. |
| Reload                    | Watcher → SIGHUP to pid 1 → generator + permission fixup + supervisor bounces Ganesha/SSSD/WebUI in place (no full container death). Container ships a system bus for Ganesha; management itself uses fragments + HUP. |

## Volumes (typical)

```yaml
volumes:
  - /media/:/export:rw                # Recommended: single (or multiple) root-level bind(s) of host parent dir(s). First dir of each share's host_path is the implicit bind root; tail becomes subpath under container_root (unless overridden by `ganesha_path`). `ganesha_path` controls the effective container path used for Ganesha *and* WebUI. pseudo_path is only for the client Pseudo (can be short).
  - ./config:/config:rw               # nfs-klldap.conf (single source)
  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
```

See container/healthcheck.sh for service checks. See TESTING.md for test coverage.

## ACL and filesystem compatibility

At validate/generate time nfs-klldap-config probes `/proc/self/mountinfo` for each share's **serve path** (`ganesha_path` when set, otherwise the derived container path from `host_path`). The generator maintains two distinct supported mainline paths:

- ACL-capable (ext4, xfs, btrfs+acl, or explicit `enable_acl=true`): full native NFSv4 ACL behavior.
- NOACL/limited (btrfs+noacl, vfat/fat, ntfs, or explicit `enable_acl=false`): 0.9.40-style simple disk/share settings (`Pseudo = /<name>;` from `pseudo_path` or share name, plus `Disable_ACL = true; Manage_Gids = true; Read_Access_Check_Policy = pre;` (auto default; explicit `manage_gids=false` overrides) emitted before SecType; no per-export Enable_NLM/Enable_RQUOTA/POSIX marker). Explicit pre (no quotes) access check policy for noacl mounts. Auto-detect via fstype+noacl mountopt (overrides allowed). WebUI disables the Pseudo field on NOACL shares and shows the derived value as muted info.

Limited filesystems automatically use the NOACL path — basic file reads and connectivity work for noacl clients (per 0.9.40). Identity resolution (UID/GID/groups via 0.9.65 nss/idhelper/UseGetpwnam) is shared by both paths.

**Ganesha 9.6 ACL-path limitation (not a regression fix):** On direct noacl, some OP_ACCESS/GETATTR may still surface NFS4ERR_NOTSUPP under ACL masks in ganesha.log for certain clients. Use `ganesha_path` staging + post-generate hook to an ACL-capable tree when full-feature `ls` / extended ACLs are required on the share. Staging remains supported.

Preflight identity uses `ganesha_identity_pipeline` (tempdir materialize + nss contract) plus runtime nss materialize, socket GRPS, `ganesha-ctl id-resolve`, and ganesha.log uid2grp tags — the same nss_wrapper getent path Ganesha uses at request time per `idmap_log_contract`.

**Staging pattern:** set `ganesha_path` to an ACL-capable tree (e.g. ext4 under `/export/staging/...`) while keeping `host_path` for WebUI chown and validation. Use `[ganesha] post_generate_hook` (see `examples/post-generate-staging-sync.sh`) to sync data into the staging path after each generate.

| Filesystem | Typical behavior |
|------------|------------------|
| ext4, xfs | Full NFSv4.2 ACL features (default; ACL path) |
| btrfs + `acl` | Full features (ACL path) |
| btrfs + `noacl` | NOACL path (0.9.40-style: Disable_ACL + Manage_Gids=true auto); basics work; may need staging for some clients |
| vfat/fat, ntfs | NOACL path (auto) |

Explicit `enable_acl` / `manage_gids` in nfs-klldap.conf override probe defaults. On limited filesystems (detected via mountinfo or ganesha_path), NOACL settings applied automatically; capable default to full native. The two paths coexist. Diagnose with `ganesha_log_contract`: ACL-path NOTSUPP vs identity-path NOTSUPP.

## NFS create inheritance, umask, and ACL default entries

New files/dirs created by NFS clients inherit mode bits from (mode & ~umask) + any applicable default ACLs on the parent dir. Ganesha VFS honors `Umask` inside the per-EXPORT `FSAL { ... }` block.

- On ACL path (enable_acl or auto-capable): generator emits `Umask = 0022;` (or explicit share.umask) inside FSAL. This is the default; set e.g. `umask = "0002"` under [[shares]] for group-writable new files.
- On NOACL path: Umask line is omitted (host-side umask + FS semantics govern).
- Common gotcha: setting named ACLs (via UI or setfacl) on a dir does *not* automatically grant inheritance to new children unless default ACL entries are also present (`setfacl -d -m u:1234:rwX,g:5678:rwX ... dir`). Umask still masks the base mode. The UI chown/chmod and ACL tools operate on existing entries; use them + client tools or post-create hooks for defaults.
- Direct Rust chown (nix::unistd) / chmod (std fs) used in UI apply; recursive walks run via spawn_blocking for responsiveness while live progress (scanning/applying) feeds the Apply Log via atomics + /apply-progress polling.

See also nfs-klldap-ui for permission apply and config generation separation of ACL/NOACL. Short comments in code mark the branches.
