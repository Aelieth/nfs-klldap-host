# Ganesha Architecture & Bind-Mount Contract

Ganesha 9.6: DIRECTORY_SERVICES + idhelper (proactive+reactive, cache) authoritative for uid0+supp groups in nss/extrausers; UseGetpwnam + nss_wrapper getgrouplist.

Single TOML (nfs-klldap.conf) is source of truth. nfs-klldap-config validates+derives+generates sssd/krb5/ganesha fragments. nfs-klldap-startup supervise (pid1) + watcher (SIGHUP) + ganesha-ctl handle reloads/bounces. nfs-klldap-ui (9630 HTTPS) edits TOML + direct chown/chmod (root, on allowed host_path trees). Ganesha VFS + SSSD (from LLDAP POSIX) serve NFSv4 krb5. No host kernel NFS.

## Key Contracts

| Contract                  | Rule |
|---------------------------|------|
| `host_path` vs container  | UI + allow-list + ownership use the host-visible absolute path (unchanged). Each share requires `container_path`: the absolute directory inside the container where Ganesha serves the export (EXPORT `Path=`), fs probes run, and the WebUI permission tree / `get_dir_meta` / ACLs / chown+chmod apply (`serve_path_for(share)` returns `container_path`). `pseudo_path` (defaults to `/<name>`) controls *only* the client-visible Pseudo path. Example: bind `/var/data:/export` with `host_path = "/var/data/nvme-raid/users"` → set `container_path = "/export/nvme-raid/users"`. Translation only at the syscall boundary (`FsManager`). |
| Hostname                  | `get_consistent_hostname()` (hostname(1) == /proc/sys/kernel/hostname). Mismatch → loud diagnostic. `--uts=host` is the normal way to get the real name. |
| Realm                     | Strictly required. No silent EXAMPLE.COM. Auto-derived from ldap_uri host or NFS_KLLDAP_KERBEROS_REALM. |
| ldap_uri                  | DNS hostname only (IP rejected). Forward+reverse DNS required. Keytab: `nfs/<short>@REALM` and `nfs/<fqdn>@REALM` when they differ (`--uts=host`). |
| Execution                 | Everything (Ganesha, SSSD, WebUI, generator) runs as root inside the container. |
| Reload                    | Watcher → SIGHUP to pid 1 → generator + permission fixup + supervisor bounces Ganesha/SSSD/WebUI in place (no full container death). Container ships a system bus for Ganesha; management itself uses fragments + HUP. |

## Volumes (typical)

```yaml
volumes:
  - /media/:/export:rw                # Recommended: bind host parent dir(s) to container_root. Each share sets container_path to the internal serve directory (e.g. /export/NVME-RAID/movies). pseudo_path is only for the client Pseudo (can be short).
  - ./config:/config:rw               # nfs-klldap.conf (single source)
  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
```

See container/healthcheck.sh for service checks. See TESTING.md for test coverage.

## ACL and filesystem compatibility

**ACL is opt-in, per share.** The generator maintains two distinct supported mainline paths, and the default is the safe one:

- **NOACL (default / opt-out)** — any share where `enable_acl` is unset or `false`. Emits 0.9.40-style simple disk/share settings (`Pseudo = /<name>;` from `pseudo_path` or share name, plus `Disable_ACL = true; Manage_Gids = true; Read_Access_Check_Policy = pre;`; explicit `manage_gids=false` overrides) before SecType; no per-export Enable_NLM/Enable_RQUOTA/POSIX marker. Basic file reads, writes, and connectivity work over krb5p on any POSIX filesystem. `read_access_policy = post` on a NOACL share is normalized to `pre` (with a warning). WebUI disables the Pseudo field on NOACL shares and shows the derived value as muted info.
- **ACL (explicit `enable_acl = true`)** — full native NFSv4 ACL behavior (`FSAL { Umask; }`, optional `Manage_Gids_Expiration`, `Read_Access_Check_Policy` omitted-or-`post`, no `Disable_ACL`).

There is **no fail-open**: an unset `enable_acl` never auto-promotes a share onto the ACL path, even on ext4/xfs, because the packaged Ganesha 9.6 VFS FSAL may not be able to service NFSv4 ACL operations (see the limitation below). At validate/generate time nfs-klldap-config still probes `/proc/self/mountinfo` for each share's **serve path** (`container_path`) to annotate limited filesystems and, for `enable_acl = true` shares, best-effort `getfacl` to warn when the serve path does not look ACL-capable. Identity resolution (UID/GID/groups via nss/idhelper/UseGetpwnam) is shared by both paths.

**Ganesha 9.6 ACL limitation (packaged VFS FSAL):** on this build, ACL-dependent OP_ACCESS/GETATTR can return `NFS4ERR_NOTSUPP` — modern Linux clients then fail `ls`/access even though the mount and krb5p auth succeed. This is why ACL is opt-in and default-NOACL. Confirm whether your specific build+filesystem can serve NFSv4 ACLs with `scripts/verify-ganesha.sh` (empirical ACL probe). When ACLs are required and the real data lives on a filesystem the VFS cannot serve ACLs from, use the **staging pattern**: set `source_path` to where the data lands and `container_path` to an ACL-capable serve tree; the post-generate hook syncs `source_path` → `container_path`.

Preflight identity uses `ganesha_identity_pipeline` (tempdir materialize + nss contract) plus runtime nss materialize, socket GRPS, `ganesha-ctl id-resolve`, and ganesha.log uid2grp tags — the same nss_wrapper getent path Ganesha uses at request time per `idmap_log_contract`.

**Staging pattern (for `enable_acl = true`):** set `source_path` to the container path where the real data is bind-mounted, and `container_path` to an ACL-capable serve tree (e.g. ext4 under `/export/staging/...`), while keeping `host_path` for WebUI chown and validation. Use `[ganesha] post_generate_hook` (see `examples/post-generate-staging-sync.sh`) to sync `source_path` → `container_path` (rsync `-aAX`, preserving ACLs) after each generate. When `source_path` is unset, source == serve and no staging runs.

| Filesystem / setting | Behavior |
|----------------------|----------|
| any, `enable_acl` unset/false | NOACL path (Disable_ACL + Manage_Gids=true); basics work over krb5p |
| ext4/xfs/btrfs+acl, `enable_acl = true` | ACL path — works only if the packaged VFS can serve NFSv4 ACLs (verify with `scripts/verify-ganesha.sh`); otherwise stage or change build |
| vfat/fat, ntfs, btrfs+noacl | limited FS — annotated with an auto-detect comment; keep NOACL |

`enable_acl` is opt-in: `true` selects the ACL path, unset/`false` selects NOACL. `manage_gids` defaults `true` on both paths. The two paths coexist per share. Diagnose with `ganesha_log_contract`: ACL-path NOTSUPP vs identity-path NOTSUPP.

## NFS create inheritance, umask, and ACL default entries

New files/dirs created by NFS clients inherit mode bits from (mode & ~umask) + any applicable default ACLs on the parent dir. Ganesha VFS honors `Umask` inside the per-EXPORT `FSAL { ... }` block.

- On ACL path (enable_acl or auto-capable): generator emits `Umask = 0022;` (or explicit share.umask) inside FSAL. This is the default; set e.g. `umask = "0002"` under [[shares]] for group-writable new files.
- On NOACL path: Umask line is omitted (host-side umask + FS semantics govern).
- Common gotcha: setting named ACLs (via UI or setfacl) on a dir does *not* automatically grant inheritance to new children unless default ACL entries are also present (`setfacl -d -m u:1234:rwX,g:5678:rwX ... dir`). Umask still masks the base mode. The UI chown/chmod and ACL tools operate on existing entries; use them + client tools or post-create hooks for defaults.
- Direct Rust chown (nix::unistd) / chmod (std fs) used in UI apply; recursive walks run via spawn_blocking for responsiveness while live progress (scanning/applying) feeds the Apply Log via atomics + /apply-progress polling.

See also nfs-klldap-ui for permission apply and config generation separation of ACL/NOACL. Short comments in code mark the branches.
