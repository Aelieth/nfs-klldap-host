# Ganesha Architecture & Bind-Mount Contract

Ganesha 9.13-1+klldap2 (custom build; 9.6→9.13 uplift 2026-07-10, one ACL-capable binary, NOACL per-export, plus the klldap2 nsswitch-getgrouplist return fix — upstream 9.13 dropped all supplementary groups for every ≥1-group user under `Pwnam_Implementation = nsswitch`, see container/ganesha/README.md): DIRECTORY_SERVICES + idhelper (proactive+reactive, cache) authoritative for uid0+supp groups in nss/extrausers; UseGetpwnam + nss_wrapper getgrouplist.

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
  - ./ganesha-recovery:/var/lib/nfs/ganesha:rw  # NFSv4 client recovery state (RecoveryBackend=fs). Without this, clients cannot reclaim locks/opens through grace after a container recreate.
```

See container/healthcheck.sh for service checks. See TESTING.md for test coverage.

## Identity & runtime hardening (refactor plan 1.4)

The generated `ganesha.conf` declares every identity/runtime decision explicitly — nothing load-bearing is inherited from Ganesha defaults. All parameter names are ground-truthed against the Ganesha source (`nfs_read_conf.c`, originally on 9.6, re-checked on the 9.13 uplift); overrides live under `[ganesha]` in nfs-klldap.conf:

| Directive (default) | `[ganesha]` override | Why |
|---------------------|----------------------|-----|
| `Root_Kerberos_Principal = nfs, root;` | `root_kerberos_principals` (tokens none/nfs/root/host/all; `none` overrides the rest) | Upstream default is `all`: any enrolled machine keytab (`host/...`) is root on every export. Excluding `host` maps client machine credentials through normal idmapping → anonymous. Setting `host` or `all` logs a loud warning. |
| *(getgroups() trust window — rides `Idmapped_*_Time_Validity` below)* | `manage_gids_expiration_secs` | Ganesha 9.13 routes the old core `Manage_Gids_Expiration` through DIRECTORY_SERVICES `Idmapped_*_Time_Validity` (emitting the core param only draws a startup warning, so it is no longer emitted). This knob feeds the DS value; the deprecated per-share key still seeds it, smallest value wins; `idmapped_validity_secs` wins over both. Note: 9.13's `nfs_init.c` logs a transitional "Using idmapped_*_time_validity … instead of manage_gids_expiration" WARN **on both the set and unset branch** — no configuration is warning-free; `ganesha-log-audit.sh` whitelists exactly the set-branch form. |
| `Max_Uid_To_Group_Reqs = 64;` | `max_uid_to_group_reqs` | Bounds concurrent uid→groups resolutions against SSSD/LLDAP on cache-cold storms (upstream: unlimited). |
| `Negative_Cache_Time_Validity = 60;` | `negative_cache_validity_secs` | Failed-lookup memory (upstream 300s): new LDAP users/groups become resolvable within a minute at the Ganesha layer. |
| `Idmapped_*_Time_Validity = 600;` | `idmapped_validity_secs` | Positive idmap cache windows — on 9.13 also the getgroups() trust window under `Manage_Gids` (see the row above). |
| `Getattrs_In_Complete_Read = false;` | `getattrs_in_complete_read` | The extra getattr-per-READ exists for ESXi EOF validation; the fleet is immutable Fedora. |
| `Enable_malloc_trim = true;` + `Malloc_trim_MinThreshold = 1024;` (MB) | `malloc_trim`, `malloc_trim_min_threshold_mb` | Returns freed heap on long-running operation; the upstream threshold (15 360 MB) never fires under the 4 GB container limit. |
| `Readdir_Res_Size = 32768;` (+ optional `Readdir_Max_Count`) | `readdir_res_size`, `readdir_max_count` | Declared readdir response sizing; tune against the 1.5 performance baseline. |
| `RecoveryRoot = /var/lib/nfs/ganesha;` | — | Must be volume-backed (see Volumes) so a container recreate is a grace period, not lost client state. |
| `Lease_Lifetime = 60;` + `Grace_Period = 90;` | — | Grace must be ≥ lease or a restarting server can refuse reclaims (9.13 warns on the old 60/45 pairing; 60/90 is upstream's). |

**Group-change propagation window (documented contract):** a membership change in LLDAP is visible to exports after at most `SSSD entry_cache_timeout` (default 3600 s) + `Idmapped_Group_Time_Validity` (600 s; the single group-trust window on 9.13) — worst case ≈ 70 min; typically much sooner once idhelper re-materializes. New users/groups (negative caches): `entry_negative_timeout` (60 s) + `Negative_Cache_Time_Validity` (60 s) ≈ ≤ 2 min. Shrink the windows via the overrides above at the cost of more LDAP/NSS load.

**Live export management gate:** `scripts/ganesha-export-reload-smoke.sh` proves add/update/remove via SIGHUP `reread_exports` (the supervisor's fast path) against the custom binary with DBus `ShowExports` as ground truth — daemon pid unchanged across all three operations.

## ACL and filesystem compatibility

**ACL is opt-in, per share.** The generator maintains two distinct supported mainline paths, and the default is the safe one:

- **NOACL (default / opt-out)** — any share where `enable_acl` is unset or `false`. Emits 0.9.40-style simple disk/share settings (`Pseudo = /<name>;` from `pseudo_path` or share name, plus `Disable_ACL = true; Manage_Gids = true; Read_Access_Check_Policy = pre;`; explicit `manage_gids=false` overrides) before SecType; no per-export Enable_NLM/Enable_RQUOTA/POSIX marker. Basic file reads, writes, and connectivity work over krb5p on any POSIX filesystem. `read_access_policy = post` on a NOACL share is normalized to `pre` (with a warning). WebUI disables the Pseudo field on NOACL shares and shows the derived value as muted info.
- **ACL (explicit `enable_acl = true`)** — full native NFSv4 ACL behavior (`Read_Access_Check_Policy` omitted-or-`post`, explicit `Disable_ACL = false;` — declared, not inherited; no per-export Umask since 9.13, see the inheritance section below). `Manage_Gids_Expiration` never appears in fragments: it is a global NFS_CORE_PARAM (see the hardening section above).

There is **no fail-open**: an unset `enable_acl` never auto-promotes a share onto the ACL path, even on ext4/xfs. Since the 9.13 uplift (2026-07-10) the packaged VFS FSAL carries the POSIX-ACL backend, but ACL remains strictly opt-in: serving NFSv4 ACLs still depends on the backing filesystem's POSIX ACL support and on the NFSv4→POSIX mapping's fidelity limits, and the ACL share class is unvalidated until the 0.9.9x track runs its gate (plan 2.6). At validate/generate time nfs-klldap-config still probes `/proc/self/mountinfo` for each share's **serve path** (`container_path`) to annotate limited filesystems and, for `enable_acl = true` shares, best-effort `getfacl` to warn when the serve path does not look ACL-capable. Identity resolution (UID/GID/groups via nss/idhelper/UseGetpwnam) is shared by both paths.

**ACL limitation (packaged VFS FSAL):** on the Phase 1 NOACL build (9.6+klldap1, the rollback anchor) ACL-dependent OP_ACCESS/GETATTR return `NFS4ERR_NOTSUPP` structurally — modern Linux clients then fail `ls`/access even though the mount and krb5p auth succeed. On the 9.13+klldap1 build the same error appears when the **backing filesystem** cannot serve POSIX ACLs. Either way, this is why ACL is opt-in and default-NOACL. Confirm whether your specific build+filesystem can serve NFSv4 ACLs with `scripts/verify-ganesha.sh` (empirical ACL probe). When ACLs are required and the real data lives on a filesystem the VFS cannot serve ACLs from, use the **staging pattern**: set `source_path` to where the data lands and `container_path` to an ACL-capable serve tree; the post-generate hook syncs `source_path` → `container_path`.

Preflight identity uses `ganesha_identity_pipeline` (tempdir materialize + nss contract) plus runtime nss materialize, socket GRPS, `ganesha-ctl id-resolve`, and ganesha.log uid2grp tags — the same nss_wrapper getent path Ganesha uses at request time per `idmap_log_contract`.

**Staging pattern (for `enable_acl = true`):** set `source_path` to the container path where the real data is bind-mounted, and `container_path` to an ACL-capable serve tree (e.g. ext4 under `/export/staging/...`), while keeping `host_path` for WebUI chown and validation. Use `[ganesha] post_generate_hook` (see `examples/post-generate-staging-sync.sh`) to sync `source_path` → `container_path` (rsync `-aAX`, preserving ACLs) after each generate. When `source_path` is unset, source == serve and no staging runs.

| Filesystem / setting | Behavior |
|----------------------|----------|
| any, `enable_acl` unset/false | NOACL path (Disable_ACL + Manage_Gids=true); basics work over krb5p |
| ext4/xfs/btrfs+acl, `enable_acl = true` | ACL path — works only if the packaged VFS can serve NFSv4 ACLs (verify with `scripts/verify-ganesha.sh`); otherwise stage or change build |
| vfat/fat, ntfs, btrfs+noacl | limited FS — annotated with an auto-detect comment; keep NOACL |

`enable_acl` is opt-in: `true` selects the ACL path, unset/`false` selects NOACL. `manage_gids` defaults `true` on both paths. The two paths coexist per share. Diagnose with `ganesha_log_contract`: ACL-path NOTSUPP vs identity-path NOTSUPP.

## NFS create inheritance, umask, and ACL default entries

New files/dirs created by NFS clients inherit mode bits from (mode & ~umask) + any applicable default ACLs on the parent dir. **Ganesha 9.13 dropped per-export `FSAL { Umask }`** (the parameter is module-global only now), so the generator no longer emits it anywhere.

- The `[[shares]] umask` TOML key is accepted but inert (loud generate-time warning) — creation-mode envelopes on ACL shares return with the 0.9.9x POSIX gate (plan 2.4: per-share group + setgid + managed tree modes).
- On NOACL path: nothing changed — host-side umask + FS semantics govern, as always.
- Common gotcha: setting named ACLs (via UI or setfacl) on a dir does *not* automatically grant inheritance to new children unless default ACL entries are also present (`setfacl -d -m u:1234:rwX,g:5678:rwX ... dir`). Umask still masks the base mode. The UI chown/chmod and ACL tools operate on existing entries; use them + client tools or post-create hooks for defaults.
- Direct Rust chown (nix::unistd) / chmod (std fs) used in UI apply; recursive walks run via spawn_blocking for responsiveness while live progress (scanning/applying) feeds the Apply Log via atomics + /apply-progress polling.

See also nfs-klldap-ui for permission apply and config generation separation of ACL/NOACL. Short comments in code mark the branches.
