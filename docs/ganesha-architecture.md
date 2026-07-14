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
| `Root_Kerberos_Principal = nfs, root;` | `root_kerberos_principals` (tokens none/nfs/root/host/all; `none` overrides the rest) | Upstream default is `all`: any enrolled machine keytab (`host/...`) is root on every export. Excluding `host` maps client machine credentials through normal idmapping → anonymous. Setting `host` or `all` logs a loud warning. **Not sufficient alone** — pair with `root_squash` (below); the 2026-07-11 stress test showed a `host/` machine credential could still write to a `no_root_squash` export. |
| `Squash = root_squash;` (per-share default) | share `squash` / UI checkbox (emits `no_root_squash` when unchecked) | **root_squash by default since 0.9.81.** No client needs uid 0 on an export — the WebUI performs privileged chown/chmod container-side on the bind mount, never over NFS — so squashing client root closes the machine-keytab-writes-as-root hole at the export layer regardless of the Kerberos principal gate. Opt out per share only with a deliberate reason. |
| *(getgroups() trust window — rides `Idmapped_*_Time_Validity` below)* | `manage_gids_expiration_secs` | Ganesha 9.13 routes the old core `Manage_Gids_Expiration` through DIRECTORY_SERVICES `Idmapped_*_Time_Validity` (emitting the core param only draws a startup warning, so it is no longer emitted). This knob feeds the DS value; the deprecated per-share key still seeds it, smallest value wins; `idmapped_validity_secs` wins over both. Note: 9.13's `nfs_init.c` logs a transitional "Using idmapped_*_time_validity … instead of manage_gids_expiration" WARN **on both the set and unset branch** — no configuration is warning-free; `ganesha-log-audit.sh` whitelists exactly the set-branch form. |
| `Max_Uid_To_Group_Reqs = 64;` | `max_uid_to_group_reqs` | Bounds concurrent uid→groups resolutions against SSSD/LLDAP on cache-cold storms (upstream: unlimited). |
| `Negative_Cache_Time_Validity = 60;` | `negative_cache_validity_secs` | Failed-lookup memory (upstream 300s): new LDAP users/groups become resolvable within a minute at the Ganesha layer. |
| `Idmapped_*_Time_Validity = 180;` | `idmapped_validity_secs` | Positive idmap cache windows — on 9.13 also the getgroups() trust window under `Manage_Gids` (see the row above). 180 s since 0.9.84 (was 600) for ~3-min group propagation; see the propagation contract below. |
| `Getattrs_In_Complete_Read = false;` | `getattrs_in_complete_read` | The extra getattr-per-READ exists for ESXi EOF validation; the fleet is immutable Fedora. |
| `Enable_malloc_trim = true;` + `Malloc_trim_MinThreshold = 1024;` (MB) | `malloc_trim`, `malloc_trim_min_threshold_mb` | Returns freed heap on long-running operation; the upstream threshold (15 360 MB) never fires under the 4 GB container limit. |
| `Readdir_Res_Size = 32768;` (+ optional `Readdir_Max_Count`) | `readdir_res_size`, `readdir_max_count` | Declared readdir response sizing; tune against the 1.5 performance baseline. |
| `Attr_Expiration_Time = 60;` (EXPORT_DEFAULTS) | `attr_expiration_secs` (+ per-share key) | The attribute/ACL cache window — the server half of the **change-visibility contract** below. `0` = attribute caching off for that export (always fresh; getattr per op). 9.13 has no DBus attr purge (2.3 audit A5), so this window is the mechanism. |
| `RecoveryRoot = /var/lib/nfs/ganesha;` | — | Must be volume-backed (see Volumes) so a container recreate is a grace period, not lost client state. |
| `Lease_Lifetime = 60;` + `Grace_Period = 90;` | — | Grace must be ≥ lease or a restarting server can refuse reclaims (9.13 warns on the old 60/45 pairing; 60/90 is upstream's). |

**Group-change propagation — three cache layers, and how to flush them.** A membership change in LLDAP must clear three server-side caches before it enforces on an export: (1) the container **SSSD** `entry_cache_timeout`; (2) the **idhelper**'s LDAP resolver + its materialized nss_wrapper/extrausers (re-read on the rebulk interval); (3) **Ganesha's uid2grp** cache (`Idmapped_Group_Time_Validity`, the getgrouplist-result cache). Flushing only SSSD (`sss_cache -E`) is not enough — the change stays masked by (2) and (3).

- **Natural (unattended):** as of 0.9.84 the defaults are `entry_cache_timeout = 180`, rebulk interval `= 180`, `Idmapped_*_Time_Validity = 180` → a change lands in **~3 min** typically, under 10 worst case (was ~70 min at the old 3600/600 defaults). New users/groups (negative caches): `entry_negative_timeout` (60 s) + `Negative_Cache_Time_Validity` (60 s) ≈ ≤ 2 min. Raise the windows (overrides above / `NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS`) to trade freshness for less LDAP/NSS load.
- **Instant (on demand):** `ganesha-ctl refresh-identity [user]` flushes all three layers in one shot — `sss_cache` (needs `sssd-tools`, shipped in the image), an idhelper `REBULK` (re-reads LDAP fresh; the rebulk clears *all* resolver caches incl. memberOf since 0.9.84), and Ganesha's `purge_gids` D-Bus method (`uid2grp_clear_cache()`). Access lands within seconds; pass a user to also print the freshly-resolved group list.

**Change-visibility contract (out-of-band edits).** WebUI chown/chmod/setfacl happen container-side behind Ganesha's back; there is no attr purge on 9.13, so visibility = cache expiry, same philosophy as the group-propagation window:

| Change | Visible to a mounted client within |
|--------|-----------------------------------|
| UI chown/chmod/ACL edit | server `Attr_Expiration_Time` (default 60 s; per-share `attr_expiration_secs`, `0` = immediate server-side) + client attr cache (`acmax`, default 60 s) |
| New/removed entries (UI-created files) | server readdir/dirent caching + client `lookupcache=all` window |
| LDAP identity changes | the three-layer group-propagation contract above (~3 min natural, `ganesha-ctl refresh-identity` instant) |

`lookupcache=all` affects name lookups (dentries), not attributes — ACL/mode changes ride the attr windows only.

**Live export management gate:** `scripts/ganesha-export-reload-smoke.sh` proves add/update/remove via SIGHUP `reread_exports` (the supervisor's fast path) against the custom binary with DBus `ShowExports` as ground truth — daemon pid unchanged across all three operations.

## ACL and filesystem compatibility

**ACL is auto per share since 0.9.90** (explicit settings always win). The generator maintains two distinct supported mainline paths:

- **NOACL** — `enable_acl = false`, or unset when the probe cannot *prove* ACL support. Emits 0.9.40-style simple disk/share settings (`Pseudo = /<name>;` from `pseudo_path` or share name, plus `Disable_ACL = true; Manage_Gids = true; Read_Access_Check_Policy = pre;`; explicit `manage_gids=false` overrides) before SecType; no per-export Enable_NLM/Enable_RQUOTA/POSIX marker. `read_access_policy = post` on a NOACL share is normalized to `pre` (with a warning). WebUI disables the Pseudo field on NOACL shares and shows the derived value as muted info.
- **ACL** — explicit `enable_acl = true`, or **auto**: `enable_acl` unset and the serve path passes the definitive **write round-trip probe** (transient setfacl/getfacl; auto-promoted fragments carry an `# Auto-enabled` comment naming the proof). Full native NFSv4 ACL behavior (`Read_Access_Check_Policy` omitted-or-`post`, explicit `Disable_ACL = false;` — declared, not inherited; no per-export Umask since 9.13, see the inheritance section below). `Manage_Gids_Expiration` never appears in fragments: it is a global NFS_CORE_PARAM (see the hardening section above). The historic NOACL-only default existed while ACL support was absent from the build and the NOACL path was being hardened; with both proven, capability-gated auto is the default.

**Store decision (2026-07-12):** the backing filesystem's POSIX ACLs (`system.posix_acl_access`/`_default`) are the authoritative per-file ACL store — no private spec/blob, no loopback materialization; see the refactor plan's Realignment (2026-07-12) and its rewritten 2.3–2.6 for the audit, UI, coherency, and validation program.

There is **no fail-open**: auto promotion requires the write round-trip *proof*, never mountinfo guesswork — an unproven path degrades to NOACL (the rock), and a broken ACL share can only arise from an explicit `enable_acl = true`, which generate hard-fails on a definitive-negative probe. Since the 9.13 uplift (2026-07-10) the packaged VFS FSAL carries the POSIX-ACL backend, but ACL remains strictly opt-in: serving NFSv4 ACLs still depends on the backing filesystem's POSIX ACL support and on the NFSv4→POSIX mapping's fidelity limits, and the ACL share class is unvalidated until the 0.9.9x track runs its gate (plan 2.6). At validate/generate time nfs-klldap-config still probes `/proc/self/mountinfo` for each share's **serve path** (`container_path`) to annotate limited filesystems and, for `enable_acl = true` shares, best-effort `getfacl` to warn when the serve path does not look ACL-capable. Identity resolution (UID/GID/groups via nss/idhelper/UseGetpwnam) is shared by both paths.

**ACL limitation (packaged VFS FSAL):** on the Phase 1 NOACL build (9.6+klldap1, the rollback anchor) ACL-dependent OP_ACCESS/GETATTR return `NFS4ERR_NOTSUPP` structurally — modern Linux clients then fail `ls`/access even though the mount and krb5p auth succeed. On the 9.13 build the failure mode is broader (2026-07-12 source audit): `vfs_sub_getattrs` fetches the POSIX ACL on **every attribute refresh regardless of the request mask or `Disable_ACL`**, so a backing filesystem that cannot store POSIX ACLs (vfat/ntfs/exfat, `noacl` mounts) is expected to fail attribute fetches for **both share classes** — such filesystems cannot be served by this build at all; use the staging pattern. Since 0.9.90, generate **hard-fails** an `enable_acl = true` share whose serve path is definitively non-ACL-capable (mountinfo denylist or the setfacl/getfacl **write round-trip probe**); an inconclusive probe stays a loud warning. Confirm empirically with `scripts/verify-ganesha.sh`. **Staging pattern:** set `source_path` to where the data lands and `container_path` to an ACL-capable serve tree; the post-generate hook syncs `source_path` → `container_path`.

**`Disable_ACL` is advisory on 9.13 VFS (2026-07-12 source audit):** its only binary effects are skipping the post-SETATTR ACL cache refresh; it does **not** trim `ATTR_ACL` from the advertised supported attributes, does not block FATTR4_ACL GETATTR (Ganesha synthesizes an ACL from mode when none exists, per RFC 8881), and does not reject client SETATTR-ACL — a file owner *can* `nfs4_setfacl` on a NOACL export and it lands on disk (client root is squashed; POSIX owner rules apply; the kernel enforces on-disk ACLs on every export class regardless). The NOACL class is therefore **declared policy plus the absence of extended ACLs on the tree**, not binary enforcement — behaviorally identical to Phase 1 as long as trees carry no extended ACLs (what the 2.2 gate proved). `fs-warnings` surfacing of extended ACLs on NOACL trees is the visibility layer (0.9.9x track).

**Client contract (2026-07-14, WI-11):** client mounts are **class-agnostic** — the `noacl` mount option only governs the NFSv3 NFSACL sideband protocol and is inert on the `vers=4.2` mounts this stack uses, so ACL and NOACL shares mount identically (no client-side alignment exists or is needed). A client also **cannot detect** a share's class over the wire: GETATTR always serves a real or mode-synthesized ACL and owner SETATTR-ACL lands on both classes (previous paragraph), so probing is structurally impossible. The host therefore declares the class: **`GET /client-manifest.json`** on the WebUI, unauthenticated by design (bootstrap data only — share name, pseudo, security flavor, rw, `acl`/`noacl` class + state label; server-internal paths never appear), live-computed per request through the same per-mount verdict cache as the UI (anonymous hits can never drive the write probe harder than the cache TTL) and served `Cache-Control: no-store`. The classification is per **share** (export serve root); ACL-incapable submounts inside a share are a config-health warning on System Settings and an `/acl-apply` 422, never a per-directory class. setup-script v5.10 consumes the manifest (`--manifest URL|FILE`) and uses the class for post-mount guidance only.

Preflight identity uses `ganesha_identity_pipeline` (tempdir materialize + nss contract) plus runtime nss materialize, socket GRPS, `ganesha-ctl id-resolve`, and ganesha.log uid2grp tags — the same nss_wrapper getent path Ganesha uses at request time per `idmap_log_contract`.

**Staging pattern (for `enable_acl = true`):** set `source_path` to the container path where the real data is bind-mounted, and `container_path` to an ACL-capable serve tree (e.g. ext4 under `/export/staging/...`), while keeping `host_path` for WebUI chown and validation. Use `[ganesha] post_generate_hook` (see `examples/post-generate-staging-sync.sh`) to sync `source_path` → `container_path` (rsync `-aAX`, preserving ACLs) after each generate. When `source_path` is unset, source == serve and no staging runs.

| Filesystem / setting | Behavior |
|----------------------|----------|
| any, `enable_acl = false` | NOACL path (Disable_ACL + Manage_Gids=true); basics work over krb5p |
| ACL-capable FS, `enable_acl` unset | **auto → ACL path** once the write round-trip proves storage; unproven stays NOACL |
| ext4/xfs/btrfs+acl, `enable_acl = true` | ACL path — works only if the packaged VFS can serve NFSv4 ACLs (verify with `scripts/verify-ganesha.sh`); otherwise stage or change build |
| vfat/fat, ntfs, btrfs+noacl | limited FS — cannot store POSIX ACLs; on the 9.13 build attribute fetches are expected to fail for both share classes (auto-detect comment says so). Stage onto an ACL-capable serve tree; `enable_acl = true` on such a path is a hard generate error |

`enable_acl` is a tri-state: `true` = ACL (hard generate error if the probe is definitively negative), `false` = NOACL, unset = **auto** (probe-proven promotion, 0.9.90). `manage_gids` defaults `true` on both paths. The two paths coexist per share. Diagnose with `ganesha_log_contract`: ACL-path NOTSUPP vs identity-path NOTSUPP.

## NFS create inheritance, umask, and ACL default entries

New files/dirs created by NFS clients inherit mode bits from (mode & ~umask) + any applicable default ACLs on the parent dir. **Ganesha 9.13 dropped per-export `FSAL { Umask }`** (the parameter is module-global only now), so the generator no longer emits it anywhere.

- The `[[shares]] umask` TOML key is **retired (0.9.90, plan 2.4 stage 2)**: generate hard-fails with a migration message, and a structured settings save drops the key. Creation-mode enveloping now lives in default ACL entries + setgid (below).
- **Share-envelope recipe (plan 2.4):** give the tree a per-share group and setgid so children inherit the group (`chgrp -R <share-group>` + the panel's setgid box), keep the mode bits as the outer envelope (Group bits = the mask on extended paths), and declare what children are born with on the panel's **Inherit** tab (e.g. group `rwX` + a default mask). Result: new files land group-owned with the declared perms, named entries grant within the mask, and `chmod g-w` on the directory still caps everything — mode stays the rock.
- On NOACL path: nothing changed — host-side umask + FS semantics govern, as always.
- Common gotcha: named ACLs on a dir do *not* automatically grant inheritance to new children unless default entries exist — that is exactly what the panel's Inherit tab manages (`setfacl -d` under the hood). Umask still masks the base mode of new children where no default ACL overrides it.
- Direct Rust chown (nix::unistd) / chmod (std fs) used in UI apply; recursive walks run via spawn_blocking for responsiveness while live progress (scanning/applying) feeds the Apply Log via atomics + /apply-progress polling.

See also nfs-klldap-ui for permission apply and config generation separation of ACL/NOACL. Short comments in code mark the branches.
