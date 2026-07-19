# Testing

**Purpose:** how we prove the stack is safe to ship — automated gates, image smokes, and live client/ACL work that already ran on real hardware.

**1.0.** Crates: `nfs-klldap-identity`, `nfs-klldap-config`, `nfs-klldap-ui`.

---

## Production gates (every commit)

These are the gates that must stay green before a release image is trusted.

| Gate | What it proves | How |
|------|----------------|-----|
| **`make gate`** | Full pre-merge bar | `scripts/safety-dance.sh` → comment lint → Ganesha version-pin check → `cargo build --workspace --bins` → `cargo test --workspace` |
| **GitHub Actions `gate.yml`** | Same bar on clean runners (no leftover sockets / root paths) | Push/PR → `make gate` |
| **`scripts/safety-dance.sh`** | No first-party `unsafe` / `libc::`; `#![deny(unsafe_code, dead_code)]`; clippy `-D warnings` | Part of `make gate` |
| **`scripts/check-version-pins.sh`** | Packaging, image install, and smoke scripts agree on `9.13-1+klldap3` | Part of `make gate` |
| **`make test` / `make clippy`** | Workspace tests only / nightly clippy only | Local iteration |

```bash
make gate          # preferred pre-commit / release check
make test          # cargo build --bins + cargo test --workspace
make clippy        # cargo +nightly clippy -D warnings
```

Supervisor integration tests run under `NFS_KLLDAP_TEST_PERSISTENT` with stubs (writable SSSD pipe, idhelper fixture). They exercise SIGHUP vs SIGUSR1 recycle, export reread, identity staging, Navahi avahi lifecycle, and steady-state respawn — the same paths pid 1 uses in production.

---

## Image & Ganesha smokes (in-container / against a live image)

Run after a `docker build` when changing packaging, generator, or entrypoint.

| Script | Proves |
|--------|--------|
| `scripts/ganesha-startup-smoke.sh` | Custom package identity (`+klldap3`), no MSPAC stub / no wbclient, POSIX-ACL backend present, daemon on 2049, VFS FSAL, GSS principal, clean NOACL export startup |
| `scripts/ganesha-export-reload-smoke.sh` | Export reread / reload path survives without client-visible hard fail |
| `scripts/ganesha-log-audit.sh` | Startup / identity log contracts (no forbidden noise, expected idmap chain) |
| `scripts/ganesha-chain-preflight.sh` | Before a Fedora mount: `UseGetpwnam`, idhelper materialize of a sample principal |
| `scripts/fedora-krb5p-client-validate.sh` | Machine kinit + `sec=krb5p` mount/write cycle (container client) |
| `scripts/verify-ganesha.sh` | Broader operator verify helper |
| `scripts/collect-server-diag.sh` | Bundle logs/conf for a failed field run |

Host client checklist (immutable Fedora / Bazzite / Silverblue): [docs/client-fedora-immutable.md](docs/client-fedora-immutable.md).

---

## Summary of the Ganesha refactor plan (closed into 1.0)

The long design doc (`nfs-klldap-host-ganesha-refactor-plan.md`, local non-product) tracked the move off stock Debian **Ganesha 9.6** into a **custom-packaged 9.13** stack with real client proof. This is that story, shortened, and where testing closed each phase.

### Governing idea

Change one variable at a time. **NOACL is the permanent rock** — every phase had to leave the NOACL path equal or better. ACL work was allowed only after NOACL was hardened and re-proven.

### Phase 1 — Custom NOACL build (done)

- Retrieve Debian packaging, ship **`+klldap*`** package identity, VFS-only FSAL trim.
- **`_MSPAC_SUPPORT=NO`** so principal→group is not a compile-time stub and **wbclient** is gone (build gates enforce both).
- Image swap + **startup smoke** (daemon, VFS, GSS, 2049, clean Disable_ACL export).
- Config hardening: explicit per-export ACL disable, NSS/`UseGetpwnam` identity path, `Manage_Gids` on NOACL, `Root_Kerberos_Principal = nfs, root` (no `host/`), NFSv4-focused runtime, export reload path.
- **1.5 rock test (merged into 2.2):** krb5 / krb5i / krb5p from Silverblue and Bazzite; multi-group users; log audit at normal verbosity; mid-write container kill + grace; performance vs stock baseline.

### Realignments (what changed mid-flight)

| Date | Decision |
|------|----------|
| **2026-07-10** | One **ACL-capable** binary for both tracks (not a NOACL-only build forever). ACL vs NOACL is **per-export** (`Disable_ACL`), proven by gates. Uplift source to **9.13**; restore stock **`ENABLE_VFS_POSIX_ACL`** (debug-ACL is in-memory only — wrong store). |
| **2026-07-12** | **Disk POSIX ACLs are truth** (`system.posix_acl_*`). WebUI writes with `setfacl` at the serve path; no private ACL blob / reconciler. Auto `enable_acl` when the write probe proves the FS; unproven → NOACL. |

Branch lines **0.9.8x** (NOACL stabilize) and **0.9.9x** (ACL stabilize) ran the **same** Ganesha package so regressions were config/feature, not version skew.

### Phase 2 — ACL on the same binary (done)

- **2.1–2.2:** 9.13 uplift + full Phase-1 regression gate green on the new package (multi-round stress on 0.9.8x).
- **2.3:** POSIX↔NFSv4 mapping audit (SETATTR/GETATTR, mask/chmod, Disable_ACL mechanics, idmapping of ACE names).
- **2.4–2.5:** Mask envelope, default-ACL inheritance (umask retired), WebUI full ACL editor (WI-2…WI-11): auto-sensing, capability cache, recursive apply, tree `+` marker, attr-cache window, per-share classification + public `/client-manifest.json`.
- **2.6 ACL validation gate (operator stress):** wire ACL, propagation (`refresh-identity`), UI↔client coherency, lifecycle/reclaim, cross-class NOACL re-proof, cost accounting — btrfs production + ext4 scratch. Recorded green across the planned rows (including B-row identity grants and WI-8 coherency window).

Packaging follow-ons still in the image today: **klldap2** (nsswitch `getgrouplist` return) and **klldap3** (uid2grp single-flight under concurrent misses).

### Production audit + supervisor (2026-07-17, done)

Rust/supervisor hardening after the ACL gate: dead **ganesha/sssd/idhelper** no longer stay dead (Idle-tick respawn with budget); recycle plan split (**SIGHUP** shares-scoped apply + identity **staged**; **SIGUSR1** forced full recycle); probe harnesses for export / identity / full recycle. Those contracts are what `tests/supervisor_loop_*.rs` and `recycle_plan.rs` lock in.

### Explicitly not done (Phase 3 — out of 1.0)

Fleet-level KLLDAP ownership of share objects, host→directory reporting, and “KLLDAP is law” remote policy loops remain **future**. 1.0 is a production NFS host for a KLLDAP domain, not a multi-host control plane.

### Navahi (0.9.99 → 1.0)

mDNS adverts + optional NFSv3/AUTH_SYS click-mount for flagged shares; global toggle full-recycle-gated; covered by `navahi_generate` + `supervisor_navahi_avahi` tests.

### What “done” means for identity

MSPAC-off **unlocks** Ganesha’s principal path and removes winbind. Production still depends on **idhelper + nss_wrapper + UseGetpwnam** for complete KLLDAP supplementals and machine principals — that was never replaced by MSPAC-off alone (see packaging notes in [container/ganesha/README.md](container/ganesha/README.md)).

---

## Real-world / production viability (plan gates that actually ran)

Field and operator work that closed the plan — not crate unit tests:

| Plan gate / drill | Evidence |
|-------------------|----------|
| **1.5 / 2.2 auth matrix** | Silverblue + Bazzite; krb5p / krb5i / krb5; multi-share trees; large supplemental groups |
| **1.5 reliability** | Mid-write container kill → client grace/reclaim; export-reload smoke; steady-state Ganesha respawn |
| **1.3 / 2.1 package smokes** | `ganesha-startup-smoke.sh` (version, no MSPAC/wbclient, POSIX ACL backend, 2049, NOACL export) |
| **2.6 ACL gate** | `setup-script/stress-test.sh` acl* phases (below) on kit clients; btrfs + ext4 |
| **2.6 NOACL re-proof** | Cross-class + NOACL legs after ACL work so the rock path never silently regressed |
| **Group flush (B7-class)** | Live `ganesha-ctl refresh-identity` during propagation phase |
| **Pre-mount chain** | `ganesha-chain-preflight.sh` + idhelper resolve of a domain user |
| **Client script** | `fedora-krb5p-client-validate.sh` (machine kinit, write/cat, host-bind visibility) |
| **CI production bar** | GitHub `gate.yml` / `make gate` on clean runners |

**Live ACL operator harness** (`setup-script/stress-test.sh` — not unit tests):

```bash
./stress-test.sh preflight          # kit, mounts, manifest, hooks, klldap Ganesha
./stress-test.sh aclgate            # full btrfs session
# phases: preflight → aclprep → aclmatrix → aclperf → aclwire →
#         aclpropagation → aclcoherency → acllifecycle → aclcrossclass
```

| Phase | Covers |
|-------|--------|
| aclwire | Wire ACL + deny-intent + server-side landing |
| aclpropagation | `refresh-identity` group flush (nonzero = layer failed) |
| aclcoherency | UI vs client ACL visibility |
| acllifecycle | Mount lifecycle / reclaim |
| aclcrossclass | Class flip via manifest + NOACL re-proof |
| aclperf | Cost |

**Redeploy smoke (field):** kill `ganesha.nfsd` → steady-state respawn; log rotate with `NFS_KLLDAP_LOG_ROTATE_MAX_MB=1` (copytruncate, no SIGHUP); stalled generate on SIGHUP fails within 120s. Archive `stress-results-*` under `setup-script/`.

| Need | Notes |
|------|--------|
| Client kit | Current `SCRIPT_VERSION` on every client |
| `nfs4-acl-tools` | Audit client only |
| Config | `WEBUI_BASE_URL`, `ACL_SHARE_NAME`, `SERVER_EXEC_CMD` |
| Operator hands | LDAP group edits, WebUI ACL edit, class flips, host `docker restart` for ext4 leg |
| ext4 leg | `scripts/make-scratch-fs.sh ext4`; leave `enable_acl` unset for auto |
| Backups | Numeric ownership (`tar --numeric-owner`, `rsync --numeric-ids`) |

---

## Strategy (workspace crates)

- Pure unit tests for derivation, validation, hostname/keytab variants, credential helpers, allow-lists.
- `tempfile` trees for `FsManager`; `tower::ServiceExt` oneshot for Axum.
- Config golden checks on generated `sssd.conf` / Ganesha fragments.
- Idhelper env-mutating tests serialize on `ENV_TEST_LOCK` + `reset_id_resolver_for_test()`.

| Area | Primary tests |
|------|----------------|
| Full-config generate | `tests/representative_generate.rs` |
| FS probe fixtures | `src/fs_probe.rs` |
| Limited-FS / ACL hard-fail | `tests/limited_fs_generate.rs`, `tests/cli_generate_gate.rs` |
| Staging / umask retirement | `tests/container_path_generate.rs` |
| Recycle plans | `src/recycle_plan.rs`, `tests/supervisor_loop_*.rs`, `tests/supervisor_navahi_avahi.rs` |
| `fs-warnings` CLI | `tests/fs_warnings_cli.rs` |

**Hard (not unit-tested):** live LLDAP/Kerberos binds, recursive chown on real binds, full entrypoint orchestration. Admin-login bind fail-closed mapping is unit-tested; wrong-password rejection against a live server is manual / stress.

## Kerberos / idmap

```bash
cargo test --workspace
cargo test -p nfs-klldap-config idmap_log_contract
```

NOACL fragments must emit `Pseudo`, `Disable_ACL = true`, `Manage_Gids = true` (unless explicit `manage_gids=false`), and `Read_Access_Check_Policy = pre`. Runtime: `ganesha-ctl id-resolve` / `id-check` / `refresh-identity`.

## NSS snapshot goldens

`build_nss_snapshot` + ensure drive complete supps; ondemand + uid0 cover the reactive getgrouplist path.

## Living specification (module → tests)

| Behavior | Tests |
|----------|--------|
| `ldap_service_creds` (verbatim DN, env override) | `nfs-klldap-ui/src/config.rs` |
| Admin pane (pane rename + per-principal render, localhost change-password matrix, LDAP-admin live re-check member/non-member/fail-closed via `TEST_LIVE_ADMIN_CHECK`, other-session invalidation, maintenance endpoint auth gates + JSON verdicts, `[webui] session_timeout_minutes` save/clear/floor) | `nfs-klldap-ui/src/web/tests.rs` (`settings_change_password_*`, `settings_admin_pane_renders_for_both_principals`, `settings_maintenance_endpoints_gate_and_report`, `settings_save_roundtrips_session_timeout`), `src/auth.rs` (atomic sidecar + TTL + invalidation), `src/ldap.rs` (`live_admin_check_fails_closed_without_service_creds`), `nfs-klldap-config/src/validate.rs` (`session_timeout_minutes_enforces_minimum`) |
| Core env overrides (NFS_KLLDAP_* only for ldap_uri, bind, realm, [webui] tls etc.) + [serde(default)] for omission | `nfs-klldap-config/src/validate.rs`, `config.rs`, lib.rs tests |
| `all_managed_roots` / `is_allowed` + host<->container path mapping | `nfs-klldap-ui/src/config.rs`, `fs.rs` |
| Vendored htmx asset (setup-gate bypass, JS content-type, no CDN refs in served HTML) | `nfs-klldap-ui/src/web/mod.rs` (`htmx_asset_served_pre_setup_and_referenced_locally`) |
| Apply Log shell single-sourcing (initial `/` render without oob/finished attrs, JS contract classes) | `nfs-klldap-ui/src/web/mod.rs` (`index_renders_apply_log_shell`) |
| Server-rendered blank share card (idx propagation, NOACL defaults, tooltips present) | `nfs-klldap-ui/src/web/mod.rs` (`share_card_fragment_renders_blank_card_with_tooltips`) |
| Generated sssd.conf shape + no dups + tls options | `nfs-klldap-config/src/lib.rs` |
| Filesystem probe (mountinfo fixtures, acl_capable, effective flags; ACL write round-trip probe + layered verdict; **auto enable_acl**: unset promotes only on a Capable verdict — static callers stay NOACL) | `nfs-klldap-config/src/fs_probe.rs` (`auto_acl_turns_on_only_with_proven_probe`), `tests/limited_fs_generate.rs` (`generate_all_auto_enables_acl_on_proven_serve_path`) |
| ACL hard-fail generate (enable_acl=true + definitively non-ACL serve path refuses with staging escape; inconclusive warns) | `nfs-klldap-config/tests/limited_fs_generate.rs` (`generate_all_refuses_enable_acl_on_incapable_fs`), `tests/cli_generate_gate.rs` |
| Full POSIX ACL table (base/named/mask/default parse, `#effective` strip, effective = entry ∧ mask, `setfacl -d`/SetMask, never `-b`/`-n`) | `nfs-klldap-ui/src/privileged.rs` (`acl_table_tests`), `src/fs.rs` (acl_* real-tree suite via `get_acl_table`) |
| ACL layers in the panel (AclApplyForm.layer, op=mask, default-on-file 422; tabbed Current/Inherit panes, columnar list, capped-cell dimming, unified Add/Remove/Modify, auto pill) | `nfs-klldap-ui/src/web/mod.rs` (`web_acl_apply_default_layer_*`, `web_acl_apply_mask_op_caps_named_entries`, `dir_perms_renders_mask_default_and_effective_sections`, `dir_perms_get_renders_posix_matrix_and_noacl_section`), `src/web/permission_tree.rs` (`acl_capability_tests`) |
| Recursive ACL apply (scoped walker, chunked setfacl, split specs — dirs take fused r→x perms, files the literal triad; default layer dirs-only; subtree remove tolerates absent entries; file targets braced) | `nfs-klldap-ui/src/fs.rs` (`acl_recursive_split_specs_dirs_fused_files_literal`, `acl_recursive_single_scope_spares_subdirs`), `src/web/mod.rs` (`web_acl_apply_scope_all_sweeps_subtree`) |
| Tree extended-ACL "+" marker (one batched getfacl per fragment, ACL-active shares only) | `nfs-klldap-ui/src/web/mod.rs` (`tree_fragment_marks_extended_acl_rows`) |
| Attr_Expiration_Time emission (EXPORT_DEFAULTS default 60, [ganesha] knob, per-share override incl. 0 = always fresh; negatives rejected) | `nfs-klldap-config/tests/limited_fs_generate.rs` (`generate_all_emits_attr_expiration_default_and_share_override`) |
| umask retirement stage 2 (hard generate error naming the Inherit-tab replacement; structured saves drop the key) | `nfs-klldap-config/tests/container_path_generate.rs` (`umask_key_is_a_hard_deprecation_error`) |
| EXPORT Disable_ACL / Manage_Gids=true (auto NOACL default) + Pseudo; distinct ACL path; Read_Access pre on NOACL only | `nfs-klldap-config/src/generate/` (two paths), `src/fs_probe.rs` / `src/fs_warnings.rs`, `tests/limited_fs_generate.rs`, `tests/cli_generate_gate.rs`, `tests/container_path_generate.rs`, `tests/ganesha_96_identity_audit.rs` |
| Ganesha NOTSUPP log classification (9.6-era signatures; ACL-path vs identity-path) + clean client-abort-before-namespace signature — committed fixture `tests/fixtures/ganesha-acl-notsupp.log`, never repo-root logs.txt | `nfs-klldap-config/src/ganesha_log_contract.rs`, `src/bin/idhelper/idmap_log_contract.rs` |
| Post-generate hook env contract (SOURCE_PATH/SERVE_PATH/CONTAINER_PATH/PSEUDO_PATH/EXPORT_PATH) | `nfs-klldap-config/src/hook.rs` |
| Wizard gates (`validate_ldap_uri`, step2/step3 test-before-continue) + session cookie extraction | `nfs-klldap-ui/src/web/setup.rs`, `web/auth.rs` |
| LDAP TLS policy (cacert ⇒ verify, reqcert=never override) | `nfs-klldap-identity/src/ldap/tls.rs` |
| idhelper full principal forms (user@REALM + host/..@REALM) + GRPS groups + resolution check | `nfs-klldap-config/src/bin/idhelper/{resolve,main}.rs` + lib check, limited_fs_generate + new fallback tests |
| Hostname consistency + keytab variants + docker-id detection | `nfs-klldap-config/src/hostname.rs`, `lib.rs` |
| Keytab status message / alert | `nfs-klldap-ui/src/web/settings/` + setup/settings handlers (hostname/keytab checks) |
| Axum settings/apply/auth + login flows + cookie policy + empty-uid apply | `nfs-klldap-ui/src/web/mod.rs` (and sub) |
| ApplyOptions (continue, dry, recursive policy, symlink skip) + WalkDir safety | `nfs-klldap-ui/src/fs.rs` |
| Tree listing (dirs-first case-insensitive sort, files with mtime, symlink exclusion, empty=Some vs unreadable=None) + type-emoji mapping + UTC mtime format | `nfs-klldap-ui/src/fs.rs` (`list_dir_*`), `src/web/permission_tree.rs` (`tree_row_tests`), `src/web/mod.rs` (`tree_lists_files_after_dirs_with_icons_and_mtime`, `tree_child_fragment_renders_empty_row_for_empty_dir`) |
| Per-kind permission editors (dir condensed matrix + specials + scope radios + file-bits editor + traverse-only warn vs file full triad) + apply scopes (none=inode only, single spares subdirs, all descends) + explicit file_mode contract (x-less stays x-less, execute only when chosen, special bits refused) + file-target brace | `nfs-klldap-ui/src/web/mod.rs` (`dir_perms_*`, `web_apply_scope_none_*`, `web_apply_scope_single_*`, `web_apply_scope_all_*`, `web_apply_rejects_special_bits_in_file_mode`, `web_recursive_apply_xless_mode_fuses_dirs_not_files`, `web_apply_on_file_target_is_single_node_and_unfused`), `src/fs.rs` (`apply_scope_*`, `apply_refuses_special_bits_in_file_mode`, `apply_file_target_non_recursive_touches_exactly_that_file`, `apply_normalizes_directory_mode_but_not_files`) |
| Ldap list filters, normalize query, cache behavior (unit) | `nfs-klldap-ui/src/ldap.rs` (list_search_tests) |
| Admin-login bind is fail-closed (JoinError/connect-fail/bind-fail ⇒ false; only a proven success authenticates) | `nfs-klldap-ui/src/ldap.rs` (`bind_verdict_is_fail_closed`) |
| ACL capability cache (per-mount write-probe verdict; Stage-A re-classified each lookup so an fstype flip invalidates instantly; TTL 300s / Inconclusive 30s; unknown ⇒ uncached; force_refresh always probes; capable-no-mount-root probes uncached) | `nfs-klldap-ui/src/web/acl_capability.rs` |
| ACL gates split per WI-11: panel/tree classify per SHARE (serve-root verdict only — a node on a divergent submount stays editable) while `/acl-apply` alone re-checks the node's mount as the 422 backstop (incapable/unverified submount refused; explicit-off/auto-off/incapable still block share-wide; explicit-on+Inconclusive editable with amber "on (unverified)") | `nfs-klldap-ui/src/web/permission_tree.rs` (`acl_capability_tests` — node-override rows are the backstop matrix), `web/mod.rs` (`dir_perms_editable_on_capable_share_regardless_of_submount`, `acl_apply_422_backstop_on_incapable_submount`, `web_acl_apply_refused_on_incapable_mount_422`) |
| One per-share classification for every surface (`share_acl_status`: cache verdict → `compute_effective_flags_probed`; label matrix on/off/unverified/unsupported/auto) driving index cards, Settings rows, and the manifest | `nfs-klldap-ui/src/web/acl_status.rs` (`state_label_covers_the_full_enable_acl_by_verdict_matrix`), `web/mod.rs` (`client_manifest_*`, `settings_auto_share_on_capable_fs_renders_acl_on`) |
| Client share manifest `GET /client-manifest.json` (no session required; JSON + `no-store`; minimal fields — internal path keys never serialized; capable auto share publishes `acl`/"auto (on)", incapable publishes `noacl`/"auto (off)"; bypasses the setup-wizard redirect) | `nfs-klldap-ui/src/web/mod.rs` (`client_manifest_is_public_and_minimal`, `client_manifest_acl_share_reports_acl`, `client_manifest_bypasses_setup_gate`) |
| Divergent-submount warning: ACL-incapable mounts strictly below an ACL-serving share's serve root warn on Settings (`fs_warning`); root's own mount never matches; NOACL-resolved shares and capable-only trees stay quiet; unreadable mountinfo ⇒ empty | `nfs-klldap-config/src/fs_probe.rs` (`incapable_submounts_exclude_the_root_mount_itself`), `src/fs_warnings.rs` (`divergent_submount_warning_fires_only_for_acl_serving_share`) |
| Dir ACL editor mirrors the POSIX dir matrix: entry rows + mask stay 2-col (`data-kind` grid), x-less submitted perms fuse r→x server-side on add/set/mask (`AclPerms::dir_r_implies_x`, the `dir_mode_r_implies_x` twin; never clears explicit x), files keep the literal triad | `nfs-klldap-ui/src/privileged.rs` (`acl_perms_dir_r_implies_x_matches_the_mode_fuse`), `web/mod.rs` (`web_acl_apply_dir_add_fuses_execute_from_read`, `web_acl_apply_file_add_keeps_literal_perms`, `web_acl_apply_mask_op_caps_named_entries`, `dir_perms_acl_grid_execute_column_matches_node_kind`) |
| Dir-panel Exec = the FILE-execute grant for recursion (one triad both sides): POSIX Exec column feeds `file_mode` (r/w ride the matrix; separate file-bits editor removed; boxes scope-gated), ACL access add form's Exec box + split walker specs — dirs in reach take fused perms, files take the literal triad (capital-X conditional grant retired) | `nfs-klldap-ui/src/fs.rs` (`acl_recursive_split_specs_dirs_fused_files_literal`, `acl_recursive_single_scope_spares_subdirs`), `web/mod.rs` (`web_acl_apply_recursive_exec_unchecked_files_stay_xless`, `web_acl_apply_scope_all_sweeps_subtree`, `dir_perms_dir_renders_condensed_matrix_with_specials_and_traverse_note`, `dir_perms_acl_grid_execute_column_matches_node_kind`) |
| Settings page probed ACL chips (auto (on)/auto (off)/on (unverified) etc.), status dot, `data-acl-probed` contract with `syncAclStatus` JS, dropdown "auto (detect)" label | `nfs-klldap-ui/src/web/mod.rs` (`settings_auto_share_on_capable_fs_renders_acl_on`, `settings_ganesha_roundtrip_cases`) |
| Recycle latch holds the kind in flight (SharesApply=SIGHUP graceful apply, FullRestart=SIGUSR1): marker mtime ≥ latch ⇒ fresh; task un-latches after marker touch or timeout so a no-op generate can't wedge it; a FullRestart escalates over an in-flight SharesApply instead of being dropped | `nfs-klldap-ui/src/web/settings/mod.rs` (`recycle_tests`), `web/mod.rs` (`recycle_latch_releases_after_marker_and_reschedules`, `full_restart_escalates_over_inflight_shares_apply`) |
| Shares-scoped graceful apply vs forced full recycle: SIGHUP reloads the WebUI in place + rereads Ganesha exports and STAGES identity changes (no daemon restarts); SIGUSR1 restarts everything even with `changed=false` fingerprints; the WebUI's SIGHUP handler surfaces conf edits in-process | `nfs-klldap-config/src/recycle_plan.rs` (unit tests), `tests/supervisor_loop_export_recycle.rs`, `tests/supervisor_loop_identity_recycle.rs`, `tests/supervisor_loop_full_recycle.rs`, `tests/supervisor_identity_recycle_probe.rs`, `nfs-klldap-ui/src/web/tests.rs` (`reload_config_and_fs_picks_up_share_edits`) |
| ACL re-probe watcher (hysteresis: two stable ticks; flapping never fires; auto flip schedules a recycle with rate limit; explicit-on incapable raises a banner + never recycles, clears on heal) | `nfs-klldap-ui/src/web/acl_watch.rs`, `web/mod.rs` (`acl_watch_auto_flip_schedules_recycle`, `acl_watch_explicit_on_incapable_raises_and_clears_banner`, `acl_alert_banner_renders_on_index_and_settings`) |
| LDAP session hygiene: `clear_cache` keeps the resolver instance (pool preserved); pooled-conn idle-staleness predicate; bulk `refresh_identity_data` via `TEST_REBULK_POPULATE`; bind count + pool state surfaced in `/settings/lldap-status`; refresh skip-window predicate | `nfs-klldap-ui/src/ldap.rs` (`clear_cache_keeps_resolver_instance_and_counts_clears`, `refresh_identity_data_bulk_loads_cache_offline`, `stats_expose_bind_count_and_pool_state`), `nfs-klldap-identity/src/ldap/resolver.rs` (`pool_entry_stale_after_idle_max`), `nfs-klldap-ui/src/main.rs` (`refresh_tests`), `web/mod.rs` (`lldap_status_reports_bind_count_and_pool_state`) |
| Mount-root exposure for capability keying (longest-prefix mount match, root-mount fallback, unresolved ⇒ None + "unknown") | `nfs-klldap-config/src/fs_probe.rs` (`mount_root_longest_prefix_wins`, `mount_root_falls_back_to_root_mount`, `mount_root_unresolved_is_none_and_unknown`) |
| Navahi generator (byte-identical output when off; core `Protocols = 3,4` + `Mount_Path_Pseudo` + `MNT_Port 20048` when on while EXPORT_DEFAULTS stays 4; flagged export widens EXPORT+CLIENT to `3,4` and appends `, sys`; advert XML content/escaping, explicit 0644, prefix-scoped prune, dir never created while off) | `nfs-klldap-config/tests/navahi_generate.rs`, `src/generate/avahi.rs` (`xml_escape_covers_the_five_reserved_chars`), `src/tests.rs` (`share_navahi_insecure_valid_no_warnings`, `navahi_effective_requires_both_flags`, `template_defaults_navahi_off_top_level`) |
| Navahi supervisor (avahi child gated on `navahi_discovery` at bring-up; full recycle is the toggle-application path; SharesApply HUPs — never bounces — avahi on advert changes via the `avahi_changed` fingerprint; managed-keyed crash respawn; flag-off recycle stops without revive) | `nfs-klldap-config/tests/supervisor_navahi_avahi.rs`, `src/recycle_plan.rs` (`restart_avahi` asserts), `src/exports_fingerprint.rs` (`avahi_fingerprint_tracks_service_files_only`) |
| Navahi UI (Core BoolAlways toggle lands top-level before the first `[section]`, staged until Restart-and-apply; share-card checkbox muted-not-hidden with passthrough persistence while the global is off and real-clear while on; `navahi` exposure chip only when effective; Overview row; blank card honors the saved global) | `nfs-klldap-ui/src/web/tests.rs` (`settings_save_roundtrips_navahi_toggle`, `settings_navahi_share_roundtrip_and_muting`), `src/web/settings/spec.rs` (`roundtrip_covers_every_field_kind`) |

## Adding tests

1. Prefer pure functions with controlled inputs.
2. Security boundaries, recycle plans, and config derivation are high priority.
3. Update this file in the same change when tests clarify behavior.
