# Testing

**0.9.x branch.** Gate chain before a commit lands: `make test`, `make clippy` (nightly, `-D warnings`), `scripts/safety-dance.sh` (unsafe-code audit; wraps clippy), and `python3 scripts/comment_lint.py` (comment quality). Workspace crates: `nfs-klldap-identity`, `nfs-klldap-config`, `nfs-klldap-ui`. Operator diagnostic for the host-side uid2grp chain (run before the first client mount): `scripts/ganesha-chain-preflight.sh`.

Representative full-config generation: `nfs-klldap-config/tests/representative_generate.rs`. Filesystem probe fixtures: unit tests in `nfs-klldap-config/src/fs_probe.rs`. Limited-FS `generate_all` path: `nfs-klldap-config/tests/limited_fs_generate.rs`. Shipped CLI generate gate: `nfs-klldap-config/tests/cli_generate_gate.rs`. `container_path` staging probe + ACL-path Umask/Manage_Gids_Expiration emission: `tests/container_path_generate.rs`. `fs-warnings` CLI: `tests/fs_warnings_cli.rs`. Post-generate hook (SOURCE_PATH/SERVE_PATH env split): unit tests in `src/hook.rs`.

## Strategy

- Pure unit tests for derivation, validation, hostname/keytab variants, credential helpers, allow-lists.
- `tempfile` trees for `FsManager`.
- `tower::ServiceExt` oneshot tests for the Axum router.
- Container/watcher/healthcheck via compose (not unit-tested).

## Well-Tested Areas

- Config: `validate_and_derive`, generate output (including sssd.conf header, no duplicate keys), `load_host_paths_only`, two-tier hostname + `nfs_keytab_host_variants` / `nfs_keytab_host_matches`.
- Probe identities: `[probe]`/env/auto-pick precedence and the no-candidate skip path (`ganesha_identity_pipeline.rs` tests; readiness gate passes `Some(user)`).
- UI config: `ldap_service_creds` (full DN verbatim, env override).
- FsManager + web handlers: path mapping, safety refusals, tree building, settings save/apply.
- Auth sessions and login cookie round-trip (`web/mod.rs`).

## Hard Areas (Not Unit-Tested)

Live LLDAP/Kerberos binds, recursive chown on real bind mounts, full entrypoint + watcher orchestration. Admin-login bind verification (`try_simple_bind`) needs a live LLDAP; the fail-closed mapping is unit-tested (`bind_verdict`) but the actual wrong-password rejection is a manual check. The pooled-connection idle discard needs a live server too; only the staleness predicate (`pool_entry_stale`) is unit-tested.

## Patterns

### Config (`nfs-klldap-config`)

- Golden checks on generated `sssd.conf` (see `generate_produces_expected_artifacts` in `lib.rs`).
- `tempfile` for generation paths.

### WebUI (`nfs-klldap-ui`)

- `FsManager` with `tempfile::tempdir()` and symlinks for WalkDir policy tests.
- Router tests with `app.oneshot(request)` — preserve exact `Set-Cookie` on 303 login flows.

### Auth sidecar

`webui-password` uses iterated SHA-256 (not bcrypt). See `nfs-klldap-ui/src/auth.rs`.

## Adding Tests — Checklist

1. Prefer pure functions with controlled inputs.
2. Security boundaries and config derivation are high priority.
3. Update docs in the same change when tests clarify behavior.

## Living Specification (module → tests)

| Behavior | Tests |
|----------|--------|
| `ldap_service_creds` (verbatim DN, env override) | `nfs-klldap-ui/src/config.rs` |
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
| EXPORT Disable_ACL / Manage_Gids=true (auto NOACL default) + Pseudo (NOACL 0.9.40-style path); distinct from ACL path; Read_Access pre on NOACL only; no post/Enable/POSIX markers | `nfs-klldap-config/src/posix_only_policy.rs` (warnings), `src/generate/` (two paths), `tests/limited_fs_generate.rs`, `tests/cli_generate_gate.rs`, `tests/container_path_generate.rs`, `tests/ganesha_96_identity_audit.rs` |
| Ganesha NOTSUPP log classification (9.6-era signatures; ACL-path vs identity-path) + clean client-abort-before-namespace signature — committed fixture `tests/fixtures/ganesha-acl-notsupp.log`, never repo-root logs.txt | `nfs-klldap-config/src/ganesha_log_contract.rs`, `src/bin/idhelper/idmap_log_contract.rs` |
| Post-generate hook env contract (SOURCE_PATH/SERVE_PATH/CONTAINER_PATH/PSEUDO_PATH/EXPORT_PATH) | `nfs-klldap-config/src/hook.rs` |
| Wizard gates (`validate_ldap_uri`, step2/step3 test-before-continue) + session cookie extraction | `nfs-klldap-ui/src/web/setup.rs`, `web/auth.rs` |
| LDAP TLS policy (cacert ⇒ verify, reqcert=never override) | `nfs-klldap-identity/src/ldap/tls.rs` |
| idhelper full principal forms (user@REALM + host/..@REALM) + GRPS groups + resolution check | `nfs-klldap-config/src/bin/idhelper/{resolve,main}.rs` + lib check, limited_fs_generate + new fallback tests |
| Hostname consistency + keytab variants + docker-id detection | `nfs-klldap-config/src/hostname.rs`, `lib.rs` |
| Keytab status message / alert | `nfs-klldap-ui/src/web/keytab.rs` |
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
| Recycle latch releases (one HUP in flight): marker mtime ≥ latch ⇒ fresh; task un-latches after marker touch or timeout so a no-op generate can't wedge it | `nfs-klldap-ui/src/web/settings/mod.rs` (`recycle_tests`), `web/mod.rs` (`recycle_latch_releases_after_marker_and_reschedules`) |
| ACL re-probe watcher (hysteresis: two stable ticks; flapping never fires; auto flip schedules a recycle with rate limit; explicit-on incapable raises a banner + never recycles, clears on heal) | `nfs-klldap-ui/src/web/acl_watch.rs`, `web/mod.rs` (`acl_watch_auto_flip_schedules_recycle`, `acl_watch_explicit_on_incapable_raises_and_clears_banner`, `acl_alert_banner_renders_on_index_and_settings`) |
| LDAP session hygiene: `clear_cache` keeps the resolver instance (pool preserved); pooled-conn idle-staleness predicate; bulk `refresh_identity_data` via `TEST_REBULK_POPULATE`; bind count + pool state surfaced in `/settings/lldap-status`; refresh skip-window predicate | `nfs-klldap-ui/src/ldap.rs` (`clear_cache_keeps_resolver_instance_and_counts_clears`, `refresh_identity_data_bulk_loads_cache_offline`, `stats_expose_bind_count_and_pool_state`), `nfs-klldap-identity/src/ldap/resolver.rs` (`pool_entry_stale_after_idle_max`), `nfs-klldap-ui/src/main.rs` (`refresh_tests`), `web/mod.rs` (`lldap_status_reports_bind_count_and_pool_state`) |
| Mount-root exposure for capability keying (longest-prefix mount match, root-mount fallback, unresolved ⇒ None + "unknown") | `nfs-klldap-config/src/fs_probe.rs` (`mount_root_longest_prefix_wins`, `mount_root_falls_back_to_root_mount`, `mount_root_unresolved_is_none_and_unknown`) |

## Kerberos user principal idmap verification
Run: `cargo test --workspace` (idmap, resolve, generate, supervisor probes). Idhelper env-mutating tests serialize on `common::ENV_TEST_LOCK` and reset `ID_RESOLVER` via `reset_id_resolver_for_test()` so parallel `cargo test` does not poison `TEST_REBULK_POPULATE` / `NFS_CONFIG` (those env stubs only exist under the `test-support` cargo feature; release binaries ignore them). Invoke `idhelper grps 'user@REALM'` and `host/..@REALM` (full forms + groups). Check emitted limited-FS (NOACL) fragments for `Pseudo = /<name>;`, `Disable_ACL = true;`, `Manage_Gids = true;` (auto default; explicit `manage_gids=false` overrides), and `Read_Access_Check_Policy = pre;` (0.9.40-style; no POSIX markers). `cargo test -p nfs-klldap-config idmap_log_contract` classifies OP_ACCESS/GETATTR ACL-path NOTSUPP vs identity-path failures against the committed fixture. `ganesha-ctl id-resolve` / `id-check` + `nfs-klldap-config generate/validate` surface the post-generate id resolution check (warns on incomplete user/host resolution).

## Fedora 44 krb5p client (container)
`scripts/fedora-krb5p-client-validate.sh` — machine kinit + sec=krb5p; on mount failure it captures `mount -vvv` output + kernel nfs/rpc/gss messages. User TGT: Kerberos principal, host rpc_pipefs, client idmapd, use-machine-creds=0. Server: NOACL default emits `Manage_Gids = true` (set `manage_gids=false` to skip AUTH_SYS managed gids only); krb5p/krb5i require `UseGetpwnam=true` + idhelper nss_wrapper supplemental groups (`getpwuid_r for uid:` + `getgrouplist for uname:` LogInfo). DOCKER_NO_CACHE after changes. Client mount steps for real Bazzite/Silverblue hosts: [docs/client-fedora-immutable.md](docs/client-fedora-immutable.md).

## NSS snapshot golden tests
`build_nss_snapshot` + ensure drive complete supps in both stores; ondemand fast cache + uid0 tests cover reactive authoritative path for getgrouplist.

Documentation and tests should be updated together when behavior changes. (See also fs.rs symlink policy comments and privileged.rs boundary.)