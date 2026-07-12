# Testing

**0.9.x branch.** `cargo test --workspace` (or `make test` + `make clippy`). Workspace crates: `nfs-klldap-identity`, `nfs-klldap-config`, `nfs-klldap-ui`.

Representative full-config generation: `nfs-klldap-config/tests/representative_generate.rs`. Filesystem probe fixtures: unit tests in `nfs-klldap-config/src/fs_probe.rs`. Limited-FS `generate_all` path: `nfs-klldap-config/tests/limited_fs_generate.rs`. Shipped CLI generate gate: `nfs-klldap-config/tests/cli_generate_gate.rs`. `container_path` staging probe + ACL-path Umask/Manage_Gids_Expiration emission: `tests/container_path_generate.rs`. `fs-warnings` CLI: `tests/fs_warnings_cli.rs`. Post-generate hook (SOURCE_PATH/SERVE_PATH env split): unit tests in `src/hook.rs`.

## Strategy

- Pure unit tests for derivation, validation, hostname/keytab variants, credential helpers, allow-lists.
- `tempfile` trees for `FsManager`.
- `tower::ServiceExt` oneshot tests for the Axum router.
- Container/watcher/healthcheck via compose (not unit-tested).

## Well-Tested Areas

- Config: `validate_and_derive`, generate output (including sssd.conf header, no duplicate keys), `load_host_paths_only`, two-tier hostname + `nfs_keytab_host_variants` / `nfs_keytab_host_matches`.
- UI config: `ldap_service_creds` (full DN verbatim, env override).
- FsManager + web handlers: path mapping, safety refusals, tree building, settings save/apply.
- Auth sessions and login cookie round-trip (`web/mod.rs`).

## Hard Areas (Not Unit-Tested)

Live LLDAP/Kerberos binds, recursive chown on real bind mounts, full entrypoint + watcher orchestration.

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
| Filesystem probe (mountinfo fixtures, acl_capable, effective flags, umask validation) | `nfs-klldap-config/src/fs_probe.rs` |
| EXPORT Disable_ACL / Manage_Gids=true (auto NOACL default) + Pseudo (NOACL 0.9.40-style path); distinct from ACL path; Read_Access pre on NOACL only; no post/Enable/POSIX markers | `nfs-klldap-config/src/posix_only_policy.rs` (warnings), `src/generate/` (two paths), `tests/limited_fs_generate.rs`, `tests/cli_generate_gate.rs`, `tests/container_path_generate.rs`, `tests/ganesha_96_identity_audit.rs` |
| Ganesha 9.6 NOTSUPP log classification (ACL-path vs identity-path) + clean client-abort-before-namespace signature — committed fixture `tests/fixtures/ganesha-acl-notsupp.log`, never repo-root logs.txt | `nfs-klldap-config/src/ganesha_log_contract.rs`, `src/bin/idhelper/idmap_log_contract.rs` |
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

## Kerberos user principal idmap verification
Run: `cargo test --workspace` (idmap, resolve, generate, supervisor probes). Idhelper env-mutating tests serialize on `common::ENV_TEST_LOCK` and reset `ID_RESOLVER` via `reset_id_resolver_for_test()` so parallel `cargo test` does not poison `TEST_REBULK_POPULATE` / `NFS_CONFIG` (those env stubs only exist under the `test-support` cargo feature; release binaries ignore them). Invoke `idhelper grps 'user@REALM'` and `host/..@REALM` (full forms + groups). Check emitted limited-FS (NOACL) fragments for `Pseudo = /<name>;`, `Disable_ACL = true;`, `Manage_Gids = true;` (auto default; explicit `manage_gids=false` overrides), and `Read_Access_Check_Policy = pre;` (0.9.40-style; no POSIX markers). `cargo test -p nfs-klldap-config idmap_log_contract` classifies OP_ACCESS/GETATTR ACL-path NOTSUPP vs identity-path failures against the committed fixture. `ganesha-ctl id-resolve` / `id-check` + `nfs-klldap-config generate/validate` surface the post-generate id resolution check (warns on incomplete user/host resolution).

## Fedora 44 krb5p client (container)
`scripts/fedora-krb5p-client-validate.sh` — machine kinit + sec=krb5p; on mount failure it captures `mount -vvv` output + kernel nfs/rpc/gss messages. User TGT: Kerberos principal, host rpc_pipefs, client idmapd, use-machine-creds=0. Server: NOACL default emits `Manage_Gids = true` (set `manage_gids=false` to skip AUTH_SYS managed gids only); krb5p/krb5i require `UseGetpwnam=true` + idhelper nss_wrapper supplemental groups (`getpwuid_r for uid:` + `getgrouplist for uname:` LogInfo). DOCKER_NO_CACHE after changes. Client mount steps for real Bazzite/Silverblue hosts: [docs/client-fedora-immutable.md](docs/client-fedora-immutable.md).

## NSS snapshot golden tests
`build_nss_snapshot` + ensure drive complete supps in both stores; ondemand fast cache + uid0 tests cover reactive authoritative path for getgrouplist.

Documentation and tests should be updated together when behavior changes. (See also fs.rs symlink policy comments and privileged.rs boundary.)