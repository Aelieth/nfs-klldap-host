# Testing

**0.9.x branch.** `cargo test --workspace` (or `make test` + `make clippy`). Workspace crates: `nfs-klldap-identity`, `nfs-klldap-config`, `nfs-klldap-ui`.

Representative full-config generation: `nfs-klldap-config/tests/representative_generate.rs`. Filesystem probe fixtures: `nfs-klldap-config/tests/fs_probe_fixtures.rs`. Limited-FS `generate_all` path: `nfs-klldap-config/tests/limited_fs_generate.rs`. `ganesha_path` staging probe: `tests/ganesha_path_generate.rs`. `fs-warnings` CLI: `tests/fs_warnings_cli.rs`. Post-generate hook: `tests/post_generate_hook.rs`.

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
| Generated sssd.conf shape + no dups + tls options | `nfs-klldap-config/src/lib.rs` |
| Filesystem probe (mountinfo fixtures, acl_capable, effective flags) | `nfs-klldap-config/src/fs_probe.rs`, `tests/fs_probe_fixtures.rs` |
| EXPORT Disable_ACL / Manage_Gids emission | `nfs-klldap-config/src/generate.rs`, `tests/limited_fs_generate.rs` |
| Hostname consistency + keytab variants + docker-id detection | `nfs-klldap-config/src/hostname.rs`, `lib.rs` |
| Keytab status message / alert | `nfs-klldap-ui/src/web/keytab.rs` |
| Axum settings/apply/auth + login flows + cookie policy + empty-uid apply | `nfs-klldap-ui/src/web/mod.rs` (and sub) |
| ApplyOptions (continue, dry, recursive policy, symlink skip) + WalkDir safety | `nfs-klldap-ui/src/fs.rs` |
| Ldap list filters, normalize query, cache behavior (unit) | `nfs-klldap-ui/src/ldap.rs` (list_search_tests) |

Documentation and tests should be updated together when behavior changes. (See also fs.rs symlink policy comments and privileged.rs boundary.)