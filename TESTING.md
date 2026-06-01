# Testing

`cargo test --workspace` (or `make test` + `make clippy`).

## Strategy

- Pure unit tests preferred for derivation, validation, hostname, credential helpers, allow-lists.
- `tempfile` trees for `FsManager` (build_tree, is_allowed, host↔container translation).
- `tower::ServiceExt` oneshot tests for the real Axum router (settings, apply, auth).
- Container/watcher/healthcheck exercised via compose (not unit-testable).

## Well-Tested Areas

- Config: validate_and_derive (realm, IP rejection, duplicate shares, security enum), generate output, load_host_paths_only, two-tier hostname contract + suggested_nfs_hostname.
- UI config: ldap_service_creds (full DN, env override).
- FsManager + web handlers: path mapping, safety refusals (uid 0, setid), tree building, settings save/apply.
- Auth sessions.

## Hard Areas (Intentionally Not Unit-Tested)

Live LLDAP binds, recursive chown on real bind mounts, full entrypoint + watcher orchestration.



## Recommended Testing Patterns

### 1. Pure Configuration & Helper Logic (`nfs-klldap-ui/src/config.rs`)

Functions like `ldap_service_creds`, `derive_lldap_url`, and `all_managed_roots` are excellent for unit tests.

Example (add under `#[cfg(test)] mod tests`):

```rust
#[test]
fn lldap_creds_parses_dn_and_prefers_env() {
    // test DN parsing + env override
}
```

### 2. Filesystem Manager (`nfs-klldap-ui/src/fs.rs`)

- Construct `FsManager` with a known `Config` containing specific shares.
- Use `tempfile::tempdir()` to create real directory trees for `build_tree` tests.
- Test `is_allowed` behavior in isolation.

### 3. In-Container Permission Logic

The primary path is now fully inside the container: the WebUI validates requests (`FsManager::is_allowed`, refusal of uid 0 / dangerous modes) and then performs `chown`/`chmod` directly on the bind-mounted host paths using libc (running as root).

Relevant testable pieces (in `nfs-klldap-ui`):
- Host path → container path translation (exercised by both `apply_permissions` writes and `build_tree` / the live directory tree browser in the WebUI)
- Recursive vs non-recursive command construction
- Safety checks before applying changes

Full end-to-end permission application is best exercised with a running container + real bind mounts.

### 4. Web Layer (when adding)

Use Axum's test utilities:

```rust
use axum::body::Body;
use http::Request;
use tower::ServiceExt; // for `oneshot`

// then
let response = app.oneshot(request).await.unwrap();
```

**Auth / login flows**: The primary integration test (`full_localhost_first_run_login_session_and_protected_route_flow` in `nfs-klldap-ui/src/web/mod.rs`) now follows real 303 redirects and round-trips the *exact* `Set-Cookie` value emitted by the handlers (parsed via the `cookie` crate) into the subsequent GET. This pattern catches "successful POST but cookie never reaches the redirect target" bugs (Secure flag, SameSite, Max-Age, extraction, etc.). Extend it or add focused helpers when touching `require_auth`, cookie builders, or login handlers.

### 5. Config Library (`nfs-klldap-config`)

Continue expanding here for:
- `load_host_paths_only` (tolerant partial parse)
- Edge cases in `validate_and_derive`
- Export ID determinism
- Share name sanitization

## Hard-to-Test Areas (Documented Limitations)

- Live interaction with external LLDAP + Kerberos (credential validation, group membership).
- Full recursive permission application on real bind-mounted host data (best done manually or via integration containers).
- Container startup, watcher, and healthcheck behavior (best exercised via `docker compose` or manual container runs).
- The `localhost` password sidecar path in auth (involves filesystem + bcrypt).

For these areas we rely on:
- Strong type safety + validation in the happy path.
- Unit tests for the pure logic around allow-lists, path mapping, and config derivation.
- Manual testing + the container healthcheck.

## Adding New Tests — Checklist

1. Can this logic be made pure or given controlled inputs? If yes → unit test.
2. Does the test exercise a security boundary or config derivation? High priority.
3. Does writing the test reveal that the code or docs are unclear? Update docs immediately.
4. Update this `TESTING.md` with any new patterns or newly testable modules.

## Currently Well-Tested Behaviors (with links to tests)

- **LDAP service credential extraction** (`ldap_service_creds`): DN parsing (`uid=`, `cn=`), environment variable override, graceful fallback. See `nfs-klldap-ui/src/config.rs` tests.
- **URL derivation** for the LLDAP client (`derive_lldap_url`, `derive_login_url`).
- **NFS client reload** (`lldap_status` + `reload_nfs_client` handlers + credential drift detection in `web/` layer).
- **Allow-list root computation** (`all_managed_roots` + `is_allowed` in `FsManager`).
- **FsManager** (`is_allowed`, `build_tree`, host→container path mapping): Tested with real temporary directory trees. See `nfs-klldap-ui/src/fs.rs` tests.
- **Axum handlers** (settings save raw + structured + permission apply): Tested using `tower::ServiceExt::oneshot` against the real router. See `nfs-klldap-ui/src/web/mod.rs` tests (WebUI router).
- **Partial config loading** (`load_host_paths_only`) — used for the WebUI share allow-list.
- **Name sanitization** and deterministic export ID generation in the generator.
- **Safety checks** before delegating to the container (root UID/GID refusal, high-bit mode refusal).

These tests serve as both regression protection and living specification.

## Documentation & Tests Are One Activity

Every time a new test is written for a previously under-documented area (e.g., `load_host_paths_only` behavior, DN parsing rules, share allow-list semantics), the corresponding documentation (in code comments, `TESTING.md`, root `README`, or architecture docs) should be updated in the same change.

This repository treats "I added a test that forced me to understand X" as the trigger for improving the docs for X.
