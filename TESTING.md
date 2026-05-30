# Testing nfs-klldap-host

This document describes the testing strategy, current coverage, and how to run tests. It is maintained alongside the code — writing or expanding tests is the primary way new behavior is documented.

## Philosophy

- **Prefer pure unit tests** for logic that does not touch the filesystem, network, or external processes.
- **Use realistic integration tests** (with `tempfile`, in-memory servers, etc.) where they provide high value without excessive fragility.
- **Document hard-to-test areas** explicitly (privileged operations delegated to the container, live LLDAP).
- Permission changes are performed inside the container after host-side validation in the web handlers and `FsManager`.

## Current State

| Crate / Area                  | Test Coverage                          | Notes |
|-------------------------------|----------------------------------------|-------|
| `nfs-klldap-config` (lib + binaries) | Good + actively expanded        | Core validation, generation, `load_host_paths_only`, helper functions. |
| `nfs-klldap-ui`               | Good for critical pure logic           | `config.rs` helpers, `FsManager` (with real temp dirs), Axum handlers for settings save. |
| Web handlers (`web.rs`)       | Targeted (settings flows)              | Uses `tower::ServiceExt` against real router + realistic `AppState`. |
| Auth (`auth.rs`)              | Partial                                | Session management well covered. |
| LLDAP client (`llap.rs`)      | None                                   | Requires live (or mocked) GraphQL server — intentionally limited. |
| Container scripts & entrypoint| None (shell)                           | Best exercised via Docker / compose runs. |

## Running Tests

```bash
# From a fresh clone
cargo test --workspace

# With the Makefile (also runs clippy targets)
make test
make clippy
```

## Recommended Testing Patterns

### 1. Pure Configuration & Helper Logic (`nfs-klldap-ui/src/config.rs`)

Functions like `lldap_login_creds`, `derive_lldap_url`, and `all_managed_roots` are excellent for unit tests.

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
- Host path → container path translation
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

- **LLDAP credential extraction** (`lldap_login_creds`): DN parsing (`uid=`, `cn=`), environment variable override, graceful fallback. See `nfs-klldap-ui/src/config.rs` tests.
- **URL derivation** for the GraphQL client (`derive_lldap_url`).
- **Allow-list root computation** (`all_managed_roots` + `is_allowed` in `FsManager`).
- **FsManager** (`is_allowed`, `build_tree`, host→container path mapping): Tested with real temporary directory trees. See `nfs-klldap-ui/src/fs.rs` tests.
- **Axum handlers** (settings save raw + structured + permission apply): Tested using `tower::ServiceExt::oneshot` against the real router. See `nfs-klldap-ui/src/web.rs` tests.
- **Partial config loading** (`load_host_paths_only`) — used for the WebUI share allow-list.
- **Name sanitization** and deterministic export ID generation in the generator.
- **Safety checks** before delegating to the container (root UID/GID refusal, high-bit mode refusal).

These tests serve as both regression protection and living specification.

## Documentation & Tests Are One Activity

Every time a new test is written for a previously under-documented area (e.g., `load_host_paths_only` behavior, DN parsing rules, share allow-list semantics), the corresponding documentation (in code comments, `TESTING.md`, root `README`, or architecture docs) should be updated in the same change.

This repository treats "I added a test that forced me to understand X" as the trigger for improving the docs for X.
