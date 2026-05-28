# Testing nfs-klldap-host

This document describes the testing strategy, current coverage, and how to run tests. It is maintained alongside the code — writing or expanding tests is the primary way new behavior is documented.

## Philosophy

- **Prefer pure unit tests** for logic that does not touch the filesystem, network, or external processes.
- **Use realistic integration tests** (with `tempfile`, in-memory servers, etc.) where they provide high value without excessive fragility.
- **Document hard-to-test areas** explicitly (privileged operations delegated to the container, live LLDAP).
- Permission changes are performed inside the container after host-side validation in the web handlers and `FsManager`.

## Current State (as of v0.3)

| Crate / Area                  | Test Coverage                          | Notes |
|-------------------------------|----------------------------------------|-------|
| `nfs-klldap-config` (lib)     | Good + actively expanded               | Core validation, generation, `load_host_paths_only`, helper functions. |
| `management` (UI)             | Good for critical pure logic           | `config.rs` helpers, `FsManager` (with real temp dirs), Axum handlers for settings save. |
| Web handlers (`web.rs`)       | Targeted (settings flows)              | Uses `tower::ServiceExt` against real router + realistic `AppState`. |
| Auth (`auth.rs`)              | Partial                                | Session management well covered; sudo interaction remains external. |
| LLDAP client (`llap.rs`)      | None                                   | Requires live (or mocked) GraphQL server — intentionally limited. |
| Container / entrypoint        | None (shell + healthcheck)             | Best exercised via Docker / compose runs. |

## Running Tests

```bash
# All tests
make test

# Or directly
cargo test --workspace

# Strict linting (used in CI)
make clippy
```

## Recommended Testing Patterns

### 1. Pure Configuration & Helper Logic (`management/src/config.rs`)

Functions like `lldap_login_creds`, `derive_lldap_url`, and `all_managed_roots` are excellent for unit tests.

Example (add under `#[cfg(test)] mod tests`):

```rust
#[test]
fn lldap_creds_parses_dn_and_prefers_env() {
    // test DN parsing + env override
}
```

### 2. Filesystem Manager (`management/src/fs.rs`)

- Construct `FsManager` with a known `Config` containing specific shares.
- Use `tempfile::tempdir()` to create real directory trees for `build_tree` tests.
- Test `is_allowed` behavior in isolation.

### 3. Container-Delegated Permission Logic

Permission changes are validated in the host UI (`FsManager::is_allowed`, refusal of uid 0 / dangerous modes) and then executed inside the container via `docker exec`.

Relevant testable pieces:
- Host path → container path translation
- Recursive vs non-recursive command construction
- Error handling when `docker exec` fails

Full end-to-end `apply_permissions` is best exercised with a running container.

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

- Anything that calls `sudo -S` or `id` externally.
- Full recursive `apply_permissions` (requires a running container with the right capabilities + docker socket access).
- End-to-end flows that need a live LLDAP + Kerberos environment.
- Container startup / watcher behavior (best exercised via manual Docker runs or compose tests).

For these areas we rely on:
- Strong type safety + validation in the happy path.
- Narrow, auditable unsafe-free privileged code (after the 2026 cleanup).
- Manual testing + healthchecks.

## Adding New Tests — Checklist

1. Can this logic be made pure or given controlled inputs? If yes → unit test.
2. Does the test exercise a security boundary or config derivation? High priority.
3. Does writing the test reveal that the code or docs are unclear? Update docs immediately.
4. Update this `TESTING.md` with any new patterns or newly testable modules.

## Currently Well-Tested Behaviors (with links to tests)

- **LLDAP credential extraction** (`lldap_login_creds`): DN parsing (`uid=`, `cn=`), environment variable override, graceful fallback. See `management/src/config.rs` tests.
- **URL derivation** for the GraphQL client (`derive_lldap_url`).
- **Allow-list root computation** (`all_managed_roots` + `is_allowed` in `FsManager`).
- **FsManager** (`is_allowed`, `build_tree`, host→container path mapping): Tested with real temporary directory trees. See `management/src/fs.rs` tests.
- **Axum handlers** (settings save raw + structured + permission apply): Tested using `tower::ServiceExt::oneshot` against the real router. See `management/src/web.rs` tests.
- **Partial config loading** (`load_host_paths_only`) — still useful for the host UI allow-list.
- **Name sanitization** and deterministic export ID generation in the generator.
- **Safety checks** before delegating to the container (root UID/GID refusal, high-bit mode refusal).

These tests serve as both regression protection and living specification.

## Documentation & Tests Are One Activity

Every time a new test is written for a previously under-documented area (e.g., `load_host_paths_only` behavior, DN parsing rules, share allow-list semantics), the corresponding documentation (in code comments, `TESTING.md`, root `README`, or architecture docs) should be updated in the same change.

This repository treats "I added a test that forced me to understand X" as the trigger for improving the docs for X.
