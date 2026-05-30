## Unreleased

### LLDAP / KLLDAP WebUI Client (nfs-klldap-ui)

- Fixed management URL derivation: `derive_lldap_url` now produces `http://<host>:17170/api/graphql` (standard LLDAP management port) using the shared `extract_host_from_uri`. Previously incorrectly glued the LDAP service port (6360/3890) and forced https.
- Switched service + per-user authentication from the legacy GraphQL `login` mutation to the documented REST endpoint `POST /auth/simple/login` (expects `{token, refreshToken}` response). Both `authenticate` (service account at startup) and `verify_user_credentials` (WebUI login) now use it.
- Added `derive_login_url`, `last_auth_time`, and `authenticated_as()` to `LldapClient`.
- Added `/settings/lldap-status` (GET fragment) and `/settings/reload-nfs-client` (POST) with HTMX support. Operators can now hot-reload the long-lived permission client (used for live user/group search + `resolve_user`/`resolve_group` before chown) after editing `sssd.ldap_default_bind_dn` / `authtok` or `management.lldap_graphql_url` without restarting the container.
- Settings page now shows current service identity, last auth time, and a yellow drift notice when on-disk creds differ from the in-memory client.
- Both new endpoints enforce the existing session auth model (`require_auth`).
- "localhost" (simple sidecar) sessions continue to use the service bind DN credentials for all LLDAP-backed NFS permission operations (unchanged behavior, now explicitly supported by the reload path).
- Updated default template comment and relevant tests.

### Documentation & Testing
- Updated TESTING.md, root + UI READMEs, and ldap-integration.md to reflect the client changes and new reload UX.
- `cargo test --workspace` + `clippy -D warnings` clean.

### Internal Modularization of `nfs-klldap-config`

- Major refactor to split the previously monolithic `src/lib.rs` (~1,529 lines) into focused, maintainable modules.
- New module layout:
  - `config.rs` — Data model (`NfsKlldapConfig`, all sections, `Share`, `GenerationPaths`)
  - `error.rs` — `ConfigError`
  - `validate.rs` — Loading, validation, and auto-derivation logic
  - `persist.rs` — Persistent volume detection and tolerant partial share loading
  - `uri.rs` — URI parsing helpers (`extract_host_from_uri`, `derive_realm_from_uri`)
  - `hostname.rs` — Hostname suggestion logic and Docker default detection
  - `template.rs` — First-run safe default template + write-if-missing helper
  - `generate.rs` — Full generation engine (sssd.conf, krb5.conf, Ganesha exports)
- `lib.rs` is now a thin, well-documented facade containing only:
  - Crate-level documentation
  - Module declarations
  - Deliberate public re-exports
- The **public API surface** (all types and functions re-exported from the crate root) remains **100% unchanged**.
- Internal module layout is explicitly documented as **not** part of the semver contract.
- All consumers (`nfs-klldap-config` binary, `nfs-klldap-startup` binary, and `nfs-klldap-ui`) continue to work without any code changes.
- This addresses long-term project growth while preserving the "single source of truth" guarantees of the crate.

### Structural Refactor
- Crates moved to top-level for a cleaner layout:
  - `nfs-klldap-config/` (library + `nfs-klldap-config` + `nfs-klldap-startup` binaries)
  - `nfs-klldap-ui/` (the in-container WebUI)
- Root `Cargo.toml` now defines a proper workspace with `[workspace.package]` (version, edition, authors, license, repository) and `[workspace.dependencies]` (shared `serde`, `toml`, `serde_json`, `tempfile`).
- All internal path dependencies, Docker build stages, Makefile targets, and documentation updated for the new structure.
- `cargo build --workspace` and `docker build` are now the primary documented build paths.

### Documentation & Cleanup
- Major weeding pass across README.md, TESTING.md, CHANGELOG.md, entrypoint.sh, and supporting scripts to remove v0.5 transition scaffolding and pre-centralization language.
- New `container/README.md` documenting the supporting scripts (`ganesha-ctl`, `nfs-klldap-conf-watcher`, `webui-certs`, `healthcheck.sh`).
- `entrypoint.sh` and `healthcheck.sh` significantly hardened (preflight checks, extracted permission logic, better logging, configurable paths, robust signal handling).
- All container scripts audited for absence of legacy host-side/sudo logic and given consistent documentation.

### Other
- Project now presents a clear "Clone → `cargo build --workspace` or `docker build`" story as the single source of truth.

---

## What's New in v0.5

This is a major release focused on correctness, simplicity, and Red Hat compatibility.

### Core Architecture Changes
- **All services now run as root inside the container** (sssd, Ganesha, config watcher, and the WebUI). This matches upstream expectations on RHEL/AlmaLinux/Fedora for sssd and Kerberos components. The previous non-root hardening attempt (dedicated `nfs` user, gosu drops, keytab group, SSSD responder pipe permission hacks, etc.) has been fully removed.
- **WebUI is now fully in-container**: `nfs-klldap-ui` is built into the image and starts automatically on port **9630** (HTTPS with self-signed certificate by default, or user-provided certs from the config directory). No separate host-side process is required for normal operation.
- Removed the legacy `docker exec` permission delegation path in the WebUI. All `chown`/`chmod` operations are now performed directly inside the container.

### WebUI Authentication (v0.5 complete)
- Full hybrid auth implemented and wired:
  - Special immutable `localhost` user + bcrypt-hashed sidecar `/config/webui-password` (0600) → local machine admin (uses the service `ldap_default_*` credentials for subsequent LLDAP lookups).
  - Any other username → LLDAP REST login (`/auth/simple/login`) + membership check in `webui_admin_group` (default `lldap_admin`) → network admin.
  - First-run experience: when no sidecar exists, the login page shows a dedicated "set initial password" form (`POST /setup-password`) that auto-logs the operator in as `localhost`.
  - All legacy sudo/wheel logic removed from auth.rs and the login flow.
- Login is now fully functional for the intended use cases (the blocking item for "even begin logging in").

### Cleanup & Documentation
- Removed large amounts of dead legacy code: gosu installation, old sudoers.d fragments, non-root daemon startup logic in entrypoint.sh, and the entire previous host-side privilege model.
- Extensive documentation refresh across all READMEs, docs/, and examples/ to reflect the current root + in-container WebUI reality. Outdated references to host-side UI, docker exec for permissions, and non-root container operation have been removed or clearly marked as historical.

### Other
- Version bumped to 0.5.0 across Cargo.toml packages and documentation.
- `webui_admin_group` support added to the `[management]` section of `nfs-klldap.conf`.

---

## What's New in v0.4

- Major migration: the 4-step guided first-run experience, reachability tests, banner,
  and runtime diagnostics have moved from `entrypoint.sh` into the Rust binary
  `nfs-klldap-startup` (part of the `nfs-klldap-config` crate).
- Realm is now shown in the startup banner via best-effort derivation from `ldap_uri`.
- Hostname guidance now recommends the DNS-friendly insertion pattern
  (`testpc.example.com` → `testpc-nfs.example.com`) and the TUI suggests the correct name.
- Step progress in the guided TUI now correctly marks completed steps with `[√]`.
- Documentation (READMEs, architecture docs, compose examples) updated for the new
  startup flow and hostname convention.
