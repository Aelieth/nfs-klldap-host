## What's New in v0.5

This is a major release focused on correctness, simplicity, and Red Hat compatibility.

### Core Architecture Changes
- **All services now run as root inside the container** (sssd, Ganesha, config watcher, and the WebUI). This matches upstream expectations on RHEL/AlmaLinux/Fedora for sssd and Kerberos components. The previous non-root hardening attempt (dedicated `nfs` user, gosu drops, keytab group, SSSD responder pipe permission hacks, etc.) has been fully removed.
- **WebUI is now fully in-container**: `nfs-klldap-ui` is built into the image and starts automatically on port **9630** (HTTPS with self-signed certificate by default, or user-provided certs from the config directory). No separate host-side process is required for normal operation.
- Removed the legacy `docker exec` permission delegation path in the WebUI. All `chown`/`chmod` operations are now performed directly inside the container.

### WebUI Authentication (v0.5 complete)
- Full hybrid auth implemented and wired:
  - Special immutable `localhost` user + bcrypt-hashed sidecar `/config/webui-password` (0600) → local machine admin.
  - Any other username → LLDAP GraphQL login + membership check in `webui_admin_group` (default `lldap_admin`) → network admin.
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
