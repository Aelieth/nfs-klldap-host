# nfs-klldap-host Code Audit TODO (2026)

This file was produced by the full code audit chore. **Actual code always takes precedence** over docs, comments, tests descriptions, and examples. Documentation and comments were aligned to match observed behavior in source. Only absolutely necessary non-behavior edits were made (version strings in usage text, explanatory comments pruned of "NEW:" markers, setup verbosity untouched).

Tests were verified passing (`cargo test --workspace`).

## Items requiring no immediate action (aligned or low impact)

- Most module docs, doc comments, and high-level READMEs / docs/*.md now reflect current validation, generation, two-tier hostname, FsManager WalkDir policy (follow_links(false) + filter, numeric only, no root/setid), async apply progress, hybrid auth, LLDAP client details, etc.
- Setup TUI in `nfs-klldap-config/src/bin/nfs_klldap_startup.rs` (the 4-step guided loop + rich diagnostics + banner) intentionally verbose for first-time users — left exactly as-is per requirements.
- Default config template (`template.rs`) long header comments kept verbatim for new users.
- Security contracts detailed in `nfs-klldap-ui/src/fs.rs` and `privileged.rs` are the source of truth (README cross-refs them).
- All unit tests (config derivation, golden sssd/krb5/exports, hostname, fs policy+translation, auth flows+cookie, apply dry/symlink/nonrec, ldap normalize+filters, web router oneshot) pass and cover the behaviors described.

## Items noted (no code changes made; behavior/code is source of truth)

1. **Versioning**
   - Workspace `Cargo.toml` declares `version = "0.7.0"`.
   - Git branch at audit start: `0.6.9` (superseded by 0.7.0 alignment; no matching tag visible in `git describe`).
   - CLI usage text shows `v0.7` (docs alignment only).
   - No `CARGO_PKG_VERSION` used at runtime for banners/usage (hardcoded or omitted). If a release process canonicalizes this, it is not reflected in source.

2. **nfs-klldap-ui structured settings editor is intentionally partial**
   - `/settings` "Structured Editor" only offers a subset of top-level fields + always-blank share rows (JS adds more; submit replaces `[[shares]]` if any provided).
   - Current shares are **not** pre-populated from disk config into the form (HTML comments + code in `web/settings.rs` + `templates/settings.html` make this explicit).
   - Raw TOML editor is the full-fidelity path (preserves comments/order via toml_edit).
   - Docs (root README, ui README) call it "Raw + structured TOML editor" — accurate at high level but the structured part is a convenience subset, not a complete round-trippable view of the TOML.
   - Template comment and H3 updated during audit for clarity; no behavior change.

3. **sssd.enumerate guidance (now aligned)**
   - Core: default `false` in `GaneshaSection`/`SssdSection` + `resolve...` + generator + `docs/ldap-integration.md` ("do NOT set true on KLLDAP without reason", "enumerate=true is discouraged").
   - UI form previously had `checked` + "recommended True for small..." (conflicted).
   - Form label + checked attr updated to match code/docs during audit. (Checkbox still present for users who know what they're doing.)

4. **Incomplete pre-pop / "fuller version" in settings UI**
   - Shares section in structured form starts with one static example row (idx 0) + add button. No server-side rendering of existing `[[shares]]` values (contrast with raw textarea which loads current text).
   - `web/settings.rs:collect_shares_from_structured_form` + `apply...` handle submitted rows as authoritative replacement when non-empty.
   - This is a known limitation of the current structured path (see template comments). Users wanting to edit existing shares without losing data must use Raw or carefully re-enter.

5. **Keytab / hostname two-tier is the law**
   - `get_consistent_hostname` + `confirm_consistent_hostname` + `nfs_keytab_host_*` are used in startup TUI banner, WebUI startup, keytab alert, dry-run, and runtime diagnostics.
   - All paths surface the rich `HostnameInconsistency` when `hostname(1)` != `/proc/sys/kernel/hostname` (after norm).
   - Docs (root, run, examples, ganesha-arch, ldap-int) consistently say `--uts=host` + short+ FQDN principals. Code and tests match exactly (including docker-default-ID detection and case sensitivity).
   - No silent fallback to `hostname` alone anywhere that matters.

6. **Ganesha fragment naming and cleanup**
   - Generator (`generate.rs:write_export_fragments`) always cleans `exports.d/*.conf` then writes `{:02}-<sanitized>.conf` (starting at 10).
   - `ganesha-ctl remove-export` / show / reload are best-effort file ops + pkill (no DBUS). Matches container scripts and entrypoint SIGHUP path.
   - Example in `examples/ganesha-exports.d/10-example.conf` updated during audit; it is reference only.

7. **LdapClient / SSSD attribute sharing**
   - `resolve_posix_attribute_mapping`, `effective_ldap_search_bases`, `ldap_tls_policy` are the single source used by generator (sssd.conf), startup bind probe (narrow attrs), and UI LdapClient.
   - Startup probe now uses the *same* narrow attr list as future SSSD (see `check_ldap_bind`).
   - WebUI "Reload NFS client" fully re-instantiates with current on-disk + env values.
   - Caches (10m identity, 2m search) + clear + stats exposed in /settings. All matches docs.

8. **FsManager / privileged security contracts**
   - `is_allowed` + `host_path_to_container_path` (prefix under share host_path, logical host namespace) + WalkDir `follow_links(false)` + `filter_entry` + numeric-only writes + refuse 0 / set*id.
   - Mutations go through `privileged::chown`/`chmod` (std following variants).
   - Non-recursive: only target dir (depth0) + immediate files (depth1).
   - Dry-run, continue_on_error, progress/cancel all exercised in tests + live UI.
   - Root README + fs.rs + privileged.rs are in sync.

9. **Auth / sessions**
    - Sidecar `webui-password` (iterated SHA-256 + 0600) next to config; or LLDAP member of `webui_admin_group` (default lldap_admin) via `verify_user_is_admin` (which does memberOf fast-path).
    - Cookies: HttpOnly + SameSite=Lax + Secure (overridable) + 12h TTL. Multiple tokens supported (last wins). require_auth context-aware redirect (?error=session for first-run vs normal).
    - Tests in `web/mod.rs` and `web/auth.rs` cover the full first-run setup + login + redirect follow + protected + logout + re-login + stale cookie flows.
    - Matches root README and `docs/run/README.md`.

10. **Container / entrypoint / watcher / ctl**
    - pid1 (entrypoint.sh) does preflight, first init, calls startup TUI (blocks), generate, perm fix, start SSSD/Ganesha/watcher/WebUI, SIGHUP handler for regen+SSSD-restart+Ganesha-prods.
    - Conf-watcher only signals pid1 (guarantees root:root 0600 for sssd.conf).
    - ganesha-ctl is pure file + pkill shim (no DBUS).
    - Healthcheck: process + listener checks for 2049 + nss pipe + 9630 (best-effort exports).
    - All scripts have "See container/README.md" headers. container/README is minimal but accurate.
    - `scripts/fix-keytab-perms.sh` is a hard-deprecated no-op (for the old non-root model).

11. **Test coverage notes (from TESTING.md + actual)**
    - Pure + tempfile + tower::oneshot cover the critical derivation, safety, auth, FS policy, and config golden paths.
    - Live LLDAP, real bind mounts chown, full entrypoint+watcher orchestration, and Ganesha runtime are intentionally out-of-unit (as documented).
    - No drift found between "Well-Tested Areas" / table and the tests that exist.

12. **Minor / cosmetic**
    - Some long explanatory comments in `fs.rs`, `ldap.rs`, `startup.rs`, `web/*` exist because they are security contracts, UX rationale for async apply, or KLLDAP compatibility notes. These were left (they are the "also documented in source" that README promises). Only "NEW:" and obviously-stale markers were trimmed for minimalism.
    - `generate.rs` has a couple of extra blank lines / comments; harmless.
    - `scripts/verify-ganesha.sh` is a convenience wrapper around the same checks; not referenced as primary in most docs (healthcheck + ganesha-ctl + getent are).

## Recommendations for next major steps (post 0.7.x)

- Consider making the structured shares editor in /settings load + render current rows (server-side) so it is a true "edit" rather than "append/replace" tool. (Would improve UX without changing core model.)
- Drive the workspace version from git tag or a single source during release (or document the Cargo vs. branch convention).
- Remove or guard the aurora.testlabby.local /etc/hosts injection (or move it behind an env var) before wider distribution.
- If "fuller" structured editor is never planned, update high-level docs to say "Raw TOML (full) + structured convenience form (common fields + shares)".
- Add a small integration note or make target in Makefile for "container smoke" using the compose example + healthcheck (currently only unit + manual).
- Audit the exact set of sssd.conf advanced fields emitted vs. the full SssdSection struct (some krb5_* etc. are conditional; docs are close but not exhaustive).

## How this audit was performed

- Full tree read of *.rs (both crates), all *.md, *.sh, Dockerfile, Makefile, examples, templates.
- Cross-checked: public API surface vs. root/docs/README usage; generator output vs. golden tests + example conf; hostname contract in 4+ call sites + tests + docs; FS safety policy (WalkDir + privileged) vs. every mention; auth flows vs. tests + cookie construction; LLDAP/SSSD attr sharing; startup TUI step machine vs. docs.
- Ran `cargo test --workspace` (all green before and after doc/comment edits).
- Changes limited to: version strings in usage, "NEW:" pruning, one UI label/checked for consistency with code default, HTML comments + H3 for accuracy, one sh comment, TESTING.md table, ui-design.md, a few docs/README wording for precision. No logic, no defaults, no control flow, no test assertions changed.

If a future change touches any of the noted areas, update this file + the corresponding docs/tests in the same PR.

End of audit notes.
