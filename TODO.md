# nfs-klldap-host Audit (reconciled to code)

**Actual implementation in *.rs always wins.** Readmes, TODO, and comments updated to match observed behavior (tests: `cargo test --workspace` green; clippy clean). Documentation kept concise and accessible to non-experts. Only config template + startup TUI kept intentionally verbose for operators.

## Lingering / dead code (may cause issues; left as-is, documented here)

- **entrypoint.sh:215** (the if ! grep aurora.testlabby.local block): always appends a lab-specific /etc/hosts entry on every start if absent. Test artifact. Can pollute container DNS view or conflict on real hosts using that name/IP. Guarded only by comment ("remove prior to release"). Recommend: env guard or delete before wider use.
- **scripts/fix-keytab-perms.sh**: hard-deprecated; prints message and `exit 1`. No-op for current root-in-container model. Safe (errors loudly) but dead for normal deploys.
- **Hardcoded versions**: Cargo.toml workspace = "0.7.0"; git branch 0.8; CLI usage texts (nfs-klldap-config main.rs:15, startup help) say "v0.7". No CARGO_PKG_VERSION at runtime. Drift only; no functional impact.
- **nfs-klldap-ui/src/fs.rs** (apply_permissions, count_applicable, apply_direct, apply_tree): marked #[allow(dead_code)]. Active handlers use the *with_progress / count_*_with_live paths only. These are legacy wrappers (used by internal tests). Kept for compat; harmless.
- **web/keytab.rs**: KeytabInfo had stray allow(dead_code) (now used by get_keytab_info in settings page); removed during audit.
- Minor: trailing blank lines in some .rs (trimmed), some internal wrappers only exercised in tests.

All other "partial" / "NEW" markers from prior audits resolved in code; docs now match (structured shares editor fully round-trips common fields + shares; two-tier hostname enforced everywhere; caches, async apply, etc. live).

## What the code actually does (high level, for docs alignment)

- Single nfs-klldap.conf (TOML) → validate+derive (dns-only ldap_uri, required realm no EXAMPLE, unique shares, pref/cache_profile validation, search bases, posix attr mapping) → generate (sssd.conf 0600 with ignores+attrs+schema when enabled, krb5.conf 644, ganesha main + per-share 10-*.conf fragments after full clean of exports.d).
- Startup TUI (3 steps, blocks): 1. persistent /config volume (different dev from /), 2. ldap_uri (DNS) + TCP reachable (getent+nc), 3. bind creds + narrow ldapsearch probe using same attr map as later SSSD/UI. Shares optional for Ready.
- Hostname: get_consistent_hostname() requires `hostname(1)` == /proc after trim-dot norm (case sensitive for principals). Rich error + remediation if not (docker ID detection). Used by TUI banner, UI keytab, generate dry-run, keytab check.
- FS ops (UI as root): is_allowed = prefix under any share host_path (logical). Translate to container_root/name only at syscall. WalkDir(follow_links=false), symlink entries skipped entirely (never descend), non-recursive = target dir (d0) + immediate files (d1) only. Refuse uid/gid=0 or set*id modes. All via std chown (follows links) / set_permissions in privileged.rs. Progress/cancel/dry/continue supported for async apply.
- Auth: sidecar `webui-password` (next to conf, 0600, iter SHA-256) for "localhost" OR LLDAP user in webui_admin_group (default lldap_admin) via memberOf fastpath + verify. 12h mem sessions, cookie HttpOnly Lax Secure (12h). Context-aware ?error on redirect.
- Web: / (tree + search + apply), /settings (raw+structured TOML + shares editor + LLDAP reload/clear/restart). Structured uses toml_edit to preserve comments on untouched sections; raw is full fidelity.
- LdapClient (UI): fresh conn+bind+search+unbind per op (KLLDAP/rustls), shared PosixAttributeMapping + tls_policy + bases with generator. 10m identity caches (name/uid/gid), 2m search caches, stats/clear in /settings.
- Container: entrypoint pid1 (preflight, startup TUI block, initial generate, start sssd/ganesha/watcher/ui, SIGHUP handler does generate+perms + bounce ganesha/sssd/ui). Watcher signals only pid1. ganesha-ctl = file ops + pkill (no dbus). Health = procs + listeners (2049 + nss pipe + 9630).
- No kernel NFS; Ganesha VFS only. --uts=host + keytab nfs/<short>+<fqdn>@REALM recommended.

## Documentation / comment changes in this audit

- Root + docs/*.md + examples + TESTING.md + container/README + scripts headers: wording tightened to observed behavior (no drift on two-tier, FS policy, cache_profile resolution, auth, generation cleanup, no shares-required at start, etc.). Average-user language, minimal verbosity.
- Code comments (outside startup TUI + config template): pruned to short engineering notes on structure, flow, or block purpose only. Verbose explanations, history, and "why" stories removed (facts live in code + tests + this TODO). Security contracts in fs/privileged kept factual but concise.
- Config template long header + entire startup bin left untouched (operator help).

## How to keep aligned

On any behavior change, update the corresponding .rs (if comments), tests, this TODO, and affected *.md in same change. Run `cargo test --workspace`.

Re-run audit when touching entrypoint, fs apply policy, hostname, generation, or auth.

End.
