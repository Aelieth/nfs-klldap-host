# nfs-klldap-ui

Axum + HTMX WebUI (port 9630 inside the container). Edits `nfs-klldap.conf` and applies direct chown/chmod on bind-mounted host paths.

Build (for development):
```bash
cargo build -p nfs-klldap-ui --release --bin nfs-klldap-ui
```

Key modules: `ldap.rs` (SSSD creds, POSIX resolution), `fs.rs` (tree + translation), `web/` (Axum handlers + templates: thin `mod.rs` orchestrator + `auth`, `permission_tree`, `settings`, `keytab`), `auth.rs` (localhost sidecar + LLDAP admin group).

See root README and TESTING.md.
