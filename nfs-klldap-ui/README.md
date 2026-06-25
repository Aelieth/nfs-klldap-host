# nfs-klldap-ui

Axum + HTMX WebUI (port 9630 inside the container). **0.9.x:** first-run `/setup/1` … `/setup/3` wizard (restarting page polls `/restart-status`), then `/login` and the main UI. Edits `nfs-klldap.conf` and applies direct chown/chmod on bind-mounted host paths. `HOST_NFS=true` sidecar mode grays out in-container NFS controls.

Build (for development):
```bash
cargo build -p nfs-klldap-ui --release --bin nfs-klldap-ui
```

Key modules: `ldap.rs` (SSSD creds, POSIX resolution), `fs.rs` (tree + translation), `web/` (Axum handlers + templates: thin `mod.rs` orchestrator + `auth`, `permission_tree`, `settings`, `keytab`, `setup`), `auth.rs` (localhost sidecar + LLDAP admin group).

See root README and TESTING.md.
