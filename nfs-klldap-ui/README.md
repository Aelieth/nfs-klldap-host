# nfs-klldap-ui

Axum + HTMX WebUI (port 9630 inside the container). **0.9.x:** first-run `/setup/1` … `/setup/3` wizard, then `/login` and the main UI. Edits `nfs-klldap.conf` and applies direct chown/chmod (nix+std, no shell Command) on bind-mounted host paths. Recursive walks use spawn_blocking with live ApplyProgress atomics visible to apply log. NFS create inheritance covered via config umask (ACL path) + docs (see root README + ganesha-architecture.md for umask/ACL default gotcha).

The Share Permissions page (`/`) edits POSIX + ACL in a **detached permissions panel** (single `GET /dir-perms` endpoint; the old inline `/dir-meta` + `/dir-editor` + `/dir-acl` are retired). POSIX offers an rwx matrix plus **setgid/sticky** toggles (setuid refused) with a live octal/symbolic readout; owner/group and ACL principals resolve names↔ids via LLDAP. The ACL section is enabled only when the share truly serves ACLs (`enable_acl = true` **and** an ACL-capable filesystem), else it shows a Non-ACL reason.

Build (for development):
```bash
cargo build -p nfs-klldap-ui --release --bin nfs-klldap-ui
```

Key modules: `ldap.rs` (SSSD creds, POSIX resolution), `fs.rs` (tree + translation), `web/` (Axum handlers + templates: thin `mod.rs` orchestrator + `auth`, `permission_tree`, `settings`, `keytab`, `setup`), `auth.rs` (localhost sidecar + LLDAP admin group).

See root README and TESTING.md.
