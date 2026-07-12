# nfs-klldap-ui

Axum + HTMX WebUI (port 9630 inside the container). **0.9.x:** first-run `/setup/1` … `/setup/3` wizard, then `/login` and the main UI. Edits `nfs-klldap.conf` and applies direct chown/chmod (nix+std, no shell Command) on bind-mounted host paths. Recursive walks use spawn_blocking with live ApplyProgress atomics visible to apply log. NFS create inheritance covered via config umask (ACL path) + docs (see root README + ganesha-architecture.md for umask/ACL default gotcha).

The Share Permissions page (`/`) browses **directories and files** (dirs first, 📁 + larger rows; files smaller with a type emoji and UTC modified stamp) and edits POSIX + ACL in a **detached permissions panel** (single `GET /dir-perms` endpoint serving both node kinds; the old inline `/dir-meta` + `/dir-editor` + `/dir-acl` are retired). Directories get a condensed **Read/Write** matrix (read implies browse/execute — the client submits x-less modes, the server fuses r→x per directory entry) plus **setgid/sticky** toggles (setuid refused), a three-way **Apply scope** (none / single directory / all directories) and, for the recursive scopes, explicit **file permission bits** that every file in scope receives verbatim; files selected individually get the full independent **rwx** triad with no special bits and no scope. Both share a live octal/symbolic readout; owner/group and ACL principals resolve names↔ids via LLDAP. The ACL section is enabled only when the share truly serves ACLs (`enable_acl = true` **and** an ACL-capable filesystem), else it shows a Non-ACL reason.

Build (for development):
```bash
cargo build -p nfs-klldap-ui --release --bin nfs-klldap-ui
```

Key modules: `ldap.rs` (SSSD creds, POSIX resolution), `fs.rs` (single-level listing + path translation + apply walks), `web/` (Axum handlers + templates: thin `mod.rs` orchestrator + `auth`, `permission_tree`, `settings`, `keytab`, `setup`), `auth.rs` (localhost sidecar + LLDAP admin group).

See root README and TESTING.md.
