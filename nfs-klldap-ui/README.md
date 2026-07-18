# nfs-klldap-ui

Axum + HTMX WebUI (port **9630** in the container). **Since 0.9.x:** first-run `/setup/1` … `/setup/3`, then `/login` and main UI. Edits `nfs-klldap.conf` and applies chown/chmod (nix + std fs; recursive walks via `spawn_blocking` with live ApplyProgress).

**NFS create inheritance:** not via a config `umask` key (retired; hard generate error). Use default ACL **Inherit** tab + setgid on the share tree. See [docs/ganesha-architecture.md](../docs/ganesha-architecture.md).

## Share Permissions (`/`)

- Tree lists **directories and files** (dirs first; files with type emoji + UTC mtime); lazy one-level `/tree` fetches; symlinks excluded.
- Detached panel: single `GET /dir-perms` for both node kinds.
- Directories: condensed Read/Write matrix (client submits x-less; server fuses r→x), setgid/sticky, apply scopes (none / single / all), file-execute grant for recursive scopes.
- Files: full rwx triad; no special bits; no recursive scope.
- ACL section only when the share class serves ACLs (`enable_acl` resolved **and** capable FS); else Non-ACL reason.

## Modules

| Module | Role |
|--------|------|
| `ldap.rs` | Directory queries via shared identity resolver |
| `fs.rs` | Path allow-list, listing, POSIX/ACL apply walks |
| `web/` | Handlers: `mod`, `auth`, `permission_tree`, `settings`, `setup`, ACL helpers |
| `auth.rs` | localhost `webui-password` + LLDAP admin group |
| `privileged.rs` | chown/chmod/setfacl boundary |

```bash
cargo build -p nfs-klldap-ui --release --bin nfs-klldap-ui
```

Further reading: [docs/security.md](docs/security.md), [docs/ui-design.md](docs/ui-design.md), root [README.md](../README.md), [TESTING.md](../TESTING.md).
