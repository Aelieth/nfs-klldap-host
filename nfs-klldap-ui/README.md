# nfs-klldap-ui

Axum + HTMX WebUI (container port **9630**). First-run `/setup/1`…`/setup/3`, then `/login`. Edits `nfs-klldap.conf` and applies chown/chmod/ACL on allow-listed trees.

**Create inheritance:** no config `umask` (retired). Use default ACL **Inherit** tab + setgid. See [docs/ganesha-architecture.md](../docs/ganesha-architecture.md).

## Surfaces

| Path | Role |
|------|------|
| `/setup/1`…`/3` | Wizard + Test Log |
| `/` | Tree + detached permission panel (dirs + files) |
| `/settings` | TOML / shares / Admin (restart, password, maintenance) |
| `/client-manifest.json` | Public share ACL class list (no session) |

- Tree: one-level lazy `/tree`; dirs first; symlinks excluded.
- ACL panel only when the share **effectively** serves ACLs (explicit or auto-promoted + capable FS).
- Shares save → SIGHUP graceful apply (no WebUI bounce). **Restart and apply** → SIGUSR1 full recycle.

## Modules

| Module | Role |
|--------|------|
| `ldap.rs` | Directory queries via shared identity resolver |
| `fs.rs` | Allow-list, listing, POSIX/ACL apply walks |
| `web/` | Handlers: auth, tree, settings, setup, ACL |
| `auth.rs` | localhost `webui-password` + LLDAP admin group |
| `privileged.rs` | chown/chmod/setfacl boundary |

```bash
cargo build -p nfs-klldap-ui --release --bin nfs-klldap-ui
```

Further: [docs/security.md](docs/security.md), [docs/ui-design.md](docs/ui-design.md), root [README.md](../README.md), [TESTING.md](../TESTING.md).
