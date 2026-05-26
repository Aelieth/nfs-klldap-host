# Management Tool (Rust)

Small visual program to manage NFSv4 shares and their POSIX permissions on the host.

## Design Principles (from user requirements)

- Real-time from the filesystem only (no database).
- Multiple managed directories shown in a tree menu.
- For each directory the admin can set:
  - Owner user (dropdown + real-time LLDAP lookup → uid)
  - Owner group (dropdown + real-time LLDAP lookup → gid)
  - Permission bits
  - Recursive flag
- "Save and apply" performs the chown/chmod on the host **and** touches the corresponding `*.exports` file so the NFS container sees the share with correct access.
- Keeps the "filesystem-oriented" + simple philosophy.

## Current Status

Early skeleton. Modules exist for the major pieces:
- `llap.rs` – LLDAP name ↔ ID translation
- `fs.rs` – Real-time tree walking + permission application (chown/chmod + recursive)
- `policy.rs` – Lightweight declarative policy (can be stored next to shares)
- `exports.rs` – Keeping `exports.d/` in sync + re-export trigger (SIGHUP)

The web/desktop UI layer (Axum+HTMX or Tauri) will sit on top of these.

## Next Steps

- The GraphQL client in `llap.rs` is now functional against your `lldap-with-kerberos` fork (with login + POSIX attribute parsing). Raw LDAP protocol support can be added via the `ldap3` crate if needed.
- Build the actual visual interface (tree + permission editor with live ID translation from KLLDAP).
- Wire "save & apply" fully (policy files, exports, helper calls).

Run with `cargo run` inside the `management/` directory to see the current flow demo.

Copy `config.toml.example` to `config.toml` to configure allowed roots, helper path, and sudo behavior.

## Security

**Never run the management tool as root in production.**

See `docs/security.md` for the recommended approach using a low-privilege user + narrow sudoers rules for `chown`/`chmod` on specific paths only.

This is currently considered the simplest secure model for this tool.
