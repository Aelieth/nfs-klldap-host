# Host Management UI (Rust)

`nfs-klldap-ui` — the host-side web interface (Axum + HTMX) for `nfs-klldap-host`.

It directly edits the shared `nfs-klldap.conf` (the single source of truth) and provides:

- **System Settings** page — edit the central TOML (raw editor with full comment preservation + basic structured view)
- **Share Permissions** page — real-time directory trees under your shares + live KLLDAP user/group search + recursive POSIX owner/group/mode changes via the narrow privileged helper

## Running

```bash
cargo run --bin management -- --config /path/to/shared/nfs-klldap.conf
```

The path must point at the same volume/directory the container mounts at `/config`.

## Key Modules (still active)

- `llap.rs` — KLLDAP GraphQL client (POSIX uidNumber/gidNumber extraction)
- `fs.rs` — Real-time tree walking + permission application via helper
- `config.rs` — Thin adapter over the shared `nfs-klldap-config` crate + save helpers
- `web.rs` + templates/ — The two-page HTMX UI

The old `policy.rs`, `ganesha.rs`, and `exports.rs` have been removed (generation now lives exclusively in the container's Rust binary).

## Security

**Never run the UI as root in production.**

See `docs/security.md` for the recommended low-privilege user + narrow `nfs-perm-helper` (setuid or sudoers) model.

The UI itself only ever talks to the helper for `chown`/`chmod` and validates paths against the shares declared in `nfs-klldap.conf`.
