# Host Management UI (Rust)

`nfs-klldap-ui` — the host-side web interface (Axum + HTMX) for `nfs-klldap-host`.

It directly edits the shared `nfs-klldap.conf` (the single source of truth) and provides:

- **System Settings** page — edit the central TOML (raw editor with full comment preservation + basic structured view)
- **Share Permissions** page — real-time directory trees under your shares + live KLLDAP user/group search + recursive POSIX owner/group/mode changes via the narrow privileged helper

## Building & Running

Use the top-level Makefile for the recommended build story (including cross-compilation):

```bash
make build                 # native release
make dist                  # cross-compiled binaries in ../dist/
```

You can still build directly:

```bash
cargo build --release --bin nfs-klldap-ui
cargo build --release -p nfs-perm-helper --manifest-path priv-helper/Cargo.toml
```

Run the UI:

```bash
./target/release/nfs-klldap-ui --config /path/to/shared/nfs-klldap.conf
# or after `make dist`:
# ./dist/nfs-klldap-ui-amd64 --config ...
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

## Testing

See the root [TESTING.md](../../TESTING.md) for current coverage. The `FsManager` and several web handlers now have solid unit/integration tests.
