# Host Management UI (Rust)

`nfs-klldap-ui` — the host-side web interface (Axum + HTMX) for `nfs-klldap-host`.

It directly edits the shared `nfs-klldap.conf` (the single source of truth) and provides:

- **System Settings** page — edit the central TOML (raw editor with full comment preservation + basic structured view)
- **Share Permissions** page — real-time directory trees under your shares + live KLLDAP user/group search + recursive POSIX owner/group/mode changes performed by the container (requested via `docker exec` from the UI)

## Building & Running

Use the top-level Makefile for the recommended build story (including cross-compilation):

```bash
make build                 # native release
make dist                  # cross-compiled binaries in ../dist/
```

You can still build directly:

```bash
cargo build --release --bin nfs-klldap-ui
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
- `fs.rs` — Real-time tree walking + permission application via `docker exec` into the container
- `config.rs` — Thin adapter over the shared `nfs-klldap-config` crate + save helpers
- `web.rs` + templates/ — The two-page HTMX UI

The old `policy.rs`, `ganesha.rs`, and `exports.rs` have been removed (generation now lives exclusively in the container's Rust binary).

## Security

**Never run the UI as root in production.**

The management UI runs unprivileged. It asks the running NFS container (via docker exec) to perform chown/chmod on the bind-mounted export paths.

The UI validates paths against the shares declared in `nfs-klldap.conf` and then asks the running container (via `docker exec`) to perform the actual `chown`/`chmod`.

## Testing

See the root [TESTING.md](../../TESTING.md) for current coverage. The `FsManager` and several web handlers now have solid unit/integration tests.
