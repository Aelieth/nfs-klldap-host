# Host Management UI (Rust)

`nfs-klldap-ui` — the WebUI (Axum + HTMX) that now runs **inside** the `nfs-klldap-host` container on port 9630.

It directly edits the shared `nfs-klldap.conf` (the single source of truth) and provides:

- **System Settings** (`/settings`) — edit the central TOML
- **Share Permissions** (`/`) — real-time directory trees + live KLLDAP search + recursive `chown`/`chmod` performed **directly** inside the container

## Building & Running

The WebUI is now built into the container image and starts automatically on port **9630**.

If you want to build the binary for development or testing (from the repository root):

```bash
cargo build --workspace          # builds both crates
cargo build -p nfs-klldap-ui --release --bin nfs-klldap-ui
```

In normal use you do **not** run the binary on the host. It runs inside the container as root (alongside the other services).

## Key Modules (still active)

- `llap.rs` — KLLDAP GraphQL client (POSIX uidNumber/gidNumber extraction)
- `fs.rs` — Real-time tree walking + direct permission application inside the container
- `config.rs` — Thin adapter over the shared `nfs-klldap-config` crate + save helpers
- `web.rs` + templates/ — The two-page HTMX UI

The old `policy.rs`, `ganesha.rs`, and `exports.rs` have been removed (generation now lives exclusively in the container's Rust binary).

## Security

The WebUI runs inside the container as root alongside the other services (SSSD, Ganesha, etc.). This is the supported and recommended model for compatibility with Red Hat expectations around sssd and Kerberos.

It performs `chown`/`chmod` directly on the bind-mounted paths using libc (no `docker exec` needed in normal operation). See the root `README.md` and `container/README.md` for the overall security model.

## Testing

See the root [TESTING.md](../TESTING.md) for current coverage. The `FsManager` and several web handlers now have solid unit/integration tests.
