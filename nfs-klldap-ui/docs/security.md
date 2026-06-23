# Security Model

The WebUI runs as root inside the container and performs chown/chmod directly on bind-mounted host_path trees via `src/privileged.rs` (safe std APIs).

Typical production runs use **host networking** (`network_mode: host` / `--network=host`) plus `uts: host`, and add `SYS_ADMIN` and `DAC_READ_SEARCH` capabilities (see the main project's `examples/docker-compose.yml` and `docs/run/README.md`). Host networking is required so Ganesha CLIENT records use host-reachable addresses, not Docker bridge `172.17.x.x`. The caps are not required for the `chown(2)`/`chmod(2)` syscalls themselves when running as root on a normal bind mount, but they improve reliability for:
- Ganesha VFS when serving the exported host trees, and
- the WebUI's recursive WalkDir scanner when the tree contains directories with restrictive permissions for intermediate owners.

The container must still be started as real root (for 0600 sssd.conf, privileged port 2049, and arbitrary numeric UID/GID mutations). The in-container root model is the supported path. Running the binary on the host is not recommended.

All mutations are still gated by the allow-list from configured shares + the WalkDir safety policy (no symlink descent for mutation, no set*id, refuse uid/gid 0). See `fs.rs` and `privileged.rs`.
