# Container Internals

This directory contains the small supporting scripts and healthcheck that run **inside** the `nfs-klldap-host` container.

These scripts are intentionally thin. All complex logic (config generation, guided first-run, diagnostics, permission application, and the WebUI itself) lives in the Rust binaries from the two top-level workspace crates (`nfs-klldap-config` and `nfs-klldap-ui`), shipped in `/usr/local/bin`:

- `nfs-klldap-config`
- `nfs-klldap-startup` (part of `nfs-klldap-config`)
- `nfs-klldap-ui`

## Design Principles

- Everything runs as root inside the container (standard for Red Hat-style appliances).
- The entrypoint (`/entrypoint.sh`) acts as pid 1 and a lightweight supervisor.
- These helpers exist only to:
  - Prepare runtime TLS material
  - Provide convenient operator tooling
  - Implement reliable file watching + signaling back to pid 1
  - Satisfy Docker/Podman healthcheck requirements

No scripts perform host-side operations or use `sudo`. All privileged work happens inside the container on bind-mounted paths.

## Scripts

### `healthcheck.sh`

Docker/Podman `HEALTHCHECK` command (see `Dockerfile`).

**Checks performed on every interval:**
- `ganesha.nfsd` process is running and listening on TCP 2049
- SSSD NSS pipe exists (`/var/lib/sss/pipes/nss`) — proves LLDAP identity mapping is active
- WebUI is listening on TCP 9630 (HTTPS)

The check is deliberately fast and has no external dependencies beyond what is already in the image (`ss`/`netstat`/`timeout` fallbacks).

### `scripts/ganesha-ctl`

Operator-facing DBUS-free management tool for Ganesha in the self-contained model.

**Primary commands:**
- `show-exports` — list current export fragments (the source of truth)
- `reload` — force the container supervisor to restart Ganesha
- `remove-export <name>` — delete a fragment file (best effort)

`add-export` is a no-op in this model — the Rust WebUI or an administrator simply writes files into the bind-mounted `/etc/ganesha/exports.d` directory. The inotify-based watcher detects the change and triggers a reload.

Intended usage:
```bash
docker exec my-nfs ganesha-ctl show-exports
docker exec my-nfs ganesha-ctl reload
```

### `scripts/nfs-klldap-conf-watcher`

Lightweight inotify watcher on the single source-of-truth `nfs-klldap.conf`.

When a change is detected it sends `SIGHUP` to pid 1 (the entrypoint). The entrypoint then:
1. Runs `nfs-klldap-config generate`
2. Fixes ownership/permissions (especially `sssd.conf` as `root:root 0600`)
3. Restarts/reloads the affected daemons

This is the mechanism that gives automatic, safe reload when the WebUI or an administrator edits the TOML file.

It falls back to direct generation only if it cannot signal pid 1 (highly unusual).

### `scripts/webui-certs`

Helps prepare TLS material for the in-container WebUI (port 9630).

Primary responsibility (now focused):
- Discover user-provided certificates (`webui.crt`/`webui.key` or `tls.crt`/`tls.key`) next to `nfs-klldap.conf`.
- Symlink them into the standard location `/var/run/webui-certs/`.
- Output the two environment variables the WebUI binary expects.

Self-signed certificate generation (when no custom certs are supplied) has moved entirely into the Rust binary (`nfs-klldap-ui`) using the pure-Rust `rcgen` crate.

See:
- `nfs-klldap-ui/src/certs.rs` — `ensure_webui_tls_certs()`
- The Rust binary now guarantees valid TLS material exists before it starts listening on 9630.

This significantly reduces shell surface area for a security-critical path and makes the logic unit-testable.

## Environment Variables Commonly Used by These Scripts

- `NFS_CONFIG` — path to the central TOML (default `/config/nfs-klldap.conf`)
- `NFS_CONFIG_DIR` — directory containing the TOML (used by `webui-certs`)
- `WATCHER_DEBOUNCE_SECONDS` — debounce interval for the config watcher

## Runtime Locations (inside the container)

| Path                                      | Purpose                              |
|-------------------------------------------|--------------------------------------|
| `/container/healthcheck.sh`               | Docker HEALTHCHECK                   |
| `/usr/local/bin/ganesha-ctl`              | Operator tooling                     |
| `/usr/local/bin/nfs-klldap-conf-watcher`  | Auto-reload on config change         |
| `/usr/local/bin/webui-certs`              | WebUI TLS preparation                |
| `/var/run/webui-certs/`                   | Runtime TLS material for the WebUI   |

All scripts are installed with `+x` during the Docker build (see `Dockerfile`).

## Future Direction

As more logic moves into the Rust binaries, some of these small shell helpers may be absorbed (especially certificate handling and parts of the watcher). For now they remain small, auditable, and easy to reason about in a pid-1 context.