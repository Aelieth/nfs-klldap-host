# Container Internals

Thin shell helpers + healthcheck only. All real logic lives in the two Rust binaries shipped at `/usr/local/bin`:

- `nfs-klldap-config` + `nfs-klldap-startup`
- `nfs-klldap-ui`

Everything runs as root. `entrypoint.sh` is the pid-1 supervisor.

## Scripts

- `healthcheck.sh` — ganesha.nfsd + 2049 + SSSD NSS pipe + WebUI 9630.
- `scripts/ganesha-ctl` — `show-exports` / `reload` (no DBUS). The watcher + supervisor handle dynamic updates.
- `scripts/nfs-klldap-conf-watcher` — inotify on `nfs-klldap.conf` → SIGHUP to pid 1 → generator + fixup + reload.
- WebUI TLS is handled internally by the UI binary (rcgen or WEBUI_TLS_*).

## Locations inside container

`/container/healthcheck.sh`, `/usr/local/bin/{ganesha-ctl,nfs-klldap-conf-watcher}`.

Env: `NFS_CONFIG` (default `/config/nfs-klldap.conf`), `WATCHER_DEBOUNCE_SECONDS`.

No host-side work, no sudo. All privileged actions (0600 files, direct chown) happen inside on bind mounts.