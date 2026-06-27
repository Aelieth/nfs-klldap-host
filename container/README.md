# Container Internals

Thin shell (entrypoint exec, healthcheck, watcher, ganesha-ctl) + Rust binaries. `entrypoint.sh` only execs `nfs-klldap-startup supervise`; orchestration (preflight, SSSD/idhelper waits, Ganesha recycle, SIGHUP) lives in Rust. Privileged work (0600 derived files, direct chown/chmod on bind-mounted host_paths) happens here only.

NSS: `nsswitch.conf` is `files extrausers sss`. idhelper materializes `/var/lib/extrausers/{passwd,group}` (no `#` lines or `:` in gecos — libnss-extrausers rejects both). The image symlinks `libnss_extrausers.so.2` into the glibc triplet dir and sets `NSS_EXTRAUSERS_PASSWD` / `NSS_EXTRAUSERS_GROUP` for Ganesha and idhelper. Ganesha additionally uses `LD_PRELOAD=nss_wrapper` against `/var/lib/nfs-klldap/nss_{passwd,group}`.

The container includes dbus-daemon (launched by the supervisor before Ganesha) and rpcbind for Ganesha/runtime compatibility. Export fragments under `/etc/ganesha/exports.d/` plus `/etc/nfs.conf` (`use-machine-creds=0`) are generated from `nfs-klldap.conf` by `nfs-klldap-config`; reload is triggered via SIGHUP to pid 1 (conf-watcher, WebUI apply, or `ganesha-ctl reload`), not D-Bus RPCs to Ganesha. The supervisor tracks the spawned `ganesha.nfsd` launcher pid and adopts the daemon pid after the real binary daemonizes (launcher exit).

When `HOST_NFS=true` the supervisor and healthcheck skip ganesha.nfsd entirely (the host NFS server at `/etc/ganesha` owns the daemon and the 2049 listener); the container remains the source of truth for config generation, keytab material, SSSD identity, and the WebUI permission tools.

## Scripts

| Path | Installed as | Role |
|------|--------------|------|
| `container/healthcheck.sh` | `/container/healthcheck.sh` | Docker liveness (hard fail on core services) |
| `container/scripts/check-common.sh` | `/container/scripts/check-common.sh` | Shared advisory checks (sourced by healthcheck + verify) |
| `container/scripts/nfs-klldap-conf-watcher` | `/usr/local/bin/nfs-klldap-conf-watcher` | inotify on nfs-klldap.conf → SIGHUP pid 1 |
| `container/scripts/ganesha-ctl` | `/usr/local/bin/ganesha-ctl` | Supervisor reload (SIGHUP) + idhelper diagnostics |
| `container/scripts/nfsidmap-idhelper` | nfsidmap shim | Principal→uid via idhelper (fallback path) |
| `scripts/verify-ganesha.sh` | `/usr/local/bin/verify-ganesha.sh` | Post-deploy diagnostics (runs healthcheck + extended checks) |

**Networking:** run with `network_mode: host` (compose) or `--network=host` (`docker run`) — see [docs/run/README.md](../docs/run/README.md).

See also `verify-ganesha.sh` inside the container for export verification.
