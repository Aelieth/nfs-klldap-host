# Container Internals

Thin shell (entrypoint, healthcheck, watcher, ganesha-ctl) + Rust binaries (`nfs-klldap-config`, `nfs-klldap-startup`, `nfs-klldap-idhelper`, `nfs-klldap-ui`) run as root inside the container. Privileged work (0600 derived files, direct chown/chmod on bind-mounted host_paths) happens here only. See [entrypoint.sh](../entrypoint.sh) and source for flow.

The container includes dbus-daemon (launched by entrypoint before Ganesha) and rpcbind for Ganesha/runtime compatibility. Export fragments under `/etc/ganesha/exports.d/` are generated from `nfs-klldap.conf` by `nfs-klldap-config`; reload is triggered via SIGHUP to pid 1 (conf-watcher, WebUI apply, or `ganesha-ctl reload`), not D-Bus RPCs to Ganesha.

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