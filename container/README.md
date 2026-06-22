# Container Internals

Thin shell (entrypoint, healthcheck, watcher, ganesha-ctl) + Rust binaries (`nfs-klldap-config`, `nfs-klldap-startup`, `nfs-klldap-idhelper`, `nfs-klldap-ui`) run as root inside the container. Privileged work (0600 derived files, direct chown/chmod on bind-mounted host_paths) happens here only. See [entrypoint.sh](../entrypoint.sh) and source for flow.

The container includes dbus-daemon (launched by entrypoint before Ganesha) and rpcbind for Ganesha/runtime compatibility. Management of Ganesha (export fragments + reload) is performed via the supervisor HUP path rather than D-Bus RPCs to ganesha.

## Scripts

| Path | Installed as | Role |
|------|--------------|------|
| `healthcheck.sh` | `/container/healthcheck.sh` | Service readiness checks |
| `scripts/nfs-klldap-conf-watcher` | `/usr/local/bin/nfs-klldap-conf-watcher` | inotify on nfs-klldap.conf → SIGHUP |
| `scripts/ganesha-ctl` | `/usr/local/bin/ganesha-ctl` | Export reload + idhelper diagnostics |
| `scripts/nfsidmap-idhelper` | nfsidmap shim | Principal→uid via idhelper |

See also [scripts/verify-ganesha.sh](../scripts/verify-ganesha.sh) for in-container export verification.