# Container Internals

**Purpose:** shell helpers and how they relate to the Rust supervisor.

Thin shell layer + Rust binaries. `entrypoint.sh` only execs `nfs-klldap-startup supervise`; preflight, SSSD/idhelper waits, Ganesha recycle, and signal handling (SIGHUP = graceful scoped apply, SIGUSR1 = forced full recycle) live in Rust. Privileged work (0600 derived files, chown/chmod on bind mounts) runs in-container only.

## Process model

```
entrypoint.sh
    └─ nfs-klldap-startup supervise  (pid 1)
           ├─ dbus-daemon (before Ganesha)
           ├─ rpcbind (best-effort)
           ├─ sssd
           ├─ nfs-klldap-idhelper
           ├─ ganesha.nfsd -F          (unless HOST_NFS)
           ├─ avahi-daemon             (when navahi_discovery = true)
           ├─ nfs-klldap-conf-watcher  → SIGHUP pid 1 on conf change (graceful apply)
           └─ nfs-klldap-ui :9630
```

- **NSS:** `files extrausers sss`. Idhelper materializes supplemental groups + uid0 into nss_wrapper + extrausers for `UseGetpwnam` / `getgrouplist`. Machine principals → 0.
- **Ganesha** starts after idhelper socket readiness under nss_wrapper env (`LD_PRELOAD`, `NSS_WRAPPER_*`).
- **SIGHUP (graceful apply):** conf-watcher, WebUI shares save, or `ganesha-ctl reload` → export reread + WebUI in-process reload (sessions kept); identity staged on disk; avahi HUPed for advert changes (never bounced on this path).
- **SIGUSR1 (full recycle):** "Restart and apply", setup completion, or `ganesha-ctl full-recycle` → restart SSSD, idhelper, Ganesha (stop/start + grace), WebUI, and avahi (only path that applies staged identity and the Navahi global toggle).
- **HOST_NFS:** skip ganesha.nfsd and 2049 checks; still write fragments under `/etc/ganesha` for a host daemon.

## Scripts

| Path | Installed as | Role |
|------|--------------|------|
| `container/healthcheck.sh` | `/container/healthcheck.sh` | Docker liveness |
| `container/scripts/check-common.sh` | `/container/scripts/check-common.sh` | Shared advisory checks |
| `container/scripts/nfs-klldap-conf-watcher` | `/usr/local/bin/nfs-klldap-conf-watcher` | inotify → SIGHUP pid 1 (graceful apply) |
| `container/scripts/ganesha-ctl` | `/usr/local/bin/ganesha-ctl` | reload / full-recycle + idhelper diagnostics |
| `scripts/verify-ganesha.sh` | `/usr/local/bin/verify-ganesha.sh` | Post-deploy diagnostics |

Networking: host network mode — see [docs/run/README.md](../docs/run/README.md). Packaging: [ganesha/README.md](ganesha/README.md).
