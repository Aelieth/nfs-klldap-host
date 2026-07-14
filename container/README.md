# Container Internals

**Purpose:** shell helpers and how they relate to the Rust supervisor.

Thin shell layer + Rust binaries. `entrypoint.sh` only execs `nfs-klldap-startup supervise`; preflight, SSSD/idhelper waits, Ganesha recycle, and SIGHUP handling live in Rust. Privileged work (0600 derived files, chown/chmod on bind mounts) runs in-container only.

## Process model

```
entrypoint.sh
    └─ nfs-klldap-startup supervise  (pid 1)
           ├─ dbus-daemon (before Ganesha)
           ├─ rpcbind (best-effort)
           ├─ sssd
           ├─ nfs-klldap-idhelper
           ├─ ganesha.nfsd -F   (unless HOST_NFS)
           ├─ nfs-klldap-conf-watcher  → SIGHUP pid 1 on conf change
           └─ nfs-klldap-ui :9630
```

- NSS: `files extrausers sss`. Idhelper materializes complete supps + uid0 into nss_wrapper + extrausers for `UseGetpwnam` / `getgrouplist`. Machines → 0.
- Ganesha starts after idhelper socket readiness, under nss_wrapper env from the supervisor (`LD_PRELOAD`, `NSS_WRAPPER_*`, idhelper socket vars).
- Reload: SIGHUP to pid 1 (conf-watcher, WebUI apply, or `ganesha-ctl reload`) — not D-Bus RPCs to Ganesha for export management.
- **HOST_NFS:** skip ganesha.nfsd and 2049 checks; still generate fragments for a host Ganesha at `/etc/ganesha`.

## Scripts

| Path | Installed as | Role |
|------|--------------|------|
| `container/healthcheck.sh` | `/container/healthcheck.sh` | Docker liveness |
| `container/scripts/check-common.sh` | `/container/scripts/check-common.sh` | Shared advisory checks |
| `container/scripts/nfs-klldap-conf-watcher` | `/usr/local/bin/nfs-klldap-conf-watcher` | inotify → SIGHUP pid 1 |
| `container/scripts/ganesha-ctl` | `/usr/local/bin/ganesha-ctl` | reload + idhelper diagnostics |
| `scripts/verify-ganesha.sh` | `/usr/local/bin/verify-ganesha.sh` | Post-deploy diagnostics |

Networking: host network mode — see [docs/run/README.md](../docs/run/README.md). Packaging: [ganesha/README.md](ganesha/README.md).
