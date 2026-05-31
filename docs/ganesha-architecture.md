# Architecture: Ganesha + Single TOML + In-Container Root WebUI

This is the only supported model.

## Model

- **nfs-klldap.conf** (TOML) is the sole editable source of truth.
- `nfs-klldap-config` (Rust) validates, derives (realm, ports, search bases, etc.), and emits:
  - `sssd.conf` (root:root 0600)
  - `krb5.conf`
  - `ganesha.conf` + per-share `exports.d/*.conf`
- `entrypoint.sh` (pid 1) + inotify watcher (SIGHUP) drive regeneration + daemon reload.
- `nfs-klldap-ui` (9630, axum + rustls, runs as root) edits the TOML and performs direct `chown`/`chmod` (via libc) on bind-mounted `host_path` trees.
- Ganesha (FSAL_VFS) + SSSD (LLDAP POSIX) provide the NFSv4 service. No kernel NFS modules required on the host.

## Key Contracts

| Contract                  | Rule |
|---------------------------|------|
| `host_path` vs container  | UI + allow-list + ownership use the host-visible absolute path. Ganesha sees `$container_root/$share_name`. Translation happens only at the syscall boundary inside the container (`FsManager`). |
| Hostname                  | `get_consistent_hostname()` (hostname(1) == /proc/sys/kernel/hostname). Mismatch → loud diagnostic. `--uts=host` is the normal way to get the real name. |
| Realm                     | Strictly required. No silent EXAMPLE.COM. Auto-derived from ldap_uri host or NFS_REALM. |
| ldap_uri                  | DNS hostname only (IP rejected at validate time). Forward+reverse DNS required for the `nfs/<host>@REALM` principal. |
| Execution                 | Everything (Ganesha, SSSD, WebUI, generator) runs as root inside the container. |
| Reload                    | Watcher → SIGHUP to pid 1 → generator + permission fixup + daemon restart/reload. No DBUS. |

## Volumes (typical)

```yaml
volumes:
  - /media/SSD-01:/export:rw          # data (host_path values live here)
  - ./config:/config:rw               # nfs-klldap.conf (single source)
  - ./krb5.keytab:/etc/krb5.keytab:ro
```

The WebUI performs chown/chmod as root on bind-mounted host paths via the `privileged` module (see `nfs-klldap-ui/src/privileged.rs`). Safe standard library APIs are used; no CHOWN/FOWNER/DAC_* capabilities are required under the documented root model.

## Health

`container/healthcheck.sh` checks ganesha.nfsd + 2049 + WebUI on 9630 + SSSD NSS pipe.

See [README.md](../README.md) for the quick diagram and contracts. See TESTING.md for FsManager + handler test coverage.
