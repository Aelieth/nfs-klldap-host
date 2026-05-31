# Architecture

Single TOML (`nfs-klldap.conf`) is the source of truth. `nfs-klldap-config` validates + generates sssd.conf, krb5.conf, ganesha exports. `entrypoint.sh` + watcher drive reloads. `nfs-klldap-ui` (9630) edits the TOML and performs direct chown/chmod on bind mounts as root. Ganesha + SSSD (LLDAP POSIX) serve NFSv4. No kernel NFS on the host.

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

See container/healthcheck.sh for service checks. See TESTING.md for test coverage.
