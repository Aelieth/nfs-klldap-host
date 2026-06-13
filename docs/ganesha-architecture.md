# Architecture

Single TOML (nfs-klldap.conf) is source of truth. nfs-klldap-config validates+derives+generates sssd/krb5/ganesha fragments. entrypoint (pid1) + watcher (SIGHUP) + ganesha-ctl handle reloads/bounces. nfs-klldap-ui (9630 HTTPS) edits TOML + direct chown/chmod (root, on allowed host_path trees). Ganesha VFS + SSSD (from LLDAP POSIX) serve NFSv4 krb5. No host kernel NFS.

## Key Contracts

| Contract                  | Rule |
|---------------------------|------|
| `host_path` vs container  | UI + allow-list + ownership use the host-visible absolute path (unchanged). Ganesha Path and container-visible location = `storage.container_root` joined with share `export_path` (defaults to `/<name>` for compat). A single root bind (host parent dir → /export) is the stable long-term pattern. Translation only at the syscall boundary (`FsManager`). |
| Hostname                  | `get_consistent_hostname()` (hostname(1) == /proc/sys/kernel/hostname). Mismatch → loud diagnostic. `--uts=host` is the normal way to get the real name. |
| Realm                     | Strictly required. No silent EXAMPLE.COM. Auto-derived from ldap_uri host or NFS_KLLDAP_KERBEROS_REALM. |
| ldap_uri                  | DNS hostname only (IP rejected). Forward+reverse DNS required. Keytab: `nfs/<short>@REALM` and `nfs/<fqdn>@REALM` when they differ (`--uts=host`). |
| Execution                 | Everything (Ganesha, SSSD, WebUI, generator) runs as root inside the container. |
| Reload                    | Watcher → SIGHUP to pid 1 → generator + permission fixup + supervisor bounces Ganesha/SSSD/WebUI in place (no full container death). Container ships a system bus for Ganesha; management itself uses fragments + HUP. |

## Volumes (typical)

```yaml
volumes:
  - /media/:/export:rw                # Recommended: single root-level bind of the host parent. host_path values live under it; Ganesha paths use container_root + export_path.
  - ./config:/config:rw               # nfs-klldap.conf (single source)
  - ./krb5.keytab:/etc/krb5.keytab:ro
```

See container/healthcheck.sh for service checks. See TESTING.md for test coverage.
