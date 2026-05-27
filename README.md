# nfs-klldap-host

**AlmaLinux 10 container that provides a complete Kerberized NFSv4 server (via NFS-Ganesha) backed by KLLDAP for POSIX attributes.**

---

## Current Status (v0.23 — May 2026)

**Full cutover complete** to the new minimal architecture:

- Single source of truth: `nfs-klldap.conf` (TOML)
- Container auto-derives **everything** (sssd.conf, krb5.conf, Ganesha EXPORT fragments) from `ldap_uri` + shares using a small, type-safe Rust binary (`nfs-klldap-config`) bundled in the image.
- Only three volume mounts in normal use.
- Host-only management UI (`nfs-klldap-ui`) that directly edits the shared `nfs-klldap.conf` volume.
- Narrow privileged helper on the host for `chown`/`chmod`.
- No templates, no host-side `ganesha-exports.d` bind mount, no DBUS, no kernel NFS on the host.

See the architecture and quick-start below.

---

## Target Docker Run (minimal)

```bash
docker run -d \
  --name nfs-klldap \
  --hostname "$(hostname)-nfs" \
  -e NFS_CONFIG=/config/nfs-klldap.conf \
  -v /path/to/config:/config \
  -v /media/sda1/krb5/krb5.keytab:/etc/krb5.keytab:ro \
  -v /media/sda1:/export \
  ghcr.io/aelieth/nfs-klldap-host:latest
```

Only three volumes.

First run creates a safe, heavily-commented `nfs-klldap.conf` for you to edit.

---

## Host-Side Management UI

The UI runs on the **host** (not inside the container) and mounts the same config volume:

```bash
cd management
cargo run --bin management -- --config /path/to/your/config/nfs-klldap.conf
```

Two pages:
- **System Settings** (`/settings`) — edit the central TOML (raw editor + basic structured view)
- **Share Permissions** (`/`) — real-time FS trees + live KLLDAP user/group search + recursive permission apply via the narrow helper

---

## Key Files

- `nfs-klldap.conf` — the **only** file users normally edit
- `entrypoint.sh` — minimal supervisor; delegates all TOML work to the Rust binary
- `management/nfs-klldap-config/` — tiny Rust crate (also the binary bundled in the container)
- `management/` — the host UI (`nfs-klldap-ui`)

Generated inside the container (never exposed):
- `sssd.conf`
- `krb5.conf`
- Ganesha `EXPORT {}` fragments

---

## Long-term Vision

One-command deployment from a KLLDAP server, extremely low maintenance for homelab/small business, still powerful for complex multi-share environments with different security requirements per share.

---

**License:** TBD (likely MIT or similar)
