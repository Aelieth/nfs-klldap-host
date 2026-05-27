# nfs-klldap-host

**AlmaLinux 10 container that provides a complete Kerberized NFSv4 server (via NFS-Ganesha) backed by KLLDAP for POSIX attributes.**

---

## Current Status (May 2026)

We are in the middle of a major simplification redesign (targeting v0.23).

### Old Approach (being replaced)
- Multiple bind mounts (templates, exports.d, keytab, data)
- Heavy template system
- Complex environment variables
- DBUS dependency (removed)

### New Approach (current direction)
- **Single source of truth**: `nfs-klldap.conf` (TOML)
- Container auto-derives almost everything from `ldap_uri`
- Generates `sssd.conf`, `krb5.conf`, and Ganesha export fragments internally
- Minimal required Docker volumes (config + keytab + storage)
- Per-share security settings (`krb5p` / `krb5i`)
- Two-page web UI:
  1. **System Settings** — define shares, NFS options, base search paths
  2. **Share Permissions** — manage POSIX ownership/groups/modes via KLLDAP
- First-run auto-generates a safe, heavily-commented template (never overwrites user config afterward)
- KLLDAP acts as both LDAP and KDC (shared hostname/realm)

---

## Vision & Goals

**"Pull, run, and it mostly just works"** while remaining flexible.

### Core Principles
- Minimal external configuration
- Config file is human-editable **and** editable through the web UI
- Smart auto-derivation wherever possible
- Clear separation between "what to share" (System Settings) and "who can access it with what permissions" (Permissions page)
- Future-ready for the KLLDAP server to export ready-to-run Docker configs for client machines

### Target Docker Run (once complete)

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

Only three volume mounts needed in normal use.

---

## Key Files (New Design)

- `nfs-klldap.conf` — The only config file users touch
- `entrypoint.sh` — Reads config, auto-derives values, generates downstream configs, watches for changes
- `management/` (Rust + Axum + HTMX) — Two-page web interface
- Generated internally (never exposed to user):
  - `sssd.conf`
  - `krb5.conf`
  - Ganesha `EXPORT {}` fragments

---

## Next Steps (Current Priority)

1. Finalize `nfs-klldap.conf` structure (done)
2. Implement first-run template generation + safe parsing in `entrypoint.sh`
3. Build TOML structs + config editor in the Rust management tool
4. Implement System Settings page (filesystem browser + share definition)
5. Wire up config watching + automatic Ganesha reload

---

## Long-term Vision

- One-command deployment from the KLLDAP server itself
- Extremely low maintenance for homelab / small business use
- Still powerful enough for complex multi-share environments with different security requirements per share

---

*This README reflects the current design direction as of May 27, 2026. It will be updated as implementation progresses.*