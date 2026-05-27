# nfs-klldap-host

**AlmaLinux 10 container that acts as a complete Kerberized NFSv4 server (via NFS-Ganesha) for systems that cannot (or do not want to) run the NFS stack on the host itself.**
- Get KLLDAP from: https://github.com/Aelieth/lldap-with-kerberos

It provides:
- Full NFSv4 serving using **NFS-Ganesha** (user-space) — no host kernel `nfs`/`nfsd`/`rpcsec_gss_krb5` modules required.
- UID/GID mapping backed by **KLLDAP** (POSIX attributes via SSSD inside the container).
- Easy visual management of shares and POSIX permissions from the host via a small Rust web tool (Axum + HTMX).
- Self-contained export management inside the container (no host DBUS socket required — ideal for ZimaOS and locked-down appliances). The container watches its own exports directory and restarts Ganesha automatically when fragments change.

**Core idea:** Plug this container into any Linux host (even one without kernel NFS) and it becomes the authoritative Kerberized NFSv4 server for that system. Clients authenticate with ordinary user Kerberos tickets (no machine principals required). POSIX ownership on the host directories must match the `uidNumber`/`gidNumber` values stored in KLLDAP.

## Goals

- Deliver a complete Kerberized NFSv4 service from inside a container (no reliance on host kernel NFS).
- Use KLLDAP (or any POSIX-capable LDAP) as the source of truth for `uidNumber`/`gidNumber`.
- Allow administrators to manage shares and POSIX permissions visually from the host using a small Rust web UI.
- Make it trivial to add/remove shares and fix permissions on any subdirectory under a share.
- Support **direct runtime management** of Ganesha exports (the management tool speaks directly to Ganesha's management interface).

## Architecture (Ganesha-only)

```
Host (any Linux — no kernel NFS needed)
├── /media/SSD-01/... or /mnt/disk*     (real data on *attached drives only* — host sees numbers)
├── ganesha-exports.d/                  (native Ganesha EXPORT {} blocks, written by the tool)
├── templates/                          (sssd, krb5, ganesha.conf templates — can live on attached drive)
├── secrets/krb5.keytab                 (nfs/<hostname>@REALM — can live on attached drive)
└── management/ (Rust web UI)           (talks KLLDAP + privileged helper; writes fragments, container watcher reloads)

Container (AlmaLinux 10)
├── NFS-Ganesha (ganesha.nfsd)          — the actual NFSv4 + Kerberos server
├── SSSD                                — talks to KLLDAP, provides nss + POSIX IDs
├── ganesha-export-watcher (inotify)    — container watches exports.d/ and restarts Ganesha on changes (self-contained)
└── Configuration rendered from templates
```

The Rust management tool (runs on the host) does:
- Live KLLDAP lookups (users/groups → uidNumber/gidNumber)
- Real-time filesystem tree per share
- Permission editor on *any* subfolder under a share (owner, group, mode, recursive)
- `chown`/`chmod` via a narrow privileged helper
- Writes native Ganesha `EXPORT {}` fragments into the bind-mounted exports directory. The container's internal `ganesha-export-watcher` (inotify) detects the change and restarts Ganesha so the new exports are loaded. No DBUS or `docker exec ganesha-ctl add-export` is required.

## Host Prerequisites

- Time synchronization (Kerberos requirement)
- A DNS-resolvable hostname that matches the NFS service principal (`nfs/<hostname>@REALM`)
- Keytab with that principal (mode 600)
- Attached/media drives that will be exported (the management tool helps keep their POSIX ownership in sync with KLLDAP). System paths such as /srv/nfs are not used. The keytab and templates may also live on an attached drive.
- Docker / Podman (no special DBUS socket mount is required — the container is self-contained)

The host does **not** need the kernel NFS stack.

## Quick Start (docker compose)

See `examples/docker-compose.yml`. The important volumes are:

```yaml
volumes:
  # All data lives on attached/media drives (no /srv/nfs style system paths)
  - /media/SSD-01/project-alpha:/export/project-alpha:rw
  - /media/SSD-01/backups:/export/backups:rw

  - ./ganesha-exports.d:/etc/ganesha/exports.d:rw
  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
  - ./templates:/container/templates:ro
```

You can also place the keytab and templates directly on an attached drive (for example `/media/SSD-01/secrets/krb5.keytab` and `/media/SSD-01/templates/`). Just point the volume mounts at those locations.

Start the container, then run the management tool (from the `management/` directory):

```bash
cd management
cp config.toml.example config.toml
# edit config.toml with your KLLDAP URL, shares, etc.
cargo run
```

Open http://127.0.0.1:3000 — you will see your configured shares, can browse trees under them, and change POSIX permissions on any subfolder with live LLDAP dropdowns + recursive apply.

## Configuration Templates

Bind-mount your own `templates/` directory (or set `TEMPLATES_DIR`) containing:

- `sssd.conf.template`
- `krb5.conf.template`
- `ganesha.conf.template`

The container renders them on every start unless final versions are bind-mounted directly to `/etc/...`.

See `container/templates/` for the starting points.

## Management Tool (Rust Web UI)

Located in `management/`.

Key behaviors (Ganesha world):

- `config.toml` now supports a `[[shares]]` list (preferred) with `name`, `host_path`, `export_path`, and optional `export_id`.
- The tool writes proper Ganesha `EXPORT { ... }` fragments into `ganesha_exports_dir`.
- On "Save & Apply" the tool writes a native Ganesha `EXPORT {}` fragment. The container's `ganesha-export-watcher` automatically detects the file change and restarts Ganesha (no DBUS involved).
- No more classic `/etc/exports.d/*.exports` or `exportfs -ra`.

The UI lets you:
- See all configured shares
- Expand the directory tree under any share
- Click any subfolder → LLDAP user/group search dropdowns → mode + recursive checkbox → apply
- The privileged helper does the actual recursive `chown`/`chmod` on the host

## Direct Ganesha Management (from the tool or manually)

Inside the container the `ganesha-ctl` wrapper is available:

```bash
docker exec alma-nfs-kerb ganesha-ctl show-exports
docker exec alma-nfs-kerb ganesha-ctl reload

# (add-export is a no-op; just write the fragment file. remove-export deletes the matching fragment file)
```

The Rust management tool normally just writes files into the bind-mounted exports directory. The container's internal watcher takes care of the rest. The `ganesha-ctl` commands above are primarily for manual inspection and troubleshooting inside the container.

## Verification (inside the container)

```bash
# Is Ganesha healthy?
/container/healthcheck.sh

# Current exports (via the management wrapper)
ganesha-ctl show-exports

# Check that SSSD sees LLDAP users
getent passwd some-ldap-user
id some-ldap-user

# Kerberos keytab
klist -k /etc/krb5.keytab

# From a client
kinit alice
mount -t nfs4 -o sec=krb5p nfs-server-01.example.com:/project-alpha /mnt/test
ls -l /mnt/test
```

## Important Notes

- Host filesystem numeric ownership **must** match the `uidNumber`/`gidNumber` values in LLDAP for the users/groups that should own the data.
- The management tool exists precisely to make keeping them in sync easy and visual.
- The container hostname must match the instance part of the NFS principal in the keytab.

## Current Status

Ganesha-only.

A pluggable, KLLDAP-backed, Kerberized NFSv4 server that any Linux machine can use without running NFS itself, with a friendly web UI for share and permission management.

## References

- NFS-Ganesha documentation
- LLDAP (POSIX attributes, GraphQL)

---

**License:** TBD (likely MIT or similar)
