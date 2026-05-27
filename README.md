# alma_nfs-kerb

**AlmaLinux 10 container that acts as a complete Kerberized NFSv4 server (via NFS-Ganesha) for systems that cannot (or do not want to) run the NFS stack on the host itself.**

It provides:
- Full NFSv4 serving using **NFS-Ganesha** (user-space) — no host kernel `nfs`/`nfsd`/`rpcsec_gss_krb5` modules required.
- UID/GID mapping backed by **LLDAP** (POSIX attributes via SSSD inside the container).
- Easy visual management of shares and POSIX permissions from the host via a small Rust web tool (Axum + HTMX).
- **Direct control** of Ganesha exports at runtime from the management tool (via DBUS / `ganesha-ctl`).

**Core idea:** Plug this container into any Linux host (even one without kernel NFS) and it becomes the authoritative Kerberized NFSv4 server for that system. Clients authenticate with ordinary user Kerberos tickets (no machine principals required). POSIX ownership on the host directories must match the `uidNumber`/`gidNumber` values stored in LLDAP.

## Goals

- Deliver a complete Kerberized NFSv4 service from inside a container (no reliance on host kernel NFS).
- Use LLDAP (or any POSIX-capable LDAP) as the source of truth for `uidNumber`/`gidNumber`.
- Allow administrators to manage shares and POSIX permissions visually from the host using a small Rust web UI.
- Make it trivial to add/remove shares and fix permissions on any subdirectory under a share.
- Support **direct runtime management** of Ganesha exports (the management tool speaks directly to Ganesha's management interface).

## Architecture (Ganesha-only)

```
Host (any Linux — no kernel NFS needed)
├── /srv/nfs/... or /media/...          (real data — host only sees numbers)
├── ganesha-exports.d/                  (native Ganesha EXPORT {} blocks, written by the tool)
├── templates/                          (sssd, krb5, ganesha.conf templates)
├── secrets/krb5.keytab                 (nfs/<hostname>@REALM)
└── management/ (Rust web UI)           (talks LLDAP + privileged helper + docker exec ganesha-ctl)

Container (AlmaLinux 10)
├── NFS-Ganesha (ganesha.nfsd)          — the actual NFSv4 + Kerberos server
├── SSSD                                — talks to LLDAP, provides nss + POSIX IDs
├── DBUS + ganesha-ctl wrapper          — allows direct Add/RemoveExport from the host tool
└── Configuration rendered from templates
```

The Rust management tool (runs on the host) does:
- Live LLDAP lookups (users/groups → uidNumber/gidNumber)
- Real-time filesystem tree per share
- Permission editor on *any* subfolder under a share (owner, group, mode, recursive)
- `chown`/`chmod` via a narrow privileged helper
- Writes native Ganesha `EXPORT {}` blocks
- Calls directly into the running Ganesha via `docker exec <name> ganesha-ctl add-export ...` (DBUS)

## Host Prerequisites

- Time synchronization (Kerberos requirement)
- A DNS-resolvable hostname that matches the NFS service principal (`nfs/<hostname>@REALM`)
- Keytab with that principal (mode 600)
- Directories on the host that will be exported (the management tool helps keep their POSIX ownership in sync with LLDAP)
- Docker / Podman with the ability to mount the host's DBUS socket (for direct Ganesha management)

The host does **not** need the kernel NFS stack.

## Quick Start (docker compose)

See `examples/docker-compose.yml`. The important volumes are:

```yaml
volumes:
  - /srv/nfs/project-alpha:/export/project-alpha:rw
  - ./ganesha-exports.d:/etc/ganesha/exports.d:rw
  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
  - ./templates:/container/templates:ro
  - /run/dbus/system_bus_socket:/run/dbus/system_bus_socket:rw   # critical for direct management
```

Start the container, then run the management tool (from the `management/` directory):

```bash
cd management
cp config.toml.example config.toml
# edit config.toml with your LLDAP URL, shares, etc.
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
- On "Save & Apply" it also calls directly into Ganesha inside the container using `ganesha-ctl` (which uses the DBUS `org.ganesha.nfsd.exportmgr` interface).
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
docker exec alma-nfs-kerb ganesha-ctl add-export /etc/ganesha/exports.d/10-myshare.conf "EXPORT(Path=/myshare)"
docker exec alma-nfs-kerb ganesha-ctl remove-export 42
```

This is the mechanism the Rust management tool uses.

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
- DBUS socket must be mounted from the host for the "direct management" path to work.

## Current Status

Ganesha-only. Kernel NFS path has been removed from the main image and tooling.

The project now fully matches the original vision: a pluggable, LLDAP-backed, Kerberized NFSv4 server that any Linux machine can use without running NFS itself, with a friendly web UI for share and permission management.

## References

- NFS-Ganesha documentation (especially the DBUS export manager interface)
- LLDAP (POSIX attributes, GraphQL)
- Your custom fork with Kerberos integration if applicable

---

**License:** TBD (likely MIT or similar)
