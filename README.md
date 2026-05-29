# nfs-klldap-host

**AlmaLinux 10 container that provides a complete Kerberized NFSv4 server using NFS-Ganesha, backed by KLLDAP for POSIX UID/GID attributes.**

Designed for hosts that cannot (or do not want to) run the kernel NFS stack.

---

## Core Idea

Plug this container into any Linux host (even one without kernel NFS modules) and it becomes a fully functional, authoritative Kerberized NFSv4 server.

**The architecture (v0.3)** uses a single source of truth:

- One `nfs-klldap.conf` (TOML) file
- A small, type-safe Rust binary (`nfs-klldap-config`) bundled in the container that auto-derives and generates everything else
- Host-side management UI that edits the shared config volume directly
- Container performs chown/chmod on exported data when requested by the UI via `docker exec`

This gives you **maximum simplicity with full power** — minimal volumes, no templates, no DBUS, no kernel NFS on the host, and automatic reloads when you change the config.

---

## Goals

- Deliver a complete Kerberized NFSv4 service from inside a container with almost zero host configuration
- Use KLLDAP (LLDAP + Kerberos in one) as the single source of truth for both POSIX attributes and Kerberos
- Make share and permission management visual and trivial through a host-side web UI
- Support per-share security settings (`krb5p` / `krb5i`) and complex multi-share environments
- Keep the container itself unprivileged (using targeted capabilities) while still allowing the host UI to request chown/chmod on exported data via `docker exec`
- Enable future one-command deployment from a KLLDAP server

---

## How It Works (Architecture)

```
Host (any Linux — no kernel NFS needed)
├── /media/SSD-01/...                  (real data on attached drives)
├── nfs-klldap.conf                    (single TOML config — the only file you edit)
├── management/ (Rust UI)
│   └── nfs-klldap-ui                  (edits config; asks the container to perform chown/chmod on exported data)
└── keytab (nfs/<hostname>@REALM)

Container (AlmaLinux 10)
├── entrypoint.sh                      (minimal supervisor + gosu launcher)
├── nfs-klldap-startup (Rust)          (guided 4-step TUI, reachability tests, realm/hostname guidance)
├── nfs-klldap-config (Rust binary)    (parses TOML → generates sssd.conf, krb5.conf, Ganesha fragments)
├── NFS-Ganesha (ganesha.nfsd)         (the actual NFSv4 + Kerberos server)
├── SSSD                               (provides POSIX IDs from KLLDAP)
└── Generated configs (internal only):
    ├── /etc/sssd/sssd.conf
    ├── /etc/krb5.conf
    └── /etc/ganesha/exports.d/*.conf
```

**Flow:**
1. You edit `nfs-klldap.conf` (via UI or by hand)
2. The Rust binary detects the change and regenerates all downstream configs
3. Ganesha and SSSD reload automatically
4. Permissions (chown/chmod) on exported data are performed by the container when requested by the host UI via `docker exec`

---

## Building

A `Makefile` provides the complete build story for both host tools and container images.

```bash
# Native release build of the host management UI
make build

# Cross-compile host tools for amd64 + arm64 (produces binaries in dist/)
make dist

# Build the container image locally
make docker

# Multi-platform build (linux/amd64/v2 + linux/arm64) using Docker Buildx
make docker-multi
```

See `make help` for all targets.



See [management/examples/sudoers.example](management/examples/sudoers.example) for recommended sudoers configuration.

## What's New in v0.4

- Major migration: the 4-step guided first-run experience, reachability tests, banner,
  and runtime diagnostics have moved from `entrypoint.sh` into the Rust binary
  `nfs-klldap-startup` (part of the `nfs-klldap-config` crate).
- Realm is now shown in the startup banner via best-effort derivation from `ldap_uri`.
- Hostname guidance now recommends the DNS-friendly insertion pattern
  (`testpc.example.com` → `testpc-nfs.example.com`) and the TUI suggests the correct name.
- Step progress in the guided TUI now correctly marks completed steps with `[√]`.
- Documentation (READMEs, architecture docs, compose examples) updated for the new
  startup flow and hostname convention.

See [TESTING.md](TESTING.md) and the root `Makefile` for details.

## Testing & Documentation

See [TESTING.md](TESTING.md) for the current testing strategy, how to run tests, and which behaviors are covered by executable tests (many of which also serve as documentation for tricky areas like credential parsing and the helper's allow-list logic).

---

## Quick Start

```bash
docker run -d \
  --name nfs-klldap \
  --uts=host \
  -p 2049:2049/tcp -p 2049:2049/udp \
  -v /path/to/nfs-config:/config \
  -v /secure/location/krb5.keytab:/etc/krb5.keytab:ro \
  -v /media/data:/export \
  ghcr.io/aelieth/nfs-klldap-host:latest
```

**First run** automatically generates a safe, heavily-commented `nfs-klldap.conf` for you to customize.

See [docs/run/README.md](docs/run/README.md) for practical examples (including the non-root `nfs` user, required capabilities, realm enforcement, and docker-compose patterns).

---

## Management UI (Host-side)

```bash
cd management
cargo run --bin management -- --config /path/to/your/config/nfs-klldap.conf
```

**Two pages:**
- **System Settings** (`/settings`) — edit the central TOML (raw editor + structured form)
- **Share Permissions** (`/`) — real-time filesystem tree browser + live KLLDAP user/group search + recursive `chown`/`chmod` performed by the container (via `docker exec` from the UI)

---

## Configuration (`nfs-klldap.conf`)

```toml
# ldap_uri host must be a DNS name (not an IP). See Prerequisites.
ldap_uri = "ldaps://lldap.example.com:6360"

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "your-password"

[server]
# hostname = "examplehost-nfs"          # optional override (recommended: start with --uts=host; TUI shows the required principal with -nfs insertion)

[kerberos]
# realm = "KRB.EXAMPLE.COM"             # required if auto-derivation from ldap_uri fails (or use NFS_REALM env)

[ganesha]
# default_security = "krb5p"            # krb5p | krb5i | krb5   (per-share override possible)

[[shares]]
name = "project-alpha"
host_path = "/export/project-alpha"
export_path = "/project-alpha"
security = "krb5p"
rw = true
squash = "no_root_squash"

[[shares]]
name = "backups"
host_path = "/export/backups"
export_path = "/backups"
security = "krb5i"
rw = false
squash = "root_squash"
```

The Rust binary handles all derivation and generation from this single file.

---

## Prerequisites

- Time synchronization (Kerberos requirement)
- **Recommended:** Use `--uts=host` when starting the container.  
  The container will share the Docker host's UTS namespace, so the hostname inside the container will be the real hostname of the machine running Docker (e.g. `aurora.satomlin.com`).  
  The guided startup TUI will automatically show you the correct Kerberos principal you need in your keytab using the `-nfs` insertion pattern (`nfs/aurora-nfs.satomlin.com@REALM`).

- You can still pass `--hostname your-chosen-name` if you want the container to use a completely different hostname (this takes precedence).

See the Quick Start above and [docs/run/README.md](docs/run/README.md) for the current recommended command line.
- Keytab with the matching principal (mode 600, readable by the container)
- Attached/media drives for exported data (system paths like `/srv/nfs` are not recommended)
- Docker / Podman

**DNS requirements for `ldap_uri`:** The host in `ldap_uri` (e.g. `ldaps://kllap.example.com:6360`) **must be a DNS hostname**, not an IP address. IP addresses are rejected at config validation time with:

> LDAP IP addresses are not supported, DNS resolution is required for operation.

Forward and reverse (PTR) DNS for both the NFS server hostname and the LDAP/KDC host are required for correct NFS service principal handling in the keytab and Kerberos authentication.

---

## Verification

**Inside the container:**
```bash
getent passwd some-ldap-user
id some-ldap-user
klist -k /etc/krb5.keytab
ganesha-ctl show-exports
```

**From a client:**
```bash
kinit alice
mount -t nfs4 -o sec=krb5p nfs-server-01.example.com:/project-alpha /mnt/test
ls -l /mnt/test
```

---

## Project Structure

```
nfs-klldap-host/
├── entrypoint.sh                      # Minimal supervisor (delegates to Rust binaries)
├── Dockerfile
├── management/
│   ├── nfs-klldap-config/             # Bundled in container:
│   │   ├── src/bin/nfs_klldap_startup.rs  # Guided first-run TUI + diagnostics
│   │   └── src/lib.rs                     # TOML loader + generator + derivation helpers
│   └── src/                           # Host UI (Axum + HTMX)
├── nfs-klldap.conf                    # Single source of truth (user-editable TOML)
└── README.md
```

**Generated inside container (never exposed):**
- `/etc/sssd/sssd.conf`
- `/etc/krb5.conf`
- `/etc/ganesha/exports.d/*.conf`

---

## Important Notes

- Host filesystem numeric ownership must match the `uidNumber`/`gidNumber` values in KLLDAP for users and groups that should own the data.
- The management UI exists precisely to make keeping permissions in sync easy and visual.
- The container hostname should match the instance part of the NFS principal in your keytab.

---

## Long-term Vision

- One-command deployment directly from a KLLDAP server
- Extremely low maintenance for homelab and small business environments
- Still powerful enough for complex multi-share setups with different security and permission requirements per share

---

**License:** TBD (likely MIT)
