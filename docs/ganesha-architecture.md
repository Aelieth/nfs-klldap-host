# Container Architecture: NFS-Ganesha (User-Space NFSv4)

**This is the canonical and only supported architecture for alma_nfs-kerb.**

The project has completed the full conversion to NFS-Ganesha. The kernel NFS path (`rpc.nfsd`, `rpc.gssd`, `rpc.idmapd`, `exportfs`, etc.) has been completely removed from the main image, entrypoint, healthcheck, management tool, and documentation.

## Why Ganesha (and Why Only Ganesha)

The goal of this project is to turn **any Linux machine** into a Kerberized NFSv4 server without requiring that machine to run the kernel NFS stack.

Many modern or minimal environments (ZimaOS, certain appliances, hardened servers, etc.) deliberately do not load `nfs`, `nfsd`, or `rpcsec_gss_krb5`. The container must therefore **be** the complete NFS server for the host.

NFS-Ganesha (user-space) is the production-grade solution that delivers:

- Full NFSv4 (including 4.1/4.2)
- Excellent Kerberos/GSS support (`sec=krb5p` etc.) for user-only tickets
- FSAL_VFS for directly exporting host directories that are bind-mounted in
- Self-contained dynamic export management via inotify watcher + supervisor restart (no DBUS, no host socket mount required)
- No dependency whatsoever on host kernel NFS modules

## Current Architecture

```
Host (no kernel NFS modules required anywhere)
├── Real data directories          (/media/SSD-01/*, /mnt/disk*/* — attached drives only)
│   └── Numeric uid/gid ownership must match LLDAP uidNumber/gidNumber
├── nfs-klldap.conf                (single source of truth TOML — edited via UI or by hand)
├── secrets/krb5.keytab            (nfs/<hostname>@REALM, mode 600)
└── management/ (Rust web UI)      (Axum + HTMX)
    ├── Talks to LLDAP (GraphQL) for live user/group → uid/gid
    ├── Requests recursive chown/chmod (performed directly inside the container)
    ├── Writes native Ganesha EXPORT {} fragments
    └── Speaks directly to Ganesha via: docker exec <name> ganesha-ctl ...

Container (AlmaLinux 10)
├── NFS-Ganesha (ganesha.nfsd)     — the complete NFSv4 + Kerberos server
├── SSSD                           — LLDAP POSIX provider (nss + id mapping)
├── nfs-klldap-config (Rust)       — bundled generator (parses central TOML → sssd/krb5/ganesha configs)
└── inotify-based watcher          — triggers regeneration + Ganesha reload on nfs-klldap.conf changes
```

The management tool (host) and container work together with a **single source of truth** (`nfs-klldap.conf`):

- One TOML file edited by the WebUI (running inside the container) or by hand.
- The Rust generator inside the container produces all derived configs.
- Permission changes (chown/chmod) on exported data are performed by the container itself when requested by the host management UI.

## Key Technical Choices (v0.5+)

- **No kernel NFS** anywhere.
- **Central `nfs-klldap.conf`** (TOML) is the *only* file users normally edit.
- **Rust generator** (`nfs-klldap-config`) is the single place that understands the schema and produces `sssd.conf`, `krb5.conf`, and Ganesha `EXPORT` fragments.
- **No host-side exports.d or templates bind mount** in the normal deployment model (everything is generated from the single `nfs-klldap.conf`).
- **Self-contained reload**: container watches the config file (or reacts to SIGHUP) and regenerates + reloads Ganesha.
- The WebUI runs inside the container as root and performs `chown`/`chmod` directly on the bind-mounted data.

See the root `TESTING.md` for current test coverage of `FsManager` path validation and the web handlers.

## Health and Verification

- Container healthcheck: `container/healthcheck.sh` (process + TCP 2049 + basic responsiveness).
- Inside container: `ganesha-ctl show-exports`, `getent passwd`, `id`, `klist -k /etc/krb5.keytab`.
- From client: `mount -t nfs4 -o sec=krb5p ...`

The old kernel-oriented commands (`rpc.idmapd -f -vvv`, `exportfs -s`, `rpcinfo`, etc.) no longer apply.

## Privileges and Volumes (Typical)

```yaml
cap_add:
  - CHOWN
  - FOWNER
  - DAC_OVERRIDE
  - DAC_READ_SEARCH   # often still useful for VFS FSAL
  - NET_BIND_SERVICE  # for listening on 2049
volumes:
  # All data lives on attached/media drives (example)
  - /media/SSD-01/project-alpha:/export/project-alpha:rw
  - /media/SSD-01/backups:/export/backups:rw

  # Single source of truth (edited by the in-container WebUI or by hand)
  - ./config:/config:rw

  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro

  # No exports.d or templates bind mounts are needed in the normal model.
  # The container generates everything from nfs-klldap.conf via the bundled Rust binary.
```

## Summary

This document now describes the **final** architecture. The kernel NFS path has been fully removed. The system is a clean, pluggable, LLDAP-backed Kerberized NFSv4 appliance that can be dropped onto any Linux host.

All future development, documentation, and tooling should assume Ganesha + self-contained inotify watcher (no DBUS) + share-centric LLDAP permission editing. The direct DBUS path is no longer used or required.
