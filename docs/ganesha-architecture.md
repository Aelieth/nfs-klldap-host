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
- Dynamic export management via DBUS (`org.ganesha.nfsd.exportmgr`)
- No dependency whatsoever on host kernel NFS modules

## Current Architecture

```
Host (no kernel NFS modules required anywhere)
├── Real data directories          (/srv/nfs/*, /media/*, etc.)
│   └── Numeric uid/gid ownership must match LLDAP uidNumber/gidNumber
├── ganesha-exports.d/             (native Ganesha EXPORT {} blocks)
├── templates/                     (sssd.conf.template, krb5.conf.template, ganesha.conf.template)
├── secrets/krb5.keytab            (nfs/<hostname>@REALM, mode 600)
└── management/ (Rust web UI)      (Axum + HTMX)
    ├── Talks to LLDAP (GraphQL) for live user/group → uid/gid
    ├── Uses narrow privileged helper for recursive chown/chmod on host
    ├── Writes native Ganesha EXPORT {} fragments
    └── Speaks directly to Ganesha via: docker exec <name> ganesha-ctl ...

Container (AlmaLinux 10)
├── NFS-Ganesha (ganesha.nfsd)     — the complete NFSv4 + Kerberos server
├── SSSD                           — LLDAP POSIX provider (nss + id mapping)
├── DBUS + ganesha-ctl wrapper     — bridge for direct runtime export management
└── Templates rendered at start (TEMPLATES_DIR)
```

The management tool (host) and container work together as a "one stop NFS plugin":

- LLDAP is the source of truth for identity and POSIX attributes.
- The container serves Kerberized NFSv4.
- The web UI lets administrators manage shares and any subdirectory permissions visually.

## Key Technical Choices

- **No kernel NFS** in the image or entrypoint.
- **Native Ganesha EXPORT blocks** (not classic `/etc/exports`).
- **Direct DBUS management** via the `ganesha-ctl` wrapper (the management tool calls `docker exec ... ganesha-ctl add-export ...` etc.).
- **SSSD** as the bridge to LLDAP POSIX attributes (`uidNumber`, `gidNumber`).
- **Templates + envsubst** for clean, host-driven configuration.
- **Share-centric UI** — each share has its own browsable tree; any subfolder can have its POSIX ownership changed with live LLDAP lookup + recursive apply.

## Runtime Export Management

Ganesha supports fully dynamic add/remove of exports at runtime via the DBUS interface `org.ganesha.nfsd.exportmgr` (`AddExport`, `RemoveExport`, `ShowExports`, etc.).

The project ships a small `ganesha-ctl` helper inside the container that the host tool (and operators) can invoke via `docker exec`. This is the preferred mechanism. A simple SIGHUP path is also supported as a fallback.

See `container/scripts/ganesha-ctl` and the management tool's `ganesha.rs` / `exports.rs` for implementation details.

## Configuration

Everything is driven by bind-mounted templates (or final configs):

- `sssd.conf.template`
- `krb5.conf.template`
- `ganesha.conf.template` (includes `/etc/ganesha/exports.d/*.conf`)

The `ganesha.conf.template` enables the DBUS management interface and includes per-share export fragments written by the management tool.

## Health and Verification

- Container healthcheck: `container/healthcheck.sh` (process + TCP 2049 + basic responsiveness).
- Inside container: `ganesha-ctl show-exports`, `getent passwd`, `id`, `klist -k /etc/krb5.keytab`.
- From client: `mount -t nfs4 -o sec=krb5p ...`

The old kernel-oriented commands (`rpc.idmapd -f -vvv`, `exportfs -s`, `rpcinfo`, etc.) no longer apply.

## Privileges and Volumes (Typical)

```yaml
cap_add: [SYS_ADMIN, DAC_READ_SEARCH]
volumes:
  - /srv/nfs/myshare:/export/myshare:rw
  - ./ganesha-exports.d:/etc/ganesha/exports.d:rw
  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
  - ./templates:/container/templates:ro
  - /run/dbus/system_bus_socket:/run/dbus/system_bus_socket:rw   # required for direct management
```

## Summary

This document now describes the **final** architecture. The kernel NFS path has been fully removed. The system is a clean, pluggable, LLDAP-backed Kerberized NFSv4 appliance that can be dropped onto any Linux host.

All future development, documentation, and tooling should assume Ganesha + direct DBUS management + share-centric LLDAP permission editing.
