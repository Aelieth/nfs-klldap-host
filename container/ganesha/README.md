# Custom Ganesha packaging (refactor plan Phase 2 uplift)

This directory holds the delta that turns the stock Debian unstable
`nfs-ganesha 9.13-1` source into the nfs-klldap-host Phase 2 build, versioned
**`9.13-1+klldap2`** (sorts above stock, so the custom package wins an
upgrade comparison). Per the 2026-07-10 realignment this is **one
ACL-capable binary** serving both share classes — NOACL is enforced
per-export via `Disable_ACL`, not by the build. Rollback is the tagged
9.6+klldap1 Phase 1 image (the last structurally-NOACL binary), or stock
`9.6-1~bpo13+1` from trixie-backports.

## Files

- `klldap-packaging.patch` — the entire packaging delta, applied with
  `patch -p1` on top of the extracted stock source. Touches exactly four
  files:
  - `debian/changelog`: prepends the `+klldap1`/`+klldap2` entries
    (package identity).
  - `debian/control`: drops the per-FSAL binary packages (ceph, rgw,
    gluster, gpfs, mem, nullfs, proxy-v4, rados-grace, mount-9p) and their
    build deps (`libcephfs-dev`, `libglusterfs-dev`, `librados-dev`,
    `librgw-dev`, `libwbclient-dev`).
  - `debian/rules`: the flag delta (see below).
  - `debian/patches/klldap-nsswitch-getgrouplist-return.patch` (+ series):
    the one **source** fix in klldap2 — upstream 9.13's
    `my_getgrouplist_alloc()` treats any non-zero return as failure, but
    with `Pwnam_Implementation = nsswitch` the wrapper is raw libc
    `getgrouplist(3)`, which returns the **group count** on success. Every
    user in ≥1 group therefore lost all supplementary groups
    (`getgrouplist for user:X failed, ngroups: 17, errno: 17` + 594
    per-request managed-gids fallbacks in the 2026-07-10 round-2 capture).
    The patch normalizes the nsswitch path to the 0-on-success convention
    the SSSD implementation uses. Candidate for upstream submission.
- `build-ganesha-debs.sh` — runs in the `ganesha-build` Docker stage:
  fetch stock source (sha256-pinned), `dpkg-source -x`, apply patch,
  `apt-get build-dep ./`, `dpkg-buildpackage -B`, then **gate** the result
  and emit `/debs` (two debs + MANIFEST).

## Flag delta from stock (plan 2.1, realigned 2026-07-10)

| Change | Why |
| --- | --- |
| `_MSPAC_SUPPORT=NO` | Stock `YES` stubs `uid2grp_allocate_by_principal()` to `return NULL` (`support/uid2grp.c` — structure unchanged on 9.13), killing principal-based group resolution. Off restores the `nfs4_gss_princ_to_grouplist()` path and drops the wbclient/winbind dependency. Carried over from Phase 1. |
| CEPH/RGW/GLUSTER/GPFS/PROXY_V4/NULL/MEM/9P/RADOS off | VFS is the only FSAL; smaller image and CVE surface. Carried over from Phase 1. |
| `USE_FSAL_LIZARDFS=NO`, `USE_FSAL_SAUNAFS=NO` | Default ON upstream; stock relied on missing libs to auto-disable. Pinned for determinism (no output change). |
| `ENABLE_VFS_POSIX_ACL=YES` **retained (stock)** | Phase 1 removed it; Phase 2 ships one ACL-capable binary and enforces NOACL per-export (`Disable_ACL`). **Inventory finding 2026-07-10:** the plan's original ACL vehicle, `ENABLE_VFS_DEBUG_ACL`, is an in-memory AVL tree (`FSAL_VFS/vfs/attrs.c`) — nothing persists, ACLs vanish on restart, and it force-disables the POSIX backend. The POSIX mapping is FSAL_VFS's only persistent ACL store, so stock disposition is restored; the delta from stock 9.13 stays at exactly MSPAC + FSAL trim. |
| Everything else unchanged | GSS (default ON), DBus, nfsidmap, admin tools, monitoring, man pages, `USE_SYSTEM_NTIRPC=YES` (libntirpc 7.2 from backports; unstable builds 9.13 against the same version), source version 9.13. `ENABLE_RFC_ACL` stays default-off — the RFC-strict variant question belongs to the 0.9.9x ACL track. |

## Building and verifying

```sh
docker build --target ganesha-build -t nfs-klldap-ganesha-debs .
docker run --rm nfs-klldap-ganesha-debs sh -c 'cat /debs/MANIFEST.txt'
```

The build **fails** (by design) if any Phase 2 invariant is violated:
`_MSPAC_SUPPORT` or `ENABLE_VFS_DEBUG_ACL` defined in the generated
`config.h`, `ENABLE_VFS_POSIX_ACL`/`ENABLE_VFS_ACL` **missing** from it
(the ACL capability is now required), a wbclient dependency on the core
deb, or any FSAL library other than `libfsalvfs.so` in the packages.

## Source provenance

Fetched from `deb.debian.org/debian/pool/main/n/nfs-ganesha/` and pinned by
sha256 in `build-ganesha-debs.sh` (hashes recorded 2026-07-10 for 9.13-1;
the `.dsc` pin transitively covers the Debian-published checksums of both
tarballs — verified at pin time). Pool files get removed when superseded —
if the fetch 404s, pull the same filenames from
<https://snapshot.debian.org> and verify against the same hashes.
9.13-1's `debian/control` is byte-identical to 9.6-1~bpo13+1's, so the
build-dependency set is already proven on trixie + backports.

## Regenerating the patch

Extract the stock source, copy `debian/` to `a/debian` (pristine) and
`b/debian` (edited), make changes in `b/`, then:

```sh
diff -Naur a/debian b/debian > container/ganesha/klldap-packaging.patch
```

The runtime image consumes these debs since plan section **1.3** (2026-07-09):
the runtime stage COPYs `/debs` from `ganesha-build` and installs them with
`-t trixie-backports` (for the libntirpc dependency), asserting the installed
version equals `GANESHA_VERSION` at build time. The startup sanity gate lives
in `scripts/ganesha-startup-smoke.sh`; the live export management gate (plan
**1.4** — add/update/remove via SIGHUP `reread_exports` without a restart,
DBus `ShowExports` as ground truth) is `scripts/ganesha-export-reload-smoke.sh`.
The plan **1.5** log-audit gate is `scripts/ganesha-log-audit.sh <capture>`:
it grades any saved ganesha.log slice (severities, managed-groups fetch
failures per uid, unmapped principals, MSPAC stub hits, capture
diagnosability) and exits non-zero if the gate criteria fail.

Two operational facts surfaced by the 1.3 gate:

- Ganesha calls `PR_SET_IO_FLUSHER` (9.6 and 9.13 alike), which needs
  `CAP_SYS_RESOURCE`. The deployed cap set (`SYS_ADMIN` + `DAC_READ_SEARCH`)
  does not include it; the config generator already emits
  `Allow_Set_Io_Flusher_Fail = true;` so this is handled — any hand-written
  config must do the same.
- In the Phase 1 NOACL build the `libacl1` dependency was dormant
  (`os/linux/acl.c` portability shim only; zero `acl_*` imports in
  `libfsalvfs.so`). Since the 2026-07-10 uplift the POSIX-ACL backend is
  compiled in, so `libfsalvfs.so` genuinely links libacl — expected, and
  gated the other way around now (the startup smoke fails if the backend is
  *missing*).
