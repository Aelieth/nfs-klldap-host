# Custom Ganesha packaging

Stock Debian **nfs-ganesha 9.13-1** → **`9.13-1+klldap3`** (sorts above stock). One ACL-capable binary; NOACL is per-export via `Disable_ACL`, not a separate build.

## Files

| Path | Role |
|------|------|
| `klldap-packaging.patch` | Packaging delta on stock source |
| `build-ganesha-debs.sh` | Fetch (sha256-pinned), patch, build, gate → `/debs` |

Patch touches:

- `debian/changelog` — `+klldap1` / `+klldap2` / `+klldap3` identity
- `debian/control` — drop unused FSAL packages and their build deps
- `debian/rules` — flag delta (below)
- `debian/patches/klldap-nsswitch-getgrouplist-return.patch` — nsswitch `getgrouplist` returns group count on success; normalize to 0-on-success so supplemental groups are not dropped (**klldap2**)
- `debian/patches/klldap-uid2grp-serialize-fetch.patch` — single-flight concurrent uid2grp cache misses so partial NSS results are not cached (**klldap3**)

## Flag delta from stock

| Change | Why |
|--------|-----|
| `_MSPAC_SUPPORT=NO` | Stock stubs principal→group resolution; off restores `nfs4_gss_princ_to_grouplist` and drops wbclient |
| CEPH/RGW/GLUSTER/GPFS/PROXY/NULL/MEM/9P/RADOS off | VFS only |
| `USE_FSAL_LIZARDFS=NO`, `USE_FSAL_SAUNAFS=NO` | Pin defaults (deterministic) |
| `ENABLE_VFS_POSIX_ACL=YES` (stock) | Persistent POSIX ACL store; do **not** enable `ENABLE_VFS_DEBUG_ACL` (in-memory only, disables POSIX backend) |

Everything else (GSS, DBus, nfsidmap, `USE_SYSTEM_NTIRPC=YES`) stays stock.

## Build & verify

```sh
docker build --target ganesha-build -t nfs-klldap-ganesha-debs .
docker run --rm nfs-klldap-ganesha-debs sh -c 'cat /debs/MANIFEST.txt'
```

Build fails if invariants break: MSPAC or DEBUG_ACL defined, POSIX ACL missing from `config.h`, wbclient on the core deb, or non-VFS FSAL libs.

Source: `deb.debian.org` pool (hashes in `build-ganesha-debs.sh`). If 404, use [snapshot.debian.org](https://snapshot.debian.org) and the same hashes.

Regenerate the patch after editing a stock `debian/` tree:

```sh
diff -Naur a/debian b/debian > container/ganesha/klldap-packaging.patch
```

## Runtime notes

- Image installs the debs and asserts version `GANESHA_VERSION`.
- Smoke / gates: `scripts/ganesha-startup-smoke.sh`, `scripts/ganesha-export-reload-smoke.sh`, `scripts/ganesha-log-audit.sh`.
- `PR_SET_IO_FLUSHER` needs `CAP_SYS_RESOURCE`; generator emits `Allow_Set_Io_Flusher_Fail = true;` so the default cap set still works.
