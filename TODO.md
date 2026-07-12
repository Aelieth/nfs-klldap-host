## Future Plans
- Slight decoupling of LLDAP code to simplify NFS share management for those that want it
- Integration into KLLDAP for quick deployment with built-in keytab
- Wizard first-share step: after LDAP setup, offer share name + host path with opinionated defaults (NOACL, RW, root_squash, auto pseudo) so first-run ends with a working share
- Custom-compiled Ganesha without _MSPAC_SUPPORT to unlock the principal-based uid2grp path (removes the idhelper/nss_wrapper backstop requirement)

## Known issues / tracking
- **RESOLVED 0.9.85 — dir-perms r/x collapse + files in the browser.** The tree
  now lists files (dirs-first sort, type emoji, UTC mtime; single-level
  `FsManager::list_dir` replaced the whole-subtree `build_tree` recursion).
  Directories present a condensed Read/Write matrix (Write⇒Read; the client
  submits the **x-less** mode and only the readout previews the fused dir
  mode) plus a three-way **Apply scope** (none = the directory inode only /
  single directory = + files directly inside / all directories = whole
  subtree) with an explicit **file-bits editor** for the recursive scopes —
  every file in scope gets exactly those bits (execute is an opt-in grant;
  special bits refused on files). Files selected individually keep the full
  rwx triad, no special bits, no scope. Server-side
  `fs::dir_mode_r_implies_x` per entry is unchanged (see ui-design.md "Read
  implies execute" + "Apply scope"). File-type icons expanded to 13
  categories (audio/scripts/software/fonts/Windows/DOS + Linux-heavy
  extension coverage + hover labels) — see ui-design.md. Follow-ups: the
  0.9.9x ACL line builds on this UX per the filesystem-ACL pivot (refactor
  plan, Realignment 2026-07-12 + rewritten 2.5: full POSIX ACL model —
  mask/defaults/effective badges, recursive ACL applies riding the same
  scopes); ARIA tree pattern still deferred (ui-design.md).
- Track regressions via `cargo test --workspace` and [TESTING.md](TESTING.md) living spec.
- **0.9.x branch**: branch name carries the release version (currently 0.9.85); Cargo workspace, Dockerfile LABEL, and nfs-klldap-host.yaml image tag are aligned to it.
- Client connects (2026-07 capture): krb5 auth + NFSv4.1 session succeed server-side, then the client destroys the session before any namespace op — failure is client-side (gssd/mount context). GANESHA_DEBUG now logs RPCSEC_GSS; see docs/client-fedora-immutable.md troubleshooting.

## Kerberos user principal idmap
Supported: idhelper (proactive+reactive+cache) authoritative for complete supps+uid0 in nss+extrausers (UseGetpwnam/getgrouplist). See plan.

## Historical: diagnosed I/O / sporadic access issues (krb5p, Dolphin, immutable clients) — 2026-06 goal run
Superseded notes: this run predates the NOACL-default refactor (7b9c18d); it references `Manage_Gids=false` emission which is no longer the default (NOACL now emits `Manage_Gids = true`, opt-out per share).
From clean build (make clean + cargo clean + docker buildx), container launch (verbatim command), Fedora 44 client runs using the committed strict script, ganesha.log during the run, and generation tests:
- Strict script (set -euo, cp keytab to /etc/krb5.keytab, exit non-zero on M!=0, visibility assert) run via canonical docker produced the transcript in fedora-client.log: M1=0 M2=0, krb5p mounts, real NFS write/cat cycles, "VISIBLE ON HOST BIND - SUCCESS", CAPTURE_RC=0.
- ganesha-during-fedora-success.log (tail from the successful run) shows NFS4 GETATTR OK + lease update with cred_flavor=6 for the Linux NFSv4.2 client during the cycles. No EIO.
- Live ganesha.conf + fragments after final clean build + launch emit the production Lease=60/Grace=45.
- Same log file also captured the env pre-success messages (rpc_pipefs empty, Operation not permitted) that are expected in this container test setup per plan Risks.
Root causes from logs: client gssd/pipefs/keytab placement + container mount syscall restrictions for NFS; server config emission of safe krb5p flags + lease values.
Fixes: Lease/Grace production values + dedicated generate_all test. Verified against the real strict-script transcript + unit tests.
