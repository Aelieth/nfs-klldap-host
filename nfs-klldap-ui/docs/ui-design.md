# UI Notes

Axum + HTMX + server templates extending `base.html`. First-run: `/setup/1` (persistent volume) → `/setup/2` and `/setup/3` (**Test Settings** then **Save and Continue**) → restarting page (polls `/restart-status`, same as settings restart) → `/login` + `POST /setup-password`. Pre-configured conf+keytab skips `/setup`. Main pages: `/` (tree + apply), `/settings` (raw/structured TOML, shares, restart).

Auth: webui-password sidecar (localhost) or LLDAP in webui_admin_group.

Handlers in web/ (mod orchestrator + auth/permission_tree/settings/keytab). FS policy + progress in fs.rs; LDAP in ldap.rs.

Apply is always async with live count-then-apply progress, cancel, oob log.

## Share Permissions page (`/`)
Permissions editing is a **detached panel** (`#perm-panel`) beside the directory tree, not inline
under each row. Selecting a `.dir` loads `GET /dir-perms?path=…` into the panel body
(`templates/dir_perms.html`) — this single endpoint replaced the retired `/dir-meta`, `/dir-editor`,
and `/dir-acl` trio. The panel shows **POSIX** (owner/group with live LLDAP search + hidden numeric
uid/gid for name→id translation, a 3×3 rwx matrix, **setgid/sticky** toggles, and a live octal +
symbolic readout) and, beside it, the **named ACL/xattr** list. POSIX Apply POSTs the existing
`/apply` (chown/chmod, incl. setgid/sticky — only setuid is refused); ACL add/remove POST `/acl-apply`
(names resolved via LDAP, same as POSIX). Edit mode locks tree/share selection until Cancel/Apply,
and the Apply Log is in-flow below the panel (driven by `/apply-progress` polling + oob swaps).

ACL support is shown only when the share **actually serves ACLs**: `enable_acl = true` AND the
serve-path filesystem is ACL-capable. If `enable_acl = true` but the filesystem cannot honor ACLs
(e.g. Ganesha 9.6 VFS FSAL → `NFS4ERR_NOTSUPP`), the section reverts to **Non-ACL** with an explicit
reason. The share-card status dot follows the same rule (green = ACL supported, blue = Non-ACL).

## System Settings → Shares

Share-card status dots use the **same effective rule** as Share Permissions and Ganesha export
emission: green only when `enable_acl = true` and the serve-path FS is ACL-capable. Values
`auto` (unset) and `off` are both NOACL (`Disable_ACL = true`) and show blue. The `enable_acl`
dropdown labels `auto` as “auto (NOACL)” to match the opt-in policy.

See templates/ + source for current UX. (Historical decisions resolved: lazy tree, detached
permissions panel, structured shares, full progress.)
