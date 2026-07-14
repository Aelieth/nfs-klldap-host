# UI Notes

Axum + HTMX + server templates extending `base.html`. First-run: `/setup/1` (persistent volume) → `/setup/2` and `/setup/3` (**Test Settings** then **Save and Continue**) → restarting page (polls `/restart-status`, same as settings restart) → `/login` + `POST /setup-password`. Pre-configured conf+keytab skips `/setup`. Main pages: `/` (tree + apply), `/settings` (raw/structured TOML, shares, restart).

Auth: webui-password sidecar (localhost) or LLDAP in webui_admin_group.

Handlers in `web/` (`mod`, `auth`, `permission_tree`, `settings`, `setup`, plus ACL helpers). FS policy + progress in `fs.rs`; LDAP in `ldap.rs`. Keytab/hostname checks live under settings/setup surfaces (no separate `keytab.rs`).

Apply is always async with live count-then-apply progress, cancel, oob log.

## Share Permissions page (`/`)
Permissions editing is a **detached panel** (`#perm-panel`) beside the directory tree, not inline
under each row. The tree lists **directories and files** (since 0.9.85): each `/tree` fetch renders
exactly one level via `FsManager::list_dir` (the old whole-subtree `build_tree` recursion is gone) —
subdirectories first, then files, each group case-insensitively sorted. **All entries render** (the
`#tree-root` panel scrollbar handles volume — no pagination by design), symlinks are excluded,
dotfiles are visible, and an empty directory shows a muted `(empty)` row. Rows share
`templates/tree_entry.html`: directory rows are **two real buttons** — `.dir-caret` only
expands/collapses (lazy 1-level fetch via `/tree`, `aria-expanded` tracks state) and `.dir-label`
(📁 + name) only selects — while file rows (`.file`, slightly smaller font) carry a category emoji
(13 kinds: 📄 text/document · 📜 script/code · 🖼️ image · 🎵 audio · 🎬 video · 💿 disk image ·
📦 software/binary · 🪟 Windows/WINE · 💾 DOS · 🔤 font · 🗄️ data/archive · ❔ unknown · 📁
directory; mapped server-side in `file_kind`, which also names the category in the icon's hover
`title`), a `.file-label` select button, and a right-aligned UTC modified stamp (`.file-mtime`).
`file_kind` matches well-known extensionless names before the extension (README-family and config
dotfiles → 📄, Makefile/Dockerfile/shell-rc → 📜) and pins the ambiguous cases in code comments
(`.ts` = MPEG-TS 🎬 not TypeScript, `config.sys` 💾 beats the `.sys` 🪟 driver rule, `go.mod` 📜
beats tracker-music `.mod`, `.bin` stays 🗄️). Selecting either kind loads `GET /dir-perms?path=…` into the panel body
(`templates/dir_perms.html`) — this single endpoint replaced the retired `/dir-meta`,
`/dir-editor`, and `/dir-acl` trio and now serves **both node kinds** (the form carries
`data-kind="dir|file"` as the JS contract). Share cards are keyboard-activatable
(`role="button"`, `tabindex`, `aria-pressed`, Enter/Space). The panel shows **POSIX** (owner/group
with live LLDAP search + hidden numeric uid/gid for name→id translation; **directories** get the
condensed 2-column Read/Write matrix, **setgid/sticky** toggles (one row), the **Apply-scope
radios** (None / single directory / all directories) and, for recursive scopes, the **File
permission bits** editor; **files** get the full 3×3 rwx matrix with no special bits and no scope
radios; per-checkbox `aria-label`s and a live octal + symbolic readout — plus a second `Files NNN`
readout while a recursive scope is selected) and, beside it, the **named ACL/xattr** list (both sections render
through the `acl_group` Askama macro). POSIX Apply POSTs the existing `/apply` (chown/chmod, incl.
setgid/sticky — only setuid is refused); ACL add/remove POST `/acl-apply` (names resolved via LDAP,
same as POSIX; unresolvable principals answer **422** so the client reports the rejection).

**Full POSIX ACL model, tabbed layout (0.9.90):** the section header is just **"ACL"** plus a
pill — `on` (explicit), `auto` (unset `enable_acl`, promoted because the serve path passed the
write probe), or `off` (one short reason line whose hover carries the detail; everything longer
lives in tooltips per the compaction contract). Two **tabs** switch layers: **Current** (the
access ACL) and, on directories, **Inherit** (the default ACL — server refuses default ops on
files with 422). Each pane is a **columnar list** aligned with the POSIX matrix: an R/W/X header,
then Users and Groups categories (collapsible headers, simple divider between them) and the
**mask** as a distinguished last row; the whole list scrolls (~8–10 rows visible). A ✓ marks the
entry as granted; a **dimmed ✓** marks bits the mask withholds (row hover names the effective
triad). Once the access ACL is extended, the POSIX **Group row grows a `mask-star`** with hover
prose — the 2.4 mask-envelope made visible. Editing matches the POSIX side
(2026-07-12 round 4): row checkboxes under **Read/Write/Exec** headers **toggle directly in edit
mode** (op=set on change; the mask row posts op=mask; node-only), clicking a row's name selects it
for **[Remove]**, and **[Add User] / [Add Group]** enter an **add mode**: a POSIX-style
LDAP-searching principal field, R/W/E boxes (labels above), and — on directories — the same
Apply-scope radios as POSIX; everything else in the panel goes inert, the state chip reads
`EDITING - ADDING ACL USER|GROUP`, and the panel's **Apply** (armed only once a principal is typed
and ≥1 permission is checked) or **Cancel** finish the flow. The `/acl-apply` endpoint itself
refuses NOACL/incapable paths with 422 (capability decision enforced server-side, probed against
the SELECTED node's own mount — submounts included), and a settings save rejects `enable_acl =
true` on a known-incapable serve path. The panel reloads from getfacl truth after every op — never
optimistic state. All ops carry `layer`; `-b` is never emitted (entry-merge + targeted remove
only). Recursive ACL grants use **split specs**: directories get fused r→x perms; files get the
literal triad from the panel Exec checkbox (capital-`X` conditional grant is retired).
Inherit-tab recursion touches directories only. Tree rows on ACL-active shares carry a
**`+` marker** (one batched getfacl per fragment) where an entry's ACL exceeds base mode.
Behavior change with `list_dir`: an unreadable or missing container directory now renders the
tree diagnostic alert (`list_dir` returns None) instead of a silently empty level.

**Owner/group resolution contract (`/apply`, since 0.9.81):** uid/gid **0 is a first-class
owner** — on-disk root is the nobody/anonymous identity NFS clients see under root-squash, so it
renders as **"nobody (0)"** and hand-typed `nobody` or `root` resolve to 0 without LDAP. The
hidden numeric fields always carry the panel's current ids (0 included) and win when untouched;
hand-editing the visible field clears them (permissions.js) so typed names/ids take over. Fields
left blank keep the directory's **current** ownership. There is no default-uid fallback — the old
0-as-unset sentinel silently rewrote 0:0 (and any untouched form) to a hardcoded `1000:1000`,
which is how a share root got flipped to uid 1000 in the 2026-07-11 round-3 test.

The 0-owner contract runs the full depth of the stack (each layer had its own 0-hostility,
found across two round-3 fix passes): `FsManager::apply_permissions_with_progress` no longer
refuses uid/gid 0 pre-walk (setuid refusal stays); the `/users/search` + `/groups/search`
live search always offers a **synthetic "nobody (UID/GID 0)" row** for queries matching
`nobody`/`root`/`0`/empty — LDAP-independent, shown even while LLDAP is unreachable; and the
suggestion-click handler in permissions.js writes `0` into the hidden id fields (its old
`uid || ''` falsy-check dropped it).

**Read implies execute on directories (round-4; UI collapse landed 0.9.85):** Ganesha's readdir
returns entry attributes only with **R+X on the directory**, so an r-without-x directory lists as
*empty* over NFS (a `0776` share root is how the users share "returned nothing"). The pair is one
concept for directories, coordinated across three layers:

- **Condensed directory matrix** — Read/Write per audience (`.perm-matrix-dir`, `.pbit`s with
  data-bit 4/2 only). Write auto-checks Read; un-checking Read drops Write, so each audience is
  none / read-only / read-write.
- **x-less submit, fused display** (the load-bearing contract) — `.mode-field` always gets the raw
  checkbox sum (e.g. `0660`), while the octal/symbolic readout previews the fused directory mode
  (`0770`). The server fuses r→x per **directory** entry via `fs::dir_mode_r_implies_x` exactly as
  before; files never receive the directory mode at all (see Apply scope below).
- **Files get the full triad** — a file selected in the tree edits its own 3×3 matrix with
  independent x (r-without-x is normal for a file), no special bits, no scope radios; a
  hand-crafted POST claiming a recursive scope on a file target is braced server-side
  (`target_is_file` forces `ApplyScope::DirOnly`).

**Apply scope + file execute (dir panels):** the fragment's `.rec-scope` radios
(`recursive_scope` = `none|single|all`) choose how far Apply reaches — **None** chowns/chmods the
directory's own inode only; **Recursive — single directory** adds the files directly inside it;
**Recursive — all directories** descends the whole subtree. There is no separate file-bits
editor: the matrix's **Exec column is the file-execute grant** for recursive scopes — files in
scope take the matrix Read/Write bits plus execute only where Exec is checked, submitted as
`file_mode` (`ApplyScope`/`ApplySpec` in fs.rs; special bits in `file_mode` are refused), while
directories always fuse execute from Read server-side. The Exec boxes disable+clear on scope
None. So file execute is always an explicit grant — asserted end-to-end by
`web_recursive_apply_xless_mode_fuses_dirs_not_files` (x-less file bits stay x-less) and
`web_apply_scope_all_grants_file_execute_only_when_chosen`. Both recursive scopes require a
`confirm()`; the fragment reload after an apply resets the scope to None on purpose.

A directory whose current mode grants x-without-r (traverse-only) shows a compact amber
`.perm-note.warn` — that state isn't representable in the condensed matrix and is stripped on
Apply.

**Compaction contract (0.9.85):** the editor carries no helper prose — descriptions live in
`title` hovers (the Read column header carries the read-implies-execute explanation; the
Apply-scope label carries the files-get-file-bits rule; setgid/sticky/radio labels are bare
single terms with their explanations on hover). There is no "Permission bits" heading (the matrix
column headers are the label), setgid + sticky share one row, and the groups are separated by
thin dashed top-borders (`.rec-scope`, `.perm-readout`) instead of text. The
readout row wraps whole items (`flex-wrap` + `white-space:nowrap` on `.symbolic`) so `Files`
drops to its own line rather than breaking the symbolic string. When adding new controls to the
panel: hover for help, dividers for grouping, no inline explanation lines.

All client behaviour lives in `/assets/permissions.js` behind the **`window.PermUI`** surface
(`isLocked/flashLock/loadDirPerms/cancelCurrentApply/setShare`); panel state (share, current path,
applying, dirty) is private JS state — never read back out of DOM text. Edit-mode visibility
(Edit/Cancel/Apply, ACL add/del) is CSS-driven off `.perm-panel.editing`; the scope radios and
Exec grants live inside the fragment form and are enable/disable-toggled with the other inputs. On a
**Non-ACL** directory (`.acl-sec.disabled`) the ACL entries stay inert even in edit mode. Edit mode
locks tree/share selection until Cancel/Apply; Cancel asks for confirmation only when edits are
dirty; both recursive scopes require a `confirm()`. Fragment loads show foreground feedback (panel
`.loading` dim + spinner + aria-live state chip, tree placeholder, busy caret on expand). The Apply
Log is in-flow below the panel, driven by `/apply-progress` polling + oob swaps — the endpoint
answers **HTTP 286** once finished (or with no progress slot) because htmx 1.9 only stops an
`every …` poll loop on 286 or element removal; `data-apply-finished="true"` on the shell is the
JS finish contract. When a directory can't be stat'd (serve path missing, unmapped, or unreadable),
the panel replaces the split editors with a full-width diagnostic (`.panel-alert`) that names the
cause, the fix, and the host + serve paths — `dir_perms` picks the message per `PathDiagnostic`
(allowed / mapped / exists).

ACL support is shown only when the share **actually serves ACLs**: `enable_acl = true` AND the
serve-path filesystem is ACL-capable. If `enable_acl = true` but the filesystem cannot honor ACLs
(e.g. an ACL-incapable filesystem under the VFS FSAL → `NFS4ERR_NOTSUPP`), the section reverts to **Non-ACL** with an explicit
reason. The share-card status dot follows the same rule (green = ACL supported, blue = Non-ACL).

## System Settings → Shares

Share-card status dots use the **same effective rule** as Share Permissions and Ganesha export
emission: green only when `enable_acl = true` and the serve-path FS is ACL-capable. Values
`auto` (unset) and `off` are both NOACL (`Disable_ACL = true`) and show blue. The `enable_acl`
dropdown labels `auto` as “auto (NOACL)” to match the opt-in policy.

New cards from **+ Add share** are server-rendered: the card markup lives once in
`templates/share_card.html` (included per row by settings.html), and `GET /settings/share-card?idx=N`
returns a blank card that `addShareRow()` appends via htmx. Never reintroduce a JS copy of the card —
that duplication is exactly what previously lost the field tooltips on new cards.

## Page shell & viewport

Every page extending `base.html` shares one centered shell: `body { margin: 2rem auto;
max-width: var(--page-max); padding: 0 1.25rem }` with `--page-max: 1280px`. Content stops growing
above the cap and centers, so the header, nav, and page content sit in the same place on every
navigation and nothing scales unbounded on large displays. 1280px keeps the Share Permissions tree
column (~660px) adjacent to the fixed 560px panel and gives Settings' two-column field grid sane
input widths; laptops ≤1366px are effectively unchanged.

Narrow form pages (login, setup 1–3) additionally wrap their content in
`<div class="content-narrow">` (`--content-narrow: 680px`, centered) — use that class for any new
form-style page. Element-level widths inside it (420px login form, 520px setup inputs, 640px test
log) are intentional and stay.

Exception: `templates/restarting.html` is deliberately standalone (services are bouncing; it must
not depend on base.html) and carries its own copied theme vars and a narrower 720px body. Keep it
self-contained; sync its palette manually if the theme vars change.

## Theme architecture

Theme scripting is two inline `<script>` blocks in base.html's head, in contract order, with the
app script external:

1. **FOUC early-init** — reads localStorage `theme` and stamps/removes `data-theme` on `<html>`
   before first paint.
2. **Theme manager (isolated)** — `window.setTheme`, a *delegated* `document`-level change listener
   for the `#theme-tray` radios, and the `prefers-color-scheme` auto-follow listener. It is a
   separate block on purpose: a runtime error in the app script can then never kill theming
   (this happened once — a top-level `document.body.addEventListener` in the shared block threw
   during head parse and silently disabled the tray).
3. **App script** — `/assets/permissions.js`, loaded with `defer` (an IIFE exposing only
   `window.PermUI`). Externalizing it keeps theming immune to app-script errors by construction.

Semantics: localStorage key `theme` ∈ `auto|dark|light`; explicit values set
`data-theme` on `<html>`, auto removes it so the `@media (prefers-color-scheme)` block applies.
**Head-script gotcha (institutional memory):** these blocks run before `<body>` exists — top-level
`document.body.*` calls throw and abort the rest of that block. Delegated listeners must target
`document`.

## Routes

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/assets/htmx-1.9.12.min.js` | vendored htmx (immutable cache) | none (setup-gate exempt) |
| GET | `/assets/permissions.js` | Share Permissions app script (no-cache) | none (setup-gate exempt) |
| GET/POST | `/login` | login page / login | none |
| POST | `/setup-password` | first-run localhost password | none |
| GET/POST | `/logout` | clear session | none |
| GET | `/restart-status` | post-restart poller | none |
| GET | `/setup`, `/setup/1..3` | wizard pages (redirect to current step) | none (pre-setup only) |
| POST | `/setup/1/verify`, `/setup/2/test`, `/setup/2/continue`, `/setup/3/test`, `/setup/3/continue` | wizard actions | none (pre-setup only) |
| GET | `/setup/3/status` | saved bind-cred probe | none (pre-setup only) |
| GET | `/` | Share Permissions page | session |
| GET | `/tree` | one-level dir+file listing: root row (`root=true`) or children fragment | session |
| GET | `/dir-perms` | detached panel body (directory or file) | session |
| GET | `/users/search`, `/groups/search` | LLDAP suggestion fragments | session |
| POST | `/apply`, `/acl-apply`, `/cancel-apply` | POSIX / ACL apply + cancel | session |
| GET | `/apply-progress` | oob Apply Log poller (286 when finished = htmx stop-polling) | session |
| GET | `/settings` | System Settings page | session |
| GET | `/settings/share-card` | blank share card fragment | session |
| POST | `/settings/save`, `/settings/save-shares`, `/settings/save-raw` | save structured / shares / raw TOML | session |
| GET | `/settings/lldap-status` | LLDAP NFS client status fragment | session |
| POST | `/settings/reload-nfs-client`, `/settings/clear-ldap-cache` | LLDAP client maintenance | session |
| POST | `/settings/restart` | apply + service bounce | session |
| POST | `/settings/test-ldap`, `/settings/test-bind` | diagnostics probes (JSON) | session |

All routes except the setup-gate allowlist (`/setup*`, `/assets/*`, `/login`, `/setup-password`,
`/restart-status`, `/logout`) redirect to the wizard while first-run setup is incomplete; session
auth is enforced per-handler via `require_auth`.

## Assets & palette

htmx **1.9.12** is vendored at `nfs-klldap-ui/assets/htmx-1.9.12.min.js` (sha256
`449317ade7881e949510db614991e195c3a099c4c791c24dacec55f9f4a2a452`, from
`unpkg.com/htmx.org@1.9.12/dist/htmx.min.js`) and embedded via `include_str!`. To upgrade: add the
new file under a new versioned name, point base.html and the route at it, delete the old one — the
filename is versioned because the route serves `Cache-Control: immutable`.

The app script lives at `nfs-klldap-ui/assets/permissions.js`, embedded the same way but served
with `Cache-Control: no-cache` — the filename is unversioned, so a redeploy must always win
(templates and assets compile into the binary; a stale build, not a stale browser cache, is this
project's historical failure mode).

Palette: CSS variables in base.html's `:root` blocks (light default, `@media` auto-dark,
explicit `[data-theme]` overrides). Tuned for parity with KLLDAP's Bootstrap-nightshade look —
dark body `#222`, BS blue `#0d6efd` link/primary family, BS alert scales — while keeping this app's
compact hand-rolled CSS instead of Bootstrap itself. Theme-invariant tokens (`--page-max`,
`--content-narrow`, `--noacl`, `--font-mono`) live in their own `:root` block below the theme vars.
Use `var(--font-mono)` for any monospace text — never restate the stack.

Resolved cleanups (2026-07-10): `--font-mono` token, app script decomposed to
`assets/permissions.js`, Share Permissions inline `style=""` fully converted to classes.
Still deferred: inline styles on the Settings/setup pages; a full ARIA tree pattern for the
directory tree (roving tabindex + arrow keys — rows are plain tab-order buttons today); wiring the
per-entry ACL rwx checkboxes to `/acl-apply` on ACL-supported shares (they render the current
perms but toggling is not persisted — on Non-ACL shares they stay disabled in edit mode).

See templates/ + source for current UX. (Historical decisions resolved: lazy tree, detached
permissions panel, structured shares, full progress.)
