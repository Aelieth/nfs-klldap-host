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
When a directory can't be stat'd (serve path missing, unmapped, or unreadable), the panel replaces
the split editors with a full-width diagnostic (`.panel-alert`) that names the cause, the fix, and the
host + serve paths — `dir_perms` picks the message per `PathDiagnostic` (allowed / mapped / exists).

ACL support is shown only when the share **actually serves ACLs**: `enable_acl = true` AND the
serve-path filesystem is ACL-capable. If `enable_acl = true` but the filesystem cannot honor ACLs
(e.g. Ganesha 9.6 VFS FSAL → `NFS4ERR_NOTSUPP`), the section reverts to **Non-ACL** with an explicit
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

Three separate `<script>` blocks in base.html's head, in contract order:

1. **FOUC early-init** — reads localStorage `theme` and stamps/removes `data-theme` on `<html>`
   before first paint.
2. **Theme manager (isolated)** — `window.setTheme`, a *delegated* `document`-level change listener
   for the `#theme-tray` radios, and the `prefers-color-scheme` auto-follow listener. It is a
   separate block on purpose: a runtime error in the app script can then never kill theming
   (this happened once — a top-level `document.body.addEventListener` in the shared block threw
   during head parse and silently disabled the tray).
3. **App script** — everything else.

Semantics: localStorage key `theme` ∈ `auto|dark|light`; explicit values set
`data-theme` on `<html>`, auto removes it so the `@media (prefers-color-scheme)` block applies.
**Head-script gotcha (institutional memory):** these blocks run before `<body>` exists — top-level
`document.body.*` calls throw and abort the rest of that block. Delegated listeners must target
`document`.

## Routes

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/assets/htmx-1.9.12.min.js` | vendored htmx (immutable cache) | none (setup-gate exempt) |
| GET/POST | `/login` | login page / login | none |
| POST | `/setup-password` | first-run localhost password | none |
| GET/POST | `/logout` | clear session | none |
| GET | `/restart-status` | post-restart poller | none |
| GET | `/setup`, `/setup/1..3` | wizard pages (redirect to current step) | none (pre-setup only) |
| POST | `/setup/1/verify`, `/setup/2/test`, `/setup/2/continue`, `/setup/3/test`, `/setup/3/continue` | wizard actions | none (pre-setup only) |
| GET | `/setup/3/status` | saved bind-cred probe | none (pre-setup only) |
| GET | `/` | Share Permissions page | session |
| GET | `/tree`, `/fs/children` | tree root / lazy children fragments | session |
| GET | `/dir-perms` | detached panel body | session |
| GET | `/users/search`, `/groups/search` | LLDAP suggestion fragments | session |
| POST | `/apply`, `/acl-apply`, `/cancel-apply` | POSIX / ACL apply + cancel | session |
| GET | `/apply-progress` | oob Apply Log poller | session |
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

Palette: CSS variables in base.html's `:root` blocks (light default, `@media` auto-dark,
explicit `[data-theme]` overrides). Tuned for parity with KLLDAP's Bootstrap-nightshade look —
dark body `#222`, BS blue `#0d6efd` link/primary family, BS alert scales — while keeping this app's
compact hand-rolled CSS instead of Bootstrap itself. Theme-invariant tokens (`--page-max`,
`--content-narrow`, `--noacl`) live in their own `:root` block below the theme vars.

Deferred cleanups: a `--font-mono` token (the monospace stack is repeated inline ~15× with varying
fallbacks), decomposing the large app script in base.html, and converting the remaining inline
`style=""` attributes on the older pages to classes.

See templates/ + source for current UX. (Historical decisions resolved: lazy tree, detached
permissions panel, structured shares, full progress.)
