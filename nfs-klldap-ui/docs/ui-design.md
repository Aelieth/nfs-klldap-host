# UI Notes

Current implementation: Axum + HTMX + server-rendered templates (no separate frontend build). Two pages: / (tree + live search + apply) and /settings (TOML + LLDAP reload).

Auth: localhost sidecar (next to config) or LLDAP users in webui_admin_group.

See `src/web/` (mod.rs + focused submodules) and `templates/` for the handlers and forms.

When you want the tool to be directly accessible without a reverse proxy, we can add a minimal login layer.

## Data Flow Summary (UI → Backend)

1. User selects directory in tree → HTMX request → backend returns current owner/group/mode + rendered form.
2. User searches for a user/group → HTMX → `ldap.resolve_user` or `list_users` (now via standard LDAP Subtree searches) → returns JSON with id + uidNumber.
3. User clicks Save → POST with desired owner/group/mode/recursive → backend:
   - Calls the LDAP permission client to confirm IDs (defense in depth).
   - Performs chown/chmod directly inside the container (only on allowed share paths).
   - The container (via its watcher or SIGHUP) picks up any share/config changes and regenerates Ganesha exports.
4. UI shows success + refreshed current state from filesystem.

Current: lazy 1-level tree expand, inline dir meta+editor (no separate panel), live async apply with progress/cancel + oob Apply Log, HTMX fragments.

See source `web/permission_tree.rs`, `fs.rs` (ApplyOptions/ApplyProgress), templates for implemented UX. The original "open decisions" list is historical; lazy tree + direct apply are live.
