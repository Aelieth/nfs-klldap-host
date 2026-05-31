# UI Notes

Current implementation: Axum + HTMX + server-rendered templates (no separate frontend build). Two pages: / (tree + live search + apply) and /settings (TOML + LLDAP reload).

Auth: localhost sidecar (next to config) or LLDAP users in webui_admin_group.

See src/web.rs and templates/ for the handlers and forms.

When you want the tool to be directly accessible without a reverse proxy, we can add a minimal login layer.

## Data Flow Summary (UI → Backend)

1. User selects directory in tree → HTMX request → backend returns current owner/group/mode + rendered form.
2. User searches for a user/group → HTMX → `ldap.resolve_user` or `list_users` (now via standard LDAP Subtree searches) → returns JSON with id + uidNumber.
3. User clicks Save → POST with desired owner/group/mode/recursive → backend:
   - Calls the LDAP permission client to confirm IDs (defense in depth).
   - Performs chown/chmod directly inside the container (only on allowed share paths).
   - The container (via its watcher or SIGHUP) picks up any share/config changes and regenerates Ganesha exports.
4. UI shows success + refreshed current state from filesystem.

## Open Decisions / Next Steps

- Exact styling (Tailwind via CDN for maximum simplicity?).
- How deep to make the tree (lazy load subdirectories?).
- Whether to show a "dry-run / preview" of the exact chown/chmod commands before applying.
- Multi-user support for the UI (who made the last change?).

This design stays true to "small program" while giving the visual, friendly experience you described.
