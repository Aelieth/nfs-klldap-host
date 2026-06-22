# UI Notes

Axum + HTMX + server templates. Pages: / (tree browser + user/group search + direct apply), /settings (raw TOML + structured editor for fields+shares, LLDAP reload/clear, restart). First-run: `/login` + `POST /setup-password` when no `webui-password` sidecar exists.

Auth: webui-password sidecar (localhost) or LLDAP in webui_admin_group.

Handlers in web/ (mod orchestrator + auth/permission_tree/settings/keytab). FS policy + progress in fs.rs; LDAP in ldap.rs.

Apply is always async with live count-then-apply progress, cancel, oob log.

See templates/ + source for current UX. (Historical decisions resolved: lazy tree, inline editor, structured shares, full progress.)
