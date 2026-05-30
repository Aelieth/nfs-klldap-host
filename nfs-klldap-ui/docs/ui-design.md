# Management Tool UI Design

## Goals
- Small, simple, reliable visual interface for managing NFSv4 share permissions and exports.
- Real-time from filesystem + LLDAP (no heavy database).
- Easy for admins who are not deep Linux experts.

## UI Technology Options (ranked for this project)

### 1. Primary Recommendation: Axum + HTMX + Askama (or minijinja)
**Why best for "small program"**
- Pure Rust backend (no separate frontend build).
- HTMX gives excellent interactivity with almost no JavaScript.
- Server-rendered HTML is simple and fast.
- Easy to add real-time previews (user/group lookup, permission simulation).
- Can run as a small web server on the host (localhost or protected by nginx NPM as user mentioned earlier).
- Very small binary.

**Key screens / interactions**
- Sidebar: Tree of managed directories (lazy-loaded with HTMX).
- Main pane: When a directory is selected:
  - Current owner/group (live from FS via stat).
  - Searchable dropdowns for User and Group (HTMX typeahead → calls LLDAP client).
  - Live preview: "aelieth (3001) : users (3002)"
  - Permission editor: Checkboxes or octal input for owner/group/other.
  - Recursive checkbox.
  - "Save & Apply" button → calls backend → direct chown/chmod inside container → (optional) SIGHUP.
- Top bar: Status of last operation, quick "Re-export all" button.
- System Settings page: central nfs-klldap.conf editing (raw + structured), LLDAP URL, helper path (from [management] section).

**Auth for the web UI**
- Simple HTTP Basic Auth (username/password) protected by a reverse proxy (nginx Proxy Manager) or built-in using a simple shared secret / htpasswd.
- Or session-based login page (still lightweight with Axum).
- Since the tool runs on the server, many deployments will just access it via `http://localhost:8080` or through a VPN.

### 2. Strong Alternative: Tauri v2 + Leptos (or Dioxus)
**When to choose**
- You want a native desktop application (no browser needed).
- Better native file picker and drag-drop for directories.
- Still fully Rust.
- Can bundle everything into a single executable for admins' laptops.

Trade-off: Slightly larger binary and more complex build than Axum+HTMX.

### 3. Fallback: ratatui TUI
Useful for headless servers where you just SSH in and want a fast terminal UI.

## Basic Auth Integration Ideas

**Option A (Simplest for now)**
- The management tool's web UI is protected by the host's nginx Proxy Manager (NPM) using its built-in "Access Lists" (Basic Auth or Authelia/Forward Auth).
- The Rust backend itself does **not** implement auth — it trusts that only authorized people can reach it.

**Option B (Self-contained)**
- Add a very simple login page + session cookies (using `tower-sessions` or axum-login).
- Or use HTTP Basic Auth directly in Axum (easy with `axum-auth` or custom extractor).

**Recommendation**
Start with **Option A** (let NPM handle auth). This matches your earlier comment that "Integration with nginx NPM would be nice."

When you want the tool to be directly accessible without a reverse proxy, we can add a minimal login layer.

## Data Flow Summary (UI → Backend)

1. User selects directory in tree → HTMX request → backend returns current owner/group/mode + rendered form.
2. User searches for a user/group → HTMX → `llap.resolve_user` or `list_users` → returns JSON with id + uidNumber.
3. User clicks Save → POST with desired owner/group/mode/recursive → backend:
   - Calls LLDAP again to confirm IDs (defense in depth).
   - Performs chown/chmod directly inside the container (only on allowed share paths).
   - The container (via its watcher or SIGHUP) picks up any share/config changes and regenerates Ganesha exports.
4. UI shows success + refreshed current state from filesystem.

## Open Decisions / Next Steps

- Exact styling (Tailwind via CDN for maximum simplicity?).
- How deep to make the tree (lazy load subdirectories?).
- Whether to show a "dry-run / preview" of the exact chown/chmod commands before applying.
- Multi-user support for the UI (who made the last change?).

This design stays true to "small program" while giving the visual, friendly experience you described.
