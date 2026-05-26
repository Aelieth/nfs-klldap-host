//! Axum + HTMX web UI for the NFS Kerb management tool.
//!
//! This is the beginning of the visual front-end.
//! It is deliberately kept simple and "small program" friendly.

use askama::Template;
use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{config::Config, fs::FsManager, llap::LldapClient};

#[derive(Clone)]
pub struct AppState {
    pub fs: Arc<FsManager>,
    pub lldap: Arc<Mutex<LldapClient>>,
    pub config: Arc<Config>,
}

// === Templates ===

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    allowed_roots: Vec<String>,
}

#[derive(Template)]
#[template(path = "tree_fragment.html")]
struct TreeFragmentTemplate {
    children: Vec<DirNode>,
    parent_path: String,
}

#[derive(Debug, Clone)]
pub struct DirNode {
    pub path: String,
    pub name: String,
}

// DirectoryFormTemplate temporarily removed while we get the basic tree + lazy loading working.
// It will be re-introduced with real Askama + HTMX form in the next iteration.

// === Handlers ===

pub async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let roots: Vec<String> = state
        .config
        .allowed_roots
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let tpl = IndexTemplate {
        allowed_roots: roots,
    };

    Html(tpl.render().unwrap())
}

/// Lazy-loads children of a directory (HTMX partial)
pub async fn tree_fragment(
    State(state): State<AppState>,
    Query(params): Query<TreeParams>,
) -> impl IntoResponse {
    let path = std::path::Path::new(&params.path);

    let children = if let Some(node) = state.fs.build_tree(path) {
        node.children
            .into_iter()
            .map(|c| DirNode {
                path: c.path.to_string_lossy().to_string(),
                name: c.name,
            })
            .collect()
    } else {
        vec![]
    };

    let tpl = TreeFragmentTemplate {
        children,
        parent_path: params.path.clone(),
    };

    Html(tpl.render().unwrap())
}

#[derive(Deserialize)]
struct TreeParams {
    path: String,
}

/// Returns the permission editor form for a directory (HTMX)
pub async fn directory_form(
    State(state): State<AppState>,
    Query(params): Query<DirParams>,
) -> impl IntoResponse {
    let path = params.path;

    // Read live on-disk state - polished display
    let current_state_html = if let Some(node) = state.fs.build_tree(std::path::Path::new(&path)) {
        let owner = node.owner.unwrap_or(0);
        let group = node.group.unwrap_or(0);
        let mode = node.mode;

        format!(
            r#"<div class="current-state">
                <strong>Current on disk</strong><br>
                <span class="state-label">Owner UID:</span> <code>{}</code><br>
                <span class="state-label">Group GID:</span> <code>{}</code><br>
                <span class="state-label">Mode:</span> <code>{:o}</code> <span class="mode-hint">(rwxrwxrwx)</span>
            </div>"#,
            owner, group, mode
        )
    } else {
        r#"<div class="current-state"><em>Unable to read current state from filesystem</em></div>"#.to_string()
    };

    let html = format!(
        "<form class=\"form\" hx-post=\"/apply\" hx-target=\"#permission-form\" hx-swap=\"innerHTML\">\
            <h3>Permissions for: <code>{}</code></h3>\
            <input type=\"hidden\" name=\"path\" value=\"{}\">\
            <div>\
                <label>Owner User<br>\
                    <input type=\"text\" name=\"owner_user\" id=\"owner_user\"\
                           hx-get=\"/users/search\"\
                           hx-trigger=\"input changed delay:250ms\"\
                           hx-target=\"#user-suggestions\"\
                           hx-swap=\"innerHTML\"\
                           placeholder=\"Type to search LLDAP users...\">\
                    <div id=\"user-suggestions\" class=\"suggestions\"></div>\
                </label>\
            </div>\
            <div>\
                <label>Owner Group<br>\
                    <input type=\"text\" name=\"owner_group\" id=\"owner_group\"\
                           hx-get=\"/groups/search\"\
                           hx-trigger=\"input changed delay:250ms\"\
                           hx-target=\"#group-suggestions\"\
                           hx-swap=\"innerHTML\"\
                           placeholder=\"Type to search LLDAP groups...\">\
                    <div id=\"group-suggestions\" class=\"suggestions\"></div>\
                </label>\
            </div>\
            <div>\
                <label>Mode (octal)<br>\
                    <input type=\"text\" name=\"mode\" value=\"770\" size=\"4\">\
                </label>\
                <label style=\"margin-left: 1rem;\">\
                    <input type=\"checkbox\" name=\"recursive\" value=\"true\"> Recursive\
                </label>\
            </div>\
            <button type=\"submit\">Save & Apply</button>\
            {}\
        </form>",
        path, path, current_state_html
    );

    Html(html)
}

// === Live LLDAP Search Handlers (for the permission form dropdowns) ===

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
}

pub async fn search_users(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let mut lldap = state.lldap.lock().await;
    let users = lldap.list_users(params.q.as_deref()).await;

    let mut html = String::new();
    for user in users.into_iter().take(12) {
        let uid = user.uid_number.unwrap_or(0);
        let name = user.display_name.unwrap_or(user.id.clone());
        html.push_str(&format!(
            "<div class=\"suggestion\" onclick=\"selectUser('{}', {})\">{}</div>",
            user.id, uid, name
        ));
    }
    if html.is_empty() {
        html = "<div class=\"suggestion\">No matches found in LLDAP</div>".to_string();
    }
    Html(html)
}

pub async fn search_groups(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let mut lldap = state.lldap.lock().await;
    let groups = lldap.list_groups(params.q.as_deref()).await;

    let mut html = String::new();
    for group in groups.into_iter().take(12) {
        let gid = group.gid_number.unwrap_or(0);
        let name = group.display_name.unwrap_or(group.id.clone());
        html.push_str(&format!(
            "<div class=\"suggestion\" onclick=\"selectGroup('{}', {})\">{}</div>",
            group.id, gid, name
        ));
    }
    if html.is_empty() {
        html = "<div class=\"suggestion\">No matches found in LLDAP</div>".to_string();
    }
    Html(html)
}

#[derive(Deserialize)]
struct DirParams {
    path: String,
}

#[derive(Deserialize)]
struct ApplyForm {
    path: String,
    owner_user: String,
    owner_group: String,
    mode: String,
    #[serde(default)] // checkbox is only sent when checked
    recursive: bool,
}

/// Handler for the permission form submission.
/// The recursive checkbox value is now properly received and displayed.
pub async fn apply_permissions(
    State(state): State<AppState>,
    Form(form): Form<ApplyForm>,
) -> impl IntoResponse {
    let mut lldap = state.lldap.lock().await;

    // Resolve names to numeric IDs via LLDAP (the core of the tool)
    let owner_uid = match lldap.resolve_user(&form.owner_user).await {
        Some((uid, _)) => uid as u32,
        None => {
            let html = format!(
                r#"<div class="form">
                    <h3>Error applying permissions for <code>{}</code></h3>
                    <p style="color: red;">Could not find user <strong>{}</strong> in LLDAP.</p>
                    <button type="button" onclick="htmx.ajax('GET', '/directory?path={}', {{target: '#permission-form', swap: 'innerHTML'}})">
                        Back to editor
                    </button>
                </div>"#,
                form.path, form.owner_user, form.path
            );
            return Html(html);
        }
    };

    let group_gid = match lldap.resolve_group(&form.owner_group).await {
        Some((gid, _)) => gid as u32,
        None => {
            let html = format!(
                r#"<div class="form">
                    <h3>Error applying permissions for <code>{}</code></h3>
                    <p style="color: red;">Could not find group <strong>{}</strong> in LLDAP.</p>
                    <button type="button" onclick="htmx.ajax('GET', '/directory?path={}', {{target: '#permission-form', swap: 'innerHTML'}})">
                        Back to editor
                    </button>
                </div>"#,
                form.path, form.owner_group, form.path
            );
            return Html(html);
        }
    };

    // Parse mode (default to 770 if invalid)
    let mode = u32::from_str_radix(&form.mode, 8).unwrap_or(0o770);

    // Apply permissions via the privileged helper (respects recursive flag)
    if let Err(e) = state.fs.apply_permissions(
        std::path::Path::new(&form.path),
        owner_uid,
        group_gid,
        mode,
        form.recursive,
    ) {
        let html = format!(
            r#"<div class="form">
                <h3>Error applying permissions</h3>
                <p style="color: red;">{}</p>
                <button type="button" onclick="htmx.ajax('GET', '/directory?path={}', {{target: '#permission-form', swap: 'innerHTML'}})">
                    Back to editor
                </button>
            </div>"#,
            e, form.path
        );
        return Html(html);
    }

    // Ensure the share is exported (touch/update *.exports)
    let exports_mgr = crate::exports::ExportsManager::new(std::path::PathBuf::from("/etc/exports.d"));
    if let Err(e) = exports_mgr.ensure_exported(&std::path::PathBuf::from(&form.path), &form.path) {
        // Non-fatal for now - permissions are already applied
        eprintln!("Warning: failed to ensure export: {}", e);
    }

    // Trigger re-export on the NFS container (SIGHUP)
    let _ = exports_mgr.trigger_reexport();

    // Success response - show updated state and offer to reload editor
    let html = format!(
        r#"<div class="form">
            <h3>Successfully applied permissions for <code>{}</code></h3>
            <p>
                <strong>Owner:</strong> {} (UID {})<br>
                <strong>Group:</strong> {} (GID {})<br>
                <strong>Mode:</strong> {}<br>
                <strong>Recursive:</strong> {}
            </p>
            <p style="color: green;">Changes applied via privileged helper. Re-export triggered.</p>
            <button type="button" onclick="htmx.ajax('GET', '/directory?path={}', {{target: '#permission-form', swap: 'innerHTML'}})">
                Reload editor (see live state)
            </button>
        </div>"#,
        form.path,
        form.owner_user, owner_uid,
        form.owner_group, group_gid,
        form.mode,
        if form.recursive { "YES" } else { "NO" },
        form.path
    );

    Html(html)
}

// === Router ===

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/tree", get(tree_fragment))
        .route("/directory", get(directory_form))
        .route("/users/search", get(search_users))
        .route("/groups/search", get(search_groups))
        .route("/apply", axum::routing::post(apply_permissions))
        .with_state(state)
}
