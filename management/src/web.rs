//! Axum + HTMX web UI for the NFS Kerb management tool (Ganesha version).
//!
//! Now with simple local sudo auth: only users who can actually do privileged
//! operations on this machine (root or wheel/sudo-capable) may log in.

use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    auth::AuthManager,
    config::Config,
    exports::ExportsManager,
    fs::FsManager,
    ganesha::GaneshaClient,
    llap::LldapClient,
};

// === State ===

#[derive(Clone)]
pub struct AppState {
    pub fs: Arc<FsManager>,
    pub lldap: Arc<Mutex<LldapClient>>,
    pub config: Arc<Config>,
    pub ganesha: Arc<GaneshaClient>,
    pub exports: Arc<ExportsManager>,
    pub auth: Arc<AuthManager>,
}

// === Public routes (no auth) ===

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    current_user: Option<String>,
}

pub async fn login_page() -> impl IntoResponse {
    Html(LoginTemplate { error: None, current_user: None }.render().unwrap())
}

#[derive(Deserialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    match state.auth.validate_local_admin(&form.username, &form.password) {
        Ok(()) => {
            let token = state.auth.create_session(&form.username);

            // Build a simple HttpOnly session cookie
            let cookie = format!(
                "session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200",
                token
            );

            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, cookie.parse().unwrap());

            (headers, Redirect::to("/")).into_response()
        }
        Err(e) => {
            let html = LoginTemplate { error: Some(e), current_user: None }.render().unwrap();
            (StatusCode::UNAUTHORIZED, Html(html)).into_response()
        }
    }
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(cookie) = headers.get("cookie") {
        if let Ok(s) = cookie.to_str() {
            if let Some(token) = extract_session_token(s) {
                state.auth.logout(&token);
            }
        }
    }
    // Clear the cookie
    let clear = "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
    let mut h = HeaderMap::new();
    h.insert(SET_COOKIE, clear.parse().unwrap());
    (h, Redirect::to("/login")).into_response()
}

fn extract_session_token(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let kv = part.trim();
        if let Some(rest) = kv.strip_prefix("session=") {
            return Some(rest.to_string());
        }
    }
    None
}

// === Auth extractor (used to protect routes) ===

#[derive(Clone)]
pub struct AuthUser(pub String);

pub async fn require_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<AuthUser, Redirect> {
    if let Some(cookie) = headers.get("cookie") {
        if let Ok(s) = cookie.to_str() {
            if let Some(token) = extract_session_token(s) {
                if let Some(user) = state.auth.validate(&token) {
                    return Ok(AuthUser(user));
                }
            }
        }
    }
    Err(Redirect::to("/login"))
}

// === Templates ===

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    shares: Vec<crate::config::Share>,
    current_user: Option<String>,
}

#[derive(Template)]
#[template(path = "tree_fragment.html")]
struct TreeFragmentTemplate {
    children: Vec<DirNode>,
}

#[derive(Debug, Clone)]
pub struct DirNode {
    pub path: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "permission_form.html")]
struct PermissionForm {
    path: String,
    current_state_html: String,
}

// === Handlers ===

pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(State(state.clone()), headers).await?;

    let tpl = IndexTemplate {
        shares: state.config.shares.clone(),
        current_user: Some(user.0),
    };

    Ok(Html(tpl.render().unwrap()))
}

/// Lazy-loads children of a directory (HTMX partial)
pub async fn tree_fragment(
    State(state): State<AppState>,
    Query(params): Query<TreeParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(State(state.clone()), headers).await?;

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
    };

    Ok(Html(tpl.render().unwrap()))
}

#[derive(Deserialize)]
pub(crate) struct TreeParams {
    path: String,
}

/// Returns the permission editor form for a directory (HTMX)
pub async fn directory_form(
    State(state): State<AppState>,
    Query(params): Query<DirParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(State(state.clone()), headers).await?;

    let path = params.path;

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
        "<div class=\"current-state\"><em>Unable to read current state from filesystem</em></div>".to_string()
    };

    let form = PermissionForm {
        path: path.clone(),
        current_state_html,
    };

    Ok(Html(form.render().unwrap()))
}

// === Live LLDAP Search Handlers ===

#[derive(Deserialize)]
pub(crate) struct SearchParams {
    q: Option<String>,
}

pub async fn search_users(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(State(state.clone()), headers).await.is_err() {
        return Html("<div class=\"suggestion\">Unauthorized</div>".to_string());
    }

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
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(State(state.clone()), headers).await.is_err() {
        return Html("<div class=\"suggestion\">Unauthorized</div>".to_string());
    }

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
pub(crate) struct DirParams {
    path: String,
}

#[derive(Deserialize)]
pub(crate) struct ApplyForm {
    path: String,
    owner_user: String,
    owner_group: String,
    mode: String,
    #[serde(default)]
    recursive: bool,
}

/// Handler for the permission form submission.
pub async fn apply_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ApplyForm>,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(State(state.clone()), headers).await?;

    let mut lldap = state.lldap.lock().await;

    // Resolve owner user from LLDAP
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
            return Ok(Html(html));
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
            return Ok(Html(html));
        }
    };

    let mode = u32::from_str_radix(&form.mode, 8).unwrap_or(0o770);

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
        return Ok(Html(html));
    }

    // Derive a reasonable pseudo path from the directory name for the ad-hoc export.
    // (The permission form doesn't ask the user for a Pseudo; the dedicated /exports UI does.)
    let pseudo = std::path::Path::new(&form.path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| format!("/{}", n))
        .unwrap_or_else(|| "/managed".to_string());

    if let Err(e) = state.exports.ensure_path_exported(
        std::path::Path::new(&form.path),
        &pseudo,
        "managed",
        None,
    ) {
        eprintln!("Warning: failed to ensure Ganesha export: {}", e);
    }

    let html = format!(
        r#"<div class="form">
            <h3>Successfully applied permissions for <code>{}</code></h3>
            <p>
                <strong>Owner:</strong> {} (UID {})<br>
                <strong>Group:</strong> {} (GID {})<br>
                <strong>Mode:</strong> {}<br>
                <strong>Recursive:</strong> {}
            </p>
            <p style="color: green;">Changes applied via privileged helper. Ganesha export ensured.</p>
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

    Ok(Html(html))
}

// === Ganesha Export Builder (protected) ===

#[derive(Template)]
#[template(path = "exports.html")]
struct ExportsTemplate {
    current_user: Option<String>,
}

pub async fn exports_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(State(state.clone()), headers).await?;
    let tpl = ExportsTemplate {
        current_user: Some(user.0),
    };
    Ok(Html(tpl.render().unwrap()))
}

#[derive(Deserialize)]
pub(crate) struct AddExportForm {
    host_path: String,
    pseudo: String,
    #[serde(default)]
    export_id: Option<u16>,
}

pub async fn add_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AddExportForm>,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(State(state.clone()), headers).await?;

    let host_path = Path::new(&form.host_path);

    let allowed = state.config.all_managed_roots();
    let is_allowed = allowed.iter().any(|root| host_path.starts_with(root));

    if !is_allowed {
        let msg = r#"<div style="color:#c00; padding:8px; background:#fff0f0; border:1px solid #fcc;">
                <strong>Error:</strong> Path outside managed roots.
              </div>"#.to_string();
        return Ok(Html(msg));
    }

    let name = host_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("export")
        .to_string();

    if let Err(e) = state.exports.ensure_path_exported(host_path, &form.pseudo, &name, form.export_id) {
        let msg = format!(
            r#"<div style="color:#c00; padding:8px; background:#fff0f0; border:1px solid #fcc;">
                <strong>Failed:</strong> {}
              </div>"#,
            e
        );
        return Ok(Html(msg));
    }

    let success = format!(
        "<div style=\"color:#060; padding:8px; background:#f0fff0; border:1px solid #9c9;\">\
            <strong>Success!</strong> Created export <code>{}</code> → <code>{}</code>.<br>\
            <button hx-get=\"/exports/current\" hx-target=\"#current_exports\">Refresh</button>\
        </div>",
        form.host_path, form.pseudo
    );

    Ok(Html(success))
}

pub async fn current_exports(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(State(state.clone()), headers).await?;

    match state.ganesha.show_exports() {
        Ok(raw) => {
            let safe = raw.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
            Ok(Html(format!(
                "<code style=\"white-space:pre-wrap; display:block; font-size:0.85em;\">{}</code>",
                safe
            )))
        }
        Err(e) => Ok(Html(format!("<span style=\"color:#c00;\">{}</span>", e))),
    }
}

// === Router ===

pub fn router(state: AppState) -> Router {
    Router::new()
        // Public
        .route("/login", get(login_page).post(login))
        .route("/logout", axum::routing::post(logout))
        // Protected
        .route("/", get(index))
        .route("/tree", get(tree_fragment))
        .route("/directory", get(directory_form))
        .route("/users/search", get(search_users))
        .route("/groups/search", get(search_groups))
        .route("/apply", axum::routing::post(apply_permissions))
        .route("/exports", get(exports_page))
        .route("/exports/add", axum::routing::post(add_export))
        .route("/exports/current", get(current_exports))
        .with_state(state)
}
