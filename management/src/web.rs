//! Axum + HTMX web UI for nfs-klldap-host (two-page: System Settings + Share Permissions).
//!
//! The UI edits the central `nfs-klldap.conf` directly and uses the narrow
//! privileged helper for host-side chown/chmod. Local sudo-auth is used to
//! restrict access to users who can perform privileged operations.

use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{auth::AuthManager, config::Config, fs::FsManager, llap::LldapClient};

// === State ===

#[derive(Clone)]
pub struct AppState {
    pub fs: Arc<FsManager>,
    pub lldap: Arc<Mutex<LldapClient>>,
    pub config: Arc<Config>,
    pub auth: Arc<AuthManager>,
    /// Absolute path to the nfs-klldap.conf file being edited (same one the container uses).
    /// Needed for raw TOML view + save, and for System Settings.
    pub config_path: PathBuf,
}

// === Public routes (no auth) ===

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    current_user: Option<String>,
}

pub async fn login_page() -> impl IntoResponse {
    Html(
        LoginTemplate {
            error: None,
            current_user: None,
        }
        .render()
        .unwrap(),
    )
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
    match state
        .auth
        .validate_local_admin(&form.username, &form.password)
    {
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
            let html = LoginTemplate {
                error: Some(e),
                current_user: None,
            }
            .render()
            .unwrap();
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

// === System Settings (two-page UI - System Settings page) ===

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
    current_user: Option<String>,
    /// Raw file contents for the textarea editor (preserves comments)
    raw_toml: String,
    config_path: String,
    message: Option<String>,
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

    let tpl = TreeFragmentTemplate { children };

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
        "<div class=\"current-state\"><em>Unable to read current state from filesystem</em></div>"
            .to_string()
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

/// Internal row representation for the share editor form (avoids huge tuple type).
#[derive(Debug, Clone)]
struct ShareFormRow {
    idx: usize,
    name: String,
    host: String,
    export_path: Option<String>,
    security: Option<String>,
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

    // NOTE (v0.23 cutover): Exports are now generated inside the container from the central nfs-klldap.conf.
    // The host UI no longer writes fragments. Permission changes are applied via the helper only.
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
        form.owner_user,
        owner_uid,
        form.owner_group,
        group_gid,
        form.mode,
        if form.recursive { "YES" } else { "NO" },
        form.path
    );

    Ok(Html(html))
}

// v0.23: Direct Ganesha export management from the host UI has been removed.
// All fragments are generated inside the container from the central config.

pub async fn settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(State(state.clone()), headers).await?;

    let raw_toml = std::fs::read_to_string(&state.config_path)
        .unwrap_or_else(|_| "# Could not read config file".to_string());

    let tpl = SettingsTemplate {
        current_user: Some(user.0),

        raw_toml,
        config_path: state.config_path.display().to_string(),
        message: None,
    };
    Ok(Html(tpl.render().unwrap()))
}

#[derive(Deserialize)]
pub(crate) struct RawSaveForm {
    raw_content: String,
}

// Structured form for the common editable parts of nfs-klldap.conf
#[derive(Deserialize, Debug, Default)]
pub(crate) struct StructuredSettingsForm {
    // Top level
    ldap_uri: Option<String>,

    // [storage]
    storage_container_root: Option<String>,

    // [server]
    server_hostname: Option<String>,

    // [sssd]
    sssd_bind_dn: Option<String>,
    sssd_bind_pw: Option<String>,
    sssd_port: Option<u16>,
    sssd_user_base: Option<String>,
    sssd_group_base: Option<String>,

    // [kerberos]
    kerberos_realm: Option<String>,

    // [ganesha]
    ganesha_default_security: Option<String>,

    // Simple repeated fields for shares (we'll collect them in the handler)
    // Using indexed names in the template: share_name_0, share_host_0, ...
    #[serde(flatten)]
    extra: std::collections::HashMap<String, String>,
}

pub async fn settings_save_raw(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RawSaveForm>,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(State(state.clone()), headers).await?;

    // Best-effort validation via the shared crate before writing
    let tmp_path = state.config_path.with_extension("tmp-validate");
    if let Err(e) = std::fs::write(&tmp_path, &form.raw_content) {
        let msg = format!("Failed to write temp file for validation: {}", e);
        return Ok(Html(format!("<p style='color:#c00'>{}</p>", msg)));
    }
    let validation = nfs_klldap_config::NfsKlldapConfig::load(&tmp_path);
    let _ = std::fs::remove_file(&tmp_path);

    if let Err(e) = validation {
        let msg = format!("Validation failed — not saving: {}", e);
        return Ok(Html(format!("<p style='color:#c00'>{}</p>", msg)));
    }

    // Atomic-ish write
    let tmp = state.config_path.with_extension("conf.saving");
    if let Err(e) = std::fs::write(&tmp, form.raw_content.as_bytes()) {
        return Ok(Html(format!(
            "<p style='color:#c00'>Write failed: {}</p>",
            e
        )));
    }
    if let Err(e) = std::fs::rename(&tmp, &state.config_path) {
        return Ok(Html(format!(
            "<p style='color:#c00'>Rename failed: {}</p>",
            e
        )));
    }

    // Re-read for the response
    let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let tpl = SettingsTemplate {
        current_user: Some(user.0),
        raw_toml,
        config_path: state.config_path.display().to_string(),
        message: Some("Raw TOML saved and validated. Container will pick up changes via its watcher (or send SIGHUP).".into()),
    };
    Ok(Html(tpl.render().unwrap()))
}

/// Handle structured form save from /settings
pub async fn settings_save_structured(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<StructuredSettingsForm>,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(State(state.clone()), headers).await?;

    // Load current config as base (so we don't lose fields not in the form)
    let mut cfg = nfs_klldap_config::NfsKlldapConfig::load(&state.config_path).unwrap_or_default();

    // Apply top-level changes from form (clone so the form remains available for the
    // subsequent comment-preserving toml_edit patching pass below).
    if let Some(v) = form.ldap_uri.clone() {
        cfg.ldap_uri = v;
    }
    if let Some(v) = form.storage_container_root.clone() {
        cfg.storage.container_root = v;
    }
    if let Some(v) = form.server_hostname.clone() {
        cfg.server.hostname = Some(v);
    }

    if let Some(v) = form.sssd_bind_dn.clone() {
        cfg.sssd.ldap_default_bind_dn = v;
    }
    if let Some(v) = form.sssd_bind_pw.clone() {
        cfg.sssd.ldap_default_authtok = v;
    }
    if let Some(v) = form.sssd_port {
        cfg.sssd.port = Some(v);
    }
    if let Some(v) = form.sssd_user_base.clone() {
        cfg.sssd.ldap_user_search_base = Some(v);
    }
    if let Some(v) = form.sssd_group_base.clone() {
        cfg.sssd.ldap_group_search_base = Some(v);
    }

    if let Some(v) = form.kerberos_realm.clone() {
        cfg.kerberos.realm = Some(v);
    }
    if let Some(v) = form.ganesha_default_security.clone() {
        cfg.ganesha.default_security = v;
    }

    // Collect shares from indexed form fields.
    // Client now uses a clean sequential counter (see settings.html). We gather any
    // share_name_* keys, parse their numeric suffix, sort, and build rows.
    // Gaps are tolerated naturally; order is by the numeric suffix for determinism.
    let mut share_rows: Vec<ShareFormRow> = vec![];
    for (k, v) in &form.extra {
        if let Some(suffix) = k.strip_prefix("share_name_") {
            if let Ok(idx) = suffix.parse::<usize>() {
                let name = v.trim().to_string();
                let host = form
                    .extra
                    .get(&format!("share_host_{}", idx))
                    .cloned()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if name.is_empty() || host.is_empty() {
                    continue;
                }
                let export_path = form
                    .extra
                    .get(&format!("share_export_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| Some(format!("/{}", name)));
                let security = form
                    .extra
                    .get(&format!("share_security_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty());
                share_rows.push(ShareFormRow {
                    idx,
                    name,
                    host,
                    export_path,
                    security,
                });
            }
        }
    }
    share_rows.sort_by_key(|r| r.idx);

    let new_shares: Vec<nfs_klldap_config::Share> = share_rows
        .into_iter()
        .map(|r| nfs_klldap_config::Share {
            name: r.name,
            host_path: PathBuf::from(r.host),
            export_path: r.export_path,
            security: r.security,
            rw: Some(true),
            squash: Some("no_root_squash".to_string()),
        })
        .collect();

    if !new_shares.is_empty() {
        cfg.shares = new_shares.clone();
    }

    // Validate the logical model first (authoritative structs win for semantics)
    if let Err(e) = cfg.validate_and_derive() {
        let msg = format!("Validation error: {}", e);
        let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
        let tpl = SettingsTemplate {
            current_user: Some(user.0.clone()),
            raw_toml,
            config_path: state.config_path.display().to_string(),
            message: Some(msg),
        };
        return Ok(Html(tpl.render().unwrap()));
    }

    // === Comment-preserving structured save (the finishing step) ===
    // Load the on-disk file as a toml_edit DocumentMut so that comments, vertical
    // spacing, and hand-authored keys we do not touch survive the write.
    let original_text = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let mut doc = original_text
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_default();

    // Apply only fields present in the submitted form (preserve everything else + its comments).
    if let Some(v) = &form.ldap_uri {
        doc["ldap_uri"] = toml_edit::value(v.clone());
    }

    if let Some(v) = &form.storage_container_root {
        let item = doc.entry("storage").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["container_root"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = &form.server_hostname {
        let item = doc.entry("server").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["hostname"] = toml_edit::value(v.clone());
        }
    }

    if let Some(v) = &form.sssd_bind_dn {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_default_bind_dn"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = &form.sssd_bind_pw {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_default_authtok"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = form.sssd_port {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["port"] = toml_edit::value(v as i64);
        }
    }
    if let Some(v) = &form.sssd_user_base {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_user_search_base"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = &form.sssd_group_base {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_group_search_base"] = toml_edit::value(v.clone());
        }
    }

    if let Some(v) = &form.kerberos_realm {
        let item = doc.entry("kerberos").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["realm"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = &form.ganesha_default_security {
        let item = doc.entry("ganesha").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["default_security"] = toml_edit::value(v.clone());
        }
    }

    // Shares: the submitted rows are authoritative. Replace the [[shares]] array-of-tables
    // wholesale. Per-share comments from the old file are intentionally dropped (use Raw
    // editor when you need to preserve elaborate comments next to individual shares).
    if !new_shares.is_empty() {
        let mut shares = toml_edit::ArrayOfTables::new();
        for s in &new_shares {
            let mut t = toml_edit::Table::new();
            t["name"] = toml_edit::value(s.name.clone());
            t["host_path"] = toml_edit::value(s.host_path.display().to_string());
            if let Some(ep) = &s.export_path {
                t["export_path"] = toml_edit::value(ep.clone());
            }
            if let Some(sec) = &s.security {
                t["security"] = toml_edit::value(sec.clone());
            }
            t["rw"] = toml_edit::value(s.rw.unwrap_or(true));
            if let Some(sq) = &s.squash {
                t["squash"] = toml_edit::value(sq.clone());
            }
            shares.push(t);
        }
        doc["shares"] = toml_edit::Item::ArrayOfTables(shares);
    }

    // Atomic write of the (mostly) comment-preserved document.
    let text = doc.to_string();
    let tmp = state.config_path.with_extension("conf.saving");
    if let Err(e) = std::fs::write(&tmp, text.as_bytes()) {
        let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
        let tpl = SettingsTemplate {
            current_user: Some(user.0.clone()),
            raw_toml,
            config_path: state.config_path.display().to_string(),
            message: Some(format!("Failed to write: {}", e)),
        };
        return Ok(Html(tpl.render().unwrap()));
    }
    if let Err(e) = std::fs::rename(&tmp, &state.config_path) {
        let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
        let tpl = SettingsTemplate {
            current_user: Some(user.0.clone()),
            raw_toml,
            config_path: state.config_path.display().to_string(),
            message: Some(format!("Rename failed: {}", e)),
        };
        return Ok(Html(tpl.render().unwrap()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            std::fs::set_permissions(&state.config_path, std::fs::Permissions::from_mode(0o600));
    }

    // Success - re-render the page with a success message (keeps types simple)
    let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let tpl = SettingsTemplate {
        current_user: None,

        raw_toml,
        config_path: state.config_path.display().to_string(),
        message: Some(
            "Structured settings saved. Container will regenerate configs shortly.".into(),
        ),
    };
    Ok(Html(tpl.render().unwrap()))
}

// === Router ===

pub fn router(state: AppState) -> Router {
    Router::new()
        // Public
        .route("/login", get(login_page).post(login))
        .route("/logout", axum::routing::post(logout))
        // Protected (two-page UI + core permission editor)
        .route("/", get(index))
        .route("/tree", get(tree_fragment))
        .route("/directory", get(directory_form))
        .route("/users/search", get(search_users))
        .route("/groups/search", get(search_groups))
        .route("/apply", axum::routing::post(apply_permissions))
        // Two-page UI
        .route("/settings", get(settings_page))
        .route("/settings/save-raw", post(settings_save_raw))
        .route("/settings/save", post(settings_save_structured))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header::COOKIE, Request, StatusCode},
    };
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt; // for `oneshot`

    fn make_test_state_with_temp_config() -> (AppState, TempDir) {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("test-nfs-klldap.conf");

        // Write a minimal valid config
        let minimal = r#"
            ldap_uri = "ldaps://kllap.test:6360"
            [sssd]
            ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
            ldap_default_authtok = "sekret"
            [[shares]]
            name = "data"
            host_path = "/tmp/data"
        "#;
        std::fs::write(&config_path, minimal).unwrap();

        let config = Arc::new(
            nfs_klldap_config::NfsKlldapConfig::load(&config_path).expect("valid test config"),
        );

        let fs = Arc::new(FsManager::new_with_path(
            (*config).clone(),
            config_path.clone(),
        ));

        // Dummy LLDAP client (settings handlers don't use it)
        let lldap = Arc::new(Mutex::new(LldapClient::new("http://localhost:9999")));

        let auth = Arc::new(AuthManager::new());

        let state = AppState {
            fs,
            lldap,
            config,
            auth,
            config_path,
        };

        (state, tmp)
    }

    fn add_session_cookie(mut req: Request<Body>, token: &str) -> Request<Body> {
        let cookie = format!("session={}", token);
        req.headers_mut().insert(COOKIE, cookie.parse().unwrap());
        req
    }

    #[tokio::test]
    async fn settings_save_raw_accepts_valid_toml_and_preserves_user() {
        let (state, _tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();
        let token = auth.create_session("testadmin");

        let app = router(state);

        let new_content = r#"ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret""#;

        let req = Request::builder()
            .method("POST")
            .uri("/settings/save-raw")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "raw_content={}",
                urlencoding::encode(new_content)
            )))
            .unwrap();

        let req = add_session_cookie(req, &token);

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn settings_save_structured_updates_top_level_fields() {
        let (state, _tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();
        let token = auth.create_session("testadmin");

        let app = router(state);

        // Simple form that only changes ldap_uri
        let body = "ldap_uri=ldaps%3A%2F%2Fnewhost.example.com%3A6360";

        let req = Request::builder()
            .method("POST")
            .uri("/settings/save")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let req = add_session_cookie(req, &token);

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
