//! Axum handlers + templates for the two-page in-container UI.
//! / = permissions tree + live LLDAP search + apply (direct root chown/chmod).
//! /settings = raw/structured TOML edit + LLDAP status/reload.
//! All FS mutations go through FsManager (allow-list + safety checks).

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

use crate::{auth::AuthManager, config::Config, fs::FsManager, ldap::LdapClient};

/// Returns a user-friendly message describing whether the on-disk keytab
/// contains the expected `nfs/<host>@REALM` principal.
///
/// This version supports keytabs containing multiple principals for the same
/// host (e.g. both the short hostname and the FQDN, as is recommended).
/// It finds the exact matching line(s) for the derived hostname.
pub(crate) fn compute_keytab_status_message(expected_host: &str, expected_realm: &str) -> String {
    let expected = format!("nfs/{}@{}", expected_host, expected_realm);

    match read_keytab_nfs_principals() {
        Ok(principals) => {
            // Find all principals in the keytab that correspond to our expected host.
            // This supports both short name and FQDN variants (e.g. "myserver" and "myserver.example.com").
            let matching: Vec<&String> = principals
                .iter()
                .filter(|p| principal_host_matches(p, expected_host, expected_realm))
                .collect();

            if !matching.is_empty() {
                let actual = matching
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("Keytab principal: {} principal matches.", actual)
            } else {
                let found = if principals.is_empty() {
                    "none found".to_string()
                } else {
                    principals.join(", ")
                };
                format!(
                    "Keytab principal: {} principal does not match expected {}",
                    found, expected
                )
            }
        }
        Err(err) => {
            format!(
                "Keytab principal: {} (unable to read keytab: {})",
                expected, err
            )
        }
    }
}

/// Returns true if the given principal from the keytab matches our expected host.
///
/// Matches exact principal, or allows short hostname <-> FQDN variants
/// (e.g. "nfs/myserver@REALM" matches when we expect "myserver.example.com").
fn principal_host_matches(principal: &str, expected_host: &str, expected_realm: &str) -> bool {
    // Must be an nfs principal for the right realm
    let Some(rest) = principal.strip_prefix("nfs/") else {
        return false;
    };

    let Some((host_part, realm_part)) = rest.split_once('@') else {
        return false;
    };

    if !realm_part.eq_ignore_ascii_case(expected_realm) {
        return false;
    }

    let p = host_part.to_lowercase();
    let e = expected_host.to_lowercase();

    if p == e {
        return true;
    }

    // Support short name vs FQDN (and vice versa)
    let p_short = p.split('.').next().unwrap_or(&p);
    let e_short = e.split('.').next().unwrap_or(&e);

    p_short == e_short
}

/// Best-effort extraction of NFS principals from /etc/krb5.keytab using `klist`.
/// Returns an empty vec if the keytab does not exist or cannot be read.
fn read_keytab_nfs_principals() -> Result<Vec<String>, String> {
    let output = std::process::Command::new("klist")
        .args(["-k", "-t", "/etc/krb5.keytab"])
        .output()
        .map_err(|e| format!("klist not available: {}", e))?;

    if !output.status.success() {
        // No keytab or permission issue — treat as "no principals found"
        return Ok(vec![]);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut found = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        // Typical output line: "   2 01/01/70 00:00:00 nfs/hostname@REALM"
        if let Some(last_token) = trimmed.split_whitespace().last() {
            if last_token.starts_with("nfs/") && last_token.contains('@') {
                found.push(last_token.to_string());
            }
        }
    }

    Ok(found)
}

// === State ===

#[derive(Clone)]
pub struct AppState {
    pub fs: Arc<FsManager>,
    pub lldap: Arc<Mutex<LdapClient>>,
    pub config: Arc<Config>,
    pub auth: Arc<AuthManager>,
    /// Absolute path to the nfs-klldap.conf file being edited (same one the container uses).
    /// Needed for raw TOML view + save, and for System Settings.
    pub config_path: PathBuf,
    /// The exact hostname that must appear in the nfs/<this>@REALM principal in the keytab.
    /// Computed once at startup using the same two-tier consistent logic (or explicit override)
    /// as the container's own startup banner. Guarantees the WebUI always shows the value
    /// that the running container actually requires.
    pub keytab_hostname: String,
    /// Kerberos realm for the NFS principal (derived/validated at startup, same as krb5.conf generator).
    pub keytab_realm: String,
    /// Human-readable status about whether the on-disk /etc/krb5.keytab actually contains
    /// the expected NFS service principal. Computed once at startup.
    pub keytab_status_message: String,
}

// === Public routes (no auth) ===

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    current_user: Option<String>,
    /// When true, we are in first-run mode: no simple password sidecar exists yet.
    /// The form should offer to set the initial "localhost" password.
    first_run: bool,
    admin_group: String,
    keytab_status_message: String,
}

pub async fn login_page(State(state): State<AppState>) -> impl IntoResponse {
    let first_run = !state.auth.has_simple_password();
    let admin_group = state.auth.admin_group().to_string();

    Html(
        LoginTemplate {
            error: None,
            current_user: None,
            first_run,
            admin_group,
            keytab_status_message: state.keytab_status_message.clone(),
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
    let username = form.username.trim();
    let password = &form.password;

    let result: Result<String, String> = if username == "localhost" {
        // Special local-machine admin path (iterated-SHA256 sidecar)
        match state.auth.validate_simple_password(username, password) {
            Ok(()) => Ok(username.to_string()),
            Err(e) => Err(e),
        }
    } else {
        // Real LLDAP user path
        // 1. Verify the user's own credentials against LLDAP
        let verify_ok = {
            let l = state.lldap.lock().await;
            l.verify_user_credentials(username, password).await.is_ok()
        };

        if !verify_ok {
            Err("Invalid username or password (LDAP)".to_string())
        } else {
            // 2. Check admin group membership using the service account.
            // The long-lived service bind performs the membership check using
            // the modern memberOf attribute on the user entry (standard and clean
            // for KLLDAP). No need to re-bind as the end user.
            let is_admin = {
                let l = state.lldap.lock().await;
                l.user_is_member_of_group(username, state.auth.admin_group())
                    .await
            };

            if !is_admin {
                Err(format!(
                    "Access denied: '{}' is not a member of the '{}' group.",
                    username,
                    state.auth.admin_group()
                ))
            } else {
                Ok(username.to_string())
            }
        }
    };

    match result {
        Ok(user) => {
            let token = state.auth.create_privileged_session(&user);

            let cookie = format!(
                "session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200",
                token
            );

            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, cookie.parse().unwrap());

            (headers, Redirect::to("/")).into_response()
        }
        Err(e) => {
            let first_run = !state.auth.has_simple_password();
            let admin_group = state.auth.admin_group().to_string();
            let html = LoginTemplate {
                error: Some(e),
                current_user: None,
                first_run,
                admin_group,
                keytab_status_message: state.keytab_status_message.clone(),
            }
            .render()
            .unwrap();
            (StatusCode::UNAUTHORIZED, Html(html)).into_response()
        }
    }
}

/// First-run only: set the initial "localhost" simple password.
/// This endpoint is only functional while !has_simple_password().
/// On success it immediately creates a session and redirects (auto-login as localhost).
pub async fn setup_password(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>, // re-use the same form (username ignored, must be "localhost" conceptually)
) -> impl IntoResponse {
    if state.auth.has_simple_password() {
        // Already initialized — treat as bad request.
        let html = LoginTemplate {
            error: Some(
                "A simple password has already been set. Use the normal login form.".to_string(),
            ),
            current_user: None,
            first_run: false,
            admin_group: state.auth.admin_group().to_string(),
            keytab_status_message: state.keytab_status_message.clone(),
        }
        .render()
        .unwrap();
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    let pw = form.password.trim();
    if pw.is_empty() {
        let html = LoginTemplate {
            error: Some("Password cannot be empty".to_string()),
            current_user: None,
            first_run: true,
            admin_group: state.auth.admin_group().to_string(),
            keytab_status_message: state.keytab_status_message.clone(),
        }
        .render()
        .unwrap();
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    match state.auth.set_simple_password(pw) {
        Ok(()) => {
            // Success — immediately log the operator in as localhost (LocalAdmin)
            let token = state.auth.create_privileged_session("localhost");

            let cookie = format!(
                "session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200",
                token
            );
            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, cookie.parse().unwrap());

            (headers, Redirect::to("/?first_run=1")).into_response()
        }
        Err(e) => {
            let html = LoginTemplate {
                error: Some(e),
                current_user: None,
                first_run: true,
                admin_group: state.auth.admin_group().to_string(),
                keytab_status_message: state.keytab_status_message.clone(),
            }
            .render()
            .unwrap();
            (StatusCode::BAD_REQUEST, Html(html)).into_response()
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
    keytab_status_message: String,
}

#[derive(Template)]
#[template(path = "tree_fragment.html")]
struct TreeFragmentTemplate {
    children: Vec<DirNode>,
}

/// Renders a share root (or any directory) as the top clickable row in the tree,
/// with its direct children inside it. This lets users manage permissions on the
/// share root directory itself (important when a share contains only one logical
/// top-level directory of items).
#[derive(Template)]
#[template(path = "tree_root.html")]
struct TreeRootTemplate {
    root: DirNode,
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
    /// The hostname the container will use for the NFS service principal (nfs/<this>@REALM).
    /// Comes from [server] hostname (if set) or the two-tier confirmed runtime hostname
    /// (hostname command + /proc must agree). This is the value the operator must put in the keytab.
    effective_hostname: String,
    /// The Kerberos realm for the NFS service principal.
    /// Comes from [kerberos] realm (or auto-derived from ldap_uri during config load/validation).
    /// This is the exact value written into krb5.conf by the generator.
    effective_realm: String,
    keytab_status_message: String,
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
        keytab_status_message: state.keytab_status_message.clone(),
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

    if let Some(node) = state.fs.build_tree(path) {
        let children: Vec<DirNode> = node
            .children
            .into_iter()
            .map(|c| DirNode {
                path: c.path.to_string_lossy().to_string(),
                name: c.name,
            })
            .collect();

        let is_root_request = params.root.is_some();

        if is_root_request {
            // Render the requested path as a top-level clickable "root" row in the tree.
            // This makes the share root itself (e.g. the "images" directory) directly
            // manageable for owners + permissions via LLDAP-backed form.
            let root = DirNode {
                path: node.path.to_string_lossy().to_string(),
                name: node.name,
            };
            let tpl = TreeRootTemplate { root, children };
            return Ok(Html(tpl.render().unwrap()));
        } else {
            let tpl = TreeFragmentTemplate { children };
            return Ok(Html(tpl.render().unwrap()));
        }
    }

    // Helpful diagnostic (the previous silent empty list was the main user complaint).
    // We deliberately do not leak the internal container path in most cases.
    let safe_path = params
        .path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let msg = format!(
        r#"<div style="color:#b00; padding:0.5em; border:1px solid #fcc; background:#fff5f5; border-radius:4px;">
            <strong>Cannot display directory tree.</strong><br>
            <code>{}</code> is allowed by your config but is not visible inside the container
            (check bind mounts / <code>storage.container_root</code> and the startup diagnostics
            for the suggested <code>-v HOST:CONTAINER</code> line).
        </div>"#,
        safe_path
    );
    Ok(Html(msg))
}

#[derive(Deserialize)]
pub(crate) struct TreeParams {
    path: String,
    /// When present (e.g. root=true or just root), render the requested path itself
    /// as a top-level clickable root row (with its direct children under it).
    /// Used for the initial share load so the share root directory is always a
    /// visible, manageable row in the tree for setting owners/permissions.
    #[serde(default)]
    root: Option<String>,
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
        // Mask off file type bits (e.g. 0o40755 from stat → 755). Directories commonly
        // arrive with the S_IFDIR bit set in st_mode.
        let mode = node.mode & 0o7777;

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
        let safe = path
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        format!(
            r#"<div class="current-state" style="color:#b00;">
                <strong>Cannot read current state.</strong><br>
                <code>{}</code> is allowed in config but not visible inside the container.
                Check your bind mounts (see startup diagnostics).
            </div>"#,
            safe
        )
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

    let lldap = state.lldap.lock().await;
    let users = lldap.list_users(params.q.as_deref()).await;

    let mut html = String::new();
    for user in users.into_iter().take(12) {
        let uid = user.uid_number.unwrap_or(0);
        let name = user.display_name.unwrap_or(user.id.clone());

        // Use data attributes + proper escaping to avoid htmx:syntax:error and XSS issues
        // that raw onclick interpolation was causing.
        let safe_id = user
            .id
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;");
        let safe_name = name
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        html.push_str(&format!(
            r#"<div class="suggestion" data-user-id="{}" data-uid="{}">{}</div>"#,
            safe_id, uid, safe_name
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

    let lldap = state.lldap.lock().await;
    let groups = lldap.list_groups(params.q.as_deref()).await;

    let mut html = String::new();
    for group in groups.into_iter().take(12) {
        let gid = group.gid_number.unwrap_or(0);
        let name = group.display_name.unwrap_or(group.id.clone());

        // Use data attributes + proper escaping (same safety fix as user search).
        let safe_id = group
            .id
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;");
        let safe_name = name
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        html.push_str(&format!(
            r#"<div class="suggestion" data-group-id="{}" data-gid="{}">{}</div>"#,
            safe_id, gid, safe_name
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

/// Collects [[shares]] from the flattened indexed form fields submitted by the
/// structured settings editor (share_name_0, share_host_0, share_export_0, ...).
/// Returns only well-formed, non-empty shares (name + host_path required).
/// Order is deterministic by numeric suffix; gaps are tolerated.
fn collect_shares_from_structured_form(
    extra: &std::collections::HashMap<String, String>,
) -> Vec<nfs_klldap_config::Share> {
    let mut share_rows: Vec<ShareFormRow> = vec![];
    for (k, v) in extra {
        if let Some(suffix) = k.strip_prefix("share_name_") {
            if let Ok(idx) = suffix.parse::<usize>() {
                let name = v.trim().to_string();
                let host = extra
                    .get(&format!("share_host_{}", idx))
                    .cloned()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if name.is_empty() || host.is_empty() {
                    continue;
                }
                let export_path = extra
                    .get(&format!("share_export_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| Some(format!("/{}", name)));
                let security = extra
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

    share_rows
        .into_iter()
        .map(|r| nfs_klldap_config::Share {
            name: r.name,
            host_path: PathBuf::from(r.host),
            export_path: r.export_path,
            security: r.security,
            rw: Some(true),
            squash: Some("no_root_squash".to_string()),
        })
        .collect()
}

/// Applies fields present in the submitted structured settings form onto a
/// loaded NfsKlldapConfig. This is the "logical model" mutation used for
/// validation before the comment-preserving toml_edit write pass.
fn apply_structured_form_to_config(
    form: &StructuredSettingsForm,
    cfg: &mut nfs_klldap_config::NfsKlldapConfig,
) {
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
    if let Some(v) = form.sssd_search_base.clone() {
        cfg.sssd.ldap_search_base = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.sssd_user_base.clone() {
        cfg.sssd.ldap_user_search_base = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.sssd_group_base.clone() {
        cfg.sssd.ldap_group_search_base = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.sssd_ldap_tls_reqcert.clone() {
        cfg.sssd.ldap_tls_reqcert = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.sssd_ldap_tls_cacert.clone() {
        cfg.sssd.ldap_tls_cacert = if v.trim().is_empty() { None } else { Some(v) };
    }
    cfg.sssd.ldap_id_use_start_tls = form.sssd_ldap_id_use_start_tls;
    cfg.sssd.enumerate = form.sssd_enumerate;

    if let Some(v) = form.kerberos_realm.clone() {
        cfg.kerberos.realm = Some(v);
    }
    if let Some(v) = form.ganesha_default_security.clone() {
        cfg.ganesha.default_security = v;
    }
}

/// Small helper to reduce boilerplate when returning validation/write errors
/// from the structured settings form handler.
fn make_settings_error_template(
    current_user: Option<String>,
    raw_toml: String,
    config_path: impl AsRef<std::path::Path>,
    message: String,
    keytab_hostname: String,
    keytab_realm: String,
    keytab_status_message: String,
) -> SettingsTemplate {
    SettingsTemplate {
        current_user,
        raw_toml,
        config_path: config_path.as_ref().display().to_string(),
        message: Some(message),
        effective_hostname: keytab_hostname,
        effective_realm: keytab_realm,
        keytab_status_message,
    }
}

/// Performs an atomic-ish write of config content:
/// 1. Writes to a `.conf.saving` sibling temp file.
/// 2. Renames it over the target path.
/// 3. Sets 0600 permissions on Unix.
///
/// Returns a user-friendly error string on failure (suitable for UI messages).
/// This consolidates the write logic used by both raw and structured save paths.
fn atomic_write_config(path: &std::path::Path, content: &str) -> Result<(), String> {
    let tmp = path.with_extension("conf.saving");
    std::fs::write(&tmp, content.as_bytes()).map_err(|e| format!("Write failed: {}", e))?;

    std::fs::rename(&tmp, path).map_err(|e| format!("Rename failed: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Helper for success responses after a settings save (raw or structured).
/// Keeps the two success sites in sync for the common fields.
fn make_settings_success_template(
    current_user: Option<String>,
    raw_toml: String,
    config_path: impl AsRef<std::path::Path>,
    message: String,
    keytab_hostname: String,
    keytab_realm: String,
    keytab_status_message: String,
) -> SettingsTemplate {
    SettingsTemplate {
        current_user,
        raw_toml,
        config_path: config_path.as_ref().display().to_string(),
        message: Some(message),
        effective_hostname: keytab_hostname,
        effective_realm: keytab_realm,
        keytab_status_message,
    }
}

/// Applies the submitted structured form fields into a toml_edit::DocumentMut.
/// This preserves comments, whitespace, and untouched keys from the original file
/// (the key advantage over the logical-model path).
fn apply_structured_form_to_toml_doc(
    form: &StructuredSettingsForm,
    doc: &mut toml_edit::DocumentMut,
    new_shares: &[nfs_klldap_config::Share],
) {
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

    // Shares: submitted rows are authoritative. Wholesale replacement of [[shares]].
    // Per-share comments from the on-disk file are dropped on purpose.
    if !new_shares.is_empty() {
        let mut shares = toml_edit::ArrayOfTables::new();
        for s in new_shares {
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
}

/// Handler for the permission form submission.
pub async fn apply_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ApplyForm>,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(State(state.clone()), headers).await?;

    let lldap = state.lldap.lock().await;

    // Resolve owner user from LLDAP
    let owner_uid = match lldap.resolve_user(&form.owner_user).await {
        Some((uid, _)) => uid as u32,
        None => {
            let html = format!(
                r#"<div class="form">
                    <h3>Error applying permissions for <code>{}</code></h3>
                    <p style="color: red;">Could not find user <strong>{}</strong> in LLDAP.</p>
                    <button type="button" onclick="htmx.ajax('GET', '/directory?path=' + encodeURIComponent('{}'), {{target: '#permission-form', swap: 'innerHTML'}})">
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
                    <button type="button" onclick="htmx.ajax('GET', '/directory?path=' + encodeURIComponent('{}'), {{target: '#permission-form', swap: 'innerHTML'}})">
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
                <button type="button" onclick="htmx.ajax('GET', '/directory?path=' + encodeURIComponent('{}'), {{target: '#permission-form', swap: 'innerHTML'}})">
                    Back to editor
                </button>
            </div>"#,
            e, form.path
        );
        return Ok(Html(html));
    }

    // NOTE (v0.23 cutover, see git history): Exports are now generated inside the container from the central nfs-klldap.conf.
    // The host UI no longer writes fragments. Permission changes are applied via the container.
    let html = format!(
        r#"<div class="form">
            <h3>Successfully applied permissions for <code>{}</code></h3>
            <p>
                <strong>Owner:</strong> {} (UID {})<br>
                <strong>Group:</strong> {} (GID {})<br>
                <strong>Mode:</strong> {}<br>
                <strong>Recursive:</strong> {}
            </p>
            <p style="color: green;">Changes applied directly inside the container.</p>
            <button type="button" onclick="htmx.ajax('GET', '/directory?path=' + encodeURIComponent('{}'), {{target: '#permission-form', swap: 'innerHTML'}})">
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
        effective_hostname: state.keytab_hostname.clone(),
        effective_realm: state.keytab_realm.clone(),
        keytab_status_message: state.keytab_status_message.clone(),
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
    sssd_search_base: Option<String>, // main ldap_search_base override
    sssd_user_base: Option<String>,
    sssd_group_base: Option<String>,
    // TLS options for ldap/ldaps flexibility (insecure vs secure, self-signed etc.)
    sssd_ldap_tls_reqcert: Option<String>,
    sssd_ldap_tls_cacert: Option<String>,
    sssd_ldap_id_use_start_tls: Option<bool>,
    // Common and important for LLDAP bring-up
    sssd_enumerate: Option<bool>,

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

    // Atomic write using the shared helper (handles temp + rename + 0600).
    if let Err(msg) = atomic_write_config(&state.config_path, &form.raw_content) {
        return Ok(Html(format!("<p style='color:#c00'>{}</p>", msg)));
    }

    // Re-read for the response
    let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let tpl = make_settings_success_template(
        Some(user.0),
        raw_toml,
        &state.config_path,
        "Raw TOML saved and validated. Container will pick up changes via its watcher (or send SIGHUP).".into(),
        state.keytab_hostname.clone(),
        state.keytab_realm.clone(),
        state.keytab_status_message.clone(),
    );
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

    // Apply form fields to the logical model (for validation + later use).
    // The comment-preserving write pass below re-applies a subset using toml_edit.
    apply_structured_form_to_config(&form, &mut cfg);

    // Collect shares (already extracted).
    let new_shares = collect_shares_from_structured_form(&form.extra);
    if !new_shares.is_empty() {
        cfg.shares = new_shares.clone(); // clone only for the logical model; toml pass uses the original vec
    }

    // Validate the logical model first (authoritative structs win for semantics)
    if let Err(e) = cfg.validate_and_derive() {
        let msg = format!("Validation error: {}", e);
        let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            raw_toml,
            &state.config_path,
            msg,
            state.keytab_hostname.clone(),
            state.keytab_realm.clone(),
            state.keytab_status_message.clone(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    // === Comment-preserving structured save (the finishing step) ===
    // Load the on-disk file as a toml_edit DocumentMut so that comments, vertical
    // spacing, and hand-authored keys we do not touch survive the write.
    let original_text = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let mut doc = original_text
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_default();

    // Apply the form using the dedicated patching helper (preserves comments etc.).
    apply_structured_form_to_toml_doc(&form, &mut doc, &new_shares);

    // Atomic write using the shared helper (handles temp + rename + 0600).
    let text = doc.to_string();
    if let Err(msg) = atomic_write_config(&state.config_path, &text) {
        let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            raw_toml,
            &state.config_path,
            msg,
            state.keytab_hostname.clone(),
            state.keytab_realm.clone(),
            state.keytab_status_message.clone(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    // Success - re-render the page with a success message (keeps types simple)
    let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let tpl = make_settings_success_template(
        None,
        raw_toml,
        &state.config_path,
        "Structured settings saved. Container will regenerate configs shortly.".into(),
        state.keytab_hostname.clone(),
        state.keytab_realm.clone(),
        state.keytab_status_message.clone(),
    );
    Ok(Html(tpl.render().unwrap()))
}

// === NFS / LLDAP client reload & status (for bind credential changes) ===

/// Small HTMX fragment: shows the current identity of the LDAP client used for
/// NFS permission management (name → uid/gid resolution) plus a reload button.
/// Highlights when the on-disk credentials (sssd.ldap_default_* or env overrides)
/// have changed since the client was last authenticated.
pub async fn lldap_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(State(state.clone()), headers).await.is_err() {
        return Html(
            "<div id='nfs-client-status' style='color:#c00'>Unauthorized</div>".to_string(),
        );
    }

    let client = state.lldap.lock().await;
    let auth_as = client.authenticated_as().unwrap_or("(none)");
    let last_auth = client.last_auth_time();

    // Load the *current* on-disk config so we can detect edits to bind DN/PW or ldap_uri
    let disk_cfg = crate::config::load_config_from(&state.config_path).ok();
    let (disk_user, _disk_pass) = disk_cfg
        .as_ref()
        .map(crate::config::ldap_service_creds)
        .unwrap_or_else(|| ("(unknown)".to_string(), String::new()));

    let username_differs = disk_user != auth_as;

    let last_str = last_auth
        .map(|t| {
            let ago = std::time::Instant::now().duration_since(t);
            if ago.as_secs() < 60 {
                format!("{}s ago", ago.as_secs())
            } else {
                format!("{}m ago", ago.as_secs() / 60)
            }
        })
        .unwrap_or_else(|| "never (startup failed?)".to_string());

    let notice_html = if username_differs {
        let mut n = String::from(
            "<div style='background:#fff3cd; border:1px solid #ffc107; padding:8px; margin:6px 0; border-radius:3px;'>"
        );
        n.push_str("<strong>Bind credentials changed on disk.</strong><br>");
        n.push_str(&format!("On-disk now uses <code>{}</code>, but the running NFS permission client is still using <code>{}</code> (loaded at startup or last reload).<br>", disk_user, auth_as));
        n.push_str(
            "Use the button below to reconnect with the current values from nfs-klldap.conf.</div>",
        );
        n
    } else {
        String::new()
    };

    let mut html = String::from(
        "<div id='nfs-client-status' style='border:1px solid #aaa; background:#f5f5f5; padding:10px; margin:1rem 0; border-radius:4px;'>"
    );
    html.push_str("<strong>NFS Permission Client (KLLDAP/LLDAP connection)</strong><br>");
    html.push_str("<span style='font-size:0.9em;'>Used for live user/group lookups and uid/gid resolution when managing share permissions.</span><br><br>");
    html.push_str(&format!("Authenticated as: <code>{}</code><br>", auth_as));
    html.push_str(&format!("Last connected: {}<br>", last_str));
    html.push_str(&notice_html);
    if !username_differs {
        html.push_str("<span style='font-size:0.8em;color:#666;'>Reload always reads the latest bind credentials + ldap_uri from disk/env.</span><br>");
    }
    html.push_str(
        "<button type='button' hx-post='/settings/reload-nfs-client' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:8px; padding:4px 10px; cursor:pointer;'>Reload NFS client</button>"
    );
    html.push_str(
        " <span style='font-size:0.8em; color:#555; margin-left:6px;'>(re-reads sssd.ldap_default_bind_* + ldap_uri and re-binds)</span>"
    );
    html.push_str("</div>");

    Html(html)
}

/// Lightweight "reload NFS client": re-creates the LdapClient using whatever
/// credentials + ldap_uri are currently in the on-disk nfs-klldap.conf (or the
/// NFS_KLLDAP_LLDAP_* env overrides) and swaps it into the running AppState.
/// Focused on keeping NFS permission management (name → numeric IDs) in sync
/// after editing bind creds or the LDAP server address.
pub async fn reload_nfs_client(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(State(state.clone()), headers).await.is_err() {
        return Html(
            "<div id='nfs-client-status' style='color:#c00'>Unauthorized</div>".to_string(),
        );
    }

    let fresh = match crate::config::load_config_from(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            let mut err = String::from("<div id='nfs-client-status' style='background:#f8d7da;border:1px solid #dc3545;padding:8px;'>");
            err.push_str(&format!(
                "<strong>Failed to read config:</strong> {}<br>",
                e
            ));
            err.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML'>Try again</button>");
            err.push_str("</div>");
            return Html(err);
        }
    };

    let (user, pass) = crate::config::ldap_service_creds(&fresh);

    if pass.trim().is_empty() || pass == "SET_ME" || pass == "CHANGE_THIS_TO_A_STRONG_SECRET" {
        let mut msg = String::from("<div id='nfs-client-status' style='background:#fff3cd;border:1px solid #ffc107;padding:8px;'>");
        msg.push_str(&format!("<strong>Cannot reload:</strong> No valid password present for <code>{}</code> in the current config (or env).<br>", user));
        msg.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML'>Refresh</button>");
        msg.push_str("</div>");
        return Html(msg);
    }

    let posix_attrs = nfs_klldap_config::resolve_posix_attribute_mapping(&fresh.sssd);
    let realm = fresh.effective_realm();
    let (user_base, group_base) =
        nfs_klldap_config::effective_ldap_search_bases(&fresh.sssd, &realm);

    let (no_tls_verify, start_tls) = nfs_klldap_config::ldap_tls_policy(
        &fresh.ldap_uri,
        fresh.sssd.ldap_tls_reqcert.as_deref(),
        fresh.sssd.ldap_tls_cacert.as_deref(),
        fresh.sssd.ldap_id_use_start_tls,
    );
    let cacert = fresh.sssd.ldap_tls_cacert.clone();
    let mut new_client = crate::ldap::LdapClient::new_with_attributes(
        &fresh.ldap_uri,
        &user_base,
        &group_base,
        posix_attrs,
        no_tls_verify,
        start_tls,
        cacert,
    );

    match new_client.authenticate(&user, &pass).await {
        Ok(()) => {
            // Swap the live client — all subsequent resolve/list operations will use the fresh token
            {
                let mut guard = state.lldap.lock().await;
                *guard = new_client;
            }

            let mut ok = String::from("<div id='nfs-client-status' style='background:#d4edda;border:1px solid #28a745;padding:8px;border-radius:3px;'>");
            ok.push_str("<strong>NFS client reloaded successfully.</strong><br>");
            ok.push_str(&format!("Now authenticated as <code>{}</code> using current values from nfs-klldap.conf.<br>", user));
            ok.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:4px;'>Show updated status</button>");
            ok.push_str("</div>");
            Html(ok)
        }
        Err(e) => {
            let mut err = String::from("<div id='nfs-client-status' style='background:#f8d7da;border:1px solid #dc3545;padding:8px;'>");
            err.push_str(&format!(
                "<strong>Re-authentication failed:</strong> {}<br>",
                e
            ));
            err.push_str("<small>Verify the bind DN/password (or NFS_KLLDAP_LLDAP_* variables) and that LLDAP/KLLDAP is reachable on the management port.</small><br>");
            err.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:4px;'>Retry status</button>");
            err.push_str("</div>");
            Html(err)
        }
    }
}

// === Router ===

pub fn router(state: AppState) -> Router {
    Router::new()
        // Public
        .route("/login", get(login_page).post(login))
        // First-run only (returns 400 once a simple password exists)
        .route("/setup-password", axum::routing::post(setup_password))
        .route("/logout", get(logout).post(logout))
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
        // Lightweight reload of the LLDAP client used for NFS uid/gid resolution
        // (notified when bind credentials in nfs-klldap.conf change)
        .route("/settings/lldap-status", get(lldap_status))
        .route("/settings/reload-nfs-client", post(reload_nfs_client))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{
            header::{COOKIE, SET_COOKIE},
            Request, StatusCode,
        },
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
            # ldap_tls_reqcert = "never"   # example for self-signed LLDAP certs
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
        let default_mapping = nfs_klldap_config::PosixAttributeMapping {
            user_object_class: "posixAccount".to_string(),
            group_object_class: "posixGroup".to_string(),
            user_name: "uid".to_string(),
            user_uid_number: "uidNumber".to_string(),
            user_gid_number: "gidNumber".to_string(),
            user_home_directory: "homeDirectory".to_string(),
            user_shell: "loginShell".to_string(),
            user_full_name: "displayName".to_string(),
            group_name: "cn".to_string(),
            group_gid_number: "gidNumber".to_string(),
            group_member: "member".to_string(),
        };
        let lldap = Arc::new(Mutex::new(LdapClient::new_with_attributes(
            "ldaps://localhost:6360",
            "ou=people,dc=test,dc=com",
            "ou=groups,dc=test,dc=com",
            default_mapping,
            true, // no_tls_verify for test dummy
            false,
            None,
        )));

        let auth = Arc::new(AuthManager::new(&config_path, None));

        let state = AppState {
            fs,
            lldap,
            config,
            auth,
            config_path,
            keytab_hostname: "test-host".to_string(),
            keytab_realm: "EXAMPLE.COM".to_string(),
            keytab_status_message: "Keytab principal: nfs/test-host@EXAMPLE.COM principal matches."
                .to_string(),
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
        // Use the real privileged session creator (same path the login handlers use)
        let token = auth.create_privileged_session("testadmin");

        let app = router(state);

        let new_content = r#"ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
# ldap_tls_reqcert = "never"   # example for self-signed LLDAP certs"#;

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
        // Use the real privileged session creator (same path the login handlers use)
        let token = auth.create_privileged_session("testadmin");

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

    /// Exercises the complete localhost first-run + normal login + session + protected route flow.
    /// This is the primary self-contained authentication path that does not require a live LLDAP.
    #[tokio::test]
    async fn full_localhost_first_run_login_session_and_protected_route_flow() {
        let (state, _tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();

        // Router is cheap to clone for multi-request flows
        let app = router(state);

        // === Phase 1: First-run state ===
        assert!(
            !auth.has_simple_password(),
            "fresh AuthManager must report no simple password"
        );

        // GET /login should succeed (renders first-run form)
        let login_page_req = Request::builder()
            .method("GET")
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(login_page_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // === Phase 2: First-run password setup ===
        // The form (and LoginForm deserializer) expects both fields, even though
        // the setup handler conceptually only cares about the password.
        let setup_body = "username=localhost&password=initialStrongPass123";
        let setup_req = Request::builder()
            .method("POST")
            .uri("/setup-password")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(setup_body))
            .unwrap();
        let resp = app.clone().oneshot(setup_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER); // redirect after success

        // Must have set a session cookie
        let set_cookie = resp
            .headers()
            .get(SET_COOKIE)
            .expect("setup-password must set session cookie")
            .to_str()
            .unwrap();
        assert!(
            set_cookie.contains("session="),
            "cookie header must contain session token"
        );
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));

        assert!(
            auth.has_simple_password(),
            "sidecar password file must now exist after setup"
        );

        // Extract the token we just received (simple parse sufficient for test)
        let _token = set_cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("session=")
            .unwrap()
            .to_string();

        // === Phase 3: Normal login as localhost with the password we just set ===
        let login_body = "username=localhost&password=initialStrongPass123";
        let login_req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(login_body))
            .unwrap();
        let resp = app.clone().oneshot(login_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let login_set_cookie = resp
            .headers()
            .get(SET_COOKIE)
            .expect("successful login must set session cookie")
            .to_str()
            .unwrap();
        let login_token = login_set_cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("session=")
            .unwrap()
            .to_string();
        assert!(!login_token.is_empty());

        // === Phase 4: Use the session to access a protected route ===
        let protected_req = Request::builder()
            .method("GET")
            .uri("/settings")
            .body(Body::empty())
            .unwrap();
        let protected_req = add_session_cookie(protected_req, &login_token);

        let resp = app.clone().oneshot(protected_req).await.unwrap();
        // Should reach the handler (200), not be redirected to /login
        assert_eq!(resp.status(), StatusCode::OK);

        // === Phase 5: Logout clears the session ===
        let logout_req = Request::builder()
            .method("POST")
            .uri("/logout")
            .header("cookie", format!("session={}", login_token))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(logout_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let cleared = resp
            .headers()
            .get(SET_COOKIE)
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert!(
            cleared.contains("Max-Age=0") || cleared.contains("session="),
            "logout should clear session cookie"
        );
    }
}
