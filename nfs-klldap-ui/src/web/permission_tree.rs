//! Permission tree UI (the "/" page) + HTMX fragments.
//!
//! This module owns everything related to the interactive directory tree,
//! live LLDAP user/group search, inline permission editors (dir-meta + dir-editor),
//! and the core "apply" action that performs direct chown/chmod inside the container.
//!
//! Extracted from the old monolithic web.rs (2026 refactor) for maintainability.
//! The corresponding templates are:
//!   index.html, tree_fragment.html, tree_root.html, dir_meta.html, dir_editor.html,
//!   (legacy) permission_form.html
//!
//! All handlers here use the improved `require_auth(&state, &headers)` from the auth module
//! (no more State clones per protected route).

use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;

use super::{AppState, require_auth};

// === Templates (private to this module) ===

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
/// share root directory itself.
#[derive(Template)]
#[template(path = "tree_root.html")]
struct TreeRootTemplate {
    root: DirNode,
    children: Vec<DirNode>,
}

#[derive(Debug, Clone)]
pub(crate) struct DirNode {
    pub path: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "permission_form.html")]
struct PermissionForm {
    path: String,
    current_state_html: String,
}

// New inline fragments (the current UX model).
#[derive(Template)]
#[template(path = "dir_meta.html")]
struct DirMetaTemplate {
    path: String,
    owner_display: String,
    group_display: String,
    mode_octal: String,
}

#[derive(Template)]
#[template(path = "dir_editor.html")]
struct DirEditorTemplate {
    path: String,
    owner_value: String,
    group_value: String,
    mode_value: String,
    recursive_checked: String,
}

// === Query/Form params ===

#[derive(Deserialize)]
pub(crate) struct TreeParams {
    path: String,
    #[serde(default)]
    root: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DirMetaParams {
    path: String,
}

#[derive(Deserialize)]
pub(crate) struct DirEditorParams {
    path: String,
}

#[derive(Deserialize)]
pub(crate) struct SearchParams {
    q: Option<String>,
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
    #[serde(default)]
    owner_user_uid: Option<u32>,
    #[serde(default)]
    owner_group_gid: Option<u32>,
}

// === Handlers ===

pub(crate) async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    let tpl = IndexTemplate {
        shares: state.config.shares.clone(),
        current_user: Some(user.0),
        keytab_status_message: state.keytab_status_message.clone(),
    };

    Ok(Html(tpl.render().unwrap()))
}

/// Lazy-loads children of a directory (HTMX partial)
pub(crate) async fn tree_fragment(
    State(state): State<AppState>,
    Query(params): Query<TreeParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

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
            // Render the requested path as a top-level clickable "root" row.
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

    // Helpful diagnostic (the previous silent empty list was the main complaint).
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

/// Returns the permission editor form for a directory (HTMX) — legacy route kept during transition.
pub(crate) async fn directory_form(
    State(state): State<AppState>,
    Query(params): Query<DirParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    let path = params.path;

    let current_state_html = if let Some(node) = state.fs.build_tree(std::path::Path::new(&path)) {
        let owner = node.owner.unwrap_or(0);
        let group = node.group.unwrap_or(0);
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

// === New inline tree meta / editor handlers ===

pub(crate) async fn dir_meta(
    State(state): State<AppState>,
    Query(params): Query<DirMetaParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    let path = params.path;

    let (owner_display, group_display, mode_octal) = if let Some((owner, group, mode)) = state.fs.get_dir_meta(std::path::Path::new(&path)) {
        let l = state.lldap.lock().await;
        let owner_disp = if let Some((name, _)) = l.resolve_user_by_uid(owner as i32).await {
            if owner > 0 { format!("{} ({})", name, owner) } else { name }
        } else if owner > 0 {
            owner.to_string()
        } else {
            "0".to_string()
        };

        let group_disp = if let Some((name, _)) = l.resolve_group_by_gid(group as i32).await {
            if group > 0 { format!("{} ({})", name, group) } else { name }
        } else if group > 0 {
            group.to_string()
        } else {
            "0".to_string()
        };

        (owner_disp, group_disp, format!("{:o}", mode))
    } else {
        let safe = path.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        ("(unavailable)".into(), "(unavailable)".into(), format!("<span style=\"color:#b00\">{}</span>", safe))
    };

    let tpl = DirMetaTemplate {
        path: path.clone(),
        owner_display,
        group_display,
        mode_octal,
    };

    Ok(Html(tpl.render().unwrap()))
}

pub(crate) async fn dir_editor(
    State(state): State<AppState>,
    Query(params): Query<DirEditorParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    let path = params.path;

    let (owner_value, group_value, mode_value) = if let Some((owner, group, mode)) = state.fs.get_dir_meta(std::path::Path::new(&path)) {
        (owner.to_string(), group.to_string(), format!("{:o}", mode))
    } else {
        ("1000".into(), "1000".into(), "755".into())
    };

    let tpl = DirEditorTemplate {
        path: path.clone(),
        owner_value,
        group_value,
        mode_value,
        recursive_checked: String::new(),
    };

    Ok(Html(tpl.render().unwrap()))
}

// === Live LLDAP Search Handlers (used by the permission editor) ===

pub(crate) async fn search_users(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return Html("<div class=\"suggestion\">Unauthorized</div>".to_string());
    }

    let lldap = state.lldap.lock().await;
    let users = lldap.list_users(params.q.as_deref()).await;

    let mut html = String::new();
    for user in users.into_iter().take(25) {
        let uid = user.uid_number.unwrap_or(0);
        let name = user.display_name.unwrap_or(user.id.clone());

        let safe_id = user.id.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        let safe_name = name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");

        let label = if uid > 0 {
            format!("{} (UID {})", safe_name, uid)
        } else {
            safe_name.clone()
        };
        html.push_str(&format!(
            r#"<div class="suggestion" data-user-id="{}" data-uid="{}">{}</div>"#,
            safe_id, uid, label
        ));
    }
    if html.is_empty() {
        html = "<div class=\"suggestion\">No matches found in LLDAP</div>".to_string();
    }
    Html(html)
}

pub(crate) async fn search_groups(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return Html("<div class=\"suggestion\">Unauthorized</div>".to_string());
    }

    let lldap = state.lldap.lock().await;
    let groups = lldap.list_groups(params.q.as_deref()).await;

    let mut html = String::new();
    for group in groups.into_iter().take(25) {
        let gid = group.gid_number.unwrap_or(0);
        let name = group.display_name.unwrap_or(group.id.clone());

        let safe_id = group.id.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        let safe_name = name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");

        let label = if gid > 0 {
            format!("{} (GID {})", safe_name, gid)
        } else {
            safe_name.clone()
        };
        html.push_str(&format!(
            r#"<div class="suggestion" data-group-id="{}" data-gid="{}">{}</div>"#,
            safe_id, gid, label
        ));
    }
    if html.is_empty() {
        html = "<div class=\"suggestion\">No matches found in LLDAP</div>".to_string();
    }
    Html(html)
}

// === Core permission apply handler ===

pub(crate) async fn apply_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ApplyForm>,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    // Numeric bypass (core of the inline editor UX):
    // - Hidden uid/gid from search click (fast, cached)
    // - Direct numeric entry (no LDAP roundtrip)
    // - Name → resolve via LLDAP (only when necessary)
    let mut owner_uid: u32 = 0;
    let mut group_gid: u32 = 0;
    let mut needs_lock = false;

    if let Some(uid) = form.owner_user_uid.filter(|&x| x > 0) {
        owner_uid = uid;
    } else if let Ok(n) = form.owner_user.trim().parse::<u32>() {
        owner_uid = n;
    } else if !form.owner_user.trim().is_empty() {
        needs_lock = true;
    }

    if let Some(gid) = form.owner_group_gid.filter(|&x| x > 0) {
        group_gid = gid;
    } else if let Ok(n) = form.owner_group.trim().parse::<u32>() {
        group_gid = n;
    } else if !form.owner_group.trim().is_empty() {
        needs_lock = true;
    }

    if needs_lock {
        let lldap = state.lldap.lock().await;
        if owner_uid == 0 && !form.owner_user.trim().is_empty() {
            match lldap.resolve_user(&form.owner_user).await {
                Some((uid, _)) => owner_uid = uid as u32,
                None => {
                    let html = format!(
                        r#"<div style="font-size:0.85em; color:#900; padding:4px; border:1px solid #fcc;">
                            Could not find user <strong>{}</strong> in LLDAP (or invalid number).
                            <button type="button" hx-get="/dir-editor?path={}" hx-target="closest .dir-meta" hx-swap="innerHTML">Retry</button>
                        </div>"#,
                        form.owner_user,
                        urlencoding::encode(&form.path)
                    );
                    return Ok(Html(html));
                }
            }
        }
        if group_gid == 0 && !form.owner_group.trim().is_empty() {
            match lldap.resolve_group(&form.owner_group).await {
                Some((gid, _)) => group_gid = gid as u32,
                None => {
                    let html = format!(
                        r#"<div style="font-size:0.85em; color:#900; padding:4px; border:1px solid #fcc;">
                            Could not find group <strong>{}</strong> in LLDAP (or invalid number).
                            <button type="button" hx-get="/dir-editor?path={}" hx-target="closest .dir-meta" hx-swap="innerHTML">Retry</button>
                        </div>"#,
                        form.owner_group,
                        urlencoding::encode(&form.path)
                    );
                    return Ok(Html(html));
                }
            }
        }
    }

    if owner_uid == 0 { owner_uid = 1000; }
    if group_gid == 0 { group_gid = 1000; }

    let mode = u32::from_str_radix(&form.mode, 8).unwrap_or(0o770);

    if let Err(e) = state.fs.apply_permissions(
        std::path::Path::new(&form.path),
        owner_uid,
        group_gid,
        mode,
        form.recursive,
    ) {
        let html = format!(
            r#"<div style="font-size:0.82em; color:#900; padding:3px 4px; border:1px solid #fcc; background:#fff5f5;">
                Apply failed: {} 
                <button type="button" hx-get="/dir-editor?path={}" hx-target="closest .dir-meta" hx-swap="innerHTML">Retry</button>
            </div>"#,
            e,
            urlencoding::encode(&form.path)
        );
        return Ok(Html(html));
    }

    // Success → return fresh compact meta (HTMX swaps it in; editor exits automatically via htmx:afterSwap listener in base.html)
    let (owner_display, group_display, mode_octal) = {
        let l = state.lldap.lock().await;
        let od = if let Some((nm, _)) = l.resolve_user_by_uid(owner_uid as i32).await {
            if owner_uid > 0 { format!("{} ({})", nm, owner_uid) } else { nm }
        } else { owner_uid.to_string() };

        let gd = if let Some((nm, _)) = l.resolve_group_by_gid(group_gid as i32).await {
            if group_gid > 0 { format!("{} ({})", nm, group_gid) } else { nm }
        } else { group_gid.to_string() };

        (od, gd, format!("{:o}", mode))
    };

    let meta = DirMetaTemplate {
        path: form.path.clone(),
        owner_display,
        group_display,
        mode_octal,
    };
    Ok(Html(meta.render().unwrap()))
}