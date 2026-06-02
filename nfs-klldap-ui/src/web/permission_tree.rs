//! Permission tree UI (the "/" page) + HTMX fragments.
//!
//! This module owns everything related to the interactive directory tree,
//! live LLDAP user/group search, inline permission editors (dir-meta + dir-editor),
//! and the core "apply" action that performs direct chown/chmod inside the container.
//!
//! Extracted from the old monolithic web.rs (2026 refactor) for maintainability.
//! The corresponding templates are:
//!   index.html, tree_fragment.html, tree_root.html, dir_meta.html, dir_editor.html
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
    owner_uid_hidden: String,
    owner_gid_hidden: String,
    mode_value: String,
    recursive_checked: String,
}

/// Friendly label for the permission editor / meta row: `display (uid)` when LDAP resolves.
async fn friendly_user_label(lldap: &crate::ldap::LdapClient, uid: u32) -> String {
    if uid == 0 {
        return "0".to_string();
    }
    if let Some((id, display)) = lldap.resolve_user_by_uid(uid as i32).await {
        let label = if !display.is_empty() && display != id {
            display
        } else {
            id
        };
        return format!("{} ({})", label, uid);
    }
    uid.to_string()
}

async fn friendly_group_label(lldap: &crate::ldap::LdapClient, gid: u32) -> String {
    if gid == 0 {
        return "0".to_string();
    }
    if let Some((id, display)) = lldap.resolve_group_by_gid(gid as i32).await {
        let label = if !display.is_empty() && display != id {
            display
        } else {
            id
        };
        return format!("{} ({})", label, gid);
    }
    gid.to_string()
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
    /// Legacy/alternate query param (some HTMX configs send `q` via js: vals).
    q: Option<String>,
    /// Live search: current Owner field value (preferred — sent via hx-include on the input).
    #[serde(default)]
    owner_user: Option<String>,
    /// Live search: current Group field value (preferred — sent via hx-include on the input).
    #[serde(default)]
    owner_group: Option<String>,
}

impl SearchParams {
    fn user_query_raw(&self) -> Option<&str> {
        let raw = self.q.as_deref().or(self.owner_user.as_deref())?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    fn group_query_raw(&self) -> Option<&str> {
        let raw = self.q.as_deref().or(self.owner_group.as_deref())?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct ApplyForm {
    path: String,
    owner_user: String,
    owner_group: String,
    mode: String,
    #[serde(default)]
    recursive: bool,
    // Strings (not Option<u32>) because the dir-editor form always includes the hidden
    // fields (often with empty value="" or "0"). Empty must deserialize cleanly; we parse
    // leniently below. This prevents 422 "cannot parse integer from empty string".
    #[serde(default)]
    owner_user_uid: String,
    #[serde(default)]
    owner_group_gid: String,
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

/// 1-level children endpoint for lazy FS tree loading (HTMX on expand).
/// Only O(1) cost; reuses the same TreeFragmentTemplate shape.
pub(crate) async fn fs_children(
    State(state): State<AppState>,
    Query(params): Query<TreeParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    let path = std::path::Path::new(&params.path);

    let children: Vec<DirNode> = state
        .fs
        .list_children(path)
        .unwrap_or_default()
        .into_iter()
        .map(|c| DirNode {
            path: c.path.to_string_lossy().to_string(),
            name: c.name,
        })
        .collect();

    let tpl = TreeFragmentTemplate { children };
    Ok(Html(tpl.render().unwrap()))
}

// === Inline tree meta / editor handlers ===

pub(crate) async fn dir_meta(
    State(state): State<AppState>,
    Query(params): Query<DirMetaParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    let path = params.path;

    let (owner_display, group_display, mode_octal) = if let Some((owner, group, mode)) = state.fs.get_dir_meta(std::path::Path::new(&path)) {
        let l = state.lldap.lock().await;
        (
            friendly_user_label(&l, owner).await,
            friendly_group_label(&l, group).await,
            format!("{:o}", mode),
        )
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

    let (owner_value, group_value, owner_uid_hidden, owner_gid_hidden, mode_value) =
        if let Some((owner, group, mode)) = state.fs.get_dir_meta(std::path::Path::new(&path)) {
            let l = state.lldap.lock().await;
            let owner_label = friendly_user_label(&l, owner).await;
            let group_label = friendly_group_label(&l, group).await;
            let uid_h = if owner > 0 { owner.to_string() } else { String::new() };
            let gid_h = if group > 0 { group.to_string() } else { String::new() };
            (owner_label, group_label, uid_h, gid_h, format!("{:o}", mode))
        } else {
            (
                "1000".into(),
                "1000".into(),
                "1000".into(),
                "1000".into(),
                "755".into(),
            )
        };

    let tpl = DirEditorTemplate {
        path: path.clone(),
        owner_value,
        group_value,
        owner_uid_hidden,
        owner_gid_hidden,
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
    let users = lldap.list_users(params.user_query_raw()).await;

    let mut html = String::new();
    for user in users.into_iter().filter(|u| u.uid_number.is_some()) {
        let uid = user.uid_number.unwrap_or(0);
        let name = user.display_name.unwrap_or(user.id.clone());

        let safe_id = user.id.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        let safe_name = name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");

        let label = format!("{} (UID {})", safe_name, uid);
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
    let groups = lldap.list_groups(params.group_query_raw()).await;

    let mut html = String::new();
    for group in groups.into_iter().filter(|g| g.gid_number.is_some()) {
        let gid = group.gid_number.unwrap_or(0);
        let name = group.display_name.unwrap_or(group.id.clone());

        let safe_id = group.id.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        let safe_name = name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");

        let label = format!("{} (GID {})", safe_name, gid);
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

    // Hidden fields arrive as strings (may be "", "0", or a valid number string).
    // We only trust a positive (>0) integer from the hidden; 0 or empty means "not provided by search".
    if let Ok(n) = form.owner_user_uid.trim().parse::<u32>() {
        if n > 0 {
            owner_uid = n;
        }
    } else if let Ok(n) = form.owner_user.trim().parse::<u32>() {
        owner_uid = n;
    } else if !form.owner_user.trim().is_empty() {
        needs_lock = true;
    }

    if let Ok(n) = form.owner_group_gid.trim().parse::<u32>() {
        if n > 0 {
            group_gid = n;
        }
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

    let apply_result = match state.fs.apply_permissions(
        std::path::Path::new(&form.path),
        owner_uid,
        group_gid,
        mode,
        form.recursive,
    ) {
        Ok(r) => r,
        Err(e) => {
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
    };

    // Fire-and-forget background cache invalidation hook
    {
        let fs = state.fs.clone();
        let p = form.path.clone();
        tokio::spawn(async move {
            fs.invalidate_path(std::path::Path::new(&p));
        });
    }

    // Build a human-readable command summary (less verbose)
    let recursive_flag = if form.recursive { " -R" } else { "" };
    let cmd = format!(
        "chown {uid}:{gid}{r} {path}\nchmod {mode:o}{r} {path}",
        uid = owner_uid,
        gid = group_gid,
        r = recursive_flag,
        path = form.path,
        mode = mode
    );

    // Build rich result text (more verbose)
    let mut result_text = format!(
        "Result: {} changed, {} skipped, {} errors",
        apply_result.changed, apply_result.skipped, apply_result.errors.len()
    );

    if !apply_result.errors.is_empty() {
        result_text.push_str("\n\nErrors:\n");
        for (p, msg) in apply_result.errors.iter().take(5) {
            result_text.push_str(&format!("  {} — {}\n", p.display(), msg));
        }
        if apply_result.errors.len() > 5 {
            result_text.push_str(&format!("  ... and {} more\n", apply_result.errors.len() - 5));
        }
    }

    if apply_result.skipped > 0 {
        result_text.push_str("\n(skipped entries were typically symlinks — never followed for safety)");
    }

    // Build the status box content (will be swapped oob into #apply-status)
    let status_html = format!(
        r#"<div id="apply-status" hx-swap-oob="true" class="apply-status" style="display:block;">
    <div style="font-size:0.85em; font-weight:600; margin-bottom:4px; color:var(--text-muted);">Apply Log</div>
    <div class="apply-status-content"
         style="font-family: ui-monospace, monospace; font-size:0.78em; background:var(--bg-alt); border:1px solid var(--border); border-radius:4px; padding:8px 10px; white-space:pre-wrap; line-height:1.35;">
<strong>Command</strong>
{cmd}

<strong>Result</strong>
{result_text}
    </div>
</div>"#,
        cmd = cmd,
        result_text = result_text
    );

    // Success → return fresh compact meta (for the clicked dir) + oob status box
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

    let meta_html = meta.render().unwrap();
    Ok(Html(format!("{}\n{}", meta_html, status_html)))
}

#[cfg(test)]
mod search_params_tests {
    use super::SearchParams;

    #[test]
    fn user_query_uses_owner_user_field_from_htmx_include() {
        let p = SearchParams {
            q: None,
            owner_user: Some("  alice  ".into()),
            owner_group: None,
        };
        assert_eq!(p.user_query_raw(), Some("alice"));
    }

    #[test]
    fn empty_owner_user_means_show_all() {
        let p = SearchParams {
            q: None,
            owner_user: Some("   ".into()),
            owner_group: None,
        };
        assert_eq!(p.user_query_raw(), None);
    }

    #[test]
    fn group_query_uses_owner_group_field() {
        let p = SearchParams {
            q: Some("legacy".into()),
            owner_user: None,
            owner_group: Some("admins".into()),
        };
        assert_eq!(p.group_query_raw(), Some("legacy"));
    }
}