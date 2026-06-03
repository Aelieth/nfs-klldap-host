//! `/` permission tree, LLDAP search, and apply (chown/chmod via FsManager).

use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::fs::ApplyProgress;

use super::{AppState, require_auth};

// === Templates (private to this module) ===

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    shares: Vec<crate::config::Share>,
    current_user: Option<String>,
    keytab_alert: Option<String>,
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
        keytab_alert: state.keytab_alert.clone(),
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

    // Build command string (used for immediate log and final result text)
    let cmd = if form.recursive {
        format!(
            "chown {uid}:{gid} -R {path}\nchmod {mode:o} -R {path}",
            uid = owner_uid,
            gid = group_gid,
            path = form.path,
            mode = mode
        )
    } else {
        format!(
            "chown {uid}:{gid} {path} (+ immediate files in directory)\nchmod {mode:o} {path} (+ immediate files in directory)",
            uid = owner_uid,
            gid = group_gid,
            path = form.path,
            mode = mode
        )
    };

    // === Always async path (for live progress in Apply Log, spinner while estimating,
    //      tree lock until done, and Cancel button). Even non-recursive on a dir with
    //      thousands of immediate entries benefits from the UX.
    let progress = Arc::new(ApplyProgress::default());
    {
        let mut slot = state.apply_progress.lock().await;
        *slot = Some(progress.clone());
    }
    {
        let mut c = progress.cmd.lock().unwrap();
        *c = Some(cmd.clone());
    }

    let fs = state.fs.clone();
    let pth = form.path.clone();
    let uid = owner_uid;
    let gid = group_gid;
    let md = mode;
    let rec = form.recursive;
    let prog = progress.clone();
    tokio::spawn(async move {
        // Count-as-you-go phase gives immediate visible feedback ("scanned N so far |")
        // via the poller + render_apply_status_oob. No long silent pre-count.
        *prog.phase.lock().unwrap() = "scanning".to_string();
        let _ = fs.count_applicable_with_live(std::path::Path::new(&pth), rec, &prog);
        let total = prog.processed.load(Ordering::Relaxed);
        prog.total.store(total, Ordering::Relaxed);
        prog.processed.store(0, Ordering::Relaxed);
        *prog.phase.lock().unwrap() = "applying".to_string();

        let apply_res = match fs.apply_permissions_with_progress(
            std::path::Path::new(&pth), uid, gid, md, rec, &prog,
        ) {
            Ok(r) => r,
            Err(e) => {
                prog.error_count.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut errs) = prog.recent_errors.lock() {
                    errs.push((PathBuf::from(&pth), e.clone()));
                }
                let err_text = format!("Apply failed before walking tree: {}", e);
                *prog.final_result_text.lock().expect("progress mutex poisoned") = Some(err_text);
                prog.finished.store(true, Ordering::Relaxed);
                // Still attempt cache invalidate (no-op) and exit task early
                {
                    let fs2 = fs.clone();
                    let p2 = pth.clone();
                    tokio::spawn(async move {
                        fs2.invalidate_path(std::path::Path::new(&p2));
                    });
                }
                return;
            }
        };

        // Existing background cache invalidation (moved inside the task)
        {
            let fs2 = fs.clone();
            let p2 = pth.clone();
            tokio::spawn(async move {
                fs2.invalidate_path(std::path::Path::new(&p2));
            });
        }

        let mut rtext = format!(
            "Result: {} changed, {} skipped, {} errors",
            apply_res.changed, apply_res.skipped, apply_res.errors.len()
        );
        if prog.cancelled.load(Ordering::Relaxed) {
            let last = prog.last_path.lock().expect("progress mutex poisoned").clone().unwrap_or_else(|| pth.clone());
            rtext = format!("CANCELLED after {}\n{}", last, rtext);
        }
        if !apply_res.errors.is_empty() {
            rtext.push_str("\n\nErrors:\n");
            for (pp, msg) in apply_res.errors.iter().take(5) {
                rtext.push_str(&format!("  {} — {}\n", pp.display(), msg));
            }
            if apply_res.errors.len() > 5 {
                rtext.push_str(&format!("  ... and {} more\n", apply_res.errors.len() - 5));
            }
        }
        if apply_res.skipped > 0 {
            rtext.push_str("\n(skipped entries were typically symlinks — never followed for safety)");
        }

        {
            let mut ft = prog.final_result_text.lock().expect("progress mutex poisoned");
            *ft = Some(rtext);
        }
        prog.finished.store(true, Ordering::Relaxed);
    });

    // Immediate response: placeholder keeps the .dir-meta target (and the edit/applying lock
    // via JS + data-applying + currentEditPath). Real meta + subtree refresh (if recursive)
    // happen only after the poller sees finished and does the final /dir-meta fetch.
    let placeholder = format!(
        r#"<div class="dir-meta-inner" data-path="{}" data-applying="1">
    <span style="color:#b8860b;">⏳ Applying permissions — see Apply Log (bottom right) for progress and Cancel. Tree navigation locked until complete.</span>
</div>"#,
        form.path
    );

    // Initial status (will be replaced by polls with live scanned/spinner or real %)
    let status_html = render_apply_status_oob(&cmd, "Stand-by, estimating total... (live updates below)", true);

    Ok(Html(format!("{}\n{}", placeholder, status_html)))
}

/// Renders the full oob-swappable #apply-status (header with Cancel on the right + content).
/// active_cancel controls the red clickable vs. muted disabled appearance of the button.
/// When !active_cancel we also emit data-apply-finished so the JS poller listener can stop itself.
fn render_apply_status_oob(cmd: &str, result_or_live: &str, active_cancel: bool) -> String {
    let cancel_btn = if active_cancel {
        r#"<button type="button" onclick="if (window.cancelCurrentApply) window.cancelCurrentApply();" style="font-size:0.72em; padding:2px 8px; border:1px solid #c33; color:#c33; background:#fff5f5; border-radius:2px; cursor:pointer;">Cancel Apply</button>"#
    } else {
        r#"<button type="button" disabled style="font-size:0.72em; padding:2px 8px; border:1px solid #aaa; color:#888; opacity:0.6; border-radius:2px;">Cancel Apply</button>"#
    };
    let finished_attr = if !active_cancel { r#"data-apply-finished="true""# } else { "" };
    format!(
        r#"<div id="apply-status" hx-swap-oob="true" class="apply-status" style="display:block;" {finished_attr}>
    <div style="display:flex; align-items:center; justify-content:space-between; font-size:0.85em; font-weight:600; margin-bottom:4px; color:var(--text-muted);">
      <span>Apply Log</span>
      {cancel_btn}
    </div>
    <div class="apply-status-content"
         style="font-family: ui-monospace, monospace; font-size:0.78em; background:var(--bg-alt); border:1px solid var(--border); border-radius:4px; padding:8px 10px; white-space:pre-wrap; line-height:1.35;">
<strong>Command</strong>
{cmd}

<strong>Status</strong>
{result_or_live}
    </div>
</div>"#,
        finished_attr = finished_attr,
        cancel_btn = cancel_btn,
        cmd = cmd,
        result_or_live = result_or_live
    )
}

pub(crate) async fn apply_progress(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    let html = {
        let guard = state.apply_progress.lock().await;
        if let Some(prog) = guard.as_ref() {
            let total = prog.total.load(Ordering::Relaxed);
            let proc = prog.processed.load(Ordering::Relaxed);
            let ch = prog.changed.load(Ordering::Relaxed);
            let sk = prog.skipped.load(Ordering::Relaxed);
            let errc = prog.error_count.load(Ordering::Relaxed);
            let phase = prog.phase.lock().expect("progress mutex poisoned").clone();
            let finished = prog.finished.load(Ordering::Relaxed);

            let cmd = prog.cmd.lock().expect("progress mutex poisoned").clone().unwrap_or_default();

            let live_or_final = if finished {
                prog.final_result_text.lock().expect("progress mutex poisoned").clone().unwrap_or_else(|| "Finished.".into())
            } else if total == 0 {
                // Still estimating (count-as-you-go phase)
                let spin_chars = ["|", "/", "-", "\\"];
                let spin = spin_chars[proc % 4];
                format!("Stand-by, estimating total... scanned {} so far {}", proc, spin)
            } else {
                let pct = if total > 0 { ((proc as f64 * 100.0) / total as f64) as u32 } else { 0 };
                format!(
                    "Phase: {}\nProcessed: {}/{} ({}%)\nchanged: {}  skipped: {}  errors: {}",
                    phase, proc, total, pct, ch, sk, errc
                )
            };

            render_apply_status_oob(&cmd, &live_or_final, !finished)
        } else {
            // Neutral / last-known state when no apply slot is active
            r#"<div id="apply-status" hx-swap-oob="true" class="apply-status" style="display:block;">
    <div style="display:flex; align-items:center; justify-content:space-between; font-size:0.85em; font-weight:600; margin-bottom:4px; color:var(--text-muted);">
      <span>Apply Log</span>
      <button type="button" disabled style="font-size:0.72em; padding:2px 8px; border:1px solid #aaa; color:#888; opacity:0.6; border-radius:2px;">Cancel Apply</button>
    </div>
    <div class="apply-status-content" style="font-family: ui-monospace, monospace; font-size:0.78em; background:var(--bg-alt); border:1px solid var(--border); border-radius:4px; padding:8px 10px; white-space:pre-wrap; line-height:1.35;">
<em style="color:var(--text-light);">No permission apply in progress.</em>
    </div>
</div>"#.to_string()
        }
    };
    Ok(Html(html))
}

pub(crate) async fn cancel_apply(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    if let Some(prog) = state.apply_progress.lock().await.as_ref() {
        prog.cancelled.store(true, Ordering::Relaxed);
    }
    Ok(Html(r#"<span style="font-size:0.7em; color:#c33;">Cancel requested.</span>"#.to_string()))
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