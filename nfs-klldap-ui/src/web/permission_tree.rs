//! Permission tree routes, LDAP search, and apply via FsManager.

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

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    shares: Vec<ShareInfo>,
    current_user: Option<String>,
    keytab_alert: Option<String>,
    /// Mirrors host_nfs_mode so the template adjusts the top Ganesha notice.
    host_nfs_mode: bool,
}

#[derive(Template)]
#[template(path = "tree_fragment.html")]
struct TreeFragmentTemplate {
    children: Vec<DirNode>,
}

/// Share root as top tree row with direct children (includes root perms).
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

/// Share card row with client NFS path and RW/squash/cache labels.
#[derive(Debug, Clone)]
struct ShareInfo {
    pub name: String,
    /// Full client NFS path, e.g. "myhost:/data" or "myhost:/exports/foo".
    pub nfs_path: String,
    pub host_path: String,
    /// Access label is either RW or RO.
    pub access: String,
    /// Squash label uses official Ganesha Squash values.
    pub squash_label: String,
    pub cache_profile: String,
    pub warning: Option<String>,
    pub acl_limited: bool,
}

#[derive(Template)]
#[template(path = "dir_meta.html")]
pub(crate) struct DirMetaTemplate {
    pub(crate) path: String,
    pub(crate) owner_display: String,
    pub(crate) group_display: String,
    pub(crate) mode_octal: String,
    /// If true, the ACL Permissions button and panel edit controls should be disabled/hidden (noacl or limited FS).
    pub(crate) acl_limited: bool,
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

#[derive(Template)]
#[template(path = "acl_fragment.html")]
pub(crate) struct AclFragmentTemplate {
    path: String,
    users_list: String,
    groups_list: String,
    acl_limited: bool,
}

/// Friendly label for permission editor / meta row.
/// Shows `display (uid)` when LDAP resolves.
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

/// Compute whether ACLs are limited for a host_path (logical) by finding owning share and using the probe.
fn acl_limited_for_path(state: &AppState, host_path: &std::path::Path) -> bool {
    let mountinfo = state.fs_probe_mountinfo_path.as_deref();
    for s in &state.config.shares {
        // Use simple prefix match on the configured host_path (same space as tree paths)
        if host_path.starts_with(&s.host_path) || host_path == s.host_path.as_path() {
            return nfs_klldap_config::share_fs_acl_limited_with_mountinfo(&state.config, s, mountinfo);
        }
    }
    false
}

// Query and form parameter types for the permission tree.

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
    /// Owner field value from hx-include live search.
    #[serde(default)]
    owner_user: Option<String>,
    /// Group field value from hx-include live search.
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
    // Strings (not Option<u32>): dir-editor always posts hidden fields. Empty.
    #[serde(default)]
    owner_user_uid: String,
    #[serde(default)]
    owner_group_gid: String,
}

#[derive(Deserialize)]
pub(crate) struct AclListParams {
    path: String,
}

#[derive(Deserialize)]
pub(crate) struct AclApplyForm {
    path: String,
    // "add" | "edit" | "delete"
    #[serde(default)]
    op: String,
    // "user" | "group"
    #[serde(default)]
    typ: String,
    // numeric id for the principal
    #[serde(default)]
    id: String,
    // perms string like "r-x" or "rwx" or "7"
    #[serde(default)]
    perms: String,
    // for delete: comma sep "u:1234,g:5678" or similar; id used for single too
    #[serde(default)]
    selected: String,
}

// HTTP handlers for the permission tree routes.

pub(crate) async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    // Build display-oriented share cards. Centralizes is - Client NFS path.
    let server = &state.keytab_hostname;
    let display_shares: Vec<ShareInfo> = state
        .config
        .shares
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            let pseudo = s
                .export_path
                .as_deref()
                .map(|p| {
                    if p.starts_with('/') {
                        p.to_string()
                    } else {
                        format!("/{}", p)
                    }
                })
                .unwrap_or_else(|| format!("/{}", s.name));
            let nfs_path = format!("{}:{}", server, pseudo);

            let access = if s.rw.unwrap_or(true) {
                "RW".to_string()
            } else {
                "RO".to_string()
            };

            let root_squash = s.squash.as_deref() == Some("root_squash");
            let squash_label = if root_squash {
                "root_squash".to_string()
            } else {
                "no_root_squash".to_string()
            };

            let cache_profile = s
                .cache_profile
                .clone()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "Default".to_string())
                .to_lowercase();

            let warning = nfs_klldap_config::ShareFieldWarning::for_share(
                &state.config.share_warnings,
                idx,
                &s.name,
            )
            .map(|w| w.display_message());
            let acl_limited = nfs_klldap_config::share_fs_acl_limited_with_mountinfo(
                &state.config,
                s,
                state.fs_probe_mountinfo_path.as_deref(),
            );

            ShareInfo {
                name: s.name.clone(),
                nfs_path,
                host_path: s.host_path.display().to_string(),
                access,
                squash_label,
                cache_profile,
                warning,
                acl_limited,
            }
        })
        .collect();

    let tpl = IndexTemplate {
        shares: display_shares,
        current_user: Some(user.0),
        keytab_alert: state.keytab_alert.lock().unwrap().clone(),
        host_nfs_mode: state.host_nfs_mode,
    };

    Ok(Html(tpl.render().unwrap()))
}

/// Lazy-loads children of a directory (HTMX partial).
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

    // Return diagnostic HTML when tree build fails (bind mount / path.
    let safe_path = params
        .path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let msg = format!(
        r#"<div class="alert alert-danger" style="padding:0.5em;">
            <strong>Cannot display directory tree.</strong><br>
            <code>{}</code> is allowed by your config but is not visible inside the container
            (check bind mounts / <code>storage.container_root</code> + share <code>host_path</code> (first dir component is the implicit bind root) + <code>export_path</code> (for Pseudo) and the startup diagnostics
            for the suggested <code>-v HOST:CONTAINER</code> line; single (or multiple) root parent bind(s) recommended for independent export names).
        </div>"#,
        safe_path
    );
    Ok(Html(msg))
}

/// Lazy-load one directory level for HTMX tree expansion.
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

// Handlers for inline tree metadata and the editor.

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
        ("(unavailable)".into(), "(unavailable)".into(), format!("<span style=\"color:var(--danger-text)\">{}</span>", safe))
    };

    let acl_limited = acl_limited_for_path(&state, std::path::Path::new(&path));
    let tpl = DirMetaTemplate {
        path: path.clone(),
        owner_display,
        group_display,
        mode_octal,
        acl_limited,
    };

    Ok(Html(tpl.render().unwrap()))
}

// ACL list fragment: returns compact Users + Groups boxes (named ACL entries only).
// Lists populated by resolving via LLDAP (reuse of friendly label + list code paths).
pub(crate) async fn acl_list(
    State(state): State<AppState>,
    Query(params): Query<AclListParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    let path = params.path;
    let entries = state
        .fs
        .get_dir_acl(std::path::Path::new(&path))
        .unwrap_or_default();

    let l = state.lldap.lock().await;

    let mut users = String::new();
    let mut groups = String::new();
    for e in entries {
        let (label, id_str, is_u) = match e.kind {
            crate::privileged::AclEntryKind::User(uid) => {
                let lab = friendly_user_label(&l, uid).await;
                (lab, uid.to_string(), true)
            }
            crate::privileged::AclEntryKind::Group(gid) => {
                let lab = friendly_group_label(&l, gid).await;
                (lab, gid.to_string(), false)
            }
        };
        let p = e.perms.to_str();
        let safe_label = label.replace('&', "&amp;").replace('<', "&lt;");
        let row = format!(
            r#"<div class="acl-item" data-id="{}" data-perms="{}" title="{} {} (click in edit modes to select)">{} <code style="font-size:0.95em">{}</code></div>"#,
            id_str, p,
            if is_u { "user" } else { "group" }, id_str,
            safe_label, p
        );
        if is_u {
            users.push_str(&row);
        } else {
            groups.push_str(&row);
        }
    }
    if users.is_empty() {
        users = r#"<em style="color:var(--text-light);font-size:0.9em;">(none)</em>"#.to_string();
    }
    if groups.is_empty() {
        groups = r#"<em style="color:var(--text-light);font-size:0.9em;">(none)</em>"#.to_string();
    }

    let acl_limited = acl_limited_for_path(&state, std::path::Path::new(&path));
    let tpl = AclFragmentTemplate {
        path,
        users_list: users,
        groups_list: groups,
        acl_limited,
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

// Live LDAP search handlers for the permission editor.

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

// Core handler that applies permission changes.

pub(crate) async fn apply_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ApplyForm>,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    // Reads hidden uid/gid fields first as the numeric bypass for the editor.
    let mut owner_uid: u32 = 0;
    let mut group_gid: u32 = 0;
    let mut needs_lock = false;

    // Hidden fields arrive as strings (may be "", "0" or a valid number.
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
                        r#"<div class="alert alert-danger" style="font-size:0.85em; padding:4px;">
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
                        r#"<div class="alert alert-danger" style="font-size:0.85em; padding:4px;">
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

    // Build command string (used for immediate log and final result text).
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

    // Always run apply asynchronously so the Apply Log can show progress.
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
        // Count-as-you-go phase gives immediate visible feedback ("scanned N.
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
                // Still attempt cache invalidate (no-op) and exit task early.
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

        // Existing background cache invalidation (moved inside the task).
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

    // Immediate response: placeholder keeps the dir-meta target. JS.
    let placeholder = format!(
        r#"<div class="dir-meta-inner" data-path="{}" data-applying="1">
    <span style="color:var(--warning-text);">⏳ Applying permissions — see Apply Log for progress. Tree navigation locked until complete.</span>
</div>"#,
        form.path
    );

    // Renders initial status HTML that polls replace with live scan progress.
    let status_html = render_apply_status_oob(&cmd, "Stand-by, estimating total... (live updates below)", true);

    Ok(Html(format!("{}\n{}", placeholder, status_html)))
}

/// Renders oob-swappable apply-status and toggles Cancel when active.
fn render_apply_status_oob(cmd: &str, result_or_live: &str, active_cancel: bool) -> String {
    let cancel_btn = if active_cancel {
        r#"<button type="button" onclick="if (window.cancelCurrentApply) window.cancelCurrentApply();" class="btn" style="font-size:0.72em; padding:2px 8px; border:1px solid var(--danger-border); color:var(--danger-text); background:var(--danger-bg); border-radius:2px; cursor:pointer;">Cancel Apply</button>"#
    } else {
        r#"<button type="button" disabled class="btn" style="font-size:0.72em; padding:2px 8px; border:1px solid var(--border); color:var(--text-light); opacity:0.6; border-radius:2px;">Cancel Apply</button>"#
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
                // Still estimating (count-as-you-go phase).
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
            // Neutral / last-known state when no apply slot is active.
            r#"<div id="apply-status" hx-swap-oob="true" class="apply-status" style="display:block;">
    <div style="display:flex; align-items:center; justify-content:space-between; font-size:0.85em; font-weight:600; margin-bottom:4px; color:var(--text-muted);">
      <span>Apply Log</span>
      <button type="button" disabled class="btn" style="font-size:0.72em; padding:2px 8px; border:1px solid var(--border); color:var(--text-light); opacity:0.6; border-radius:2px;">Cancel Apply</button>
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
    Ok(Html(r#"<span style="font-size:0.7em; color:var(--danger-text);">Cancel requested.</span>"#.to_string()))
}

// ACL apply handler. Performs real on-disk named ACL change via FsManager (distinct path from POSIX).
// Builds synthetic "setfacl ..." cmd for the Apply Log (lower right). Fast op, uses progress slot for oob updates.
// Feedback returned to caller; JS refreshes the ACL list and clears mode. Reuses search machinery indirectly via prior add UI.
pub(crate) async fn acl_apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AclApplyForm>,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;

    let _p = std::path::Path::new(&form.path);
    let op = form.op.trim().to_lowercase();
    let typ = form.typ.trim().to_lowercase();
    let is_user = typ == "user" || typ == "u";

    // Parse id
    let id: u32 = form.id.trim().parse().or_else(|_| {
        // fallback from selected if single
        if let Some(first) = form.selected.split(',').next() {
            if let Some(num) = first.split(':').last() {
                return num.trim().parse();
            }
        }
        Ok(0u32)
    }).unwrap_or(0);

    if id == 0 && op != "delete" {
        let fb = format!(r#"<div style="color:var(--danger-text);font-size:0.7em;">Invalid principal id</div>"#);
        return Ok(Html(format!("{}\n{}", fb, render_apply_status_oob("acl: invalid id", "error", false))));
    }

    let kind = if is_user {
        crate::privileged::AclEntryKind::User(id)
    } else {
        crate::privileged::AclEntryKind::Group(id)
    };

    // Build modification + cmd string for log
    let (modification, cmd) = if op == "add" || op == "edit" || op == "set" {
        let pstr = if form.perms.trim().is_empty() { "r--".to_string() } else { form.perms.trim().to_string() };
        let perms = crate::privileged::AclPerms::from_str(&pstr);
        let c = format!("setfacl -m {}:{}:{} {}", if is_user {"u"} else {"g"}, id, perms.to_str(), form.path);
        (crate::privileged::AclModification::Set { kind, perms }, c)
    } else if op == "delete" || op == "del" {
        // support multi via selected or single id
        let mut ks: Vec<crate::privileged::AclEntryKind> = vec![];
        if !form.selected.trim().is_empty() {
            for tok in form.selected.split(',') {
                let t = tok.trim();
                if t.is_empty() { continue; }
                let num: u32 = t.split(':').last().unwrap_or("0").trim().parse().unwrap_or(0);
                if num > 0 {
                    if t.starts_with('g') || t.starts_with("group") {
                        ks.push(crate::privileged::AclEntryKind::Group(num));
                    } else {
                        ks.push(crate::privileged::AclEntryKind::User(num));
                    }
                }
            }
        }
        if ks.is_empty() && id > 0 {
            ks.push(kind);
        }
        let c = if ks.is_empty() {
            format!("setfacl -x (no-op) {}", form.path)
        } else {
            let specs: Vec<String> = ks.iter().map(|k| match k {
                crate::privileged::AclEntryKind::User(u) => format!("u:{}", u),
                crate::privileged::AclEntryKind::Group(g) => format!("g:{}", g),
            }).collect();
            format!("setfacl -x {} {}", specs.join(","), form.path)
        };
        (crate::privileged::AclModification::Remove { kinds: ks }, c)
    } else {
        let fb = r#"<div style="color:var(--danger-text);font-size:0.7em;">Unknown ACL op</div>"#.to_string();
        return Ok(Html(format!("{}\n{}", fb, render_apply_status_oob("acl: bad op", "error", false))));
    };

    // Drive Apply Log like POSIX path (reuse slot + oob render)
    let progress = Arc::new(ApplyProgress::default());
    {
        let mut slot = state.apply_progress.lock().await;
        *slot = Some(progress.clone());
    }
    {
        let mut c = progress.cmd.lock().unwrap();
        *c = Some(cmd.clone());
    }
    *progress.phase.lock().unwrap() = "applying".to_string();
    progress.total.store(1, Ordering::Relaxed);
    progress.processed.store(0, Ordering::Relaxed);

    let fs = state.fs.clone();
    let pth = form.path.clone();
    let prog = progress.clone();
    let modf = modification;
    let op_for_log = op.clone();

    tokio::spawn(async move {
        prog.processed.store(1, Ordering::Relaxed);
        let res = fs.apply_acl_mod(std::path::Path::new(&pth), modf);
        let (ok, msg) = match res {
            Ok(m) => (true, m),
            Err(e) => (false, e),
        };

        let rtext = if ok {
            format!("ACL {} OK: {}", op_for_log, msg)
        } else {
            format!("ACL {} failed: {}", op_for_log, msg)
        };
        if !ok {
            prog.error_count.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut errs) = prog.recent_errors.lock() {
                errs.push((PathBuf::from(&pth), msg.clone()));
            }
        }
        prog.changed.fetch_add(1, Ordering::Relaxed);
        {
            let mut ft = prog.final_result_text.lock().expect("progress mutex poisoned");
            *ft = Some(rtext);
        }
        prog.finished.store(true, Ordering::Relaxed);
    });

    // Immediate feedback + oob for Apply Log (no long wait for ACL)
    let fb = format!(
        r#"<div style="font-size:0.72em; color:var(--success-text);">ACL {} submitted — see Apply Log.</div>"#,
        op
    );
    let oob = render_apply_status_oob(&cmd, "Stand-by (ACL op)...", true);

    Ok(Html(format!("{}\n{}", fb, oob)))
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
