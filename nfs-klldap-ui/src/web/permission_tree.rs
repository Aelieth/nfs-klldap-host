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

type Ldap = crate::ldap::LdapClient;
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
    /// True when the share actually serves ACLs (operator opted in via enable_acl AND the
    /// serve-path filesystem can honor them). Drives the share-card status dot.
    pub acl_capable: bool,
}

/// Panel body for the detached Permissions view (POSIX matrix + ACL/xattr), served by /dir-perms.
#[derive(Template)]
#[template(path = "dir_perms.html")]
pub(crate) struct DirPermsTemplate {
    path: String,
    owner_display: String,
    group_display: String,
    owner_uid_hidden: String,
    owner_gid_hidden: String,
    mode_octal: String,
    u_r: bool, u_w: bool, u_x: bool,
    g_r: bool, g_w: bool, g_x: bool,
    o_r: bool, o_w: bool, o_x: bool,
    setgid: bool, sticky: bool,
    /// False when the directory could not be stat'd; the template shows a full-width diagnostic
    /// (meta_hint + the paths below) instead of the POSIX/ACL editors.
    meta_available: bool,
    meta_hint: String,
    /// Serve (container) path shown in the diagnostic; empty when it could not be resolved.
    serve_path_display: String,
    acl_supported: bool,
    acl_reason: String,
    users: Vec<AclEntryView>,
    groups: Vec<AclEntryView>,
}

/// One named ACL row for the panel (friendly name already LDAP-resolved).
#[derive(Clone)]
pub(crate) struct AclEntryView {
    name: String,
    id: u32,
    r: bool,
    w: bool,
    x: bool,
}
/// Friendly label for permission editor / meta row.
/// Shows `display (uid)` when LDAP resolves.
async fn friendly_user_label(lldap: &Ldap, uid: u32) -> String {
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
async fn friendly_group_label(lldap: &Ldap, gid: u32) -> String {
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
/// Bare friendly name (no trailing "(id)") for ACL rows; falls back to the numeric id.
async fn friendly_user_name(lldap: &Ldap, uid: u32) -> String {
    if let Some((id, display)) = lldap.resolve_user_by_uid(uid as i32).await {
        if !display.is_empty() && display != id { display } else { id }
    } else {
        uid.to_string()
    }
}
async fn friendly_group_name(lldap: &Ldap, gid: u32) -> String {
    if let Some((id, display)) = lldap.resolve_group_by_gid(gid as i32).await {
        if !display.is_empty() && display != id { display } else { id }
    } else {
        gid.to_string()
    }
}
/// (acl_supported, reason) for a host_path. ACLs are supported only when the owning share opted in
/// (enable_acl = true) AND its serve-path filesystem can honor them; otherwise a reason explains the
/// limited case (including enable_acl=true on a filesystem that cannot support it → treated Non-ACL).
/// Prefers the most specific (longest host_path) matching share so nested shares stay independent.
fn acl_capability_for_path(state: &AppState, host_path: &std::path::Path) -> (bool, String) {
    let cfg = state.config.read().expect("config lock poisoned");
    let mountinfo = state.fs_probe_mountinfo_path.as_deref();
    let best = cfg
        .shares
        .iter()
        .filter(|s| host_path.starts_with(&s.host_path) || host_path == s.host_path.as_path())
        .max_by_key(|s| s.host_path.as_os_str().len());

    let Some(s) = best else {
        return (false, "Path is not under a configured share.".to_string());
    };
    let fs_limited = nfs_klldap_config::share_fs_acl_limited_with_mountinfo(&cfg, s, mountinfo);
    let warn = nfs_klldap_config::share_fs_warning_message_with_mountinfo(&cfg, s, mountinfo)
        .unwrap_or_default();
    acl_capability_decision(s.enable_acl, fs_limited, &warn)
}
/// Pure ACL-support decision: supported only when opted-in AND fs-capable; the reason
/// distinguishes explicit enable_acl=false, the NOACL default (unset), and enabled-but-limited-FS.
fn acl_capability_decision(enable_acl: Option<bool>, fs_limited: bool, warn: &str) -> (bool, String) {
    let with_warn = |mut msg: String| {
        if fs_limited && !warn.is_empty() {
            msg.push(' ');
            msg.push_str(warn);
        }
        (false, msg)
    };
    match (enable_acl, fs_limited) {
        (Some(true), false) => (true, String::new()),
        (Some(true), true) => (
            false,
            format!("enable_acl = true, but the serve-path filesystem is not ACL-capable — treated as Non-ACL. {}", warn),
        ),
        (Some(false), _) => with_warn(
            "This share is exported without ACL support (enable_acl = false); ACL entries here are not honored by the NFS export.".to_string(),
        ),
        (None, _) => with_warn(
            "This share uses the NOACL default (ACL not opted in); ACL entries here are not honored by the NFS export.".to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct TreeParams {
    path: String,
    #[serde(default)]
    root: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DirPermsQuery {
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
    #[serde(default)]
    owner_user_uid: String,
    #[serde(default)]
    owner_group_gid: String,
}
#[derive(Deserialize)]
pub(crate) struct AclApplyForm {
    path: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    typ: String,
    #[serde(default)]
    id: String,
    /// Optional principal name (or "name (id)") to resolve via LDAP when a numeric id is absent.
    #[serde(default)]
    name: String,
    #[serde(default)]
    perms: String,
    #[serde(default)]
    selected: String,
}

pub(crate) async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;
    let server = &state.keytab_hostname;
    let cfg = state.config.read().expect("config lock poisoned");
    let display_shares: Vec<ShareInfo> = cfg
        .shares
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            let pseudo = s
                .pseudo_path
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
                &cfg.share_warnings,
                idx,
                &s.name,
            )
            .map(|w| w.display_message());
            let fs_limited = nfs_klldap_config::share_fs_acl_limited_with_mountinfo(
                &cfg,
                s,
                state.fs_probe_mountinfo_path.as_deref(),
            );
            // ACL-capable only when the operator opted in AND the serve-path FS can honor ACLs.
            let acl_capable = s.enable_acl == Some(true) && !fs_limited;
            ShareInfo {
                name: s.name.clone(),
                nfs_path,
                host_path: s.host_path.display().to_string(),
                access,
                squash_label,
                cache_profile,
                warning,
                acl_capable,
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
    let fs = state.fs.read().expect("fs lock poisoned");
    if let Some(node) = fs.build_tree(path) {
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

    let diag = fs.diagnose_path(path);
    drop(fs);
    let safe_path = params
        .path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let mapped = diag
        .container_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(mapping failed)".into());
    let safe_mapped = mapped
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let hint: String = if !diag.allowed {
        "Path is outside configured share <code>host_path</code> roots.".to_string()
    } else if diag.container_path.is_none() {
        "Could not map this <code>host_path</code> to a container serve path.".to_string()
    } else if !diag.container_exists {
        format!(
            "Mapped container path <code>{safe_mapped}</code> does not exist (configured serve path <code>{}</code>). \
             Set <code>container_path</code> to the real directory under <code>storage.container_root</code> and ensure the volume is mounted.",
            diag.serve_path.replace('<', "&lt;"),
        )
    } else {
        "Directory exists but could not be read (permissions?).".to_string()
    };
    let msg = format!(
        r#"<div class="alert alert-danger" style="padding:0.5em;">
            <strong>Cannot display directory tree.</strong><br>
            Logical path: <code>{safe_path}</code><br>
            {hint}
        </div>"#
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
    let fs = state.fs.read().expect("fs lock poisoned");
    let children: Vec<DirNode> = fs
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

// GET /dir-perms?path=... — panel body: POSIX (owner/group + rwx matrix + setgid/sticky) and the
// named ACL list, both LDAP-resolved. Replaces the retired /dir-meta + /dir-editor + /dir-acl trio.
pub(crate) async fn dir_perms(
    State(state): State<AppState>,
    Query(q): Query<DirPermsQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    let path = q.path;
    let host = std::path::Path::new(&path);
    let (meta, diag) = {
        let fs = state.fs.read().expect("fs lock poisoned");
        (fs.get_dir_meta(host), fs.diagnose_path(host))
    };

    let mut owner_display = "(unavailable)".to_string();
    let mut group_display = "(unavailable)".to_string();
    let mut owner_uid_hidden = String::new();
    let mut owner_gid_hidden = String::new();
    let mut mode_octal = "0755".to_string();
    let (mut u_r, mut u_w, mut u_x) = (false, false, false);
    let (mut g_r, mut g_w, mut g_x) = (false, false, false);
    let (mut o_r, mut o_w, mut o_x) = (false, false, false);
    let (mut setgid, mut sticky) = (false, false);
    let mut meta_available = false;
    let mut meta_hint = String::new();

    if let Some((owner, group, mode)) = meta {
        let l = state.lldap.lock().await;
        owner_display = friendly_user_label(&l, owner).await;
        group_display = friendly_group_label(&l, group).await;
        drop(l);
        owner_uid_hidden = if owner > 0 { owner.to_string() } else { String::new() };
        owner_gid_hidden = if group > 0 { group.to_string() } else { String::new() };
        mode_octal = format!("{:04o}", mode & 0o7777);
        u_r = mode & 0o400 != 0; u_w = mode & 0o200 != 0; u_x = mode & 0o100 != 0;
        g_r = mode & 0o040 != 0; g_w = mode & 0o020 != 0; g_x = mode & 0o010 != 0;
        o_r = mode & 0o004 != 0; o_w = mode & 0o002 != 0; o_x = mode & 0o001 != 0;
        setgid = mode & 0o2000 != 0; sticky = mode & 0o1000 != 0;
        meta_available = true;
    } else {
        // Askama escapes {{ meta_hint }}, so keep it plain text (no manual HTML escaping).
        // Cover the distinct failure modes so the message names a cause and a fix; the paths
        // themselves are shown separately (host path + serve path) by the template.
        meta_hint = if !diag.allowed {
            "This directory is outside the managed share roots, so its permissions can't be read here.".to_string()
        } else if diag.container_path.is_none() {
            "This host path couldn't be mapped to a serve path. Check the share's host_path and container_path in System Settings.".to_string()
        } else if !diag.container_exists {
            "The serve path below doesn't exist. Create it, or set the share's container_path to the directory where this share is bind-mounted.".to_string()
        } else {
            "The serve path below exists, but its ownership and mode couldn't be read — the WebUI may lack permission to stat it.".to_string()
        };
    }

    let (acl_supported, acl_reason) = acl_capability_for_path(&state, host);

    // Named ACL entries are always listed (resolved to friendly names); the section greys when unsupported.
    let entries = {
        let fs = state.fs.read().expect("fs lock poisoned");
        fs.get_dir_acl(host).unwrap_or_default()
    };
    let mut users: Vec<AclEntryView> = Vec::new();
    let mut groups: Vec<AclEntryView> = Vec::new();
    {
        let l = state.lldap.lock().await;
        for e in entries {
            match e.kind {
                crate::privileged::AclEntryKind::User(uid) => users.push(AclEntryView {
                    name: friendly_user_name(&l, uid).await, id: uid, r: e.perms.r, w: e.perms.w, x: e.perms.x,
                }),
                crate::privileged::AclEntryKind::Group(gid) => groups.push(AclEntryView {
                    name: friendly_group_name(&l, gid).await, id: gid, r: e.perms.r, w: e.perms.w, x: e.perms.x,
                }),
            }
        }
    }

    let tpl = DirPermsTemplate {
        path,
        owner_display,
        group_display,
        owner_uid_hidden,
        owner_gid_hidden,
        mode_octal,
        u_r, u_w, u_x, g_r, g_w, g_x, o_r, o_w, o_x,
        setgid, sticky,
        meta_available,
        meta_hint,
        serve_path_display: diag
            .container_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| diag.serve_path.clone()),
        acl_supported,
        acl_reason,
        users,
        groups,
    };
    Ok(Html(tpl.render().unwrap()))
}
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

pub(crate) async fn apply_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ApplyForm>,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    let mut owner_uid: u32 = 0;
    let mut group_gid: u32 = 0;
    let mut needs_lock = false;
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
                            <button type="button" hx-get="/dir-perms?path={}" hx-target=".perm-body" hx-swap="innerHTML">Retry</button>
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
                            <button type="button" hx-get="/dir-perms?path={}" hx-target=".perm-body" hx-swap="innerHTML">Retry</button>
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
    let progress = Arc::new(ApplyProgress::default());
    {
        let mut slot = state.apply_progress.lock().await;
        *slot = Some(progress.clone());
    }
    {
        let mut c = progress.cmd.lock().unwrap();
        *c = Some(cmd.clone());
    }
    let fs = state.fs.read().expect("fs lock poisoned").clone();
    let pth = form.path.clone();
    let uid = owner_uid;
    let gid = group_gid;
    let md = mode;
    let rec = form.recursive;
    let prog = progress.clone();
    tokio::spawn(async move {
        *prog.phase.lock().unwrap() = "scanning".to_string();
        let pth1 = pth.clone();
        let fs1 = fs.clone();
        let prog1 = prog.clone();
        let count_res = tokio::task::spawn_blocking(move || {
            fs1.count_applicable_with_live(std::path::Path::new(&pth1), rec, &prog1)
        }).await;
        match count_res {
            Ok(Ok(_)) | Ok(Err(_)) => { /* count fn itself pushes errors to progress on problems */ }
            Err(_) => {
                prog.finished.store(true, Ordering::Relaxed);
                return;
            }
        }
        let total = prog.processed.load(Ordering::Relaxed);
        prog.total.store(total, Ordering::Relaxed);
        prog.processed.store(0, Ordering::Relaxed);
        *prog.phase.lock().unwrap() = "applying".to_string();

        let pth2 = pth.clone();
        let fs2 = fs.clone();
        let prog2 = prog.clone();
        let apply_res = match tokio::task::spawn_blocking(move || {
            fs2.apply_permissions_with_progress(
                std::path::Path::new(&pth2), uid, gid, md, rec, &prog2,
            )
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                prog.error_count.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut errs) = prog.recent_errors.lock() {
                    errs.push((PathBuf::from(&pth), e.clone()));
                }
                let err_text = format!("Apply error during walk: {}", e);
                *prog.final_result_text.lock().expect("progress mutex poisoned") = Some(err_text);
                prog.finished.store(true, Ordering::Relaxed);
                {
                    let fs3 = fs.clone();
                    let p3 = pth.clone();
                    tokio::spawn(async move {
                        fs3.invalidate_path(std::path::Path::new(&p3));
                    });
                }
                return;
            }
            Err(_e) => {
                prog.finished.store(true, Ordering::Relaxed);
                return;
            }
        };
        {
            let fs_i = fs.clone();
            let p_i = pth.clone();
            tokio::spawn(async move {
                fs_i.invalidate_path(std::path::Path::new(&p_i));
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
    // Lands in #perm-panel .perm-body; the poller drives the Apply Log and, on finish, permissions.js
    // refetches /dir-perms for this data-path. data-attrs are the coordination points for the client.
    let safe_path = form.path.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let placeholder = format!(
        r#"<div class="perm-applying" data-path="{}" data-applying="1" style="padding:10px 4px;">
    <span style="color:var(--warning-amber-text);">⏳ Applying permissions — see the Apply Log below. Navigation locked until complete.</span>
</div>"#,
        safe_path
    );

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
    <div id="apply-status-content" class="apply-status-content apply-log-content"
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
            r#"<div id="apply-status" hx-swap-oob="true" class="apply-status" style="display:block;">
    <div style="display:flex; align-items:center; justify-content:space-between; font-size:0.85em; font-weight:600; margin-bottom:4px; color:var(--text-muted);">
      <span>Apply Log</span>
      <button type="button" disabled class="btn" style="font-size:0.72em; padding:2px 8px; border:1px solid var(--border); color:var(--text-light); opacity:0.6; border-radius:2px;">Cancel Apply</button>
    </div>
    <div id="apply-status-content" class="apply-status-content apply-log-content" style="font-family: ui-monospace, monospace; font-size:0.78em; background:var(--bg-alt); border:1px solid var(--border); border-radius:4px; padding:8px 10px; white-space:pre-wrap; line-height:1.35;">
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

    let mut id: u32 = form.id.trim().parse().or_else(|_| {
        if let Some(first) = form.selected.split(',').next() {
            if let Some(num) = first.split(':').next_back() {
                return num.trim().parse();
            }
        }
        Ok(0u32)
    }).unwrap_or(0);
    // No numeric id but a typed principal name: resolve it via LDAP (same name translation as POSIX).
    if id == 0 && op != "delete" && !form.name.trim().is_empty() {
        if let Some(stripped) = crate::ldap::LdapClient::normalize_editor_search_query(Some(&form.name)) {
            let lldap = state.lldap.lock().await;
            if let Ok(n) = stripped.parse::<u32>() {
                id = n;
            } else if is_user {
                if let Some((uid, _)) = lldap.resolve_user(&stripped).await { id = uid as u32; }
            } else if let Some((gid, _)) = lldap.resolve_group(&stripped).await {
                id = gid as u32;
            }
        }
    }
    if id == 0 && op != "delete" {
        let fb = r#"<div style="color:var(--danger-text);font-size:0.7em;">Could not resolve that user/group (unknown name or invalid id).</div>"#.to_string();
        return Ok(Html(format!("{}\n{}", fb, render_apply_status_oob("acl: unresolved principal", "error", false))));
    }
    let kind = if is_user {
        crate::privileged::AclEntryKind::User(id)
    } else {
        crate::privileged::AclEntryKind::Group(id)
    };

    let (modification, cmd) = if op == "add" || op == "edit" || op == "set" {
        let pstr = if form.perms.trim().is_empty() { "r--".to_string() } else { form.perms.trim().to_string() };
        let perms = crate::privileged::AclPerms::from_str(&pstr);
        let c = format!("setfacl -m {}:{}:{} {}", if is_user {"u"} else {"g"}, id, perms.to_str(), form.path);
        (crate::privileged::AclModification::Set { kind, perms }, c)
    } else if op == "delete" || op == "del" {
        let mut ks: Vec<crate::privileged::AclEntryKind> = vec![];
        if !form.selected.trim().is_empty() {
            for tok in form.selected.split(',') {
                let t = tok.trim();
                if t.is_empty() { continue; }
                let num: u32 = t.split(':').next_back().unwrap_or("0").trim().parse().unwrap_or(0);
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

    let fs = state.fs.read().expect("fs lock poisoned").clone();
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

    let fb = format!(
        r#"<div style="font-size:0.72em; color:var(--success-text);">ACL {} submitted — see Apply Log.</div>"#,
        op
    );
    let oob = render_apply_status_oob(&cmd, "Stand-by (ACL op)...", true);
    Ok(Html(format!("{}\n{}", fb, oob)))
}

#[cfg(test)]
mod acl_capability_tests {
    use super::acl_capability_decision;

    #[test]
    fn supported_only_when_enabled_and_fs_capable() {
        let (ok, reason) = acl_capability_decision(Some(true), false, "");
        assert!(ok && reason.is_empty(), "enable_acl + capable FS must be supported with no reason");
    }

    #[test]
    fn enabled_but_limited_fs_reverts_to_non_acl_with_reason() {
        let (ok, reason) = acl_capability_decision(Some(true), true, "share \"x\": vfat limited filesystem");
        assert!(!ok, "enable_acl on a limited FS must NOT be supported");
        assert!(reason.contains("treated as Non-ACL"), "must explain the fallback: {reason}");
        assert!(reason.contains("limited filesystem"), "must surface the fs warning: {reason}");
    }

    #[test]
    fn disabled_reports_enable_acl_false() {
        let (ok, reason) = acl_capability_decision(Some(false), false, "");
        assert!(!ok);
        assert!(reason.contains("enable_acl = false"), "reason must name enable_acl=false: {reason}");
    }

    #[test]
    fn unset_reports_noacl_default_not_false() {
        let (ok, reason) = acl_capability_decision(None, false, "");
        assert!(!ok);
        assert!(reason.contains("NOACL default"), "auto must not claim enable_acl=false: {reason}");
        assert!(!reason.contains("enable_acl = false"));
    }

    #[test]
    fn disabled_and_limited_appends_fs_warning() {
        let (ok, reason) = acl_capability_decision(Some(false), true, "share \"x\": ntfs limited filesystem");
        assert!(!ok);
        assert!(reason.contains("limited filesystem"), "reason must cite the FS warning: {reason}");
    }
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
