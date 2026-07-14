//! Axum router + AppState; handlers in auth/permission_tree/settings/setup.

use axum::{
    body::Body,
    extract::State,
    http::{
        header::{CACHE_CONTROL, CONTENT_TYPE},
        HeaderMap, Request, Response,
    },
    middleware::{self, Next},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;
use tower_http::normalize_path::NormalizePathLayer;

use crate::{auth::AuthManager, config::Config, fs::FsManager};

pub mod acl_capability;
pub(crate) mod acl_status;
pub mod acl_watch;
mod auth;
mod manifest;
mod permission_tree;
mod settings_form;
mod settings;
pub mod setup;

// Pub(crate) re-exports for router assembly and in-module integration tests.
pub(crate) use auth::{login, login_page, logout, require_auth, setup_password};
pub(crate) use permission_tree::{
    acl_apply, apply_permissions, apply_progress, cancel_apply, dir_perms, index,
    search_groups, search_users, tree_fragment,
};
pub(crate) use settings::{
    clear_ldap_cache, lldap_status, reload_nfs_client, restart_status, settings_page,
    settings_save_raw, settings_save_structured, settings_save_shares,
    settings_test_bind, settings_test_ldap, share_card_blank, system_restart,
};

/// Shared state for all handlers.
#[derive(Clone)]
pub struct AppState {
    pub fs: Arc<RwLock<FsManager>>,
    pub lldap: Arc<Mutex<crate::ldap::LdapClient>>,
    pub config: Arc<RwLock<Config>>,
    pub auth: Arc<AuthManager>,
    pub config_path: PathBuf,
    pub keytab_hostname: String,
    pub keytab_realm: String,
    /// Shows a display-only keytab mismatch banner when the invariant fails.
    pub keytab_alert: Arc<StdMutex<Option<String>>>,
    /// Tracks in-flight apply state for /apply-progress and cancel_apply.
    pub apply_progress: Arc<Mutex<Option<Arc<crate::fs::ApplyProgress>>>>,
    /// Latches after the first restart POST to prevent duplicate HUP signals.
    pub restart_requested: Arc<Mutex<bool>>,
    /// Returns true when the WebUI terminates TLS internally.
    pub direct_tls: bool,
    /// Overrides the setup marker path during tests only.
    pub setup_marker_override: Option<PathBuf>,
    /// Stores last wizard test inputs until the user clicks continue.
    pub setup_test: Arc<StdMutex<setup::SetupTestState>>,
    /// Enables HOST_NFS mode where the sidecar writes Ganesha fragments.
    pub host_nfs_mode: bool,
    /// Points at a mountinfo fixture that drives fs_warning badges in tests.
    pub fs_probe_mountinfo_path: Option<PathBuf>,
    /// Per-mount ACL write-probe verdict cache, shared by every UI surface.
    pub acl_caps: Arc<acl_capability::AclCapabilityCache>,
    /// Persistent banner set by the ACL re-probe loop when an explicit-ACL
    /// share lands on a filesystem that can no longer store ACLs.
    pub acl_alert: Arc<StdMutex<Option<String>>>,
}

impl AppState {
    /// Returns true for direct TLS or X-Forwarded-Proto https (cookie Secure).
    pub fn is_https(&self, headers: &HeaderMap) -> bool {
        self.direct_tls
            || headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.eq_ignore_ascii_case("https"))
    }

    /// Snapshot of keytab display fields for settings/permission templates.
    pub fn keytab_display(&self) -> KeytabDisplayContext {
        KeytabDisplayContext {
            hostname: self.keytab_hostname.clone(),
            realm: self.keytab_realm.clone(),
            alert: self.keytab_alert.lock().unwrap().clone(),
        }
    }

    /// Re-read nfs-klldap.conf and rebuild the in-memory FsManager (share paths / allow-list).
    pub fn reload_config_and_fs(&self) -> Result<(), String> {
        let cfg = crate::config::load_config_from(&self.config_path)?;
        let fs = FsManager::new(cfg.clone());
        *self
            .config
            .write()
            .map_err(|e| format!("config lock poisoned: {e}"))? = cfg;
        *self
            .fs
            .write()
            .map_err(|e| format!("fs lock poisoned: {e}"))? = fs;
        // Share paths may now sit on different mounts; drop stale verdicts.
        self.acl_caps.invalidate_all();
        Ok(())
    }
}

/// Keytab hostname/realm/alert bundle passed into settings templates.
#[derive(Clone, Debug)]
pub struct KeytabDisplayContext {
    pub hostname: String,
    pub realm: String,
    pub alert: Option<String>,
}

/// Serves the vendored htmx build so the UI needs no CDN/internet access.
async fn htmx_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "application/javascript"),
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        include_str!("../../assets/htmx-1.9.12.min.js"),
    )
}

/// Serves the Share Permissions app script (compiled in like the templates).
/// Unversioned filename, so no immutable caching — a redeploy must always win.
async fn permissions_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "application/javascript"),
            (CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../../assets/permissions.js"),
    )
}

/// Serves the shared stylesheet (compiled in like the templates).
/// Unversioned filename with a short public cache: repeat page loads skip
/// the ~25KB payload while a redeploy wins within the hour. When a deploy
/// pairs HTML structure changes with CSS, bump the `?v=` query on the
/// base.html link instead — the route matches the path only.
async fn style_css() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css"),
            (CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../../assets/style.css"),
    )
}

/// Redirect to the setup wizard when first-run steps are incomplete.
async fn require_setup_complete(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let path = req.uri().path();
    if path.starts_with("/setup")
        || path.starts_with("/assets/")
        || path == "/login"
        || path == "/setup-password"
        || path == "/restart-status"
        || path == "/logout"
        // Machine endpoint: clients need JSON even pre-setup (it then reports
        // the empty share set), never a wizard redirect.
        || path == "/client-manifest.json"
    {
        return next.run(req).await;
    }
    if setup::setup_wizard_required_with_marker(
        &state.config_path,
        state.setup_marker_override.as_deref(),
    ) {
        let target = setup::setup_redirect_for_step(&state.config_path);
        return Redirect::to(&target).into_response();
    }
    next.run(req).await
}

pub fn router(state: AppState) -> Router {
    let setup_gate_state = state.clone();
    let app = Router::new()
        // Public routes that do not require authentication.
        .route("/assets/htmx-1.9.12.min.js", get(htmx_js))
        .route("/assets/permissions.js", get(permissions_js))
        .route("/assets/style.css", get(style_css))
        .route("/login", get(login_page).post(login))
        .route("/setup-password", post(setup_password))
        .route("/logout", get(logout).post(logout))
        // Public status for the post-restart poller (no auth required).
        .route("/restart-status", get(restart_status))
        // Public per-share ACL/Non-ACL manifest for the client setup script
        // (clients cannot detect the class over NFSv4; the host declares it).
        .route("/client-manifest.json", get(manifest::client_manifest))
        // Public first-run setup wizard (replaces the old terminal TUI).
        .route("/setup", get(setup::setup_redirect))
        .route("/setup/1", get(setup::setup_step1))
        .route("/setup/1/verify", post(setup::setup_step1_verify))
        .route("/setup/2", get(setup::setup_step2))
        .route("/setup/2/test", post(setup::setup_step2_test))
        .route("/setup/2/continue", post(setup::setup_step2_continue))
        .route("/setup/3", get(setup::setup_step3))
        .route("/setup/3/test", post(setup::setup_step3_test))
        .route("/setup/3/status", get(setup::setup_step3_status))
        .route("/setup/3/continue", post(setup::setup_step3_continue))

        // The === protected is Main permission tree UI (/) ===.
        .route("/", get(index))
        .route("/tree", get(tree_fragment))
        // Lazy-loading (1-level only, cheap) for tree expands.
        // Detached Permissions panel body (POSIX + named ACL), replaces dir-meta/dir-editor/dir-acl.
        .route("/dir-perms", get(dir_perms))
        .route("/users/search", get(search_users))
        .route("/groups/search", get(search_groups))
        .route("/apply", post(apply_permissions))
        .route("/apply-progress", get(apply_progress))
        .route("/cancel-apply", post(cancel_apply))
        // ACL apply (reuses search + Apply Log; distinct from POSIX apply).
        .route("/acl-apply", post(acl_apply))

        // The === protected is System Settings + LLDAP client management ===.
        .route("/settings", get(settings_page))
        .route("/settings/share-card", get(share_card_blank))
        .route("/settings/save-raw", post(settings_save_raw))
        .route("/settings/save", post(settings_save_structured))
        .route("/settings/save-shares", post(settings_save_shares))
        .route("/settings/lldap-status", get(lldap_status))
        .route("/settings/reload-nfs-client", post(reload_nfs_client))
        .route("/settings/clear-ldap-cache", post(clear_ldap_cache))
        .route("/settings/restart", post(system_restart))
        .route("/settings/test-ldap", post(settings_test_ldap))
        .route("/settings/test-bind", post(settings_test_bind))

        .with_state(state);

    app.layer(middleware::from_fn_with_state(
        setup_gate_state,
        require_setup_complete,
    ))
    .layer(NormalizePathLayer::trim_trailing_slash())
}



// Integration tests (auth flows, settings, apply, cookie policy).
#[cfg(test)]
mod tests;
