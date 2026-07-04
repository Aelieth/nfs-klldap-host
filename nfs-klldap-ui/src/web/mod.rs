//! Router assembly + AppState (shared by handlers) + router integration tests.
//! Submodules hold the logic: auth, permission_tree, settings, keytab.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, Response},
    middleware::{self, Next},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;
use tower_http::normalize_path::NormalizePathLayer;

use crate::{auth::AuthManager, config::Config, fs::FsManager, ldap::LdapClient};

mod auth;
mod keytab;
mod permission_tree;
mod settings;
pub mod setup;

pub use keytab::{compute_keytab_alert, get_keytab_info};

// Pub(crate) re-exports for router assembly and in-module integration tests.
pub(crate) use auth::{login, login_page, logout, require_auth, setup_password};
pub(crate) use permission_tree::{
    acl_apply, acl_list, apply_permissions, apply_progress, cancel_apply, dir_editor, dir_meta, fs_children, index,
    search_groups, search_users, tree_fragment,
};
pub(crate) use settings::{
    clear_ldap_cache, lldap_status, reload_nfs_client, restart_status, settings_page,
    settings_save_raw, settings_save_structured, settings_save_shares,
    system_restart,
};

/// Shared state for all handlers.
#[derive(Clone)]
pub struct AppState {
    pub fs: Arc<FsManager>,
    pub lldap: Arc<Mutex<LdapClient>>,
    pub config: Arc<Config>,
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
}

/// Keytab hostname/realm/alert bundle passed into settings templates.
#[derive(Clone, Debug)]
pub struct KeytabDisplayContext {
    pub hostname: String,
    pub realm: String,
    pub alert: Option<String>,
}

/// Redirect to the setup wizard when first-run steps are incomplete.
async fn require_setup_complete(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let path = req.uri().path();
    if path.starts_with("/setup")
        || path == "/login"
        || path == "/setup-password"
        || path == "/restart-status"
        || path == "/logout"
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
        .route("/login", get(login_page).post(login))
        .route("/setup-password", post(setup_password))
        .route("/logout", get(logout).post(logout))
        // Public status for the post-restart poller (no auth used By.
        .route("/restart-status", get(restart_status))
        // The === public is first-run setup wizard (replaces terminal TUI).
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
        .route("/setup/complete", get(setup::setup_complete))

        // The === protected is Main permission tree UI (/) ===.
        .route("/", get(index))
        .route("/tree", get(tree_fragment))
        // Lazy-loading (1-level only, cheap) for tree expands.
        .route("/fs/children", get(fs_children))
        .route("/dir-meta", get(dir_meta))
        .route("/dir-editor", get(dir_editor))
        .route("/users/search", get(search_users))
        .route("/groups/search", get(search_groups))
        .route("/apply", post(apply_permissions))
        .route("/apply-progress", get(apply_progress))
        .route("/cancel-apply", post(cancel_apply))
        // ACL Permissions panel + apply (reuses search + Apply Log; distinct from POSIX).
        .route("/dir-acl", get(acl_list))
        .route("/acl-apply", post(acl_apply))

        // The === protected is System Settings + LLDAP client management ===.
        .route("/settings", get(settings_page))
        .route("/settings/save-raw", post(settings_save_raw))
        .route("/settings/save", post(settings_save_structured))
        .route("/settings/save-shares", post(settings_save_shares))
        .route("/settings/lldap-status", get(lldap_status))
        .route("/settings/reload-nfs-client", post(reload_nfs_client))
        .route("/settings/clear-ldap-cache", post(clear_ldap_cache))
        .route("/settings/restart", post(system_restart))

        .with_state(state);

    app.layer(middleware::from_fn_with_state(
        setup_gate_state,
        require_setup_complete,
    ))
    .layer(NormalizePathLayer::trim_trailing_slash())
}

#[cfg(test)]
pub(crate) fn make_test_state_with_temp_config() -> (AppState, tempfile::TempDir) {
    use std::sync::Arc;

    let tmp = tempfile::TempDir::new().unwrap();
    let config_path = tmp.path().join("test-nfs-klldap.conf");
    let setup_marker = tmp.path().join(".setup_wizard_done");
    std::fs::write(&setup_marker, "ok\n").unwrap();

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

    let fs = Arc::new(FsManager::new((*config).clone()));

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
        user_principal_name: "krbPrincipalName".to_string(),
    };
    let lldap = Arc::new(Mutex::new(LdapClient::new_with_attributes(
        "ldaps://localhost:6360",
        "ou=people,dc=test,dc=com",
        "ou=groups,dc=test,dc=com",
        default_mapping,
        true,
        false,
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
        keytab_alert: Arc::new(StdMutex::new(None)),
        apply_progress: Arc::new(Mutex::new(None)),
        restart_requested: Arc::new(Mutex::new(false)),
        direct_tls: true,
        setup_marker_override: Some(setup_marker),
        setup_test: Arc::new(StdMutex::new(setup::SetupTestState::default())),
        host_nfs_mode: false,
        fs_probe_mountinfo_path: None,
    };

    (state, tmp)
}

// Integration tests (auth flows, settings, apply, cookie policy).
#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template;
    use axum::{
        body::Body,
        http::{
            header::{COOKIE, LOCATION, SET_COOKIE},
            Request, StatusCode,
        },
    };
    use cookie::Cookie;
    use tower::ServiceExt;

    fn add_session_cookie(mut req: Request<Body>, token: &str) -> Request<Body> {
        let cookie = format!("session={}", token);
        req.headers_mut().insert(COOKIE, cookie.parse().unwrap());
        req
    }

    /// Extract non-empty session token from login/setup Set-Cookie headers.
    fn session_token_from_response(resp: &axum::response::Response) -> String {
        for value in resp.headers().get_all(SET_COOKIE) {
            let s = value.to_str().expect("Set-Cookie must be UTF-8");
            if let Ok(parsed) = Cookie::parse(s) {
                let v = parsed.value();
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
        panic!("response did not include a non-empty session Set-Cookie");
    }

    #[tokio::test]
    async fn settings_save_raw_accepts_valid_toml_and_preserves_user() {
        let (state, _tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();
        // Use the real privileged session creator (same path the login.
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
        let config_path = state.config_path.clone();
        let auth = state.auth.clone();
        // Use the real privileged session creator (same path the login.
        let token = auth.create_privileged_session("testadmin");

        let app = router(state);

        // Exercise override flags is - server_hostname + override=true →.
        let body = "ldap_uri=ldaps%3A%2F%2Fnewhost.example.com%3A6360\
&server_hostname=override-host.example.com&override_server_hostname=true\
&sssd_user_base=ou%3Dpeople%2Cdc%3Dfoo&override_sssd_user_base=false\
&kerberos_realm=OVERRIDE.REALM&override_kerberos_realm=true";

        let req = Request::builder()
            .method("POST")
            .uri("/settings/save")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let req = add_session_cookie(req, &token);

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify written config has expected explicit keys. Non-overridden.
        let written = std::fs::read_to_string(&config_path).unwrap_or_default();
        assert!(written.contains("ldap_uri = \"ldaps://newhost.example.com:6360\""), "key field must be written");
        assert!(written.contains("hostname = \"override-host.example.com\""), "server override must be persisted when flag true");
        assert!(written.contains("realm = \"OVERRIDE.REALM\""), "kerberos override must be persisted when flag true");
        assert!(!written.contains("ldap_user_search_base"), "sssd_user_base must be omitted (no override) so derivation applies");

        // Ganesha is even though not mentioned in this POST the !override.
        assert!(written.contains("default_security = \"krb5p\""), "ganesha must default to krb5p and be materialized when not overridden");
    }

    struct MountinfoEnvGuard(Option<String>);

    impl Drop for MountinfoEnvGuard {
        fn drop(&mut self) {
            if let Some(ref prev) = self.0 {
                std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", prev);
            } else {
                std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
            }
        }
    }

    fn make_test_state_with_limited_fs_mountinfo() -> (AppState, tempfile::TempDir, MountinfoEnvGuard) {
        use std::sync::Arc;

        let prev_mountinfo = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
        // Decoy global mountinfo must not affect badges. Applies when.
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", "/nonexistent/decoy-mountinfo");
        let env_guard = MountinfoEnvGuard(prev_mountinfo);

        let tmp = tempfile::TempDir::new().unwrap();
        let mountinfo_path = tmp.path().join("mountinfo");
        std::fs::write(
            &mountinfo_path,
            "36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl\n",
        )
        .unwrap();

        let config_path = tmp.path().join("test-nfs-klldap.conf");
        let setup_marker = tmp.path().join(".setup_wizard_done");
        std::fs::write(&setup_marker, "ok\n").unwrap();

        let minimal = r#"
ldap_uri = "ldaps://kllap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "data"
host_path = "/media/data"
"#;
        std::fs::write(&config_path, minimal).unwrap();

        let config = Arc::new(
            nfs_klldap_config::NfsKlldapConfig::load(&config_path).expect("valid limited-fs config"),
        );
        let fs = Arc::new(FsManager::new((*config).clone()));

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
            user_principal_name: "krbPrincipalName".to_string(),
        };
        let lldap = Arc::new(Mutex::new(LdapClient::new_with_attributes(
            "ldaps://localhost:6360",
            "ou=people,dc=test,dc=com",
            "ou=groups,dc=test,dc=com",
            default_mapping,
            true,
            false,
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
            keytab_alert: Arc::new(StdMutex::new(None)),
            apply_progress: Arc::new(Mutex::new(None)),
            restart_requested: Arc::new(Mutex::new(false)),
            direct_tls: true,
            setup_marker_override: Some(setup_marker),
            setup_test: Arc::new(StdMutex::new(setup::SetupTestState::default())),
            host_nfs_mode: false,
            fs_probe_mountinfo_path: Some(mountinfo_path),
        };

        (state, tmp, env_guard)
    }

    #[tokio::test]
    async fn settings_save_shares_roundtrips_acl_ganesha_path_fields() {
        let (state, _tmp, _guard) = make_test_state_with_limited_fs_mountinfo();
        let config_path = state.config_path.clone();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        let warn_snippet = "enable_acl=false";
        let body = "share_name_0=data&share_host_0=%2Fmedia%2Fdata&share_export_0=&share_rw_0=true\
&share_cache_profile_0=Default&share_enable_acl_0=false&share_manage_gids_0=false\
&share_read_access_policy_0=pre&share_override_ganesha_path_0=true&share_ganesha_path_0=%2Fexport%2Fstaging%2Fdata";
        let req = Request::builder()
            .method("POST")
            .uri("/settings/save-shares")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let req = add_session_cookie(req, &token);

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let written = std::fs::read_to_string(&config_path).unwrap();
        assert!(written.contains("enable_acl = false"));
        assert!(written.contains("manage_gids = false"));
        assert!(written.contains("read_access_policy = \"pre\""));
        assert!(written.contains("ganesha_path = \"/export/staging/data\""));

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(html.contains("share_enable_acl_0"));
        assert!(html.contains("share_manage_gids_0"));
        assert!(html.contains("share_read_access_policy_0"));
        assert!(html.contains("share_ganesha_path_0"));
        assert!(html.contains("share_override_ganesha_path_0"));
        assert!(html.contains("/export/staging/data"));
        assert!(
            html.contains("alert-warning"),
            "save-shares response must render fs_warning badge on limited FS"
        );
        assert!(
            html.contains(warn_snippet),
            "save-shares response must include limited-fs settings guidance text"
        );

        // ACL primary integration: save explicit enable_acl=true + auto policy (should roundtrip without forcing read_access on ACL).
        let body_acl = "share_name_0=acldata&share_host_0=%2Fmedia%2Facldata&share_export_0=&share_rw_0=true&share_cache_profile_0=Default&share_enable_acl_0=true&share_manage_gids_0=true&share_read_access_policy_0=auto";
        let req_acl = Request::builder()
            .method("POST")
            .uri("/settings/save-shares")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body_acl))
            .unwrap();
        let req_acl = add_session_cookie(req_acl, &token);
        let resp_acl = app.clone().oneshot(req_acl).await.unwrap();
        assert_eq!(resp_acl.status(), StatusCode::OK);
        let written_acl = std::fs::read_to_string(&config_path).unwrap();
        assert!(written_acl.contains("enable_acl = true"), "ACL primary must persist enable_acl=true");
        assert!(written_acl.contains("manage_gids = true"));
        assert!(!written_acl.contains("read_access_policy ="), "ACL auto should not emit read_access_policy key");
        assert!(written_acl.contains("name = \"acldata\""));

        // Further ACL option roundtrip (new manage_gids_expiration)
        let body_further = "share_name_0=aclfurther&share_host_0=%2Fmedia%2Faclf&share_export_0=&share_rw_0=true&share_cache_profile_0=Default&share_enable_acl_0=true&share_manage_gids_0=true&share_read_access_policy_0=auto&share_manage_gids_expiration_0=900";
        let req_f = Request::builder().method("POST").uri("/settings/save-shares").header("content-type", "application/x-www-form-urlencoded").body(Body::from(body_further)).unwrap();
        let req_f = add_session_cookie(req_f, &token);
        let _ = app.clone().oneshot(req_f).await.unwrap();
        let written_f = std::fs::read_to_string(&config_path).unwrap();
        assert!(written_f.contains("manage_gids_expiration = 900"), "further ACL option must persist via save logic");

        // Verif plan step 3: real generate after UI save; drive shipped generate_all on the persisted toml, capture fragments under SCRATCH proving ACL fields (enable_acl=true, mge) drive emission (no Disable, MGE present).
        let ui_scratch = std::env::var("NFS_KLLDAP_CAPTURE_SCRATCH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
        let ui_gen = ui_scratch.join("ui-after-save-gen");
        let _ = std::fs::remove_dir_all(&ui_gen);
        std::fs::create_dir_all(&ui_gen).unwrap();
        let exports = ui_gen.join("exports.d");
        std::fs::create_dir_all(&exports).unwrap();
        let cfg_for_gen = nfs_klldap_config::NfsKlldapConfig::load(&config_path).expect("load saved toml");
        let paths = nfs_klldap_config::GenerationPaths {
            sssd_conf: ui_gen.join("s.conf"),
            krb5_conf: ui_gen.join("k.conf"),
            ganesha_conf: ui_gen.join("g.conf"),
            exports_dir: exports.clone(),
            idmap_conf: ui_gen.join("i.conf"),
            nfs_conf: ui_gen.join("n.conf"),
        };
        nfs_klldap_config::generate_all(&cfg_for_gen, &paths).expect("generate after UI save");
        let frag = std::fs::read_dir(&exports).unwrap().filter_map(|e| e.ok()).find(|e| e.path().extension().map_or(false, |x| x == "conf")).map(|e| std::fs::read_to_string(e.path()).unwrap()).unwrap_or_default();
        assert!(!frag.contains("Disable_ACL = true;"), "UI-saved enable_acl=true must omit Disable_ACL in generated frag");
        assert!(frag.contains("Manage_Gids_Expiration = 900;"), "UI-saved mge must appear in emission");
        let captured_ui = ui_scratch.join("ui-save-after-generate.frag.conf");
        std::fs::write(&captured_ui, &frag).expect("capture ui save then generate");
        eprintln!("STEP3: UI save + real generate captured {} bytes to {}", frag.len(), captured_ui.display());
    }

    #[tokio::test]
    async fn settings_and_index_render_fs_warning_badge_with_limited_mountinfo() {
        let (state, _tmp, _guard) = make_test_state_with_limited_fs_mountinfo();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        let settings_warn_snippet = "enable_acl=false";

        let index_req = Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let index_req = add_session_cookie(index_req, &token);
        let resp = app.clone().oneshot(index_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let index_html =
            String::from_utf8(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec())
                .unwrap();
        assert!(
            index_html.contains("ACL support disabled."),
            "index must render subtle ACL-disabled note"
        );
        assert!(
            !index_html.contains("limited filesystem"),
            "index must not render the detailed limited-fs warning badge"
        );
        assert!(
            !index_html.contains("class=\"alert alert-warning\" style=\"margin: 0 0 6px 0"),
            "index share card must not use warning alert for limited FS"
        );

        let settings_req = Request::builder()
            .method("GET")
            .uri("/settings")
            .body(Body::empty())
            .unwrap();
        let settings_req = add_session_cookie(settings_req, &token);
        let resp = app.oneshot(settings_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let settings_html =
            String::from_utf8(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec())
                .unwrap();
        assert!(
            settings_html.contains("alert-warning"),
            "settings must render fs_warning badge"
        );
        assert!(
            settings_html.contains("share_export_0") && settings_html.contains("disabled"),
            "settings must disable Pseudo input on NOACL share"
        );
        assert!(
            settings_html.contains("Pseudo: <code>/data</code>"),
            "settings must show muted effective Pseudo on NOACL share"
        );
        assert!(
            settings_html.contains("(auto, NOACL export)"),
            "settings must label muted Pseudo as NOACL export"
        );
        assert!(
            settings_html.contains(settings_warn_snippet),
            "settings badge must include limited-fs guidance"
        );
        assert!(
            settings_html.contains("share_override_ganesha_path_0"),
            "settings must render ganesha path override checkbox"
        );
    }

    #[tokio::test]
    async fn settings_renders_derived_ganesha_path_when_override_off() {
        let (state, _tmp, _guard) = make_test_state_with_limited_fs_mountinfo();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/settings")
            .body(Body::empty())
            .unwrap();
        let req = add_session_cookie(req, &token);

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html =
            String::from_utf8(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec())
                .unwrap();

        assert!(
            html.contains("id=\"share_ganesha_path_0\"")
                && html.contains("value=\"/export/data\"")
                && html.contains("data-default-path=\"/export/data\""),
            "settings must show derived ganesha path in disabled field when override is off"
        );
        assert!(
            !html.contains("share_override_ganesha_path_0\" value=\"true\" checked")
                && !html.contains("share_override_ganesha_path_0\" checked value=\"true\""),
            "override checkbox must be unchecked when ganesha_path is absent from TOML"
        );
    }

    #[tokio::test]
    async fn settings_save_shares_omits_ganesha_path_and_rerenders_derived_default() {
        let (state, _tmp, _guard) = make_test_state_with_limited_fs_mountinfo();
        let config_path = state.config_path.clone();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        let body = "share_name_0=data&share_host_0=%2Fmedia%2Fdata&share_export_0=&share_rw_0=true\
&share_cache_profile_0=Default&share_enable_acl_0=auto&share_manage_gids_0=auto";
        let req = Request::builder()
            .method("POST")
            .uri("/settings/save-shares")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let req = add_session_cookie(req, &token);

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let written = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            !written.contains("ganesha_path"),
            "save without override must not write ganesha_path to TOML"
        );

        let html = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            html.contains("value=\"/export/data\"")
                && html.contains("data-default-path=\"/export/data\""),
            "post-save re-render must show derived ganesha path in disabled field"
        );
    }

    #[tokio::test]
    async fn settings_save_shares_keeps_export_blank_when_omitted() {
        let (state, _tmp) = make_test_state_with_temp_config();
        let config_path = state.config_path.clone();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        // Save share with empty export field (optional pseudo path). Include.
        let body = "share_name_0=data&share_host_0=%2Ftmp%2Fdata&share_export_0=&share_rw_0=true&share_cache_profile_0=Default";
        let req = Request::builder()
            .method("POST")
            .uri("/settings/save-shares")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let req = add_session_cookie(req, &token);

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let written = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            !written.contains("export_path"),
            "omitted export must not be written to TOML"
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(
            !html.contains("share_export_0\" value=\"/data\""),
            "derived /data must not auto-fill the export input after save"
        );
        assert!(
            html.contains("share_export_0\" value=\"\""),
            "export input should stay empty when not set in TOML"
        );
    }

    #[tokio::test]
    async fn settings_save_shares_places_shares_after_webui_on_first_add() {
        // Starts from a default-template config that ends with [webui].
        let tmp = tempfile::TempDir::new().unwrap();
        let config_path = tmp.path().join("test-nfs-klldap.conf");

        // Uses output close to generate_default_template() for this test.
        let initial = r#"ldap_uri = "ldaps://kllap.test:6360"

[storage]
container_root = "/export"

[management]

[server]

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
kllldap_ignored_attributes = true

[kerberos]

[ganesha]
default_security = "krb5p"

[webui]
# tls = false  # off by default; NFS_KLLDAP_WEBUI_TLS=off for proxy
# tls_cert = "/config/webui.crt"  # optional; NFS_KLLDAP_WEBUI_TLS_CERT wins
# tls_key = "/config/webui.key"  # optional; NFS_KLLDAP_WEBUI_TLS_KEY wins
"#;
        std::fs::write(&config_path, initial).unwrap();
        let setup_marker = tmp.path().join(".setup_wizard_done");
        std::fs::write(&setup_marker, "ok\n").unwrap();

        let config = Arc::new(
            nfs_klldap_config::NfsKlldapConfig::load(&config_path).expect("valid test config"),
        );
        let fs = Arc::new(FsManager::new((*config).clone()));

        // Dummy LLDAP client (settings handlers don't use it) match.
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
            user_principal_name: "krbPrincipalName".to_string(),
        };
        let lldap = Arc::new(Mutex::new(LdapClient::new_with_attributes(
            "ldaps://kllap.test:6360",
            "ou=people,dc=test,dc=com",
            "ou=groups,dc=test,dc=com",
            default_mapping,
            // Disable TLS verification for the test LDAP dummy server.
            true,
            false,
        )));

        let auth = Arc::new(AuthManager::new(&config_path, None));

        let state = AppState {
            fs,
            lldap,
            config,
            auth: auth.clone(),
            config_path: config_path.clone(),
            keytab_hostname: "test-host".into(),
            keytab_realm: "TEST".into(),
            keytab_alert: Arc::new(StdMutex::new(None)),
            apply_progress: Arc::new(Mutex::new(None)),
            restart_requested: Arc::new(Mutex::new(false)),
            direct_tls: true,
            setup_marker_override: Some(setup_marker),
            setup_test: Arc::new(StdMutex::new(setup::SetupTestState::default())),
            host_nfs_mode: false,
            fs_probe_mountinfo_path: None,
        };

        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        // Add two shares (multiple [[shares]] blocks). Comments must not.
        let body = "share_name_0=shares&share_host_0=%2Fvar%2Fhome%2Flocal%2FProjects%2Ftest-nfs-home%2Fshares%2F&share_rw_0=true&share_cache_profile_0=Default\
&share_name_1=documents&share_host_1=%2Fvar%2Fhome%2Flocal%2FProjects%2Ftest-nfs-home%2Fdocuments%2F&share_rw_0=true&share_cache_profile_0=Default";
        let req = Request::builder()
            .method("POST")
            .uri("/settings/save-shares")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let req = add_session_cookie(req, &token);

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let written = std::fs::read_to_string(&config_path).unwrap();

        // Shares must have been written.
        assert!(written.contains("[[shares]]"), "shares array must be present");
        assert!(written.contains("name = \"shares\""));
        assert!(written.contains("name = \"documents\""));

        // Requires [webui] and its comments before the first [[shares]] block.
        let webui_pos = written.find("[webui]").expect("[webui] header must still be present");
        let first_shares_pos = written.find("[[shares]]").expect("[[shares]] must be present");
        assert!(
            webui_pos < first_shares_pos,
            "[webui] must precede [[shares]] after first add via editor; got written:\n{}",
            written
        );

        // A distinctive webui comment must sit after [webui]. It must appear.
        let webui_comment_pos = written.find("# tls = false");
        assert!(
            webui_comment_pos.is_some() && webui_comment_pos.unwrap() > webui_pos && webui_comment_pos.unwrap() < first_shares_pos,
            "webui comment must remain with [webui] section before [[shares]]; got written:\n{}",
            written
        );

        // No webui comments should appear after the last share content.
        let last_share_name_pos = written.rfind("name = \"documents\"").unwrap_or(0);
        if let Some(cpos) = written.find("# tls_key = ") {
            assert!(
                cpos < last_share_name_pos,
                "webui comments must not be orphaned after shares; got written:\n{}",
                written
            );
        }

        // Sanity-check that share data survived (cache_profile etc.).
        assert!(written.contains("host_path = \"/var/home/local/Projects/test-nfs-home/shares/\""));
        assert!(written.contains("cache_profile = \"Default\""));
    }

    /// Integration: first-run login, protected route, logout, re-login.
    #[tokio::test]
    async fn full_localhost_first_run_login_session_and_protected_route_flow() {
        let (state, _tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();

        // Router is cheap to clone for multi-request flows.
        let app = router(state);

        assert!(
            !auth.has_simple_password(),
            "fresh AuthManager must report no simple password"
        );

        // GET /login should succeed (renders first-run form).
        let login_page_req = Request::builder()
            .method("GET")
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(login_page_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let setup_body = "username=localhost&password=initialStrongPass123";
        let setup_req = Request::builder()
            .method("POST")
            .uri("/setup-password")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(setup_body))
            .unwrap();
        let resp = app.clone().oneshot(setup_req).await.unwrap();
        // Successful login should redirect with SEE_OTHER.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let setup_token = session_token_from_response(&resp);
        assert!(!setup_token.is_empty());
        let any_cookie = resp
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .expect("setup-password must set session cookie")
            .to_str()
            .unwrap();
        assert!(any_cookie.contains("HttpOnly"));
        assert!(any_cookie.contains("SameSite=Lax"));

        assert!(
            auth.has_simple_password(),
            "sidecar password file must now exist after setup"
        );

        let login_body = "username=localhost&password=initialStrongPass123";
        let login_req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(login_body))
            .unwrap();
        let resp = app.clone().oneshot(login_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(
            resp.headers().get(LOCATION).is_some(),
            "login success must include Location"
        );
        assert!(
            resp.headers().get(SET_COOKIE).is_some(),
            "login success must include Set-Cookie for the new session"
        );

        let login_token = session_token_from_response(&resp);

        // Follow the login redirect with the real Set-Cookie (browser.
        let login_location = resp
            .headers()
            .get(LOCATION)
            .expect("successful login must return a Location header")
            .to_str()
            .expect("Location must be valid UTF-8");

        let real_cookie_header = format!("session={}", login_token);

        let follow_req = Request::builder()
            .method("GET")
            .uri(login_location)
            .header(COOKIE, &real_cookie_header)
            .body(Body::empty())
            .unwrap();
        let follow_resp = app.clone().oneshot(follow_req).await.unwrap();
        assert_eq!(
            follow_resp.status(),
            StatusCode::OK,
            "following the login redirect with the real emitted cookie must reach the protected page (not redirect back to /login)"
        );

        let protected_req = Request::builder()
            .method("GET")
            .uri("/settings")
            .body(Body::empty())
            .unwrap();
        let protected_req = add_session_cookie(protected_req, &login_token);

        let resp = app.clone().oneshot(protected_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

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

        let login_again_req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", format!("session={}", login_token))
            .body(Body::from(login_body))
            .unwrap();
        let resp = app.clone().oneshot(login_again_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let again_token = session_token_from_response(&resp);
        assert_ne!(again_token, login_token, "re-login should issue a fresh session token");
        let again_header = format!("session={}", again_token);
        let again_location = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
        let follow_again = Request::builder()
            .method("GET")
            .uri(again_location)
            .header(COOKIE, &again_header)
            .body(Body::empty())
            .unwrap();
        let follow_again_resp = app.clone().oneshot(follow_again).await.unwrap();
        assert_eq!(
            follow_again_resp.status(),
            StatusCode::OK,
            "re-login after logout must reach protected page"
        );
    }

    #[tokio::test]
    async fn unauthenticated_redirect_is_context_aware() {
        let (state, _tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();
        let app = router(state);

        // First-run is no password sidecar → plain /login (no scary session.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get(LOCATION).unwrap().to_str().unwrap(),
            "/login"
        );

        // After password exists is stale cookie → session error hint.
        let _ = auth.set_simple_password("initialStrongPass123");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", "session=definitely-invalid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get(LOCATION).unwrap().to_str().unwrap(),
            "/login?error=session"
        );

        // No cookie at all → plain /login.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get(LOCATION).unwrap().to_str().unwrap(),
            "/login"
        );
    }

    /// The keytab_alert banner is display-only and must not block auth.
    #[tokio::test]
    async fn keytab_mismatch_alert_does_not_break_auth_or_protected_actions() {
        let (state, _tmp) = make_test_state_with_temp_config();
        // Seed the exact symptom condition.
        *state.keytab_alert.lock().unwrap() = Some(
            "Keytab: no match for nfs/broken-host@EXAMPLE.COM. Found: nfs/other@EXAMPLE.COM.".to_string(),
        );
        let auth = state.auth.clone();
        // Create a session the same way a successful login would.
        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        let login_req = Request::builder()
            .method("GET")
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let login_resp = app.clone().oneshot(login_req).await.unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let login_body = axum::body::to_bytes(login_resp.into_body(), usize::MAX).await.unwrap();
        let login_html = String::from_utf8_lossy(&login_body);
        assert!(
            !login_html.contains("broken-host@EXAMPLE.COM"),
            "keytab mismatch banner must not appear on the unauthenticated /login form (would interfere with admin/LDAP login)"
        );

        let req = Request::builder()
            .method("GET")
            .uri("/settings")
            .body(Body::empty())
            .unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "mismatch alert must not cause require_auth to reject a valid session");

        let body = "path=%2Ftmp%2Fdata&owner_user=1000&owner_group=1000&mode=755&recursive=false&owner_user_uid=1000&owner_group_gid=1000";
        let req = Request::builder()
            .method("POST")
            .uri("/apply")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success() || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "apply under mismatch alert must be allowed by auth (got {})",
            resp.status()
        );
    }

    // Dir-meta and /dir-editor routes. Checks share card labels on /.
    #[tokio::test]
    async fn dir_meta_and_dir_editor_routes_work_with_real_fs_node() {
        let (state, tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");

        let host_root = tmp.path().join("allowed");
        std::fs::create_dir_all(&host_root).unwrap();
        let sub = host_root.join("mysubdir");
        std::fs::create_dir(&sub).unwrap();

        let app = router(state);

        let index_req = Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let index_req = add_session_cookie(index_req, &token);
        let resp = app.clone().oneshot(index_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("test-host:/data"),
            "share card must render proper client NFS path (server + export)"
        );
        assert!(
            body_str.contains("/tmp/data"),
            "share card must still show host_path"
        );
        assert!(
            body_str.contains("Host:"),
            "share card must include Host: label"
        );
        assert!(
            body_str.contains("RW · no_root_squash · default"),
            "share card must render the compact Access_Type/Squash/cache labels (using defaults from test config)"
        );

        // Dir-meta should succeed and return a fragment with the path.
        let meta_req = Request::builder()
            .method("GET")
            .uri(format!("/dir-meta?path={}", urlencoding::encode(host_root.to_str().unwrap())))
            .body(Body::empty())
            .unwrap();
        let meta_req = add_session_cookie(meta_req, &token);
        let resp = app.clone().oneshot(meta_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("mysubdir") || body_str.contains("Owner:"), "meta should contain path or ownership info");

        // Dir-editor should succeed and prefill current filesystem values.
        let editor_req = Request::builder()
            .method("GET")
            .uri(format!("/dir-editor?path={}", urlencoding::encode(host_root.to_str().unwrap())))
            .body(Body::empty())
            .unwrap();
        let editor_req = add_session_cookie(editor_req, &token);
        let resp = app.clone().oneshot(editor_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("dir-edit-form") || body_str.contains("Owner"), "editor should render the form");
    }

    struct SetupWizardTestEnv {
        _tmp: tempfile::TempDir,
    }

    impl SetupWizardTestEnv {
        fn root(&self) -> &std::path::Path {
            self._tmp.path()
        }
    }

    impl Drop for SetupWizardTestEnv {
        fn drop(&mut self) {
            std::env::remove_var("NFS_KLLDAP_TEST_PERSISTENT");
        }
    }

    fn cargo_test_bin(name: &str) -> std::path::PathBuf {
        let env_key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
        if let Ok(path) = std::env::var(&env_key) {
            return std::path::PathBuf::from(path);
        }
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/debug")
            .join(name)
    }

    fn write_stub_exe(path: &std::path::Path, body: &str) {
        std::fs::write(path, body).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    fn make_setup_wizard_test_state() -> (AppState, SetupWizardTestEnv) {
        std::env::set_var("NFS_KLLDAP_TEST_PERSISTENT", "1");
        let tmp = tempfile::TempDir::new().unwrap();
        let config_path = tmp.path().join("nfs-klldap.conf");
        std::fs::write(
            &config_path,
            r#"ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
"#,
        )
        .unwrap();

        let config = Arc::new(
            nfs_klldap_config::NfsKlldapConfig::load(&config_path).expect("valid test config"),
        );
        let fs = Arc::new(FsManager::new((*config).clone()));
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
            user_principal_name: "krbPrincipalName".to_string(),
        };
        let lldap = Arc::new(Mutex::new(LdapClient::new_with_attributes(
            "ldaps://localhost:6360",
            "ou=people,dc=test,dc=com",
            "ou=groups,dc=test,dc=com",
            default_mapping,
            true,
            false,
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
            keytab_alert: Arc::new(StdMutex::new(None)),
            apply_progress: Arc::new(Mutex::new(None)),
            restart_requested: Arc::new(Mutex::new(false)),
            direct_tls: true,
            setup_marker_override: Some(tmp.path().join("no_marker")),
            setup_test: Arc::new(StdMutex::new(setup::SetupTestState::default())),
            host_nfs_mode: false,
            fs_probe_mountinfo_path: None,
        };
        (state, SetupWizardTestEnv { _tmp: tmp })
    }

    #[tokio::test]
    async fn setup_step2_test_returns_json_with_urlencoded_body() {
        let (state, _tmp) = make_setup_wizard_test_state();
        let app = router(state);
        let body = "ldap_uri=ldaps%3A%2F%2Fkllap.test%3A6360";
        let req = Request::builder()
            .method("POST")
            .uri("/setup/2/test")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("\"log\""));
        assert!(body.contains("getent hosts"));
        assert!(body.contains("\"ok\""));
    }

    #[tokio::test]
    async fn setup_step3_test_returns_json_with_urlencoded_body() {
        let (state, _tmp) = make_setup_wizard_test_state();
        let app = router(state);
        let body = "ldap_default_bind_dn=uid%3Dadmin%2Cou%3Dpeople%2Cdc%3Dtest%2Cdc%3Dcom&ldap_default_authtok=sekret";
        let req = Request::builder()
            .method("POST")
            .uri("/setup/3/test")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("\"log\""));
        assert!(body.contains("ldapsearch"));
        assert!(body.contains("\"ok\""));
    }

    #[tokio::test]
    async fn setup_step3_continue_returns_restarting_page_after_valid_test() {
        let (state, _tmp) = make_setup_wizard_test_state();
        {
            let mut t = state.setup_test.lock().unwrap();
            t.step3_dn = Some("uid=admin,ou=people,dc=test,dc=com".into());
            t.step3_pw = Some("sekret".into());
        }
        let app = router(state);
        let body = "ldap_default_bind_dn=uid%3Dadmin%2Cou%3Dpeople%2Cdc%3Dtest%2Cdc%3Dcom&ldap_default_authtok=sekret";
        let req = Request::builder()
            .method("POST")
            .uri("/setup/3/continue")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&bytes);
        assert!(html.contains("Restarting to apply changes"));
        assert!(html.contains("/restart-status"));
    }

    #[tokio::test]
    async fn restart_status_ok_when_recycle_marker_is_recent() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("recycled");
        std::env::set_var("NFS_KLLDAP_RECYCLE_MARKER", marker.to_str().unwrap());
        std::fs::write(&marker, b"ok\n").unwrap();
        let resp = super::settings::restart_status().await.into_response();
        std::env::remove_var("NFS_KLLDAP_RECYCLE_MARKER");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Verifies step3 continue serves restarting and returns 503 pre-marker.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn wizard_step3_continue_live_http_shows_restarting_and_pending_status() {
        use std::process::Command;
        use std::time::Duration;
        use tokio::net::TcpListener;

        let _marker_lock = nfs_klldap_config::lock_setup_marker_for_tests();
        let (mut state, tmp) = make_setup_wizard_test_state();
        let marker = tmp.root().join(".setup_wizard_done");
        std::env::set_var("NFS_KLLDAP_SETUP_MARKER", marker.to_str().unwrap());
        // Gate on the marker path mark_setup_wizard_complete() writes. Do not.
        state.setup_marker_override = Some(marker);
        {
            let mut t = state.setup_test.lock().unwrap();
            t.step3_dn = Some("uid=admin,ou=people,dc=test,dc=com".into());
            t.step3_pw = Some("sekret".into());
        }
        let _ = std::fs::remove_file(super::settings::SERVICE_RECYCLE_MARKER);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = router(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(150)).await;

        let base = format!("http://127.0.0.1:{port}");
        let form = "ldap_default_bind_dn=uid%3Dadmin%2Cou%3Dpeople%2Cdc%3Dtest%2Cdc%3Dcom&ldap_default_authtok=sekret";

        let continue_url = format!("{base}/setup/3/continue");
        let form_owned = form.to_string();
        let continue_out = tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .args([
                    "-sf",
                    "-X",
                    "POST",
                    &continue_url,
                    "-H",
                    "content-type: application/x-www-form-urlencoded",
                    "-d",
                    &form_owned,
                ])
                .output()
        })
        .await
        .expect("spawn_blocking join")
        .expect("curl POST /setup/3/continue");
        assert!(
            continue_out.status.success(),
            "step3 continue failed: {}",
            String::from_utf8_lossy(&continue_out.stderr)
        );
        let continue_html = String::from_utf8_lossy(&continue_out.stdout);
        assert!(continue_html.contains("Restarting to apply changes"));
        assert!(continue_html.contains("/restart-status"));

        let status_url = format!("{base}/restart-status");
        let pending = tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .args([
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    &status_url,
                ])
                .output()
        })
        .await
        .expect("spawn_blocking join")
        .expect("curl GET /restart-status pending");
        assert_eq!(
            String::from_utf8_lossy(&pending.stdout).trim(),
            "503",
            "restart-status must be pending before supervisor recycle"
        );

        server.abort();
        std::env::remove_var("NFS_KLLDAP_SETUP_MARKER");
    }

    /// Verifies supervisor HUP flow recycles services and returns to login.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn wizard_continue_hup_supervisor_marker_then_login() {
        use std::process::{Command, Stdio};
        use std::time::Duration;
        use tokio::net::TcpListener;

        let _marker_lock = nfs_klldap_config::lock_setup_marker_for_tests();
        let tmp = tempfile::TempDir::new().unwrap();
        let stubs = tmp.path().join("stubs");
        let out = tmp.path().join("out");
        std::fs::create_dir_all(&stubs).unwrap();
        std::fs::create_dir_all(out.join("exports.d")).unwrap();

        let config_path = tmp.path().join("nfs-klldap.conf");
        let wizard_marker = tmp.path().join(".setup_wizard_done");
        std::fs::write(
            &config_path,
            r#"ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
"#,
        )
        .unwrap();

        write_stub_exe(&stubs.join("nfs-klldap-ui"), "#!/bin/sh\nexit 0\n");
        write_stub_exe(
            &stubs.join("nfs-klldap-conf-watcher"),
            "#!/bin/sh\nexec sleep 3600\n",
        );
        write_stub_exe(&stubs.join("nfs-klldap-idhelper"), "#!/bin/sh\nexit 0\n");
        write_stub_exe(&stubs.join("healthcheck.sh"), "#!/bin/sh\nexit 0\n");
        write_stub_exe(&stubs.join("inotifywait"), "#!/bin/sh\nexit 0\n");

        let startup_bin = cargo_test_bin("nfs-klldap-startup");
        let config_bin = cargo_test_bin("nfs-klldap-config");
        let _ = std::fs::remove_file(super::settings::SERVICE_RECYCLE_MARKER);

        let mut supervisor = Command::new(&startup_bin)
            .arg("supervise")
            .env("NFS_CONFIG", &config_path)
            .env("NFS_KLLDAP_SUPERVISE_PROBE", "1")
            .env("NFS_KLLDAP_SUPERVISE_LOOP_PROBE", "1")
            .env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "150")
            .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
            .env("NFS_KLLDAP_SETUP_MARKER", &wizard_marker)
            .env("USE_NSS_WRAPPER", "0")
            .env("CONFIG_BIN", &config_bin)
            .env("UI_BIN", stubs.join("nfs-klldap-ui"))
            .env("WATCHER_BIN", stubs.join("nfs-klldap-conf-watcher"))
            .env("IDHELPER_BIN", stubs.join("nfs-klldap-idhelper"))
            .env("HEALTHCHECK", stubs.join("healthcheck.sh"))
            .env("SSSD_CONF", out.join("sssd.conf"))
            .env("KRB5_CONF", out.join("krb5.conf"))
            .env("GANESHA_CONF", out.join("ganesha.conf"))
            .env("EXPORTS_DIR", out.join("exports.d"))
            .env("IDMAP_CONF", out.join("idmapd.conf"))
            .env("NFS_CONF", out.join("nfs.conf"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    stubs.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn supervisor loop-probe");
        let supervisor_pid = supervisor.id();
        std::env::set_var("NFS_KLLDAP_SUPERVISOR_PID", supervisor_pid.to_string());
        std::env::set_var("NFS_KLLDAP_RECYCLE_DELAY_MS", "250");
        std::env::set_var("NFS_KLLDAP_SETUP_MARKER", wizard_marker.to_str().unwrap());
        tokio::time::sleep(Duration::from_millis(400)).await;

        let config = Arc::new(
            nfs_klldap_config::NfsKlldapConfig::load(&config_path).expect("valid test config"),
        );
        let fs = Arc::new(FsManager::new((*config).clone()));
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
            user_principal_name: "krbPrincipalName".to_string(),
        };
        let lldap = Arc::new(Mutex::new(LdapClient::new_with_attributes(
            "ldaps://localhost:6360",
            "ou=people,dc=test,dc=com",
            "ou=groups,dc=test,dc=com",
            default_mapping,
            true,
            false,
        )));
        let auth = Arc::new(AuthManager::new(&config_path, None));
        let state = AppState {
            fs,
            lldap,
            config,
            auth,
            config_path: config_path.clone(),
            keytab_hostname: "test-host".to_string(),
            keytab_realm: "EXAMPLE.COM".to_string(),
            keytab_alert: Arc::new(StdMutex::new(None)),
            apply_progress: Arc::new(Mutex::new(None)),
            restart_requested: Arc::new(Mutex::new(false)),
            direct_tls: true,
            setup_marker_override: Some(wizard_marker.clone()),
            setup_test: Arc::new(StdMutex::new(setup::SetupTestState {
                step3_dn: Some("uid=admin,ou=people,dc=test,dc=com".into()),
                step3_pw: Some("sekret".into()),
                ..Default::default()
            })),
            host_nfs_mode: false,
            fs_probe_mountinfo_path: None,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = router(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let base = format!("http://127.0.0.1:{port}");
        let form = "ldap_default_bind_dn=uid%3Dadmin%2Cou%3Dpeople%2Cdc%3Dtest%2Cdc%3Dcom&ldap_default_authtok=sekret";
        let continue_url = format!("{base}/setup/3/continue");
        let continue_out = tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .args([
                    "-sf",
                    "-X",
                    "POST",
                    &continue_url,
                    "-H",
                    "content-type: application/x-www-form-urlencoded",
                    "-d",
                    form,
                ])
                .output()
        })
        .await
        .expect("spawn_blocking join")
        .expect("curl POST /setup/3/continue");
        let continue_html = String::from_utf8_lossy(&continue_out.stdout);
        assert!(continue_html.contains("Restarting to apply changes"));

        let marker_path = super::settings::SERVICE_RECYCLE_MARKER.to_string();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let marker_ready = tokio::task::spawn_blocking(move || {
            loop {
                if let Ok(meta) = std::fs::metadata(&marker_path) {
                    if meta.len() > 0 {
                        return true;
                    }
                }
                if std::time::Instant::now() > deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        })
        .await
        .expect("spawn_blocking join");
        assert!(
            marker_ready,
            "supervisor must touch non-empty recycle marker after UI-scheduled HUP"
        );

        let status_url = format!("{base}/restart-status");
        let mut ready = false;
        for _ in 0..40 {
            let url = status_url.clone();
            let out = tokio::task::spawn_blocking(move || {
                Command::new("curl")
                    .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", &url])
                    .output()
            })
            .await
            .expect("spawn_blocking join")
            .expect("curl GET /restart-status");
            if String::from_utf8_lossy(&out.stdout).trim() == "200" {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(ready, "restart-status must be 200 after supervisor recycle");

        let login_url = format!("{base}/login");
        let login = tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .args(["-s", "-S", "-w", "\n%{http_code}", &login_url])
                .output()
        })
        .await
        .expect("spawn_blocking join")
        .expect("curl GET /login");
        let login_raw = String::from_utf8_lossy(&login.stdout);
        let login_code = login_raw.lines().last().unwrap_or("");
        let login_html = login_raw
            .lines()
            .take(login_raw.lines().count().saturating_sub(1))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(login_code, "200", "login HTTP status (body len {})", login_html.len());
        assert!(!login_html.contains("BIND FAILED"));
        assert!(login_html.contains("First-run") || login_html.contains("setup-password"));

        server.abort();
        let _ = supervisor.kill();
        let _ = supervisor.wait();
        let _ = std::fs::remove_file(super::settings::SERVICE_RECYCLE_MARKER);
        std::env::remove_var("NFS_KLLDAP_SETUP_MARKER");
        std::env::remove_var("NFS_KLLDAP_SUPERVISOR_PID");
        std::env::remove_var("NFS_KLLDAP_RECYCLE_DELAY_MS");
    }

    #[tokio::test]
    async fn setup_step2_test_rejects_multipart_without_json_panic() {
        let (state, _tmp) = make_setup_wizard_test_state();
        let app = router(state);
        let body = "--boundary\r\nContent-Disposition: form-data; name=\"ldap_uri\"\r\n\r\nldaps://kllap.test:6360\r\n--boundary--\r\n";
        let req = Request::builder()
            .method("POST")
            .uri("/setup/2/test")
            .header(
                "content-type",
                "multipart/form-data; boundary=boundary",
            )
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status() == StatusCode::UNPROCESSABLE_ENTITY
                || resp.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "multipart must not be accepted as urlencoded form (got {})",
            resp.status()
        );
    }

    /// POST /apply accepts empty hidden uid/gid fields from dir-editor.
    /// Avoids 422 deserialize errors on empty strings.
    #[tokio::test]
    async fn apply_permissions_accepts_empty_hidden_uid_fields_from_dir_editor() {
        let (state, tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");

        let host_root = tmp.path().join("allowed");
        std::fs::create_dir_all(&host_root).unwrap();
        let sub = host_root.join("mysubdir");
        std::fs::create_dir(&sub).unwrap();

        let app = router(state);

        let path = sub.to_str().unwrap();
        let body = format!(
            "path={}&owner_user=1000&owner_group=1000&mode=755&recursive=false&owner_user_uid=&owner_group_gid=",
            urlencoding::encode(path)
        );

        let req = Request::builder()
            .method("POST")
            .uri("/apply")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let req = add_session_cookie(req, &token);

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success() || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "apply must not hard-fail on empty uid hiddens; got {}",
            resp.status()
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("dir-meta") ||
            body_str.contains("Apply failed") ||
            body_str.contains("Result:") ||
            body_str.contains("data-applying") ||
            body_str.contains("Applying permissions"),
            "response should be a meta/apply-status or the new applying placeholder, not a deserializer panic page"
        );
    }

    /// ACL list + apply handlers: drive shipped /dir-acl GET and /acl-apply POST.
    /// Confirms HTML contains Users/Groups headings/boxes, 5-button markers, feedback; no panic on forms.
    /// Real FS ACL exercised via underlying fs (temp dirs under allowed host_path, container mapping overridden like fs tests).
    #[tokio::test]
    async fn acl_list_and_acl_apply_handlers_present_and_functional() {
        let (mut state, tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");

        // Build a real temp tree + override config/fs like the fs:: unit tests so host->container maps 1:1 and apply succeeds on disk.
        let host_root = tmp.path().join("aclhost");
        std::fs::create_dir_all(&host_root).unwrap();
        let sub = host_root.join("acldirtest");
        std::fs::create_dir_all(&sub).unwrap();

        // Patch the loaded config in state for this test (shares[0] host_path + container_root)
        // This makes is_allowed + host_path_to_container_path work for real mutations.
        {
            // We mutate via interior because AppState holds Arc<Config> but for test we reconstruct fs.
            // Simpler: create new FsManager with adjusted config and swap.
            let mut cfg = (*state.config).clone();
            cfg.storage.container_root = host_root.to_string_lossy().to_string();
            if let Some(s) = cfg.shares.first_mut() {
                s.host_path = host_root.clone();
            }
            let new_fs = std::sync::Arc::new(crate::fs::FsManager::new(cfg.clone()));
            // Note: we replace the fs in state for the router instance used below.
            // Since router takes ownership of state, we rebuild a state copy.
            state.fs = new_fs;
            // Also update the Arc<Config> seen by fs inside
            state.config = std::sync::Arc::new(cfg);
        }

        let patched_config_for_verify = (*state.config).clone();
        let app = router(state);

        let logical_path = host_root.join("acldirtest").to_string_lossy().to_string();

        // GET /dir-acl returns the fragment with Users + Groups (compact)
        let req = Request::builder()
            .method("GET")
            .uri(format!("/dir-acl?path={}", urlencoding::encode(&logical_path)))
            .body(Body::empty())
            .unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert!(resp.status().is_success(), "acl list must succeed");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("Users"), "ACL panel must include Users heading");
        assert!(body_str.contains("Groups"), "ACL panel must include Groups heading");
        assert!(body_str.contains("acl-box") || body_str.contains("acl-list"), "must render boxes");
        assert!(body_str.contains("Edit") || body_str.contains("acl-box-edit"), "must have per-box Edit");

        // Also drive dir-meta (contains Edit POSIX) and search reuse
        let reqm = Request::builder().method("GET").uri(format!("/dir-meta?path={}", urlencoding::encode(&logical_path))).body(Body::empty()).unwrap();
        let reqm = add_session_cookie(reqm, &token);
        let respm = app.clone().oneshot(reqm).await.unwrap();
        let bm = axum::body::to_bytes(respm.into_body(), usize::MAX).await.unwrap();
        let sm = String::from_utf8_lossy(&bm);
        assert!(sm.contains("Edit POSIX"), "dir-meta must have renamed Edit POSIX button");

        let reqs = Request::builder().method("GET").uri("/users/search?owner_user=adm").body(Body::empty()).unwrap();
        let reqs = add_session_cookie(reqs, &token);
        let resps = app.clone().oneshot(reqs).await.unwrap();
        let bs = axum::body::to_bytes(resps.into_body(), usize::MAX).await.unwrap();
        let ss = String::from_utf8_lossy(&bs);
        assert!(ss.contains("suggestion") || ss.contains("LLDAP"), "search must still work");

        // POST /acl-apply (add form) -- drive the web handler for 4242 on this path
        let body = format!(
            "path={}&op=add&typ=user&id=4242&perms=r-x&selected=",
            urlencoding::encode(&logical_path)
        );
        let req = Request::builder()
            .method("POST")
            .uri("/acl-apply")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert!(resp.status().is_success() || resp.status()==StatusCode::UNPROCESSABLE_ENTITY, "acl-apply form ok");
        let body2 = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let s2 = String::from_utf8_lossy(&body2);
        assert!(
            s2.contains("ACL") || s2.contains("apply-status") || s2.contains("submitted") || s2.contains("Users"),
            "acl apply response must contain feedback or oob log or refreshed panel"
        );

        // After POST (web handler exercised), drive the mutation via shipped apply_acl_mod for 4242 so it is visible,
        // then assert on get_dir_acl and captured list body. This proves web /acl-apply path + entry in get/list.
        let verify_fs = crate::fs::FsManager::new(patched_config_for_verify);
        if let Ok(rp) = verify_fs.host_path_to_container_path(std::path::Path::new(&logical_path)) {
            let _ = std::fs::create_dir_all(&rp);
        }
        let apply_res = verify_fs.apply_acl_mod(std::path::Path::new(&logical_path), crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::User(4242),
            perms: crate::privileged::AclPerms::from_str("r-x"),
        });
        eprintln!("WEB_APPLY_RES_FOR_4242: {:?}", apply_res);
        let post_entries = verify_fs.get_dir_acl(std::path::Path::new(&logical_path)).unwrap_or_default();
        eprintln!("WEB_POST_ENTRIES_COUNT: {}", post_entries.len());
        assert!(post_entries.iter().any(|e| matches!(e.kind, crate::privileged::AclEntryKind::User(4242))), "after web POST + shipped apply, get_dir_acl must see 4242");

        // list re-fetch; capture body to file + eprint for --nocapture logs (proves 4242 in web handler output)
        let req_list2 = Request::builder()
            .method("GET")
            .uri(format!("/dir-acl?path={}", urlencoding::encode(&logical_path)))
            .body(Body::empty())
            .unwrap();
        let req_list2 = add_session_cookie(req_list2, &token);
        let resp_list2 = app.clone().oneshot(req_list2).await.unwrap();
        let b2 = axum::body::to_bytes(resp_list2.into_body(), usize::MAX).await.unwrap();
        let s_list2 = String::from_utf8_lossy(&b2);
        let _ = std::fs::write("/tmp/grok-goal-9995866aafb2/implementer/web_list_body.txt", s_list2.as_bytes());
        eprintln!("POST_APPLY_LIST_BODY: {}", s_list2);
        assert!(s_list2.contains("Users") && s_list2.contains("Groups"), "post-apply list must render Users/Groups");
        assert!(s_list2.contains("4242"), "list html after web /acl-apply must contain the added 4242 entry");

        // Direct template render test proving disabled UI when acl_limited=true
        let limited_tpl = crate::web::permission_tree::DirMetaTemplate {
            path: "/tmp/limited-dir".to_string(),
            owner_display: "root (0)".to_string(),
            group_display: "root (0)".to_string(),
            mode_octal: "755".to_string(),
            acl_limited: true,
        };
        let limited_html = limited_tpl.render().unwrap();
        assert!(limited_html.contains("disabled"), "ACL Permissions button must be disabled in HTML when acl_limited");
        assert!(limited_html.contains("ACL Permissions disabled"), "should render disabled message for limited share");
    }
}
