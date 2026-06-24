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

// pub(crate) re-exports for router assembly and in-module integration tests.
pub(crate) use auth::{login, login_page, logout, require_auth, setup_password};
pub(crate) use permission_tree::{
    apply_permissions, apply_progress, cancel_apply, dir_editor, dir_meta, fs_children, index,
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
    /// Display-only keytab mismatch banner; see `keytab.rs` for the invariant.
    pub keytab_alert: Arc<StdMutex<Option<String>>>,
    /// Shared state for an in-flight (recursive or non-recursive) permission apply.
    /// Populated when /apply starts the background task; read by /apply-progress for the
    /// live Apply Log (with XXXX/XXXX + spinner while estimating) and by cancel_apply.
    pub apply_progress: Arc<Mutex<Option<Arc<crate::fs::ApplyProgress>>>>,
    /// Latched true on first successful POST /settings/restart. Guards against duplicate
    /// scheduling of the delayed HUP (e.g. fast double-click, or browser re-POST on
    /// refresh of the /settings/restart result "page"). Once set we just re-serve the
    /// standalone restarting.html without side-effects.
    pub restart_requested: Arc<Mutex<bool>>,
    /// true when WebUI terminates TLS; false when `NFS_KLLDAP_WEBUI_TLS=off` (proxy mode).
    pub direct_tls: bool,
    /// Test-only: when set, gates setup completion on this marker path instead of the default.
    pub setup_marker_override: Option<PathBuf>,
    /// Last successful wizard test inputs (probe-only; not persisted until continue).
    pub setup_test: Arc<StdMutex<setup::SetupTestState>>,
}

impl AppState {
    /// true when direct TLS or `X-Forwarded-Proto: https` (drives cookie `Secure` flag).
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
        // === Public (no auth) ===
        .route("/login", get(login_page).post(login))
        .route("/setup-password", post(setup_password))
        .route("/logout", get(logout).post(logout))
        // Public status for the post-restart poller (no auth; used by restarting.html)
        .route("/restart-status", get(restart_status))
        // === Public: first-run setup wizard (replaces terminal TUI) ===
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

        // === Protected: Main permission tree UI (/) ===
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

        // === Protected: System Settings + LLDAP client management ===
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
    };

    (state, tmp)
}

// Integration tests (auth flows, settings, apply, cookie policy).
#[cfg(test)]
mod tests {
    use super::*;
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

    /// Login/setup responses emit clear + set cookies; return the non-empty session token.
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
        let config_path = state.config_path.clone();
        let auth = state.auth.clone();
        // Use the real privileged session creator (same path the login handlers use)
        let token = auth.create_privileged_session("testadmin");

        let app = router(state);

        // Exercise override flags:
        // - server_hostname + override=true → should be written explicitly
        // - sssd_user_base sent but override=false (or absent) → should be removed (allow derive)
        // - kerberos_realm + override → written
        // ldap_uri (key) always written
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

        // Verify the written config has the expected explicit keys (and omits non-overridden).
        let written = std::fs::read_to_string(&config_path).unwrap_or_default();
        assert!(written.contains("ldap_uri = \"ldaps://newhost.example.com:6360\""), "key field must be written");
        assert!(written.contains("hostname = \"override-host.example.com\""), "server override must be persisted when flag true");
        assert!(written.contains("realm = \"OVERRIDE.REALM\""), "kerberos override must be persisted when flag true");
        assert!(!written.contains("ldap_user_search_base"), "sssd_user_base must be omitted (no override) so derivation applies");

        // ganesha: even though not mentioned in this POST, the !override path forces the default into the source
        // (addresses the "value removed entirely" complaint; other derived fields intentionally omit).
        assert!(written.contains("default_security = \"krb5p\""), "ganesha must default to krb5p and be materialized when not overridden");
    }

    #[tokio::test]
    async fn settings_save_shares_keeps_export_blank_when_omitted() {
        let (state, _tmp) = make_test_state_with_temp_config();
        let config_path = state.config_path.clone();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        // Save share with empty export field (optional pseudo path).
        // Include the cache_profile field so collect + apply exercise the profile path.
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
        // Start from a config shaped like the default template: ends with [webui] + its
        // commented keys and has no [[shares]] yet. This reproduces the reported ordering bug.
        let tmp = tempfile::TempDir::new().unwrap();
        let config_path = tmp.path().join("test-nfs-klldap.conf");

        // Close approximation of generate_default_template() output for the sections
        // the shares-save path must not disturb, plus the exact [webui] trailer.
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
# tls = false                                                   # commented off by default (tls on). Set via NFS_KLLDAP_WEBUI_TLS=off for reverse-proxy.
# tls_cert = "/config/webui.crt"                                # optional custom cert (NFS_KLLDAP_WEBUI_TLS_CERT env wins)
# tls_key = "/config/webui.key"                                 # optional custom key (NFS_KLLDAP_WEBUI_TLS_KEY env wins; 0600)
"#;
        std::fs::write(&config_path, initial).unwrap();
        let setup_marker = tmp.path().join(".setup_wizard_done");
        std::fs::write(&setup_marker, "ok\n").unwrap();

        let config = Arc::new(
            nfs_klldap_config::NfsKlldapConfig::load(&config_path).expect("valid test config"),
        );
        let fs = Arc::new(FsManager::new((*config).clone()));

        // Dummy LLDAP client (settings handlers don't use it) — match make_test_state_with_temp_config.
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
            true, // no_tls_verify for test dummy
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
        };

        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        // Add two shares (exercises multiple [[shares]] and "comments must not appear after last share").
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

        // The critical ordering requirement:
        // [webui] (and its comments) must appear before the first [[shares]].
        let webui_pos = written.find("[webui]").expect("[webui] header must still be present");
        let first_shares_pos = written.find("[[shares]]").expect("[[shares]] must be present");
        assert!(
            webui_pos < first_shares_pos,
            "[webui] must precede [[shares]] after first add via editor; got written:\n{}",
            written
        );

        // At least one distinctive webui comment must appear after [webui] and before the first [[shares]].
        let webui_comment_pos = written.find("# tls = false");
        assert!(
            webui_comment_pos.is_some() && webui_comment_pos.unwrap() > webui_pos && webui_comment_pos.unwrap() < first_shares_pos,
            "webui comment must remain with [webui] section before [[shares]]; got written:\n{}",
            written
        );

        // No webui comments should appear after the last share content.
        // (Search after the last known share name.)
        let last_share_name_pos = written.rfind("name = \"documents\"").unwrap_or(0);
        if let Some(cpos) = written.find("# tls_key = ") {
            assert!(
                cpos < last_share_name_pos,
                "webui comments must not be orphaned after shares; got written:\n{}",
                written
            );
        }

        // Also sanity-check that the shares data survived correctly (cache_profile etc.).
        assert!(written.contains("host_path = \"/var/home/local/Projects/test-nfs-home/shares/\""));
        assert!(written.contains("cache_profile = \"Default\""));
    }

    /// Localhost first-run, login (SameSite=Lax), redirect follow, protected route, logout, re-login.
    #[tokio::test]
    async fn full_localhost_first_run_login_session_and_protected_route_flow() {
        let (state, _tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();

        // Router is cheap to clone for multi-request flows
        let app = router(state);

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

        let setup_body = "username=localhost&password=initialStrongPass123";
        let setup_req = Request::builder()
            .method("POST")
            .uri("/setup-password")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(setup_body))
            .unwrap();
        let resp = app.clone().oneshot(setup_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER); // redirect after success

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

        // Follow the login redirect with the real Set-Cookie (browser behavior).
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

        // First-run: no password sidecar → plain /login (no scary session message)
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

        // After password exists: stale cookie → session error hint
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

        // No cookie at all → plain /login
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

    /// keytab_alert is display-only; must not block auth or protected routes (see keytab.rs).
    #[tokio::test]
    async fn keytab_mismatch_alert_does_not_break_auth_or_protected_actions() {
        let (state, _tmp) = make_test_state_with_temp_config();
        // Seed the exact symptom condition.
        *state.keytab_alert.lock().unwrap() = Some(
            "Keytab: no match for nfs/broken-host@EXAMPLE.COM. Found: nfs/other@EXAMPLE.COM.".to_string(),
        );
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin"); // same as real login success path
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

    /// /dir-meta and /dir-editor with a real temp dir; also checks share card labels on /.
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
            body_str.contains("rw · no-squash · default"),
            "share card must render the compact rw/squash/cache labels (using defaults from test config)"
        );

        // /dir-meta should succeed and return a fragment containing the path
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

        // /dir-editor should also succeed (prefills with current FS values)
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

    impl Drop for SetupWizardTestEnv {
        fn drop(&mut self) {
            std::env::remove_var("NFS_KLLDAP_TEST_PERSISTENT");
        }
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

    /// POST /apply accepts empty hidden uid/gid fields from dir-editor (no 422 deserialize error).
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
}
