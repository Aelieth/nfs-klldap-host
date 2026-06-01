//! Thin orchestration for the WebUI (Axum handlers + templates).
//!
//! The real logic lives in focused submodules:
//! - `auth`      : login, cookies (using the `cookie` crate), require_auth guard + fixes
//! - `permission_tree` : the / page (tree, HTMX fragments, searches, apply)
//! - `settings`  : /settings + raw/structured TOML editing + LLDAP client reload
//!
//! This file stays small (<500 lines target, tests at bottom are acceptable per review).
//! It owns AppState (the god-object passed to every handler) and assembles the Router.

use axum::{routing::{get, post}, Router};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{auth::AuthManager, config::Config, fs::FsManager, ldap::LdapClient};

// Declare submodules (the actual logic lives here).
mod auth;
mod keytab;
mod permission_tree;
mod settings;

// Re-exports needed by main.rs (and for the router assembly below).
pub use keytab::compute_keytab_status_message;

// Re-export handlers as pub(crate) so that the integration tests (which live
// inside this module) can use `use super::*;` in a natural way (keeps the
// port of the large test module as mechanical as possible).
pub(crate) use auth::{login, login_page, logout, require_auth, setup_password};
pub(crate) use permission_tree::{
    apply_permissions, dir_editor, dir_meta, directory_form, index, search_groups,
    search_users, tree_fragment,
};
pub(crate) use settings::{
    clear_ldap_cache, lldap_status, reload_nfs_client, settings_page,
    settings_save_raw, settings_save_structured,
};

// The pub(crate) re-exports below serve two purposes:
// 1. They give us short, clean names for the router registration in this file.
// 2. They make the handlers available to the integration tests via `use super::*;`.

/// The single piece of state shared by all handlers.
/// (Kept here for now; could move to a state.rs if it grows further.)
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

/// Assembles all routes (public + protected).
/// Routes are grouped for readability. Handler implementations live in the
/// focused submodules (auth, permission_tree, settings).
pub fn router(state: AppState) -> Router {
    Router::new()
        // === Public (no auth) ===
        .route("/login", get(login_page).post(login))
        .route("/setup-password", post(setup_password))
        .route("/logout", get(logout).post(logout))

        // === Protected: Main permission tree UI (/) ===
        .route("/", get(index))
        .route("/tree", get(tree_fragment))
        .route("/directory", get(directory_form)) // legacy (kept for compatibility)
        .route("/dir-meta", get(dir_meta))
        .route("/dir-editor", get(dir_editor))
        .route("/users/search", get(search_users))
        .route("/groups/search", get(search_groups))
        .route("/apply", post(apply_permissions))

        // === Protected: System Settings + LLDAP client management ===
        .route("/settings", get(settings_page))
        .route("/settings/save-raw", post(settings_save_raw))
        .route("/settings/save", post(settings_save_structured))
        .route("/settings/lldap-status", get(lldap_status))
        .route("/settings/reload-nfs-client", post(reload_nfs_client))
        .route("/settings/clear-ldap-cache", post(clear_ldap_cache))

        .with_state(state)
}

// === Integration tests ===
//
// These were originally in the monolithic web.rs. They are kept here (at the
// bottom of the thin orchestration module) per review feedback. The critical
// `full_localhost_first_run_login_session_and_protected_route_flow` test
// exercises the entire auth + session + cookie + protected route path and
// must continue to pass after the refactor and cookie policy changes.
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
    ///
    /// Updated during refactor: SameSite assertion changed from Strict → Lax to match
    /// the deliberate security improvement (Lax is required for reliable POST→303 redirect login).
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
        assert!(set_cookie.contains("SameSite=Lax")); // Updated: we use Lax for reliable login redirects

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

        // === Phase 3b (NEW): Follow the *actual* login redirect using the real Set-Cookie ===
        // This is the critical missing coverage for the original bug: "login handler returns 303 + cookie,
        // but the subsequent GET to the Location (with the cookie the browser would have received) was
        // never exercised." Manual add_session_cookie bypass hid exactly the symptom (Secure, Max-Age,
        // SameSite propagation, require_auth on the real redirect target).
        let login_location = resp
            .headers()
            .get(LOCATION)
            .expect("successful login must return a Location header")
            .to_str()
            .expect("Location must be valid UTF-8");

        // Parse the *exact* Set-Cookie the login handler emitted (not our manual string).
        // This exercises build_session_cookie end-to-end with the browser-like roundtrip.
        let parsed = Cookie::parse(login_set_cookie)
            .expect("login must emit a parseable Set-Cookie header");
        let real_cookie_header = format!("{}={}", parsed.name(), parsed.value());

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

        // === Phase 4: Use the session to access a protected route (existing manual path kept for coverage) ===
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

    /// Exercises the new inline tree meta + editor routes introduced for the
    /// directory permissions UI refresh. Uses a real temp dir so get_dir_meta
    /// has something to stat.
    #[tokio::test]
    async fn dir_meta_and_dir_editor_routes_work_with_real_fs_node() {
        let (state, tmp) = make_test_state_with_temp_config();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");

        // Create a real subdirectory under one of the allowed host_paths so
        // the UI routes have something to stat.
        let host_root = tmp.path().join("allowed");
        std::fs::create_dir_all(&host_root).unwrap();
        let sub = host_root.join("mysubdir");
        std::fs::create_dir(&sub).unwrap();

        let app = router(state);

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
}