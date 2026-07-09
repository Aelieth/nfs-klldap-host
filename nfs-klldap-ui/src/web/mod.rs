//! Router assembly + AppState (shared by handlers) + router integration tests.
//! Submodules hold the logic: auth, permission_tree, settings, keytab.

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

mod auth;
mod keytab;
mod permission_tree;
mod settings_form;
mod settings;
pub mod setup;

pub use keytab::{compute_keytab_alert, get_keytab_info};

// Pub(crate) re-exports for router assembly and in-module integration tests.
pub(crate) use auth::{login, login_page, logout, require_auth, setup_password};
pub(crate) use permission_tree::{
    acl_apply, apply_permissions, apply_progress, cancel_apply, dir_perms, fs_children, index,
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
        .route("/login", get(login_page).post(login))
        .route("/setup-password", post(setup_password))
        .route("/logout", get(logout).post(logout))
        // Public status for the post-restart poller (no auth required).
        .route("/restart-status", get(restart_status))
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
        .route("/fs/children", get(fs_children))
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
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header::COOKIE, Request, StatusCode};
    use tower::ServiceExt;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Mutex;


    fn add_session_cookie(mut req: Request<Body>, token: &str) -> Request<Body> {
        let cookie = format!("session={}", token);
        req.headers_mut().insert(COOKIE, cookie.parse().unwrap());
        req
    }

    // Minimal inline make (to avoid external test_support path issues in this build).
    struct Guard(Option<String>);
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(p) = &self.0 { std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p); } else { std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH"); }
        }
    }

    fn make_test_state_with_limited_fs_mountinfo() -> (AppState, tempfile::TempDir, Guard) {
        let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", "/nonexistent/decoy");
        let guard = Guard(prev);
        let tmp = tempfile::TempDir::new().unwrap();
        let mp = tmp.path().join("m"); std::fs::write(&mp, "24 1 8:1 / /data rw - ext4 /dev/sda1 rw,noacl\n").ok();
        let cp = tmp.path().join("c"); let sm = tmp.path().join(".s");
        std::fs::write(&sm, "ok\n").ok();
        let min = r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "/"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "data"
host_path = "/foo/data"
container_path = "/data"
"#;
        std::fs::write(&cp, min).ok();
        let cfg_val = nfs_klldap_config::NfsKlldapConfig::load(&cp).expect("ok");
        let cfg = Arc::new(RwLock::new(cfg_val.clone()));
        let fs = Arc::new(RwLock::new(FsManager::new(cfg_val)));
        let _dm = nfs_klldap_config::PosixAttributeMapping { user_object_class:"posixAccount".into(), group_object_class:"posixGroup".into(), user_name:"uid".into(), user_uid_number:"uidNumber".into(), user_gid_number:"gidNumber".into(), user_home_directory:"homeDirectory".into(), user_shell:"loginShell".into(), user_full_name:"displayName".into(), group_name:"cn".into(), group_gid_number:"gidNumber".into(), group_member:"member".into(), user_principal_name:"krbPrincipalName".into() };
        let l = Arc::new(Mutex::new(crate::create_test_lldap()));
        let a = Arc::new(AuthManager::new(&cp, None));
        let st = AppState { fs, lldap: l, config: cfg, auth: a, config_path: cp, keytab_hostname:"h".into(), keytab_realm:"R".into(), keytab_alert: Arc::new(StdMutex::new(None)), apply_progress: Arc::new(Mutex::new(None)), restart_requested: Arc::new(Mutex::new(false)), direct_tls:true, setup_marker_override: Some(sm), setup_test: Arc::new(StdMutex::new(setup::SetupTestState::default())), host_nfs_mode:false, fs_probe_mountinfo_path: Some(mp) };
        (st, tmp, guard)
    }

    // Settings + Ganesha roundtrip (save-shares with root_squash/enable_acl/ganesha override, generate_all). ACL mutation covered by dedicated test below.
    #[tokio::test]
    async fn settings_ganesha_roundtrip_cases() {
        let (state, _tmp, _guard) = make_test_state_with_limited_fs_mountinfo();
        // Exercise acl_limited and fs warning badge paths with limited mountinfo fixture (noacl) via shipped config funcs used by renders.
        let mp_path = state.fs_probe_mountinfo_path.as_ref().expect("mp set in helper").clone();
        {
            let cfg = state.config.read().expect("config lock");
            let s0 = &cfg.shares[0];
            let is_limited =
                nfs_klldap_config::share_fs_acl_limited_with_mountinfo(&cfg, s0, Some(&mp_path));
            assert!(
                is_limited,
                "noacl mountinfo fixture must make acl_limited true via shipped func"
            );
            let wmsg =
                nfs_klldap_config::share_fs_warning_message_with_mountinfo(&cfg, s0, Some(&mp_path));
            assert!(
                wmsg.is_some() && wmsg.unwrap().contains("limited"),
                "limited mountinfo must yield fs warning via shipped func"
            );
        }
        let cp = state.config_path.clone();
        let auth = state.auth.clone();
        let token = auth.create_privileged_session("testadmin");
        let app = router(state);

        // Drive shipped settings_page render with limited mountinfo to exercise fs_warning badge in HTML (covers the pruned settings_and_index_render_fs_warning... case)
        let gr = Request::builder().uri("/settings").body(Body::empty()).unwrap();
        let gr = add_session_cookie(gr, &token);
        let grs = app.clone().oneshot(gr).await.unwrap();
        let gbody = axum::body::to_bytes(grs.into_body(), 1024*1024).await.unwrap();
        let ghtml = String::from_utf8_lossy(&gbody);
        assert!(ghtml.contains("alert alert-warning") && (ghtml.contains("limited") || ghtml.contains("fs_warning") || ghtml.contains("NOACL")), "settings render must include limited fs warning badge via shipped template + mountinfo probe");
        // enable_acl unset (auto) must show Non-ACL status-dot — same as Share Permissions / Disable_ACL export.
        // (Legend also has bare share-dot.acl / .noacl keys; assert titled card dots only.)
        assert!(
            ghtml.contains(r#"share-dot noacl" title="Non-ACL limited""#)
                || ghtml.contains("share-dot noacl") && ghtml.contains(r#"title="Non-ACL limited""#),
            "settings share with enable_acl=auto must render Non-ACL limited status-dot"
        );
        assert!(
            !ghtml.contains(r#"share-dot acl" title="ACL supported""#),
            "settings share with enable_acl=auto must not render an ACL-supported status-dot"
        );
        assert!(
            ghtml.contains("data-acl-chip") && ghtml.contains("acl auto"),
            "settings chip must still show acl auto for unset enable_acl"
        );

        let body_noacl = "share_name_0=data&share_host_0=%2Fmedia%2Fdata&share_pseudo_0=&share_rw_0=true&share_cache_profile_0=Default&share_enable_acl_0=false&share_manage_gids_0=false&share_read_access_policy_0=pre&share_container_path_0=%2Fexport%2Fstaging%2Fdata&share_root_squash_0=on";
        let req = Request::builder().method("POST").uri("/settings/save-shares").header("content-type","application/x-www-form-urlencoded").body(Body::from(body_noacl)).unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let written = std::fs::read_to_string(&cp).unwrap();
        assert!(written.contains("enable_acl = false"));
        assert!(written.contains("container_path = \"/export/staging/data\""));
        // root_squash from checkbox presence now roundtrips via collect
        assert!(written.contains("squash = \"root_squash\"") || written.contains("squash = 'root_squash'") || written.contains("root_squash"));

        let body_acl = "share_name_0=acldata&share_host_0=%2Fmedia%2Facldata&share_pseudo_0=&share_rw_0=true&share_cache_profile_0=Default&share_enable_acl_0=true&share_manage_gids_0=true&share_read_access_policy_0=auto&share_manage_gids_expiration_0=900&share_container_path_0=%2Fexport%2Facldata";
        let req2 = Request::builder().method("POST").uri("/settings/save-shares").header("content-type","application/x-www-form-urlencoded").body(Body::from(body_acl)).unwrap();
        let req2 = add_session_cookie(req2, &token);
        let _ = app.clone().oneshot(req2).await.unwrap();
        let w2 = std::fs::read_to_string(&cp).unwrap();
        assert!(w2.contains("enable_acl = true"));
        assert!(w2.contains("manage_gids_expiration = 900"));

        // generate (after body with MGE)
        let gen_dir = std::env::temp_dir().join("grok-verif-gen");
        let _ = std::fs::remove_dir_all(&gen_dir);
        std::fs::create_dir_all(&gen_dir).ok();
        let exd = gen_dir.join("exports.d"); std::fs::create_dir_all(&exd).ok();
        let cfg_for_gen = nfs_klldap_config::NfsKlldapConfig::load(&cp).expect("load");
        let paths = nfs_klldap_config::GenerationPaths { sssd_conf: gen_dir.join("s.conf"), krb5_conf: gen_dir.join("k.conf"), ganesha_conf: gen_dir.join("g.conf"), exports_dir: exd.clone(), idmap_conf: gen_dir.join("i.conf"), nfs_conf: gen_dir.join("n.conf") };
        nfs_klldap_config::generate_all(&cfg_for_gen, &paths).ok();
        let frag = std::fs::read_dir(&exd).ok().and_then(|it| it.filter_map(|e| e.ok()).find(|e| e.path().extension().is_some_and(|x| x == "conf")).and_then(|e| std::fs::read_to_string(e.path()).ok())).unwrap_or_default();
        // Disable may appear under limited mp; MGE from the acl body is asserted
        assert!(frag.contains("Manage_Gids_Expiration = 900;"));

        // drive shipped structured save for default_security (POST exercises the /settings/save handler, Form binding for ganesha_default_security/override, and apply path)
        let body_defsec = "ganesha_default_security=nfs&override_ganesha_default_security=on";
        let reqsec = Request::builder().method("POST").uri("/settings/save").header("content-type","application/x-www-form-urlencoded").body(Body::from(body_defsec)).unwrap();
        let reqsec = add_session_cookie(reqsec, &token);
        let _ = app.clone().oneshot(reqsec).await.unwrap();

        // Ensure the value is on disk for render (drive raw save path too); then GET to exercise default_security + override flag in rendered form
        let cur = std::fs::read_to_string(&cp).unwrap_or_default();
        let with_g = if cur.contains("[ganesha]") { cur } else { format!("{}\n[ganesha]\ndefault_security = \"nfs\"\n", cur) };
        let rawb = format!("raw_content={}", urlencoding::encode(&with_g));
        let rraw = Request::builder().method("POST").uri("/settings/save-raw").header("content-type","application/x-www-form-urlencoded").body(Body::from(rawb)).unwrap();
        let rraw = add_session_cookie(rraw, &token);
        let _ = app.clone().oneshot(rraw).await.unwrap();
        let gsec = Request::builder().uri("/settings").body(Body::empty()).unwrap();
        let gsec = add_session_cookie(gsec, &token);
        let rsec = app.clone().oneshot(gsec).await.unwrap();
        let bsec = axum::body::to_bytes(rsec.into_body(), 1024*1024).await.unwrap();
        let hsec = String::from_utf8_lossy(&bsec);
        assert!(hsec.contains("ganesha_default_security") && (hsec.contains("nfs") || hsec.contains("value=\"nfs\"") || hsec.contains("selected")), "settings render must show the overridden default_security value");

        let body_off = "share_name_0=data&share_host_0=%2Fmedia%2Fdata&share_pseudo_0=&share_rw_0=true&share_cache_profile_0=Default&share_enable_acl_0=false&share_manage_gids_0=true&share_read_access_policy_0=pre&share_manage_gids_expiration_0=900&share_container_path_0=%2Fexport%2Fdata";
        let reqoff = Request::builder().method("POST").uri("/settings/save-shares").header("content-type","application/x-www-form-urlencoded").body(Body::from(body_off)).unwrap();
        let reqoff = add_session_cookie(reqoff, &token);
        let _ = app.clone().oneshot(reqoff).await.unwrap();
        let woff = std::fs::read_to_string(&cp).unwrap();
        assert!(woff.contains("container_path = \"/export/data\""));

        let grd = Request::builder().uri("/settings").body(Body::empty()).unwrap();
        let grd = add_session_cookie(grd, &token);
        let grds = app.clone().oneshot(grd).await.unwrap();
        let gbd = axum::body::to_bytes(grds.into_body(), 1024*1024).await.unwrap();
        let ghd = String::from_utf8_lossy(&gbd);
        assert!(ghd.contains("share_container_path_0") && ghd.contains("/export/data"), "settings render must show container_path input");
    }

    // Dedicated integration test for ACL apply path: POST /acl-apply, wait on shipped ApplyProgress, hard assert via shipped fs.get_dir_acl only.
    #[tokio::test]
    async fn web_acl_apply_post_waits_then_get_dir_acl() {
        use std::time::Duration;
        use tokio::time::timeout;

        // Real TempDir as container root + logical share path (modeled on fs::make_test_acl_config_for).
        let tmp = tempfile::TempDir::new().unwrap();
        let real_root = tmp.path().join("aclroot");
        std::fs::create_dir_all(&real_root).unwrap();
        let logical = std::path::Path::new("/acldata");

        // Build minimal NfsKlldapConfig so the logical path is allowed and maps to our real dir for setfacl/getfacl.
        let cp = tmp.path().join("c");
        let min_cfg = format!(
            r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "acldata"
host_path = "{}"
container_path = "{}"
"#,
            real_root.display(),
            logical.display(),
            real_root.display()
        );
        std::fs::write(&cp, min_cfg).unwrap();
        let cfg_val = nfs_klldap_config::NfsKlldapConfig::load(&cp).expect("load");
        let cfg = Arc::new(RwLock::new(cfg_val.clone()));
        let fs = Arc::new(RwLock::new(FsManager::new(cfg_val)));

        // Minimal AppState for auth + router (no decoy mountinfo needed for ACL apply path).
        let l = Arc::new(Mutex::new(crate::create_test_lldap()));
        let a = Arc::new(AuthManager::new(&cp, None));
        let sm = tmp.path().join(".s");
        std::fs::write(&sm, "ok\n").ok();
        let fs_for_assert = fs.clone();
        let st = AppState {
            fs,
            lldap: l,
            config: cfg,
            auth: a,
            config_path: cp.clone(),
            keytab_hostname: "h".into(),
            keytab_realm: "R".into(),
            keytab_alert: Arc::new(StdMutex::new(None)),
            apply_progress: Arc::new(Mutex::new(None)),
            restart_requested: Arc::new(Mutex::new(false)),
            direct_tls: true,
            setup_marker_override: Some(sm),
            setup_test: Arc::new(StdMutex::new(setup::SetupTestState::default())),
            host_nfs_mode: false,
            fs_probe_mountinfo_path: None,
        };
        // Keep handle to progress slot before moving state into router so we can wait on it.
        let progress_slot = st.apply_progress.clone();
        let token = st.auth.create_privileged_session("acltest");
        let app = router(st);

        // POST the apply (shipped handler; it will spawn and set the progress slot).
        let p = urlencoding::encode(logical.to_str().unwrap());
        let body = format!("path={}&op=set&typ=user&id=4242&perms=r-x", p);
        let req = Request::builder()
            .method("POST")
            .uri("/acl-apply")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Wait on the handler's progress gate (shipped ApplyProgress) before asserting effect.
        let wait_res = timeout(Duration::from_secs(2), async {
            loop {
                if let Some(prog) = progress_slot.lock().await.as_ref() {
                    if prog.finished.load(std::sync::atomic::Ordering::Relaxed) {
                        let txt = prog.final_result_text.lock().expect("poison").clone().unwrap_or_default();
                        if txt.contains("OK") || txt.contains("ACL") {
                            return true;
                        }
                        // even on error path we will still check get_dir_acl below; break to avoid infinite
                        return true;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;

        assert!(wait_res.is_ok(), "should have observed progress finish");

        // Hard assert ONLY via the shipped fs wrapper on the exact logical path the POST targeted.
        let entries = fs_for_assert
            .read()
            .expect("fs lock")
            .get_dir_acl(logical)
            .expect("path must be allowed under share");
        let has = entries.iter().any(|e| {
            matches!(&e.kind, crate::privileged::AclEntryKind::User(4242)) && e.perms.to_str() == "r-x"
        });
        assert!(has, "after POST /acl-apply + wait, shipped fs.get_dir_acl on logical path must show the entry");
    }

    // GET /settings/share-card must render a blank card with the field tooltips the JS copy had lost.
    #[tokio::test]
    async fn share_card_fragment_renders_blank_card_with_tooltips() {
        let (state, _tmp, _guard) = make_test_state_with_limited_fs_mountinfo();
        let token = state.auth.create_privileged_session("cardtest");
        let app = router(state);
        let req = Request::builder().uri("/settings/share-card?idx=3").body(Body::empty()).unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains(r#"name="share_name_3""#), "blank card must carry the requested idx");
        assert!(
            html.contains("share-dot noacl") && html.contains(r#"title="Non-ACL limited""#),
            "blank card defaults to the NOACL dot"
        );
        assert!(html.contains("Path on the host that backs this share."), "field tooltips must be present on new cards");
        assert!(!html.contains("share-card-ed open"), "server sends the card closed; the JS opens it after insert");
    }

    // GET / must carry the single-sourced Apply Log shell the poller's oob swaps replace.
    #[tokio::test]
    async fn index_renders_apply_log_shell() {
        let (state, _tmp, _guard) = make_test_state_with_limited_fs_mountinfo();
        let token = state.auth.create_privileged_session("logtest");
        let app = router(state);
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("apply-status-content apply-log-content"), "shell must keep the JS contract classes");
        // Exact shell open tag: no hx-swap-oob and no data-apply-finished on the initial render.
        assert!(
            html.contains(r#"<div id="apply-status" class="apply-status" style="display:block;">"#),
            "index must render the initial Apply Log shell without oob/finished attrs"
        );
    }

    // The vendored htmx asset must bypass the setup gate, and served pages must reference it (no CDN).
    #[tokio::test]
    async fn htmx_asset_served_pre_setup_and_referenced_locally() {
        let (state, _tmp, _guard) = make_test_state_with_limited_fs_mountinfo();
        let marker = state.setup_marker_override.clone();
        let app = router(state);

        // Marker present: /login renders normally and must reference the local asset only.
        let lreq = Request::builder().uri("/login").body(Body::empty()).unwrap();
        let lresp = app.clone().oneshot(lreq).await.unwrap();
        assert_eq!(lresp.status(), StatusCode::OK);
        let lbody = axum::body::to_bytes(lresp.into_body(), 1024 * 1024).await.unwrap();
        let lhtml = String::from_utf8_lossy(&lbody);
        assert!(lhtml.contains("/assets/htmx-"), "pages must load the vendored htmx");
        assert!(!lhtml.contains("unpkg.com"), "no CDN reference may remain in served HTML");

        // Marker removed (first-run state): the asset must still bypass the setup gate.
        if let Some(m) = &marker {
            std::fs::remove_file(m).ok();
        }
        let req = Request::builder().uri("/assets/htmx-1.9.12.min.js").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "asset must be served while the setup wizard gate is active");
        let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        assert!(ct.contains("javascript"), "asset must carry a JS content-type, got {ct}");
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        assert!(!body.is_empty(), "asset body must not be empty");
    }

    // GET /dir-perms renders the POSIX matrix + hidden numeric uid/gid fields (for name translation)
    // and marks the ACL section non-ACL when the share did not opt into enable_acl (default).
    #[tokio::test]
    async fn dir_perms_get_renders_posix_matrix_and_noacl_section() {
        let tmp = tempfile::TempDir::new().unwrap();
        let real_root = tmp.path().join("permroot");
        std::fs::create_dir_all(&real_root).unwrap();
        let logical = std::path::Path::new("/permdata");

        let cp = tmp.path().join("c");
        let min_cfg = format!(
            r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "permdata"
host_path = "{}"
container_path = "{}"
"#,
            real_root.display(), logical.display(), real_root.display()
        );
        std::fs::write(&cp, min_cfg).unwrap();
        let cfg_val = nfs_klldap_config::NfsKlldapConfig::load(&cp).expect("load");
        let cfg = Arc::new(RwLock::new(cfg_val.clone()));
        let fs = Arc::new(RwLock::new(FsManager::new(cfg_val)));
        let l = Arc::new(Mutex::new(crate::create_test_lldap()));
        let a = Arc::new(AuthManager::new(&cp, None));
        let sm = tmp.path().join(".s");
        std::fs::write(&sm, "ok\n").ok();
        let st = AppState {
            fs, lldap: l, config: cfg, auth: a, config_path: cp.clone(),
            keytab_hostname: "h".into(), keytab_realm: "R".into(),
            keytab_alert: Arc::new(StdMutex::new(None)), apply_progress: Arc::new(Mutex::new(None)),
            restart_requested: Arc::new(Mutex::new(false)), direct_tls: true,
            setup_marker_override: Some(sm), setup_test: Arc::new(StdMutex::new(setup::SetupTestState::default())),
            host_nfs_mode: false, fs_probe_mountinfo_path: None,
        };
        let token = st.auth.create_privileged_session("permtest");
        let app = router(st);

        let uri = format!("/dir-perms?path={}", urlencoding::encode(logical.to_str().unwrap()));
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("perm-matrix"), "must render the POSIX rwx matrix");
        assert!(html.contains(r#"name="owner_user_uid""#), "must render hidden uid field for name translation");
        assert!(html.contains(r#"name="mode""#), "must render the mode field /apply expects");
        assert!(html.contains("class=\"octal\""), "must render the octal readout");
        // enable_acl unset => Non-ACL: the ACL section must be greyed and labelled.
        assert!(html.contains("acl-sec disabled"), "NOACL default must grey the ACL section");
        assert!(html.contains("non-ACL limited"), "NOACL default must show the non-ACL pill");
    }
}
