//! First-run 3-step WebUI setup wizard (replaces the terminal TUI).

use askama::Template;
use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
};
use nfs_klldap_config::{
    attempt_realm_from_config, check_ldap_bind, check_ldap_reachability, check_persistent_writable,
    compute_startup_step, extract_host_from_uri, format_nfs_principal_list, get_consistent_hostname,
    is_preconfigured_deployment, is_setup_wizard_complete, is_step_complete,
    mark_setup_wizard_complete, resolve_keytab_path, StartupStep,
};
use serde::Deserialize;
use std::path::Path;

/// Shared context for all setup step templates.
#[derive(Template)]
#[template(path = "setup_step1.html")]
pub(crate) struct SetupStep1Template {
    pub message: Option<String>,
    pub error: Option<String>,
    pub verified: bool,
    pub hostname: String,
    pub principals: String,
    pub realm: String,
    pub config_path: String,
    pub current_user: Option<String>,
    pub keytab_alert: Option<String>,
}

#[derive(Template)]
#[template(path = "setup_step2.html")]
pub(crate) struct SetupStep2Template {
    pub message: Option<String>,
    pub error: Option<String>,
    pub ldap_uri: String,
    pub test_passed: bool,
    pub step1_done: bool,
    pub hostname: String,
    pub principals: String,
    pub current_user: Option<String>,
    pub keytab_alert: Option<String>,
}

#[derive(Template)]
#[template(path = "setup_step3.html")]
pub(crate) struct SetupStep3Template {
    pub message: Option<String>,
    pub error: Option<String>,
    pub bind_dn: String,
    pub test_passed: bool,
    pub step1_done: bool,
    pub step2_done: bool,
    pub hostname: String,
    pub principals: String,
    pub current_user: Option<String>,
    pub keytab_alert: Option<String>,
}

#[derive(Template)]
#[template(path = "setup_complete.html")]
pub(crate) struct SetupCompleteTemplate;

#[derive(Deserialize)]
pub(crate) struct LdapUriForm {
    pub ldap_uri: String,
}

#[derive(Deserialize)]
pub(crate) struct BindForm {
    pub ldap_default_bind_dn: String,
    pub ldap_default_authtok: String,
}

/// True when the wizard must run before login and protected routes.
pub fn setup_wizard_required_with_marker(
    config_path: &Path,
    marker_override: Option<&Path>,
) -> bool {
    if is_preconfigured_deployment(config_path, &resolve_keytab_path()) {
        return false;
    }
    let complete = marker_override
        .map(|p| p.is_file())
        .unwrap_or_else(is_setup_wizard_complete);
    if complete {
        return false;
    }
    compute_startup_step(config_path) != StartupStep::Ready
}

/// Redirect target for incomplete setup.
pub fn setup_redirect_for_step(config_path: &Path) -> String {
    if is_preconfigured_deployment(config_path, &resolve_keytab_path()) {
        return "/login".into();
    }
    match compute_startup_step(config_path).wizard_index() {
        Some(n) => format!("/setup/{n}"),
        None => "/login".into(),
    }
}

fn banner_context(config_path: &Path) -> (String, String) {
    let hostname = get_consistent_hostname()
        .map(|c| c.hostname)
        .unwrap_or_else(|_| "your-container-hostname".into());
    let realm = attempt_realm_from_config(config_path)
        .or_else(|| {
            nfs_klldap_config::NfsKlldapConfig::load(config_path)
                .ok()
                .map(|c| c.display_realm())
        })
        .unwrap_or_else(|| "YOUR.REALM".into());
    let principals = format_nfs_principal_list(&hostname, &realm);
    (hostname, principals)
}

fn read_ldap_uri_from_disk(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| {
            let doc: toml_edit::DocumentMut = raw.parse().ok()?;
            doc.get("ldap_uri")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default()
}

fn read_bind_dn_from_disk(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| {
            let doc: toml_edit::DocumentMut = raw.parse().ok()?;
            doc.get("sssd")
                .and_then(|v| v.get("ldap_default_bind_dn"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default()
}

fn write_ldap_uri(path: &Path, uri: &str) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = raw.parse().unwrap_or_default();
    doc["ldap_uri"] = toml_edit::value(uri.trim().to_string());
    atomic_write_config(path, &doc.to_string())
}

fn write_bind_creds(path: &Path, dn: &str, pw: &str) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = raw.parse().unwrap_or_default();
    let item = doc.entry("sssd").or_insert(toml_edit::table());
    if let Some(tbl) = item.as_table_mut() {
        tbl["ldap_default_bind_dn"] = toml_edit::value(dn.trim().to_string());
        tbl["ldap_default_authtok"] = toml_edit::value(pw.to_string());
    }
    atomic_write_config(path, &doc.to_string())
}

fn atomic_write_config(path: &Path, content: &str) -> Result<(), String> {
    let tmp = path.with_extension("conf.saving");
    std::fs::write(&tmp, content.as_bytes()).map_err(|e| format!("Write failed: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("Rename failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// GET /setup — jump to the current wizard step.
pub async fn setup_redirect(State(state): State<super::AppState>) -> impl IntoResponse {
    Redirect::to(&setup_redirect_for_step(&state.config_path)).into_response()
}

/// GET /setup/1
pub async fn setup_step1(State(state): State<super::AppState>) -> impl IntoResponse {
    let step = compute_startup_step(&state.config_path);
    if step != StartupStep::WaitForPersistentVolume && step != StartupStep::Ready {
        return Redirect::to(&setup_redirect_for_step(&state.config_path)).into_response();
    }
    if step == StartupStep::Ready {
        return Redirect::to("/login").into_response();
    }
    let (hostname, principals) = banner_context(&state.config_path);
    let realm = attempt_realm_from_config(&state.config_path).unwrap_or_else(|| "YOUR.REALM".into());
    let verified = check_persistent_writable(&state.config_path);
    Html(
        SetupStep1Template {
            message: None,
            error: None,
            verified,
            hostname,
            principals,
            realm,
            config_path: state.config_path.display().to_string(),
            current_user: None,
            keytab_alert: None,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// POST /setup/1/verify
pub async fn setup_step1_verify(State(state): State<super::AppState>) -> impl IntoResponse {
    if check_persistent_writable(&state.config_path) {
        Redirect::to("/setup/2").into_response()
    } else {
        let (hostname, principals) = banner_context(&state.config_path);
        let realm =
            attempt_realm_from_config(&state.config_path).unwrap_or_else(|| "YOUR.REALM".into());
        let html = SetupStep1Template {
            message: None,
            error: Some(
                "Persistent volume not detected or not writable. Bind-mount a host directory at /config.".into(),
            ),
            verified: false,
            hostname,
            principals,
            realm,
            config_path: state.config_path.display().to_string(),
            current_user: None,
            keytab_alert: None,
        }
        .render()
        .unwrap();
        (StatusCode::BAD_REQUEST, Html(html)).into_response()
    }
}

/// GET /setup/2
pub async fn setup_step2(State(state): State<super::AppState>) -> impl IntoResponse {
    let step = compute_startup_step(&state.config_path);
    if step == StartupStep::WaitForPersistentVolume {
        return Redirect::to("/setup/1").into_response();
    }
    if step == StartupStep::AddBindCredentials || step == StartupStep::Ready {
        return Redirect::to(&setup_redirect_for_step(&state.config_path)).into_response();
    }
    let (hostname, principals) = banner_context(&state.config_path);
    let ldap_uri = read_ldap_uri_from_disk(&state.config_path);
    let step1_done = is_step_complete(StartupStep::WaitForPersistentVolume, step);
    Html(
        SetupStep2Template {
            message: None,
            error: None,
            ldap_uri,
            test_passed: false,
            step1_done,
            hostname,
            principals,
            current_user: None,
            keytab_alert: None,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// POST /setup/2/test — save ldap_uri and probe reachability without advancing.
pub async fn setup_step2_test(
    State(state): State<super::AppState>,
    Form(form): Form<LdapUriForm>,
) -> impl IntoResponse {
    let uri = form.ldap_uri.trim();
    if uri.is_empty() || (!uri.starts_with("ldap://") && !uri.starts_with("ldaps://")) {
        return render_step2_error(&state, "ldap_uri must start with ldap:// or ldaps://", Some(uri))
            .into_response();
    }
    if nfs_klldap_config::host_is_ip(&nfs_klldap_config::extract_host_from_uri(uri)) {
        return render_step2_error(
            &state,
            "ldap_uri must use a DNS hostname, not an IP address.",
            Some(uri),
        )
        .into_response();
    }
    if let Err(e) = write_ldap_uri(&state.config_path, uri) {
        return render_step2_error(&state, &e, Some(uri)).into_response();
    }
    let host = extract_host_from_uri(uri);
    match check_ldap_reachability(&host, uri) {
        nfs_klldap_config::LdapReachability::Reachable => {
            render_step2_page(&state, Some("Reachability test passed."), None, true, None)
                .into_response()
        }
        other => render_step2_error(&state, &other.user_message(), None).into_response(),
    }
}

/// POST /setup/2/continue — re-probe saved ldap_uri and advance to step 3.
pub async fn setup_step2_continue(State(state): State<super::AppState>) -> impl IntoResponse {
    let uri = read_ldap_uri_from_disk(&state.config_path);
    if uri.trim().is_empty() {
        return render_step2_error(&state, "Test settings before continuing.", None).into_response();
    }
    let host = extract_host_from_uri(&uri);
    match check_ldap_reachability(&host, &uri) {
        nfs_klldap_config::LdapReachability::Reachable => Redirect::to("/setup/3").into_response(),
        other => render_step2_error(&state, &other.user_message(), None).into_response(),
    }
}

/// GET /setup/3
pub async fn setup_step3(State(state): State<super::AppState>) -> impl IntoResponse {
    let step = compute_startup_step(&state.config_path);
    if step == StartupStep::WaitForPersistentVolume {
        return Redirect::to("/setup/1").into_response();
    }
    if step == StartupStep::SetLdapUri {
        return Redirect::to("/setup/2").into_response();
    }
    if step == StartupStep::Ready {
        return Redirect::to("/login").into_response();
    }
    let (hostname, principals) = banner_context(&state.config_path);
    let bind_dn = read_bind_dn_from_disk(&state.config_path);
    let step = compute_startup_step(&state.config_path);
    Html(
        SetupStep3Template {
            message: None,
            error: None,
            bind_dn,
            test_passed: false,
            step1_done: is_step_complete(StartupStep::WaitForPersistentVolume, step),
            step2_done: is_step_complete(StartupStep::SetLdapUri, step),
            hostname,
            principals,
            current_user: None,
            keytab_alert: None,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// POST /setup/3/test — save bind creds and probe ldapsearch without advancing.
pub async fn setup_step3_test(
    State(state): State<super::AppState>,
    Form(form): Form<BindForm>,
) -> impl IntoResponse {
    if form.ldap_default_bind_dn.trim().is_empty() {
        return render_step3_error(&state, "Bind DN is required.", Some(&form.ldap_default_bind_dn))
            .into_response();
    }
    if form.ldap_default_authtok.trim().is_empty() {
        return render_step3_error(&state, "Bind password is required.", Some(&form.ldap_default_bind_dn))
            .into_response();
    }
    if let Err(e) = write_bind_creds(
        &state.config_path,
        &form.ldap_default_bind_dn,
        &form.ldap_default_authtok,
    ) {
        return render_step3_error(&state, &e, Some(&form.ldap_default_bind_dn)).into_response();
    }
    let cfg = match nfs_klldap_config::NfsKlldapConfig::load(&state.config_path) {
        Ok(c) => c,
        Err(e) => return render_step3_error(&state, &e.to_string(), None).into_response(),
    };
    match check_ldap_bind(&cfg) {
        Ok(()) => render_step3_page(
            &state,
            Some("Bind test passed."),
            None,
            true,
            Some(&form.ldap_default_bind_dn),
        )
        .into_response(),
        Err(e) => render_step3_error(&state, &e, Some(&form.ldap_default_bind_dn)).into_response(),
    }
}

/// POST /setup/3/continue — re-probe bind, mark wizard done, show completion interstitial.
pub async fn setup_step3_continue(State(state): State<super::AppState>) -> impl IntoResponse {
    let cfg = match nfs_klldap_config::NfsKlldapConfig::load(&state.config_path) {
        Ok(c) => c,
        Err(e) => return render_step3_error(&state, &e.to_string(), None).into_response(),
    };
    match check_ldap_bind(&cfg) {
        Ok(()) => {
            if compute_startup_step(&state.config_path) == StartupStep::Ready {
                let _ = mark_setup_wizard_complete();
                Redirect::to("/setup/complete").into_response()
            } else {
                render_step3_error(
                    &state,
                    "Test settings before continuing.",
                    Some(&cfg.sssd.ldap_default_bind_dn),
                )
                .into_response()
            }
        }
        Err(e) => render_step3_error(&state, &e, None).into_response(),
    }
}

/// GET /setup/complete — brief pause before redirecting to login.
pub async fn setup_complete() -> impl IntoResponse {
    Html(SetupCompleteTemplate.render().unwrap()).into_response()
}

fn render_step2_page(
    state: &super::AppState,
    message: Option<&str>,
    error: Option<&str>,
    test_passed: bool,
    ldap_uri_override: Option<&str>,
) -> (StatusCode, Html<String>) {
    let step = compute_startup_step(&state.config_path);
    let (hostname, principals) = banner_context(&state.config_path);
    let ldap_uri = ldap_uri_override
        .map(str::to_string)
        .unwrap_or_else(|| read_ldap_uri_from_disk(&state.config_path));
    let html = SetupStep2Template {
        message: message.map(str::to_string),
        error: error.map(str::to_string),
        ldap_uri,
        test_passed,
        step1_done: is_step_complete(StartupStep::WaitForPersistentVolume, step),
        hostname,
        principals,
        current_user: None,
        keytab_alert: None,
    }
    .render()
    .unwrap();
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    (status, Html(html))
}

fn render_step2_error(
    state: &super::AppState,
    err: &str,
    ldap_uri_override: Option<&str>,
) -> (StatusCode, Html<String>) {
    render_step2_page(state, None, Some(err), false, ldap_uri_override)
}

fn render_step3_page(
    state: &super::AppState,
    message: Option<&str>,
    error: Option<&str>,
    test_passed: bool,
    bind_dn_override: Option<&str>,
) -> (StatusCode, Html<String>) {
    let step = compute_startup_step(&state.config_path);
    let (hostname, principals) = banner_context(&state.config_path);
    let bind_dn = bind_dn_override
        .map(str::to_string)
        .unwrap_or_else(|| read_bind_dn_from_disk(&state.config_path));
    let html = SetupStep3Template {
        message: message.map(str::to_string),
        error: error.map(str::to_string),
        bind_dn,
        test_passed,
        step1_done: is_step_complete(StartupStep::WaitForPersistentVolume, step),
        step2_done: is_step_complete(StartupStep::SetLdapUri, step),
        hostname,
        principals,
        current_user: None,
        keytab_alert: None,
    }
    .render()
    .unwrap();
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    (status, Html(html))
}

fn render_step3_error(
    state: &super::AppState,
    err: &str,
    bind_dn_override: Option<&str>,
) -> (StatusCode, Html<String>) {
    render_step3_page(state, None, Some(err), false, bind_dn_override)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TestPersistentEnv;

    impl TestPersistentEnv {
        fn set() -> Self {
            std::env::set_var("NFS_KLLDAP_TEST_PERSISTENT", "1");
            Self
        }
    }

    impl Drop for TestPersistentEnv {
        fn drop(&mut self) {
            std::env::remove_var("NFS_KLLDAP_TEST_PERSISTENT");
        }
    }

    fn complete_preconf_toml() -> &'static str {
        r#"
ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
"#
    }

    struct TestKeytabEnv {
        _tmp: tempfile::TempDir,
        _persist: TestPersistentEnv,
    }

    impl TestKeytabEnv {
        fn with_keytab(contents: &[u8]) -> (Self, std::path::PathBuf, std::path::PathBuf) {
            let persist = TestPersistentEnv::set();
            let tmp = tempfile::tempdir().unwrap();
            let conf = tmp.path().join("nfs-klldap.conf");
            let kt = tmp.path().join("krb5.keytab");
            fs::write(&conf, complete_preconf_toml()).unwrap();
            fs::write(&kt, contents).unwrap();
            std::env::set_var("NFS_KLLDAP_KEYTAB_PATH", kt.to_str().unwrap());
            (Self { _tmp: tmp, _persist: persist }, conf, kt)
        }
    }

    impl Drop for TestKeytabEnv {
        fn drop(&mut self) {
            std::env::remove_var("NFS_KLLDAP_KEYTAB_PATH");
            std::env::remove_var("NFS_KLLDAP_TEST_PERSISTENT");
        }
    }

    #[test]
    fn setup_wizard_skipped_for_preconfigured_conf_and_keytab() {
        let (_env, conf, _kt) = TestKeytabEnv::with_keytab(b"fake-keytab");
        assert!(!setup_wizard_required_with_marker(&conf, None));
    }

    #[test]
    fn setup_redirect_goes_to_login_for_preconfigured_deployment() {
        let (_env, conf, _kt) = TestKeytabEnv::with_keytab(b"fake-keytab");
        assert_eq!(setup_redirect_for_step(&conf), "/login");
    }

    #[test]
    fn setup_wizard_required_when_config_incomplete() {
        let _persist = TestPersistentEnv::set();
        std::env::remove_var("NFS_KLLDAP_KEYTAB_PATH");
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        let absent_marker = tmp.path().join("no_marker");
        fs::write(&conf, "ldap_uri = \"ldaps://x.test:6360\"\n").unwrap();
        assert!(setup_wizard_required_with_marker(
            &conf,
            Some(&absent_marker)
        ));
    }

    #[test]
    fn setup_redirect_for_step_maps_indices() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        fs::write(&conf, "").unwrap();
        let target = setup_redirect_for_step(&conf);
        assert!(target.starts_with("/setup/") || target == "/login");
    }

    #[test]
    fn write_ldap_uri_updates_document() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        fs::write(&conf, "# empty\n").unwrap();
        write_ldap_uri(&conf, "ldaps://ldap.example.com:6360").unwrap();
        let raw = fs::read_to_string(&conf).unwrap();
        assert!(raw.contains("ldaps://ldap.example.com:6360"));
    }

    #[test]
    fn write_bind_creds_updates_sssd_section() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        fs::write(&conf, "ldap_uri = \"ldaps://x.test:6360\"\n").unwrap();
        write_bind_creds(&conf, "uid=admin,dc=test", "sekret").unwrap();
        let raw = fs::read_to_string(&conf).unwrap();
        assert!(raw.contains("uid=admin,dc=test"));
        assert!(raw.contains("sekret"));
    }

    #[test]
    fn setup_complete_template_renders() {
        let html = SetupCompleteTemplate.render().unwrap();
        assert!(html.contains("Settings successfully saved, loading"));
    }
}