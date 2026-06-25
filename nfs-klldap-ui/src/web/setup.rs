//! First-run 3-step WebUI setup wizard at /setup/1 … /setup/3.

use askama::Template;
use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json, Redirect},
};
use serde::Serialize;
use nfs_klldap_config::{
    attempt_realm_from_config, check_ldap_bind, check_ldap_reachability, check_persistent_writable,
    compute_wizard_step, extract_host_from_uri, format_bind_probe, format_nfs_principal_list,
    format_reachability_probe, format_volume_probe, get_consistent_hostname,
    is_preconfigured_deployment, is_setup_wizard_complete, is_step_complete,
    mark_setup_wizard_complete, resolve_keytab_path, StartupStep,
};
use serde::Deserialize;
use std::path::Path;

/// Last successful probe inputs per wizard step.
/// Not written to disk until continue.
#[derive(Default)]
pub struct SetupTestState {
    pub step2_uri: Option<String>,
    pub step3_dn: Option<String>,
    pub step3_pw: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct SetupTestResponse {
    ok: bool,
    message: Option<String>,
    error: Option<String>,
    log: Option<String>,
}

/// Shared context for all setup step templates.
#[derive(Template)]
#[template(path = "setup_step1.html")]
pub(crate) struct SetupStep1Template {
    pub message: Option<String>,
    pub error: Option<String>,
    pub test_log: Option<String>,
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
    pub step1_done: bool,
    pub step2_done: bool,
    pub hostname: String,
    pub principals: String,
    pub current_user: Option<String>,
    pub keytab_alert: Option<String>,
}

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
    !complete
}

/// Redirect for incomplete setup (structural checks only, no LDAP probes).
pub fn setup_redirect_for_step(config_path: &Path) -> String {
    if is_preconfigured_deployment(config_path, &resolve_keytab_path()) {
        return "/login".into();
    }
    if is_setup_wizard_complete() {
        return "/login".into();
    }
    match compute_wizard_step(config_path).wizard_index() {
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

fn is_wizard_complete(state: &super::AppState) -> bool {
    state
        .setup_marker_override
        .as_ref()
        .map(|p| p.is_file())
        .unwrap_or_else(is_setup_wizard_complete)
}

fn validate_ldap_uri(uri: &str) -> Result<&str, String> {
    let uri = uri.trim();
    if uri.is_empty() || (!uri.starts_with("ldap://") && !uri.starts_with("ldaps://")) {
        return Err("ldap_uri must start with ldap:// or ldaps://".into());
    }
    if nfs_klldap_config::host_is_ip(&nfs_klldap_config::extract_host_from_uri(uri)) {
        return Err("ldap_uri must use a DNS hostname, not an IP address.".into());
    }
    Ok(uri)
}

/// True when continue may proceed for step 2.
pub(crate) fn step2_test_matches(cached: Option<&str>, submitted: &str) -> bool {
    cached.is_some_and(|c| c == submitted.trim())
}

/// True when continue may proceed for step 3.
pub(crate) fn step3_test_matches(
    cached_dn: Option<&str>,
    cached_pw: Option<&str>,
    dn: &str,
    pw: &str,
) -> bool {
    cached_dn.is_some_and(|c| c == dn.trim())
        && cached_pw.is_some_and(|c| c == pw)
}

fn run_bind_probe_from_disk(path: &Path) -> Option<(Result<(), String>, String)> {
    let cfg = nfs_klldap_config::NfsKlldapConfig::load(path).ok()?;
    if cfg.ldap_uri.trim().is_empty()
        || cfg.sssd.ldap_default_bind_dn.trim().is_empty()
        || cfg.sssd.ldap_default_authtok.trim().is_empty()
    {
        return None;
    }
    let result = check_ldap_bind(&cfg);
    let log = format_bind_probe(&cfg, result.clone());
    Some((result, log))
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

/// GET /setup/1.
pub async fn setup_step1(State(state): State<super::AppState>) -> impl IntoResponse {
    if is_wizard_complete(&state) {
        return Redirect::to("/login").into_response();
    }
    let step = compute_wizard_step(&state.config_path);
    if step != StartupStep::WaitForPersistentVolume {
        return Redirect::to(&setup_redirect_for_step(&state.config_path)).into_response();
    }
    let (hostname, principals) = banner_context(&state.config_path);
    let realm = attempt_realm_from_config(&state.config_path).unwrap_or_else(|| "YOUR.REALM".into());
    let config_path = state.config_path.clone();
    let verified = tokio::task::spawn_blocking(move || check_persistent_writable(&config_path))
        .await
        .unwrap_or(false);
    let test_log = Some(format_volume_probe(&state.config_path, verified));
    Html(
        SetupStep1Template {
            message: None,
            error: None,
            test_log,
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

/// POST /setup/1/verify.
pub async fn setup_step1_verify(State(state): State<super::AppState>) -> impl IntoResponse {
    let config_path = state.config_path.clone();
    let verified = tokio::task::spawn_blocking(move || check_persistent_writable(&config_path))
        .await
        .unwrap_or(false);
    if verified {
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
            test_log: Some(format_volume_probe(&state.config_path, false)),
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

/// GET /setup/2.
pub async fn setup_step2(State(state): State<super::AppState>) -> impl IntoResponse {
    if is_wizard_complete(&state) {
        return Redirect::to("/login").into_response();
    }
    let step = compute_wizard_step(&state.config_path);
    if step == StartupStep::WaitForPersistentVolume {
        return Redirect::to("/setup/1").into_response();
    }
    if step == StartupStep::AddBindCredentials {
        return Redirect::to("/setup/3").into_response();
    }
    let (hostname, principals) = banner_context(&state.config_path);
    let ldap_uri = read_ldap_uri_from_disk(&state.config_path);
    let step1_done = is_step_complete(StartupStep::WaitForPersistentVolume, step);
    Html(
        SetupStep2Template {
            message: None,
            error: None,
            ldap_uri,
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

/// POST /setup/2/test — probe reachability from form without writing config.
pub async fn setup_step2_test(
    State(state): State<super::AppState>,
    Form(form): Form<LdapUriForm>,
) -> impl IntoResponse {
    let uri = match validate_ldap_uri(&form.ldap_uri) {
        Ok(u) => u,
        Err(e) => {
            clear_step2_test(&state);
            let log = format!(
                "<strong>Command</strong>\n(validation)\n\n<strong>Status</strong>\n{e}"
            );
            return Json(SetupTestResponse {
                ok: false,
                message: None,
                error: Some(e),
                log: Some(log),
            })
            .into_response();
        }
    };
    let host = extract_host_from_uri(uri);
    let host_probe = host.clone();
    let uri_owned = uri.to_string();
    let result = tokio::task::spawn_blocking(move || check_ldap_reachability(&host_probe, &uri_owned))
        .await
        .unwrap_or(nfs_klldap_config::LdapReachability::Unreachable {
            detail: "Reachability probe task failed".into(),
        });
    let log = format_reachability_probe(&host, uri, &result);
    match result {
        nfs_klldap_config::LdapReachability::Reachable => {
            store_step2_test(&state, uri);
            Json(SetupTestResponse {
                ok: true,
                message: Some("Reachability test passed.".into()),
                error: None,
                log: Some(log),
            })
            .into_response()
        }
        other => {
            clear_step2_test(&state);
            Json(SetupTestResponse {
                ok: false,
                message: None,
                error: Some(other.user_message()),
                log: Some(log),
            })
            .into_response()
        }
    }
}

/// POST /setup/2/continue — save ldap_uri after a matching test, then advance.
pub async fn setup_step2_continue(
    State(state): State<super::AppState>,
    Form(form): Form<LdapUriForm>,
) -> impl IntoResponse {
    let uri = match validate_ldap_uri(&form.ldap_uri) {
        Ok(u) => u,
        Err(e) => return render_step2_error(&state, &e, Some(&form.ldap_uri)).into_response(),
    };
    let cached = state.setup_test.lock().unwrap().step2_uri.clone();
    if !step2_test_matches(cached.as_deref(), uri) {
        return render_step2_error(&state, "Test settings before continuing.", Some(uri))
            .into_response();
    }
    if let Err(e) = write_ldap_uri(&state.config_path, uri) {
        return render_step2_error(&state, &e, Some(uri)).into_response();
    }
    clear_step2_test(&state);
    Redirect::to("/setup/3").into_response()
}

fn store_step2_test(state: &super::AppState, uri: &str) {
    let mut t = state.setup_test.lock().unwrap();
    t.step2_uri = Some(uri.trim().to_string());
}

fn clear_step2_test(state: &super::AppState) {
    state.setup_test.lock().unwrap().step2_uri = None;
}

/// GET /setup/3.
pub async fn setup_step3(State(state): State<super::AppState>) -> impl IntoResponse {
    if is_wizard_complete(&state) {
        return Redirect::to("/login").into_response();
    }
    let step = compute_wizard_step(&state.config_path);
    if step == StartupStep::WaitForPersistentVolume {
        return Redirect::to("/setup/1").into_response();
    }
    if step == StartupStep::SetLdapUri {
        return Redirect::to("/setup/2").into_response();
    }
    let (hostname, principals) = banner_context(&state.config_path);
    let bind_dn = read_bind_dn_from_disk(&state.config_path);
    Html(
        SetupStep3Template {
            message: None,
            error: None,
            bind_dn,
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

/// POST /setup/3/test — probe bind from form without writing config.
pub async fn setup_step3_test(
    State(state): State<super::AppState>,
    Form(form): Form<BindForm>,
) -> impl IntoResponse {
    if form.ldap_default_bind_dn.trim().is_empty() {
        clear_step3_test(&state);
        let log = "<strong>Command</strong>\n(validation)\n\n<strong>Status</strong>\nBind DN is required.".to_string();
        return Json(SetupTestResponse {
            ok: false,
            message: None,
            error: Some("Bind DN is required.".into()),
            log: Some(log),
        })
        .into_response();
    }
    if form.ldap_default_authtok.trim().is_empty() {
        clear_step3_test(&state);
        let log = "<strong>Command</strong>\n(validation)\n\n<strong>Status</strong>\nBind password is required.".to_string();
        return Json(SetupTestResponse {
            ok: false,
            message: None,
            error: Some("Bind password is required.".into()),
            log: Some(log),
        })
        .into_response();
    }
    let config_path = state.config_path.clone();
    let dn = form.ldap_default_bind_dn.clone();
    let pw = form.ldap_default_authtok.clone();
    let (result, log) = tokio::task::spawn_blocking(move || {
        run_bind_probe_blocking(&config_path, &dn, &pw)
    })
    .await
    .unwrap_or((
        Err("Bind probe task failed".into()),
        "<strong>Status</strong>\nBind probe task failed".to_string(),
    ));
    match result {
        Ok(()) => {
            store_step3_test(
                &state,
                &form.ldap_default_bind_dn,
                &form.ldap_default_authtok,
            );
            Json(SetupTestResponse {
                ok: true,
                message: Some("Bind test passed.".into()),
                error: None,
                log: Some(log),
            })
            .into_response()
        }
        Err(e) => {
            clear_step3_test(&state);
            Json(SetupTestResponse {
                ok: false,
                message: None,
                error: Some(e),
                log: Some(log),
            })
            .into_response()
        }
    }
}

/// POST /setup/3/continue: save bind creds after test, finish wizard.
pub async fn setup_step3_continue(
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
    let matches = {
        let cached = state.setup_test.lock().unwrap();
        step3_test_matches(
            cached.step3_dn.as_deref(),
            cached.step3_pw.as_deref(),
            &form.ldap_default_bind_dn,
            &form.ldap_default_authtok,
        )
    };
    if !matches {
        return render_step3_error(&state, "Test settings before continuing.", Some(&form.ldap_default_bind_dn))
            .into_response();
    }
    if let Err(e) = write_bind_creds(
        &state.config_path,
        &form.ldap_default_bind_dn,
        &form.ldap_default_authtok,
    ) {
        return render_step3_error(&state, &e, Some(&form.ldap_default_bind_dn)).into_response();
    }
    let _ = mark_setup_wizard_complete();
    clear_step3_test(&state);
    let _ = super::settings::try_schedule_service_recycle(
        &state,
        "First-run setup complete",
    )
    .await;
    super::settings::render_restarting_page().into_response()
}

/// GET /setup/3/status: background bind probe with on-disk creds.
pub async fn setup_step3_status(State(state): State<super::AppState>) -> impl IntoResponse {
    let config_path = state.config_path.clone();
    let probe = tokio::task::spawn_blocking(move || run_bind_probe_from_disk(&config_path))
        .await
        .ok()
        .flatten();
    let Some((result, log)) = probe else {
        return Json(SetupTestResponse {
            ok: false,
            message: None,
            error: Some("Bind credentials not yet saved on disk.".into()),
            log: Some(
                "<strong>Status</strong>\nEnter bind credentials and click Test Settings.".into(),
            ),
        })
        .into_response();
    };
    Json(SetupTestResponse {
        ok: result.is_ok(),
        message: result.as_ref().ok().map(|_| "Bind test passed.".into()),
        error: result.err(),
        log: Some(log),
    })
    .into_response()
}

fn store_step3_test(state: &super::AppState, dn: &str, pw: &str) {
    let mut t = state.setup_test.lock().unwrap();
    t.step3_dn = Some(dn.trim().to_string());
    t.step3_pw = Some(pw.to_string());
}

fn clear_step3_test(state: &super::AppState) {
    let mut t = state.setup_test.lock().unwrap();
    t.step3_dn = None;
    t.step3_pw = None;
}

/// GET /setup/complete: legacy URL, same restart poller as step 3.
pub async fn setup_complete(State(state): State<super::AppState>) -> impl IntoResponse {
    let _ = super::settings::try_schedule_service_recycle(&state, "First-run setup complete").await;
    super::settings::render_restarting_page().into_response()
}

fn run_bind_probe_blocking(
    config_path: &Path,
    dn: &str,
    pw: &str,
) -> (Result<(), String>, String) {
    let mut cfg = match nfs_klldap_config::NfsKlldapConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            let log = format!(
                "<strong>Command</strong>\n(load config failed)\n\n<strong>Status</strong>\n{e}"
            );
            return (Err(e.to_string()), log);
        }
    };
    cfg.sssd.ldap_default_bind_dn = dn.trim().to_string();
    cfg.sssd.ldap_default_authtok = pw.to_string();
    let result = check_ldap_bind(&cfg);
    let log = format_bind_probe(&cfg, result.clone());
    (result, log)
}

fn render_step2_page(
    state: &super::AppState,
    message: Option<&str>,
    error: Option<&str>,
    ldap_uri_override: Option<&str>,
) -> (StatusCode, Html<String>) {
    let step = compute_wizard_step(&state.config_path);
    let (hostname, principals) = banner_context(&state.config_path);
    let ldap_uri = ldap_uri_override
        .map(str::to_string)
        .unwrap_or_else(|| read_ldap_uri_from_disk(&state.config_path));
    let html = SetupStep2Template {
        message: message.map(str::to_string),
        error: error.map(str::to_string),
        ldap_uri,
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
    render_step2_page(state, None, Some(err), ldap_uri_override)
}

fn render_step3_page(
    state: &super::AppState,
    message: Option<&str>,
    error: Option<&str>,
    bind_dn_override: Option<&str>,
) -> (StatusCode, Html<String>) {
    let step = compute_wizard_step(&state.config_path);
    let (hostname, principals) = banner_context(&state.config_path);
    let bind_dn = bind_dn_override
        .map(str::to_string)
        .unwrap_or_else(|| read_bind_dn_from_disk(&state.config_path));
    let html = SetupStep3Template {
        message: message.map(str::to_string),
        error: error.map(str::to_string),
        bind_dn,
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
    render_step3_page(state, None, Some(err), bind_dn_override)
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
    fn run_bind_probe_blocking_loads_config_from_path() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        fs::write(
            &conf,
            r#"ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,dc=test"
ldap_default_authtok = "old"
"#,
        )
        .unwrap();
        let (_result, log) = run_bind_probe_blocking(&conf, "uid=admin,dc=test", "sekret");
        assert!(log.contains("ldapsearch"));
        assert!(log.contains("uid=admin,dc=test"));
    }

    #[test]
    fn step2_test_matches_requires_exact_uri() {
        assert!(step2_test_matches(Some("ldaps://x.test:6360"), "ldaps://x.test:6360"));
        assert!(!step2_test_matches(Some("ldaps://x.test:6360"), "ldaps://y.test:6360"));
        assert!(!step2_test_matches(None, "ldaps://x.test:6360"));
    }

    #[test]
    fn step3_test_matches_requires_dn_and_password() {
        assert!(step3_test_matches(
            Some("uid=admin,dc=test"),
            Some("sekret"),
            "uid=admin,dc=test",
            "sekret"
        ));
        assert!(!step3_test_matches(
            Some("uid=admin,dc=test"),
            Some("sekret"),
            "uid=admin,dc=test",
            "wrong"
        ));
        assert!(!step3_test_matches(None, None, "uid=admin,dc=test", "sekret"));
    }

    #[test]
    fn validate_ldap_uri_rejects_ip_hosts() {
        assert!(validate_ldap_uri("ldaps://192.168.1.1:6360").is_err());
        assert!(validate_ldap_uri("ldaps://ldap.example.com:6360").is_ok());
    }
}
