//! First-run wizard: /setup/1 volume, /setup/2 ldap_uri, /setup/3 bind creds.

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

use super::settings::atomic_write_config;

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
    pub(crate) ok: bool,
    pub(crate) message: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) log: Option<String>,
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

pub(crate) fn validate_ldap_uri(uri: &str) -> Result<&str, String> {
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

/// Bind probe + formatted transcript for a loaded config.
fn bind_probe(cfg: &nfs_klldap_config::NfsKlldapConfig) -> (Result<(), String>, String) {
    let result = check_ldap_bind(cfg);
    let log = format_bind_probe(cfg, result.clone());
    (result, log)
}

fn run_bind_probe_from_disk(path: &Path) -> Option<(Result<(), String>, String)> {
    // Lenient load so the emptiness checks below (not full validation) decide
    // whether creds are "saved on disk" — the wizard config is incomplete.
    let cfg = nfs_klldap_config::NfsKlldapConfig::load_lenient(path).ok()?;
    if cfg.ldap_uri.trim().is_empty()
        || cfg.sssd.ldap_default_bind_dn.trim().is_empty()
        || cfg.sssd.ldap_default_authtok.trim().is_empty()
    {
        return None;
    }
    Some(bind_probe(&cfg))
}

/// GET /setup — jump to the current wizard step.
pub async fn setup_redirect(State(state): State<super::AppState>) -> impl IntoResponse {
    Redirect::to(&setup_redirect_for_step(&state.config_path)).into_response()
}

/// Renders setup wizard step 1 for the persistent volume check.
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

/// Renders setup wizard step 2 for LDAP URI configuration.
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

/// Renders setup wizard step 3 for LDAP bind credential testing.
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

/// Saves bind credentials after a successful test and finishes the wizard.
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

/// Runs a background bind probe against on-disk credentials for step 3 status.
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

pub(crate) fn run_bind_probe_blocking(
    config_path: &Path,
    dn: &str,
    pw: &str,
) -> (Result<(), String>, String) {
    // Lenient load: on first-run the bind fields are not on disk yet — this
    // probe is what establishes them — so the strict validated load would
    // reject the config for missing the very values the form supplies.
    let mut cfg = match nfs_klldap_config::NfsKlldapConfig::load_lenient(config_path) {
        Ok(c) => c,
        Err(e) => {
            let log = format!(
                "<strong>Command</strong>\n(load config failed)\n\n<strong>Status</strong>\n{e}"
            );
            return (Err(e.to_string()), log);
        }
    };
    if cfg.ldap_uri.trim().is_empty() {
        let msg = "ldap_uri is not set. Complete the LDAP server step first.".to_string();
        let log =
            format!("<strong>Command</strong>\n(validation)\n\n<strong>Status</strong>\n{msg}");
        return (Err(msg), log);
    }
    cfg.sssd.ldap_default_bind_dn = dn.trim().to_string();
    // Blank password keeps the stored authtok (settings test-bind fallback).
    if !pw.is_empty() {
        cfg.sssd.ldap_default_authtok = pw.to_string();
    }
    bind_probe(&cfg)
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

    #[test]
    fn validate_ldap_uri_requires_ldap_scheme_and_dns_hostname() {
        assert_eq!(validate_ldap_uri(" ldaps://kl.example:6360 "), Ok("ldaps://kl.example:6360"));
        assert!(validate_ldap_uri("ldap://kl.example").is_ok());
        assert!(validate_ldap_uri("").is_err());
        assert!(validate_ldap_uri("http://kl.example").is_err());
        assert!(validate_ldap_uri("ldaps://10.0.0.5:636").is_err(), "IP hosts break Kerberos rDNS");
    }

    #[test]
    fn step2_continue_requires_exact_tested_uri() {
        assert!(step2_test_matches(Some("ldaps://kl:636"), " ldaps://kl:636 "));
        assert!(!step2_test_matches(Some("ldaps://kl:636"), "ldaps://other:636"));
        assert!(!step2_test_matches(None, "ldaps://kl:636"), "continue without a test must stall");
    }

    #[test]
    fn step3_continue_requires_tested_dn_and_password_pair() {
        let (dn, pw) = ("uid=admin,ou=people,dc=x,dc=com", "s3cret");
        assert!(step3_test_matches(Some(dn), Some(pw), &format!(" {dn} "), pw));
        assert!(!step3_test_matches(Some(dn), Some(pw), dn, "different"));
        assert!(!step3_test_matches(None, Some(pw), dn, pw));
        assert!(!step3_test_matches(Some(dn), None, dn, pw));
    }

    #[test]
    fn step3_bind_probe_runs_on_first_run_config_without_stored_creds() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nfs-klldap.conf");
        std::fs::write(&path, "ldap_uri = \"ldap://127.0.0.1:9\"\n").unwrap();
        let (result, log) =
            run_bind_probe_blocking(&path, "uid=admin,ou=people,dc=x,dc=com", "pw");
        assert!(
            log.contains("ldapsearch -H"),
            "probe must get past config load on a creds-less first-run config: {log}"
        );
        let err = result.unwrap_err();
        assert!(
            !err.contains("is required"),
            "validated-load rejection leaked through: {err}"
        );
    }

    #[test]
    fn step3_bind_probe_reports_missing_ldap_uri_clearly() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nfs-klldap.conf");
        std::fs::write(&path, "").unwrap();
        let (result, _log) =
            run_bind_probe_blocking(&path, "uid=admin,ou=people,dc=x,dc=com", "pw");
        assert!(result.unwrap_err().contains("ldap_uri is not set"));
    }
}


