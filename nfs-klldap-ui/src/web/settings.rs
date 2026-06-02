//! System Settings page + TOML editing (raw + structured form) + LLDAP/NFS client status and reload.
//!
//! This module owns the entire "/settings" experience:
//! - Raw TOML editor with validation
//! - Structured form editor (with comment-preserving toml_edit writes)
//! - LLDAP client status, reload, and cache clear (HTMX fragments)
//!
//! Extracted from the old monolithic web.rs during the 2026 modular refactor.
//! All the heavy form-to-config + toml_edit logic lives here.

use askama::Template;
use axum::{
    extract::{Form, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;
use std::path::PathBuf;

use super::{AppState, require_auth};

// === Template ===

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
    current_user: Option<String>,
    /// Raw file contents for the textarea editor (preserves comments)
    raw_toml: String,
    config_path: String,
    message: Option<String>,
    /// The hostname the container will use for the NFS service principal.
    effective_hostname: String,
    /// The Kerberos realm for the NFS service principal.
    effective_realm: String,
    keytab_status_message: String,
}

// === Forms ===

#[derive(Deserialize)]
pub(crate) struct RawSaveForm {
    raw_content: String,
}

// Structured form for the common editable parts of nfs-klldap.conf
#[derive(Deserialize, Debug, Default)]
pub(crate) struct StructuredSettingsForm {
    // Top level
    ldap_uri: Option<String>,

    // [storage]
    storage_container_root: Option<String>,

    // [server]
    server_hostname: Option<String>,

    // [sssd]
    sssd_bind_dn: Option<String>,
    sssd_bind_pw: Option<String>,
    sssd_port: Option<u16>,
    sssd_search_base: Option<String>,
    sssd_user_base: Option<String>,
    sssd_group_base: Option<String>,
    // TLS options
    sssd_ldap_tls_reqcert: Option<String>,
    sssd_ldap_tls_cacert: Option<String>,
    sssd_ldap_id_use_start_tls: Option<bool>,
    sssd_enumerate: Option<bool>,

    // [kerberos]
    kerberos_realm: Option<String>,

    // [ganesha]
    ganesha_default_security: Option<String>,

    // Shares (indexed fields via flatten)
    #[serde(flatten)]
    extra: std::collections::HashMap<String, String>,
}

// === Internal helper types ===

/// Internal row representation for the share editor form.
#[derive(Debug, Clone)]
struct ShareFormRow {
    idx: usize,
    name: String,
    host: String,
    export_path: Option<String>,
    security: Option<String>,
}

// === Helpers (used by both raw and structured save paths) ===

fn collect_shares_from_structured_form(
    extra: &std::collections::HashMap<String, String>,
) -> Vec<nfs_klldap_config::Share> {
    let mut share_rows: Vec<ShareFormRow> = vec![];
    for (k, v) in extra {
        if let Some(suffix) = k.strip_prefix("share_name_") {
            if let Ok(idx) = suffix.parse::<usize>() {
                let name = v.trim().to_string();
                let host = extra
                    .get(&format!("share_host_{}", idx))
                    .cloned()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if name.is_empty() || host.is_empty() {
                    continue;
                }
                let export_path = extra
                    .get(&format!("share_export_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| Some(format!("/{}", name)));
                let security = extra
                    .get(&format!("share_security_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty());
                share_rows.push(ShareFormRow {
                    idx,
                    name,
                    host,
                    export_path,
                    security,
                });
            }
        }
    }
    share_rows.sort_by_key(|r| r.idx);

    share_rows
        .into_iter()
        .map(|r| nfs_klldap_config::Share {
            name: r.name,
            host_path: PathBuf::from(r.host),
            export_path: r.export_path,
            security: r.security,
            rw: Some(true),
            squash: Some("no_root_squash".to_string()),
        })
        .collect()
}

fn apply_structured_form_to_config(
    form: &StructuredSettingsForm,
    cfg: &mut nfs_klldap_config::NfsKlldapConfig,
) {
    if let Some(v) = form.ldap_uri.clone() {
        cfg.ldap_uri = v;
    }
    if let Some(v) = form.storage_container_root.clone() {
        cfg.storage.container_root = v;
    }
    if let Some(v) = form.server_hostname.clone() {
        cfg.server.hostname = Some(v);
    }

    if let Some(v) = form.sssd_bind_dn.clone() {
        cfg.sssd.ldap_default_bind_dn = v;
    }
    if let Some(v) = form.sssd_bind_pw.clone() {
        cfg.sssd.ldap_default_authtok = v;
    }
    if let Some(v) = form.sssd_port {
        cfg.sssd.port = Some(v);
    }
    if let Some(v) = form.sssd_search_base.clone() {
        cfg.sssd.ldap_search_base = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.sssd_user_base.clone() {
        cfg.sssd.ldap_user_search_base = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.sssd_group_base.clone() {
        cfg.sssd.ldap_group_search_base = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.sssd_ldap_tls_reqcert.clone() {
        cfg.sssd.ldap_tls_reqcert = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.sssd_ldap_tls_cacert.clone() {
        cfg.sssd.ldap_tls_cacert = if v.trim().is_empty() { None } else { Some(v) };
    }
    cfg.sssd.ldap_id_use_start_tls = form.sssd_ldap_id_use_start_tls;
    cfg.sssd.enumerate = form.sssd_enumerate;

    if let Some(v) = form.kerberos_realm.clone() {
        cfg.kerberos.realm = Some(v);
    }
    if let Some(v) = form.ganesha_default_security.clone() {
        cfg.ganesha.default_security = v;
    }
}

fn make_settings_error_template(
    current_user: Option<String>,
    raw_toml: String,
    config_path: impl AsRef<std::path::Path>,
    message: String,
    keytab_hostname: String,
    keytab_realm: String,
    keytab_status_message: String,
) -> SettingsTemplate {
    SettingsTemplate {
        current_user,
        raw_toml,
        config_path: config_path.as_ref().display().to_string(),
        message: Some(message),
        effective_hostname: keytab_hostname,
        effective_realm: keytab_realm,
        keytab_status_message,
    }
}

fn atomic_write_config(path: &std::path::Path, content: &str) -> Result<(), String> {
    let tmp = path.with_extension("conf.saving");
    std::fs::write(&tmp, content.as_bytes()).map_err(|e| format!("Write failed: {}", e))?;

    std::fs::rename(&tmp, path).map_err(|e| format!("Rename failed: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

fn make_settings_success_template(
    current_user: Option<String>,
    raw_toml: String,
    config_path: impl AsRef<std::path::Path>,
    message: String,
    keytab_hostname: String,
    keytab_realm: String,
    keytab_status_message: String,
) -> SettingsTemplate {
    SettingsTemplate {
        current_user,
        raw_toml,
        config_path: config_path.as_ref().display().to_string(),
        message: Some(message),
        effective_hostname: keytab_hostname,
        effective_realm: keytab_realm,
        keytab_status_message,
    }
}

fn apply_structured_form_to_toml_doc(
    form: &StructuredSettingsForm,
    doc: &mut toml_edit::DocumentMut,
    new_shares: &[nfs_klldap_config::Share],
) {
    if let Some(v) = &form.ldap_uri {
        doc["ldap_uri"] = toml_edit::value(v.clone());
    }

    if let Some(v) = &form.storage_container_root {
        let item = doc.entry("storage").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["container_root"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = &form.server_hostname {
        let item = doc.entry("server").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["hostname"] = toml_edit::value(v.clone());
        }
    }

    if let Some(v) = &form.sssd_bind_dn {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_default_bind_dn"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = &form.sssd_bind_pw {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_default_authtok"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = form.sssd_port {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["port"] = toml_edit::value(v as i64);
        }
    }
    if let Some(v) = &form.sssd_user_base {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_user_search_base"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = &form.sssd_group_base {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_group_search_base"] = toml_edit::value(v.clone());
        }
    }

    if let Some(v) = &form.kerberos_realm {
        let item = doc.entry("kerberos").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["realm"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = &form.ganesha_default_security {
        let item = doc.entry("ganesha").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["default_security"] = toml_edit::value(v.clone());
        }
    }

    // Shares: submitted rows are authoritative. Wholesale replacement of [[shares]].
    if !new_shares.is_empty() {
        let mut shares = toml_edit::ArrayOfTables::new();
        for s in new_shares {
            let mut t = toml_edit::Table::new();
            t["name"] = toml_edit::value(s.name.clone());
            t["host_path"] = toml_edit::value(s.host_path.display().to_string());
            if let Some(ep) = &s.export_path {
                t["export_path"] = toml_edit::value(ep.clone());
            }
            if let Some(sec) = &s.security {
                t["security"] = toml_edit::value(sec.clone());
            }
            t["rw"] = toml_edit::value(s.rw.unwrap_or(true));
            if let Some(sq) = &s.squash {
                t["squash"] = toml_edit::value(sq.clone());
            }
            shares.push(t);
        }
        doc["shares"] = toml_edit::Item::ArrayOfTables(shares);
    }
}

// === Handlers ===

pub(crate) async fn settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    let raw_toml = std::fs::read_to_string(&state.config_path)
        .unwrap_or_else(|_| "# Could not read config file".to_string());

    let tpl = SettingsTemplate {
        current_user: Some(user.0),
        raw_toml,
        config_path: state.config_path.display().to_string(),
        message: None,
        effective_hostname: state.keytab_hostname.clone(),
        effective_realm: state.keytab_realm.clone(),
        keytab_status_message: state.keytab_status_message.clone(),
    };
    Ok(Html(tpl.render().unwrap()))
}

pub(crate) async fn settings_save_raw(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RawSaveForm>,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    let tmp_path = state.config_path.with_extension("tmp-validate");
    if let Err(e) = std::fs::write(&tmp_path, &form.raw_content) {
        let msg = format!("Failed to write temp file for validation: {}", e);
        return Ok(Html(format!("<p style='color:#c00'>{}</p>", msg)));
    }
    let validation = nfs_klldap_config::NfsKlldapConfig::load(&tmp_path);
    let _ = std::fs::remove_file(&tmp_path);

    if let Err(e) = validation {
        let msg = format!("Validation failed — not saving: {}", e);
        return Ok(Html(format!("<p style='color:#c00'>{}</p>", msg)));
    }

    if let Err(msg) = atomic_write_config(&state.config_path, &form.raw_content) {
        return Ok(Html(format!("<p style='color:#c00'>{}</p>", msg)));
    }

    let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let tpl = make_settings_success_template(
        Some(user.0),
        raw_toml,
        &state.config_path,
        "Raw TOML saved and validated. Container will pick up changes via its watcher (or send SIGHUP).".into(),
        state.keytab_hostname.clone(),
        state.keytab_realm.clone(),
        state.keytab_status_message.clone(),
    );
    Ok(Html(tpl.render().unwrap()))
}

pub(crate) async fn settings_save_structured(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<StructuredSettingsForm>,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    let mut cfg = nfs_klldap_config::NfsKlldapConfig::load(&state.config_path).unwrap_or_default();

    apply_structured_form_to_config(&form, &mut cfg);

    let new_shares = collect_shares_from_structured_form(&form.extra);
    if !new_shares.is_empty() {
        cfg.shares = new_shares.clone();
    }

    if let Err(e) = cfg.validate_and_derive() {
        let msg = format!("Validation error: {}", e);
        let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            raw_toml,
            &state.config_path,
            msg,
            state.keytab_hostname.clone(),
            state.keytab_realm.clone(),
            state.keytab_status_message.clone(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    let original_text = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let mut doc = original_text
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_default();

    apply_structured_form_to_toml_doc(&form, &mut doc, &new_shares);

    let text = doc.to_string();
    if let Err(msg) = atomic_write_config(&state.config_path, &text) {
        let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            raw_toml,
            &state.config_path,
            msg,
            state.keytab_hostname.clone(),
            state.keytab_realm.clone(),
            state.keytab_status_message.clone(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    let raw_toml = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let tpl = make_settings_success_template(
        None,
        raw_toml,
        &state.config_path,
        "Structured settings saved. Container will regenerate configs shortly.".into(),
        state.keytab_hostname.clone(),
        state.keytab_realm.clone(),
        state.keytab_status_message.clone(),
    );
    Ok(Html(tpl.render().unwrap()))
}

// === LLDAP / NFS client status + reload (HTMX) ===

pub(crate) async fn lldap_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return Html(
            "<div id='nfs-client-status' style='color:#c00'>Unauthorized</div>".to_string(),
        );
    }

    let client = state.lldap.lock().await;
    let auth_as = client.authenticated_as().unwrap_or("(none)");
    let last_auth = client.last_auth_time();

    let disk_cfg = crate::config::load_config_from(&state.config_path).ok();
    let (disk_user, _disk_pass) = disk_cfg
        .as_ref()
        .map(crate::config::ldap_service_creds)
        .unwrap_or_else(|| ("(unknown)".to_string(), String::new()));

    let username_differs = disk_user != auth_as;

    let last_str = last_auth
        .map(|t| {
            let ago = std::time::Instant::now().duration_since(t);
            if ago.as_secs() < 60 {
                format!("{}s ago", ago.as_secs())
            } else {
                format!("{}m ago", ago.as_secs() / 60)
            }
        })
        .unwrap_or_else(|| "never (startup failed?)".to_string());

    let notice_html = if username_differs {
        let mut n = String::from(
            "<div style='background:#fff3cd; border:1px solid #ffc107; padding:8px; margin:6px 0; border-radius:3px;'>"
        );
        n.push_str("<strong>Bind credentials changed on disk.</strong><br>");
        n.push_str(&format!("On-disk now uses <code>{}</code>, but the running NFS permission client is still using <code>{}</code> (loaded at startup or last reload).<br>", disk_user, auth_as));
        n.push_str(
            "Use the button below to reconnect with the current values from nfs-klldap.conf.</div>",
        );
        n
    } else {
        String::new()
    };

    let mut html = String::from(
        "<div id='nfs-client-status' style='border:1px solid #aaa; background:#f5f5f5; padding:10px; margin:1rem 0; border-radius:4px;'>"
    );
    html.push_str("<strong>NFS Permission Client (KLLDAP/LLDAP connection)</strong><br>");
    html.push_str("<span style='font-size:0.9em;'>Used for live user/group lookups and uid/gid resolution when managing share permissions.</span><br><br>");
    html.push_str(&format!("Authenticated as: <code>{}</code><br>", auth_as));
    html.push_str(&format!("Last connected: {}<br>", last_str));
    html.push_str(&notice_html);
    if !username_differs {
        html.push_str("<span style='font-size:0.8em;color:#666;'>Reload always reads the latest bind credentials + ldap_uri from disk/env.</span><br>");
    }
    html.push_str(
        "<button type='button' hx-post='/settings/reload-nfs-client' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:8px; padding:4px 10px; cursor:pointer;'>Reload NFS client</button>"
    );
    html.push_str(
        " <span style='font-size:0.8em; color:#555; margin-left:6px;'>(re-reads sssd.ldap_default_bind_* + ldap_uri and re-binds)</span>"
    );

    html.push_str(
        r#"<button type='button' hx-post='/settings/clear-ldap-cache' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:8px; margin-left:8px; padding:4px 10px; cursor:pointer;'>Clear identity cache</button>"#
    );
    html.push_str(r#" <span style='font-size:0.8em;color:#555'>(10m user/group cache + 2m search cache)</span>"#);

    let stats = client.cache_stats_summary();
    let hit_rate = if stats.hits + stats.misses > 0 {
        (stats.hits as f64 * 100.0 / (stats.hits + stats.misses) as f64) as u32
    } else { 0 };
    let last_cleared = stats.last_cleared_ago_secs.map(|s| format!(" • last cleared {}s ago", s)).unwrap_or_default();
    html.push_str(&format!(
        r#"<div style='font-size:0.75em;color:#666;margin-top:6px;'>Cache: {} users, {} groups, {} searches • {}% hit ({} hits / {} misses) • clears: {}{}</div>"#,
        stats.user_entries, stats.group_entries, stats.recent_search_entries, hit_rate, stats.hits, stats.misses, stats.clears, last_cleared
    ));

    html.push_str("</div>");

    Html(html)
}

pub(crate) async fn reload_nfs_client(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return Html(
            "<div id='nfs-client-status' style='color:#c00'>Unauthorized</div>".to_string(),
        );
    }

    let fresh = match crate::config::load_config_from(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            let mut err = String::from("<div id='nfs-client-status' style='background:#f8d7da;border:1px solid #dc3545;padding:8px;'>");
            err.push_str(&format!(
                "<strong>Failed to read config:</strong> {}<br>",
                e
            ));
            err.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML'>Try again</button>");
            err.push_str("</div>");
            return Html(err);
        }
    };

    let (user, pass) = crate::config::ldap_service_creds(&fresh);

    if pass.trim().is_empty() || pass == "SET_ME" || pass == "CHANGE_THIS_TO_A_STRONG_SECRET" {
        let mut msg = String::from("<div id='nfs-client-status' style='background:#fff3cd;border:1px solid #ffc107;padding:8px;'>");
        msg.push_str(&format!("<strong>Cannot reload:</strong> No valid password present for <code>{}</code> in the current config (or env).<br>", user));
        msg.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML'>Refresh</button>");
        msg.push_str("</div>");
        return Html(msg);
    }

    let posix_attrs = nfs_klldap_config::resolve_posix_attribute_mapping(&fresh.sssd);
    let realm = fresh.effective_realm();
    let (user_base, group_base) =
        nfs_klldap_config::effective_ldap_search_bases(&fresh.sssd, &realm);

    let (no_tls_verify, start_tls) = nfs_klldap_config::ldap_tls_policy(
        &fresh.ldap_uri,
        fresh.sssd.ldap_tls_reqcert.as_deref(),
        fresh.sssd.ldap_tls_cacert.as_deref(),
        fresh.sssd.ldap_id_use_start_tls,
    );
    let mut new_client = crate::ldap::LdapClient::new_with_attributes(
        &fresh.ldap_uri,
        &user_base,
        &group_base,
        posix_attrs,
        no_tls_verify,
        start_tls,
    );

    match new_client.authenticate(&user, &pass).await {
        Ok(()) => {
            {
                let mut guard = state.lldap.lock().await;
                *guard = new_client;
            }

            let mut ok = String::from("<div id='nfs-client-status' style='background:#d4edda;border:1px solid #28a745;padding:8px;border-radius:3px;'>");
            ok.push_str("<strong>NFS client reloaded successfully.</strong><br>");
            ok.push_str(&format!("Now authenticated as <code>{}</code> using current values from nfs-klldap.conf.<br>", user));
            ok.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:4px;'>Show updated status</button>");
            ok.push_str("</div>");
            Html(ok)
        }
        Err(e) => {
            let mut err = String::from("<div id='nfs-client-status' style='background:#f8d7da;border:1px solid #dc3545;padding:8px;'>");
            err.push_str(&format!(
                "<strong>Re-authentication failed:</strong> {}<br>",
                e
            ));
            err.push_str("<small>Verify the bind DN/password (or NFS_KLLDAP_LLDAP_* variables) and that LLDAP/KLLDAP is reachable on the management port.</small><br>");
            err.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:4px;'>Retry status</button>");
            err.push_str("</div>");
            Html(err)
        }
    }
}

pub(crate) async fn clear_ldap_cache(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return Html(
            "<div id='nfs-client-status' style='color:#c00'>Unauthorized</div>".to_string(),
        );
    }

    {
        let client = state.lldap.lock().await;
        client.clear_cache();
    }

    let mut ok = String::from("<div id='nfs-client-status' style='background:#d4edda;border:1px solid #28a745;padding:8px;border-radius:3px;'>");
    ok.push_str("<strong>LDAP identity cache cleared.</strong><br>");
    ok.push_str("<span style='font-size:0.8em'>Next lookups will hit KLLDAP (10m TTL restarts after first fetch).</span><br>");
    ok.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:4px;'>Show status</button>");
    ok.push_str("</div>");
    Html(ok)
}