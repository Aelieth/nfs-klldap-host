//! The /settings is raw TOML + structured form (top + shares) LLDAP.
//! Status/reload/clear, restart (HUP pid1).

use askama::Template;
use axum::{
    extract::{Form, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;
use std::path::PathBuf;

use super::{get_keytab_info, AppState, KeytabDisplayContext, require_auth};

// This section defines settings page templates.

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
    current_user: Option<String>,
    /// Raw file contents for the textarea editor (preserves comments).
    raw_toml: String,
    config_path: String,
    message: Option<String>,
    /// The hostname the container will use for the NFS service principal.
    effective_hostname: String,
    /// The Kerberos realm for the NFS service principal.
    effective_realm: String,
    keytab_alert: Option<String>,

    /// NFS principals from keytab (template underline highlight).
    keytab_found_principals: Vec<String>,

    ldap_uri: String,
    storage_container_root: String,
    server_hostname: String,
    sssd_bind_dn: String,
    sssd_search_base: String,
    sssd_user_base: String,
    sssd_group_base: String,
    sssd_ldap_tls_reqcert: String,
    sssd_ldap_tls_cacert: String,
    sssd_ldap_id_use_start_tls: bool,
    sssd_enumerate: bool,
    kerberos_realm: String,
    ganesha_default_security: String,
    kllldap_ignored_attributes: bool,

    // True when the key is explicitly present in raw TOML. Structured save.
    override_server_hostname: bool,
    override_kerberos_realm: bool,
    override_ganesha_default_security: bool,
    override_sssd_search_base: bool,
    override_sssd_user_base: bool,
    override_sssd_group_base: bool,
    override_sssd_ldap_tls_reqcert: bool,
    override_sssd_ldap_tls_cacert: bool,
    override_sssd_ldap_id_use_start_tls: bool,
    override_sssd_enumerate: bool,

    /// Server-rendered shares for edit/delete via row removal.
    current_shares: Vec<ShareTemplateRow>,
    /// Holds the next share row index the client JS uses for Add Share rows.
    next_share_idx: usize,

    /// Reflects HOST_NFS mode where host Ganesha serves exports and WebUI.
    host_nfs_mode: bool,
}

/// Self-contained restart page (JS polls until new UI ready, then to /login).
#[derive(Template)]
#[template(path = "restarting.html")]
pub(crate) struct RestartingTemplate;

/// Default path touched after a full service recycle.
/// Polled by restarting.html.
pub(crate) const SERVICE_RECYCLE_MARKER: &str = "/tmp/.nfs-klldap-services-recycled";

fn service_recycle_marker_path() -> std::path::PathBuf {
    std::env::var("NFS_KLLDAP_RECYCLE_MARKER")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(SERVICE_RECYCLE_MARKER))
}

/// Render the standalone restarting page.
/// Shared by settings restart and setup step 3.
pub(crate) fn render_restarting_page() -> Html<String> {
    Html(RestartingTemplate.render().unwrap())
}

/// Clear recycle marker and schedule delayed HUP (pid 1 or test override).
pub(crate) async fn try_schedule_service_recycle(state: &super::AppState, log_context: &str) -> bool {
    {
        let mut flag = state.restart_requested.lock().await;
        if *flag {
            return false;
        }
        *flag = true;
    }
    let _ = std::fs::remove_file(service_recycle_marker_path());
    let label = log_context.to_string();
    let hup_pid = std::env::var("NFS_KLLDAP_SUPERVISOR_PID").unwrap_or_else(|_| "1".to_string());
    let delay_ms = std::env::var("NFS_KLLDAP_RECYCLE_DELAY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1400);
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        let pid = match hup_pid.parse::<u32>() {
            Ok(p) if p > 0 => p,
            _ => {
                eprintln!(
                    "WARN: '{label}' — invalid NFS_KLLDAP_SUPERVISOR_PID '{hup_pid}', skipping HUP"
                );
                return;
            }
        };
        eprintln!("INFO: '{label}' — triggering service bounce (HUP to pid {pid})");
        if let Err(e) = nfs_klldap_config::signal_supervisor_hup(pid) {
            eprintln!("WARN: '{label}' — SIGHUP failed: {e}");
        }
    });
    true
}

// This section defines settings form types.

#[derive(Deserialize)]
pub(crate) struct RawSaveForm {
    raw_content: String,
}

// Structured form (top-level + shares rows). Shares POST reuses subset of.
#[derive(Deserialize, Debug, Default)]
pub(crate) struct StructuredSettingsForm {
    // Captures top-level TOML fields such as ldap_uri.
    ldap_uri: Option<String>,

    // Handle the storage section fields.
    storage_container_root: Option<String>,

    // Handle the server section fields.
    server_hostname: Option<String>,
    override_server_hostname: Option<bool>,

    // Handle the sssd section fields.
    sssd_bind_dn: Option<String>,
    sssd_bind_pw: Option<String>,
    sssd_port: Option<u16>,
    sssd_search_base: Option<String>,
    override_sssd_search_base: Option<bool>,
    sssd_user_base: Option<String>,
    override_sssd_user_base: Option<bool>,
    sssd_group_base: Option<String>,
    override_sssd_group_base: Option<bool>,
    // Captures SSSD TLS-related override fields for the structured editor.
    sssd_ldap_tls_reqcert: Option<String>,
    override_sssd_ldap_tls_reqcert: Option<bool>,
    sssd_ldap_tls_cacert: Option<String>,
    override_sssd_ldap_tls_cacert: Option<bool>,
    sssd_ldap_id_use_start_tls: Option<bool>,
    override_sssd_ldap_id_use_start_tls: Option<bool>,
    sssd_enumerate: Option<bool>,
    override_sssd_enumerate: Option<bool>,
    // Controls KLLDAP ignore lists and ldap_group_member in sssd.conf.
    kllldap_ignored_attributes: Option<bool>,

    // Handle the kerberos section fields.
    kerberos_realm: Option<String>,
    override_kerberos_realm: Option<bool>,

    // Handle the ganesha section fields.
    ganesha_default_security: Option<String>,
    override_ganesha_default_security: Option<bool>,

    // Shares (indexed fields via flatten).
    #[serde(flatten)]
    extra: std::collections::HashMap<String, String>,
}

// This section defines internal helper types.

/// Internal row for the share editor form. Built while collecting POST fields.
/// Used by structured save + dedicated shares save.
#[derive(Debug, Clone)]
struct ShareFormRow {
    idx: usize,
    name: String,
    host: String,
    export_path: Option<String>,
    security: Option<String>,
    rw: bool,
    root_squash: bool,
    cache_profile: Option<String>,
    // Legacy numeric pref_read values are still parsed when posted.
    pref_read: Option<String>,
    pref_write: Option<String>,
    enable_acl: Option<bool>,
    manage_gids: Option<bool>,
    read_access_policy: Option<String>,
    ganesha_path: Option<String>,
}

/// Template row for server-rendered shares in structured editor.
/// String values simplify Askama rendering.
#[derive(Debug, Clone)]
struct ShareTemplateRow {
    idx: usize,
    name: String,
    host_path: String,
    export_path: String,
    security: String,
    rw: bool,
    root_squash: bool,
    cache_profile: String,
    enable_acl: String,
    manage_gids: String,
    read_access_policy: String,
    override_ganesha_path: bool,
    /// Effective value shown in the Path input (explicit ganesha_path override or derived default).
    ganesha_path: String,
    /// Derived container path from host_path; used for data-default-path and when override is off.
    default_ganesha_path: String,
    warning: Option<String>,
    fs_warning: Option<String>,
}

/// Key present in raw TOML (drives override checkbox visibility).
fn has_explicit(doc: &toml_edit::DocumentMut, section: &str, key: &str) -> bool {
    if section.is_empty() {
        doc.get(key).is_some()
    } else {
        doc.get(section)
            .and_then(|i| i.as_table())
            .is_some_and(|t| t.get(key).is_some())
    }
}

/// Raw string value if present (for structured prefill of overrides).
fn get_explicit_str(doc: &toml_edit::DocumentMut, section: &str, key: &str) -> Option<String> {
    let val = if section.is_empty() {
        doc.get(key)
    } else {
        doc.get(section)
            .and_then(|i| i.as_table())
            .and_then(|t| t.get(key))
    };
    val.and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// True when ganesha_path is explicit in raw TOML for a share row.
fn share_override_ganesha_path_from_raw(doc: &toml_edit::DocumentMut, idx: usize) -> bool {
    let Some(arr) = doc.get("shares").and_then(|s| s.as_array_of_tables()) else {
        return false;
    };
    let Some(tbl) = arr.get(idx) else {
        return false;
    };
    tbl.get("ganesha_path").is_some()
}

/// Share export_path for the editor when explicit in raw TOML.
/// Normalized to an absolute path.
fn share_export_path_from_raw(doc: &toml_edit::DocumentMut, idx: usize) -> String {
    let Some(arr) = doc.get("shares").and_then(|s| s.as_array_of_tables()) else {
        return String::new();
    };
    let Some(tbl) = arr.get(idx) else {
        return String::new();
    };
    if tbl.get("export_path").is_none() {
        return String::new();
    }
    let raw = tbl.get("export_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let t = raw.trim();
    if t.is_empty() {
        String::new()
    } else if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{}", t)
    }
}

/// Maps legacy pref_read/pref_write pairs to cache profile names.
/// Used to prefill the dropdown.
fn infer_profile_from_prefs(pref_read: Option<u64>, pref_write: Option<u64>) -> String {
    match (pref_read, pref_write) {
        (Some(1048576), Some(1048576)) => "Default".to_string(),
        (Some(4194304), Some(4194304)) => "Read - Basic".to_string(),
        (Some(16777216), Some(8388608)) => "Read - Heavy".to_string(),
        (Some(2097152), Some(16777216)) => "Write - Heavy".to_string(),
        // Mixed Use has identical numbers to Read-Basic in the spec. Pick one.
        _ => "Default".to_string(),
    }
}

/// Build SettingsTemplate from on-disk config.
/// Used on page load and post-save re-render.
fn build_settings_template(
    current_user: Option<String>,
    config_path: impl AsRef<std::path::Path>,
    message: Option<String>,
    keytab: KeytabDisplayContext,
    host_nfs_mode: bool,
    fs_probe_mountinfo_path: Option<&std::path::Path>,
) -> SettingsTemplate {
    let p = config_path.as_ref();
    let raw_toml = std::fs::read_to_string(p)
        .unwrap_or_else(|_| "# Could not read config file".to_string());

    // Parse raw (un-derived) TOML to detect which fields are *explicit.
    let doc: toml_edit::DocumentMut = raw_toml.parse().unwrap_or_default();

    let cfg = nfs_klldap_config::NfsKlldapConfig::load(p).unwrap_or_default();

    let current_shares: Vec<ShareTemplateRow> = cfg
        .shares
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            let override_ganesha_path = share_override_ganesha_path_from_raw(&doc, idx);
            let default_ganesha_path = cfg.container_path_for(s);
            let ganesha_path = if override_ganesha_path {
                s.ganesha_path.clone().unwrap_or_default()
            } else {
                default_ganesha_path.clone()
            };
            ShareTemplateRow {
            idx,
            name: s.name.clone(),
            host_path: s.host_path.display().to_string(),
            export_path: share_export_path_from_raw(&doc, idx),
            security: s.security.clone().unwrap_or_default(),
            rw: s.rw.unwrap_or(true),
            root_squash: s.squash.as_deref() == Some("root_squash"),
            cache_profile: s
                .cache_profile
                .clone()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| infer_profile_from_prefs(s.pref_read, s.pref_write)),
            enable_acl: match s.enable_acl {
                Some(true) => "true".to_string(),
                Some(false) => "false".to_string(),
                None => "auto".to_string(),
            },
            manage_gids: match s.manage_gids {
                Some(true) => "true".to_string(),
                Some(false) => "false".to_string(),
                None => "auto".to_string(),
            },
            read_access_policy: match s.read_access_policy.as_deref() {
                Some("pre") => "pre".to_string(),
                Some("post") => "post".to_string(),
                _ => "auto".to_string(),
            },
            override_ganesha_path,
            ganesha_path,
            default_ganesha_path,
            warning: nfs_klldap_config::ShareFieldWarning::for_share(
                &cfg.share_warnings,
                idx,
                &s.name,
            )
            .map(|w| w.display_message()),
            fs_warning: nfs_klldap_config::share_fs_warning_message_with_mountinfo(
                &cfg,
                s,
                fs_probe_mountinfo_path,
            ),
        }
        })
        .collect();
    let next_share_idx = current_shares.len();

    SettingsTemplate {
        current_user,
        raw_toml,
        config_path: p.display().to_string(),
        message,
        effective_hostname: keytab.hostname.clone(),
        effective_realm: keytab.realm.clone(),
        keytab_alert: keytab.alert.clone(),
        keytab_found_principals: get_keytab_info(&keytab.hostname, &keytab.realm)
            .found_nfs_principals,
        ldap_uri: cfg.ldap_uri,
        storage_container_root: cfg.storage.container_root.clone(),
        server_hostname: cfg.server.hostname.clone().unwrap_or_default(),
        sssd_bind_dn: cfg.sssd.ldap_default_bind_dn.clone(),
        sssd_search_base: cfg.sssd.ldap_search_base.clone().unwrap_or_default(),
        sssd_user_base: cfg.sssd.ldap_user_search_base.clone().unwrap_or_default(),
        sssd_group_base: cfg.sssd.ldap_group_search_base.clone().unwrap_or_default(),
        sssd_ldap_tls_reqcert: cfg.sssd.ldap_tls_reqcert.clone().unwrap_or_default(),
        sssd_ldap_tls_cacert: cfg.sssd.ldap_tls_cacert.clone().unwrap_or_default(),
        sssd_ldap_id_use_start_tls: cfg.sssd.ldap_id_use_start_tls.unwrap_or(false),
        sssd_enumerate: cfg.sssd.enumerate.unwrap_or(false),
        kerberos_realm: cfg.kerberos.realm.clone().unwrap_or_default(),
        ganesha_default_security: cfg.ganesha.default_security.clone(),
        kllldap_ignored_attributes: cfg.sssd.kllldap_ignored_attributes.unwrap_or(true),

        // Computed from *raw source presence* (not from derived cfg values).
        override_server_hostname: has_explicit(&doc, "server", "hostname"),
        override_kerberos_realm: has_explicit(&doc, "kerberos", "realm"),
        // Treat explicit krb5p as non-override writer always materializes.
        override_ganesha_default_security: get_explicit_str(&doc, "ganesha", "default_security")
            .is_some_and(|v| v != "krb5p"),
        override_sssd_search_base: has_explicit(&doc, "sssd", "ldap_search_base"),
        override_sssd_user_base: has_explicit(&doc, "sssd", "ldap_user_search_base"),
        override_sssd_group_base: has_explicit(&doc, "sssd", "ldap_group_search_base"),
        override_sssd_ldap_tls_reqcert: has_explicit(&doc, "sssd", "ldap_tls_reqcert"),
        override_sssd_ldap_tls_cacert: has_explicit(&doc, "sssd", "ldap_tls_cacert"),
        override_sssd_ldap_id_use_start_tls: has_explicit(&doc, "sssd", "ldap_id_use_start_tls"),
        override_sssd_enumerate: has_explicit(&doc, "sssd", "enumerate"),

        current_shares,
        next_share_idx,
        host_nfs_mode,
    }
}

// Helpers shared by raw and structured save paths.

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
                    .filter(|s| !s.trim().is_empty());
                // The no auto-fill is leave None so it stays optional/blank.
                let security = extra
                    .get(&format!("share_security_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty());
                let rw = extra
                    .get(&format!("share_rw_{}", idx))
                    .map(|v| v.trim() == "true")
                    .unwrap_or(true);
                let root_squash = extra.contains_key(&format!("share_root_squash_{}", idx));
                let cache_profile = extra
                    .get(&format!("share_cache_profile_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty());
                let pref_read = extra
                    .get(&format!("share_pref_read_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty());
                let pref_write = extra
                    .get(&format!("share_pref_write_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty());
                let parse_tri_bool = |key: &str| -> Option<bool> {
                    extra.get(key).and_then(|v| match v.trim() {
                        "true" => Some(true),
                        "false" => Some(false),
                        _ => None,
                    })
                };
                let enable_acl =
                    parse_tri_bool(&format!("share_enable_acl_{}", idx));
                let manage_gids =
                    parse_tri_bool(&format!("share_manage_gids_{}", idx));
                let read_access_policy = extra
                    .get(&format!("share_read_access_policy_{}", idx))
                    .and_then(|v| match v.trim() {
                        "pre" => Some("pre".to_string()),
                        "post" => Some("post".to_string()),
                        _ => None,
                    });
                let override_ganesha_path =
                    extra.contains_key(&format!("share_override_ganesha_path_{}", idx));
                let ganesha_path = if override_ganesha_path {
                    extra
                        .get(&format!("share_ganesha_path_{}", idx))
                        .cloned()
                        .filter(|s| !s.trim().is_empty())
                } else {
                    None
                };
                share_rows.push(ShareFormRow {
                    idx,
                    name,
                    host,
                    export_path,
                    security,
                    rw,
                    root_squash,
                    cache_profile,
                    pref_read,
                    pref_write,
                    enable_acl,
                    manage_gids,
                    read_access_policy,
                    ganesha_path,
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
            rw: Some(r.rw),
            squash: if r.root_squash {
                Some("root_squash".to_string())
            } else {
                // Omit defaults so they are not written into raw TOML.
                None
            },
            cache_profile: r.cache_profile,
            pref_read: r.pref_read.and_then(|s| s.trim().parse::<u64>().ok()),
            pref_write: r.pref_write.and_then(|s| s.trim().parse::<u64>().ok()),
            enable_acl: r.enable_acl,
            manage_gids: r.manage_gids,
            read_access_policy: r.read_access_policy,
            ganesha_path: r.ganesha_path,
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
    if form.override_server_hostname.unwrap_or(false) {
        if let Some(v) = form.server_hostname.clone() {
            cfg.server.hostname = if v.trim().is_empty() { None } else { Some(v) };
        }
    }

    if let Some(v) = form.sssd_bind_dn.clone() {
        cfg.sssd.ldap_default_bind_dn = v;
    }
    // Only overwrite bind pw when a non-empty value was submitted. Structured.
    if let Some(v) = form.sssd_bind_pw.clone() {
        if !v.trim().is_empty() {
            cfg.sssd.ldap_default_authtok = v;
        }
    }
    if let Some(v) = form.sssd_port {
        cfg.sssd.port = Some(v);
    }
    if form.override_sssd_search_base.unwrap_or(false) {
        if let Some(v) = form.sssd_search_base.clone() {
            cfg.sssd.ldap_search_base = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_user_base.unwrap_or(false) {
        if let Some(v) = form.sssd_user_base.clone() {
            cfg.sssd.ldap_user_search_base = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_group_base.unwrap_or(false) {
        if let Some(v) = form.sssd_group_base.clone() {
            cfg.sssd.ldap_group_search_base = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_ldap_tls_reqcert.unwrap_or(false) {
        if let Some(v) = form.sssd_ldap_tls_reqcert.clone() {
            cfg.sssd.ldap_tls_reqcert = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_ldap_tls_cacert.unwrap_or(false) {
        if let Some(v) = form.sssd_ldap_tls_cacert.clone() {
            cfg.sssd.ldap_tls_cacert = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_ldap_id_use_start_tls.unwrap_or(false) {
        cfg.sssd.ldap_id_use_start_tls = form.sssd_ldap_id_use_start_tls;
    }
    if form.override_sssd_enumerate.unwrap_or(false) {
        cfg.sssd.enumerate = form.sssd_enumerate;
    }

    // The kllldap_ignored_attributes is absent checkbox means explicit false.
    cfg.sssd.kllldap_ignored_attributes = Some(form.kllldap_ignored_attributes.unwrap_or(false));

    if form.override_kerberos_realm.unwrap_or(false) {
        if let Some(v) = form.kerberos_realm.clone() {
            cfg.kerberos.realm = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_ganesha_default_security.unwrap_or(false) {
        if let Some(v) = form.ganesha_default_security.clone() {
            if !v.trim().is_empty() {
                cfg.ganesha.default_security = v;
            } else {
                cfg.ganesha.default_security = "krb5p".to_string();
            }
        }
    } else {
        // Not overriding is materialize the standard default (so ganesha.conf.
        cfg.ganesha.default_security = "krb5p".to_string();
    }
}

fn make_settings_error_template(
    current_user: Option<String>,
    config_path: impl AsRef<std::path::Path>,
    message: String,
    keytab: KeytabDisplayContext,
    host_nfs_mode: bool,
    fs_probe_mountinfo_path: Option<&std::path::Path>,
) -> SettingsTemplate {
    // Always re-read current on-disk state for prefilled structured fields.
    build_settings_template(
        current_user,
        config_path,
        Some(message),
        keytab,
        host_nfs_mode,
        fs_probe_mountinfo_path,
    )
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
    config_path: impl AsRef<std::path::Path>,
    message: String,
    keytab: KeytabDisplayContext,
    host_nfs_mode: bool,
    fs_probe_mountinfo_path: Option<&std::path::Path>,
) -> SettingsTemplate {
    // Re-reads config after write so structured fields pre-fill correctly.
    build_settings_template(
        current_user,
        config_path,
        Some(message),
        keytab,
        host_nfs_mode,
        fs_probe_mountinfo_path,
    )
}

fn apply_structured_form_to_toml_doc(
    form: &StructuredSettingsForm,
    doc: &mut toml_edit::DocumentMut,
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
    if form.override_server_hostname.unwrap_or(false) {
        if let Some(v) = &form.server_hostname {
            let item = doc.entry("server").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["hostname"] = toml_edit::value(v.clone());
            }
        }
    } else if let Some(item) = doc.get_mut("server") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("hostname");
        }
    }

    if let Some(v) = &form.sssd_bind_dn {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_default_bind_dn"] = toml_edit::value(v.clone());
        }
    }
    // Writes bind password when non-empty since the editor never prefills it.
    if let Some(v) = &form.sssd_bind_pw {
        if !v.trim().is_empty() {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["ldap_default_authtok"] = toml_edit::value(v.clone());
            }
        }
    }
    if let Some(v) = form.sssd_port {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["port"] = toml_edit::value(v as i64);
        }
    }
    if form.override_sssd_search_base.unwrap_or(false) {
        if let Some(v) = &form.sssd_search_base {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                if v.trim().is_empty() {
                    let _ = tbl.remove("ldap_search_base");
                } else {
                    tbl["ldap_search_base"] = toml_edit::value(v.clone());
                }
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_search_base");
        }
    }
    if form.override_sssd_user_base.unwrap_or(false) {
        if let Some(v) = &form.sssd_user_base {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["ldap_user_search_base"] = toml_edit::value(v.clone());
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_user_search_base");
        }
    }
    if form.override_sssd_group_base.unwrap_or(false) {
        if let Some(v) = &form.sssd_group_base {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["ldap_group_search_base"] = toml_edit::value(v.clone());
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_group_search_base");
        }
    }

    if form.override_sssd_ldap_tls_reqcert.unwrap_or(false) {
        if let Some(v) = &form.sssd_ldap_tls_reqcert {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                if v.trim().is_empty() {
                    let _ = tbl.remove("ldap_tls_reqcert");
                } else {
                    tbl["ldap_tls_reqcert"] = toml_edit::value(v.clone());
                }
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_tls_reqcert");
        }
    }
    if form.override_sssd_ldap_tls_cacert.unwrap_or(false) {
        if let Some(v) = &form.sssd_ldap_tls_cacert {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                if v.trim().is_empty() {
                    let _ = tbl.remove("ldap_tls_cacert");
                } else {
                    tbl["ldap_tls_cacert"] = toml_edit::value(v.clone());
                }
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_tls_cacert");
        }
    }
    if form.override_sssd_ldap_id_use_start_tls.unwrap_or(false) {
        let v = form.sssd_ldap_id_use_start_tls.unwrap_or(false);
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_id_use_start_tls"] = toml_edit::value(v);
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_id_use_start_tls");
        }
    }
    if form.override_sssd_enumerate.unwrap_or(false) {
        let v = form.sssd_enumerate.unwrap_or(false);
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["enumerate"] = toml_edit::value(v);
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("enumerate");
        }
    }

    // Kllldap_ignored_attributes is always emitted from the structured path.
    {
        let kll = form.kllldap_ignored_attributes.unwrap_or(false);
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["kllldap_ignored_attributes"] = toml_edit::value(kll);
        }
    }

    if form.override_kerberos_realm.unwrap_or(false) {
        if let Some(v) = &form.kerberos_realm {
            let item = doc.entry("kerberos").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["realm"] = toml_edit::value(v.clone());
            }
        }
    } else if let Some(item) = doc.get_mut("kerberos") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("realm");
        }
    }
    if form.override_ganesha_default_security.unwrap_or(false) {
        if let Some(v) = &form.ganesha_default_security {
            let val = if v.trim().is_empty() { "krb5p".to_string() } else { v.clone() };
            let item = doc.entry("ganesha").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["default_security"] = toml_edit::value(val);
            }
        } else {
            // Override checked but no value submitted (e.g. was disabled.
            let item = doc.entry("ganesha").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["default_security"] = toml_edit::value("krb5p");
            }
        }
    } else {
        // Ensures default_security stays krb5p when ganesha override is off.
        let item = doc.entry("ganesha").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["default_security"] = toml_edit::value("krb5p");
        }
    }
}

/// Replace only the `[[shares]]` array in the raw TOML doc (shares-save path).
fn apply_shares_to_toml_doc(doc: &mut toml_edit::DocumentMut, new_shares: &[nfs_klldap_config::Share]) {
    // Replaces [[shares]] from submitted rows, including an empty share list.
    let had_shares = doc.get("shares").is_some();
    // Remove first so we can control insertion position for the first-add.
    let _ = doc.as_table_mut().remove("shares");

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
        // Only persist non-defaults in the source TOML (keeps conf clean.
        let rw = s.rw.unwrap_or(true);
        if !rw {
            t["rw"] = toml_edit::value(false);
        }
        if let Some(sq) = &s.squash {
            if sq != "no_root_squash" {
                t["squash"] = toml_edit::value(sq.clone());
            }
        }
        // Write cache_profile (Pref Cache UI → Ganesha PrefRead/PrefWrite).
        if let Some(cp) = &s.cache_profile {
            if !cp.trim().is_empty() {
                t["cache_profile"] = toml_edit::value(cp.clone());
            }
        } else {
            if let Some(pr) = s.pref_read {
                t["pref_read"] = toml_edit::value(pr as i64);
            }
            if let Some(pw) = s.pref_write {
                t["pref_write"] = toml_edit::value(pw as i64);
            }
        }
        if let Some(v) = s.enable_acl {
            t["enable_acl"] = toml_edit::value(v);
        }
        if let Some(v) = s.manage_gids {
            t["manage_gids"] = toml_edit::value(v);
        }
        if let Some(ref rap) = s.read_access_policy {
            if !rap.trim().is_empty() {
                t["read_access_policy"] = toml_edit::value(rap.clone());
            }
        }
        if let Some(gp) = &s.ganesha_path {
            if !gp.trim().is_empty() {
                t["ganesha_path"] = toml_edit::value(gp.clone());
            }
        }
        shares.push(t);
    }

    let shares_item = toml_edit::Item::ArrayOfTables(shares);

    if !had_shares {
        // Inserts [[shares]] after the first anchor when shares are added.
        let anchor = if doc.get("webui").is_some() {
            Some("webui")
        } else if doc.get("ganesha").is_some() {
            Some("ganesha")
        } else if doc.get("kerberos").is_some() {
            Some("kerberos")
        } else if doc.get("sssd").is_some() {
            Some("sssd")
        } else {
            None
        };

        if let Some(anchor_key) = anchor {
            // Preserve document-level trailing trivia after the last key.
            let trailing = doc.trailing().clone();

            // Snapshots top-level items before rebuilding the document table.
            let items: Vec<(String, toml_edit::Item)> = doc
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();

            // Clear the root table to re-add keys in desired order. Includes.
            for (k, _) in &items {
                let _ = doc.as_table_mut().remove(k.as_str());
            }

            let mut inserted = false;
            for (k, v) in items {
                doc[k.as_str()] = v;
                if k == anchor_key {
                    doc["shares"] = shares_item.clone();
                    inserted = true;
                }
            }
            if !inserted {
                // Appends shares when the anchor key was missing in snapshot.
                doc["shares"] = shares_item;
            }

            // Restore trailing so comments that were not attached to any key.
            doc.set_trailing(trailing);
        } else {
            // Appends shares at document end when no anchor section exists.
            doc["shares"] = shares_item;
        }
    } else {
        // Shares key already existed in the source replace it in its prior.
        doc["shares"] = shares_item;
    }

    // Toml_edit may park [webui] comments as trailing trivia after [[shares]].
    if !had_shares {
        let mut full = doc.to_string();

        let shares_tail = if let Some(start) = full.find("[[shares]]") {
            let t = full[start..].trim_end().to_string();
            full = full[..start].to_string();
            Some(t)
        } else {
            None
        };

        if let Some(tail) = shares_tail {
            let lines: Vec<&str> = tail.lines().collect();
            let mut peel_count = 0usize;
            for line in lines.iter().rev() {
                let t = line.trim_start();
                if t.is_empty() || t.starts_with('#') {
                    peel_count += 1;
                } else {
                    break;
                }
            }
            let (shares_part_owned, peeled_comments) = if peel_count > 0 {
                let keep = lines.len() - peel_count;
                let s = if keep == 0 { String::new() } else { lines[..keep].join("\n") };
                let c = lines[keep..].join("\n");
                (s, c)
            } else {
                (tail.clone(), String::new())
            };
            let shares_text = shares_part_owned.trim().to_string();

            if let Some(wstart) = full.find("[webui]") {
                let mut insert_at = wstart;
                if let Some(nl) = full[insert_at..].find('\n') {
                    insert_at += nl + 1;
                } else {
                    insert_at = full.len();
                }
                let tail_after = &full[insert_at..];
                let mut consumed = 0usize;
                for line in tail_after.lines() {
                    let t = line.trim_start();
                    if t.is_empty() || t.starts_with('#') {
                        consumed += line.len() + 1;
                    } else {
                        break;
                    }
                }
                insert_at += consumed;

                let before = &full[..insert_at];
                let after = &full[insert_at..];

                let mut middle = String::new();
                if !peeled_comments.is_empty() {
                    middle.push('\n');
                    middle.push_str(&peeled_comments);
                }
                if !shares_text.is_empty() {
                    middle.push_str("\n\n");
                    middle.push_str(&shares_text);
                }

                let reassembled = if after.trim().is_empty() {
                    format!("{}{}\n", before.trim_end(), middle)
                } else {
                    format!("{}{}{}", before.trim_end(), middle, after)
                };

                if let Ok(reparsed) = reassembled.parse::<toml_edit::DocumentMut>() {
                    *doc = reparsed;
                }
            }
        }
    }
}

// HTTP handlers for the permission tree routes.

pub(crate) async fn settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    let tpl = build_settings_template(
        Some(user.0),
        &state.config_path,
        None,
        state.keytab_display(),
        state.host_nfs_mode,
        state.fs_probe_mountinfo_path.as_deref(),
    );
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
        return Ok(Html(format!("<p class='alert alert-danger'>{}</p>", msg)));
    }
    let validation = nfs_klldap_config::NfsKlldapConfig::load(&tmp_path);
    let _ = std::fs::remove_file(&tmp_path);

    if let Err(e) = validation {
        let msg = format!("Validation failed — not saving: {}", e);
        return Ok(Html(format!("<p class='alert alert-danger'>{}</p>", msg)));
    }

    if let Err(msg) = atomic_write_config(&state.config_path, &form.raw_content) {
        return Ok(Html(format!("<p class='alert alert-danger'>{}</p>", msg)));
    }

    let tpl = make_settings_success_template(
        Some(user.0),
        &state.config_path,
        "Raw TOML saved and validated. Container will pick up changes via its watcher (or send SIGHUP).".into(),
        state.keytab_display(),
        state.host_nfs_mode,
        state.fs_probe_mountinfo_path.as_deref(),
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

    // Note is shares are *not* collected or touched here. The dedicated.
    if let Err(e) = cfg.validate_and_derive() {
        let msg = format!("Validation error: {}", e);
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            &state.config_path,
            msg,
            state.keytab_display(),
            state.host_nfs_mode,
            state.fs_probe_mountinfo_path.as_deref(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    let original_text = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let mut doc = original_text
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_default();

    apply_structured_form_to_toml_doc(&form, &mut doc);

    let text = doc.to_string();
    if let Err(msg) = atomic_write_config(&state.config_path, &text) {
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            &state.config_path,
            msg,
            state.keytab_display(),
            state.host_nfs_mode,
            state.fs_probe_mountinfo_path.as_deref(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    let tpl = make_settings_success_template(
        Some(user.0),
        &state.config_path,
        "Structured settings saved (shares left untouched in TOML). Container will regenerate configs shortly.".into(),
        state.keytab_display(),
        state.host_nfs_mode,
        state.fs_probe_mountinfo_path.as_deref(),
    );
    Ok(Html(tpl.render().unwrap()))
}

/// Saves the shares editor form and mutates only [[shares]] in on-disk TOML.
pub(crate) async fn settings_save_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<StructuredSettingsForm>,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    // Collect only share_* indexed fields from flatten extra. Other form.
    let new_shares = collect_shares_from_structured_form(&form.extra);

    let mut cfg = nfs_klldap_config::NfsKlldapConfig::load(&state.config_path).unwrap_or_default();
    cfg.shares = new_shares.clone();

    if let Err(e) = cfg.validate_and_derive() {
        let msg = format!("Validation error: {}", e);
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            &state.config_path,
            msg,
            state.keytab_display(),
            state.host_nfs_mode,
            state.fs_probe_mountinfo_path.as_deref(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    let original_text = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let mut doc = original_text
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_default();

    apply_shares_to_toml_doc(&mut doc, &new_shares);

    let text = doc.to_string();
    if let Err(msg) = atomic_write_config(&state.config_path, &text) {
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            &state.config_path,
            msg,
            state.keytab_display(),
            state.host_nfs_mode,
            state.fs_probe_mountinfo_path.as_deref(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    let tpl = make_settings_success_template(
        Some(user.0),
        &state.config_path,
        "Shares saved (SSSD and other sections left untouched in TOML). The config watcher (or Restart and apply) will make Ganesha + WebUI see them shortly.".into(),
        state.keytab_display(),
        state.host_nfs_mode,
        state.fs_probe_mountinfo_path.as_deref(),
    );
    Ok(Html(tpl.render().unwrap()))
}

// Handlers for LLDAP status and NFS client reload.

pub(crate) async fn lldap_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return Html(
            "<div id='nfs-client-status' class='alert alert-danger'>Unauthorized</div>".to_string(),
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
            "<div class='alert alert-warning' style='margin:6px 0;'>"
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
        "<div id='nfs-client-status' style='border:1px solid var(--border); background:var(--bg-alt); padding:10px; margin:1rem 0; border-radius:4px;'>"
    );
    html.push_str("<strong>NFS Permission Client (KLLDAP/LLDAP connection)</strong><br>");
    html.push_str(&format!("Authenticated as: <code>{}</code><br>", auth_as));
    html.push_str(&format!("Last connected: {}<br>", last_str));
    html.push_str(&notice_html);
    if !username_differs {
        html.push_str("<span style='font-size:0.8em;color:var(--text-light);'>Reload always reads the latest bind credentials + ldap_uri from disk/env.</span><br>");
    }
    html.push_str(
        "<button type='button' hx-post='/settings/reload-nfs-client' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:8px; padding:4px 10px; cursor:pointer;'>Reload NFS client</button>"
    );
    html.push_str(
        " <span style='font-size:0.8em; color:var(--text-light); margin-left:6px;'>(re-reads sssd.ldap_default_bind_* + ldap_uri and re-binds)</span>"
    );

    html.push_str(
        r#"<button type='button' hx-post='/settings/clear-ldap-cache' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:8px; margin-left:8px; padding:4px 10px; cursor:pointer;'>Clear identity cache</button>"#
    );
    html.push_str(r#" <span style='font-size:0.8em;color:var(--text-light)'>(10m user/group cache + 2m search cache)</span>"#);

    let stats = client.cache_stats_summary();
    let hit_rate = if stats.hits + stats.misses > 0 {
        (stats.hits as f64 * 100.0 / (stats.hits + stats.misses) as f64) as u32
    } else { 0 };
    let last_cleared = stats.last_cleared_ago_secs.map(|s| format!(" • last cleared {}s ago", s)).unwrap_or_default();
    html.push_str(&format!(
        r#"<div style='font-size:0.75em;color:var(--text-light);margin-top:6px;'>Cache: {} users, {} groups, {} searches • {}% hit ({} hits / {} misses) • clears: {}{}</div>"#,
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
            "<div id='nfs-client-status' class='alert alert-danger'>Unauthorized</div>".to_string(),
        );
    }

    let fresh = match crate::config::load_config_from(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            let mut err = String::from("<div id='nfs-client-status' class='alert alert-danger'>");
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
        let mut msg = String::from("<div id='nfs-client-status' class='alert alert-warning'>");
        msg.push_str(&format!("<strong>Cannot reload:</strong> No valid password present for <code>{}</code> in the current config (or env).<br>", user));
        msg.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML'>Refresh</button>");
        msg.push_str("</div>");
        return Html(msg);
    }

    let realm = fresh.effective_realm();
    let resolver =
        nfs_klldap_config::from_sssd_section(&fresh.ldap_uri, &fresh.sssd, &realm);
    let posix_attrs = resolver.posix_attributes().clone();
    let user_base = resolver.user_base().to_string();
    let group_base = resolver.group_base().to_string();

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

            let mut ok = String::from("<div id='nfs-client-status' class='alert alert-success'>");
            ok.push_str("<strong>NFS client reloaded successfully.</strong><br>");
            ok.push_str(&format!("Now authenticated as <code>{}</code> using current values from nfs-klldap.conf.<br>", user));
            ok.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:4px;'>Show updated status</button>");
            ok.push_str("</div>");
            Html(ok)
        }
        Err(e) => {
            let mut err = String::from("<div id='nfs-client-status' class='alert alert-danger'>");
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
            "<div id='nfs-client-status' class='alert alert-danger'>Unauthorized</div>".to_string(),
        );
    }

    {
        let client = state.lldap.lock().await;
        client.clear_cache();
    }

    let mut ok = String::from("<div id='nfs-client-status' class='alert alert-success'>");
    ok.push_str("<strong>LDAP identity cache cleared.</strong><br>");
    ok.push_str("<span style='font-size:0.8em'>Next lookups will hit KLLDAP (10m TTL restarts after first fetch).</span><br>");
    ok.push_str("<button type='button' hx-get='/settings/lldap-status' hx-target='#nfs-client-status' hx-swap='outerHTML' style='margin-top:4px;'>Show status</button>");
    ok.push_str("</div>");
    Html(ok)
}

/// GET /restart-status — public poller endpoint 200 only when the supervisor.
/// Recycle marker is recent.
pub(crate) async fn restart_status() -> impl IntoResponse {
    let marker = service_recycle_marker_path();
    if marker.exists() {
        // Only trust a recent marker (this particular apply, not a Leftover.
        if let Ok(meta) = std::fs::metadata(&marker) {
            if let Ok(mtime) = meta.modified() {
                if let Ok(age) = mtime.elapsed() {
                    if age < std::time::Duration::from_secs(10 * 60) {
                        return (axum::http::StatusCode::OK, "recycled");
                    }
                }
            }
        }
    }
    (axum::http::StatusCode::SERVICE_UNAVAILABLE, "pending")
}

// Handlers for graceful restart and apply.

/// Schedules a one-shot HUP recycle and renders the restarting page.
pub(crate) async fn system_restart(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;
    let _ = try_schedule_service_recycle(&state, &format!("Restart and apply by '{}'", user.0)).await;
    Ok(render_restarting_page())
}
