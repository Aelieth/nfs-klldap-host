//! `/settings`: raw + structured TOML editor (settings + separate shares), LLDAP reload, cache clear (HTMX).
//! + graceful "Restart and apply" that returns a self-contained retry-to-login page and then
//!   HUPs pid 1 so the supervisor bounces just Ganesha + SSSD + this WebUI (the services that
//!   must re-read generated configs or the shares list for the permission tree).

use askama::Template;
use axum::{
    extract::{Form, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;
use std::path::PathBuf;

use super::{get_keytab_info, AppState, require_auth};

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
    keytab_alert: Option<String>,

    /// NFS principals found in the keytab (for display + matching underline in template).
    keytab_found_principals: Vec<String>,

    // === Structured editor prefill (populated from on-disk nfs-klldap.conf on every render) ===
    // Raw TOML remains the full-fidelity path (comments, order, advanced fields).
    ldap_uri: String,
    storage_container_root: String,
    server_hostname: String,
    sssd_bind_dn: String,
    // bind_pw is *never* prefilled into the form (security + source visibility; raw textarea already shows it).
    // Submit non-empty value to change it.
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

    // Override flags (from explicit presence in raw source TOML, not derivation).
    // These control whether structured save will write the value as an override
    // or omit it (allowing derivation on next load/generate). Key fields (ldap_uri,
    // container_root, bind_* , kllldap_ignored_attributes) have no override flag.
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

    /// Server-rendered current shares (enables proper edit + delete via row removal before submit).
    current_shares: Vec<ShareTemplateRow>,
    /// Next index the client-side JS should use when the user clicks "+ Add share".
    next_share_idx: usize,
}

/// Standalone template for the post-"Restart and apply" page.
/// Deliberately does not extend base.html: it is rendered once, then the current
/// WebUI process is terminated as part of the service bounce (the JS inside
/// performs the retry-to-login loop until the fresh WebUI is listening again).
#[derive(Template)]
#[template(path = "restarting.html")]
struct RestartingTemplate;

// === Forms ===

#[derive(Deserialize)]
pub(crate) struct RawSaveForm {
    raw_content: String,
}

// Structured form for the common editable parts of nfs-klldap.conf.
// (Also reused for /save-shares POSTs; only the share_* keys in the flatten extra matter for that path.)
#[derive(Deserialize, Debug, Default)]
pub(crate) struct StructuredSettingsForm {
    // Top level
    ldap_uri: Option<String>,

    // [storage]
    storage_container_root: Option<String>,

    // [server]
    server_hostname: Option<String>,
    override_server_hostname: Option<bool>,

    // [sssd]
    sssd_bind_dn: Option<String>,
    sssd_bind_pw: Option<String>,
    sssd_port: Option<u16>,
    sssd_search_base: Option<String>,
    override_sssd_search_base: Option<bool>,
    sssd_user_base: Option<String>,
    override_sssd_user_base: Option<bool>,
    sssd_group_base: Option<String>,
    override_sssd_group_base: Option<bool>,
    // TLS options
    sssd_ldap_tls_reqcert: Option<String>,
    override_sssd_ldap_tls_reqcert: Option<bool>,
    sssd_ldap_tls_cacert: Option<String>,
    override_sssd_ldap_tls_cacert: Option<bool>,
    sssd_ldap_id_use_start_tls: Option<bool>,
    override_sssd_ldap_id_use_start_tls: Option<bool>,
    sssd_enumerate: Option<bool>,
    override_sssd_enumerate: Option<bool>,
    // Control for server-side KLLDAP ignore lists (and ldap_group_member choice) emitted into sssd.conf.
    kllldap_ignored_attributes: Option<bool>,

    // [kerberos]
    kerberos_realm: Option<String>,
    override_kerberos_realm: Option<bool>,

    // [ganesha]
    ganesha_default_security: Option<String>,
    override_ganesha_default_security: Option<bool>,

    // Shares (indexed fields via flatten)
    #[serde(flatten)]
    extra: std::collections::HashMap<String, String>,
}

// === Internal helper types ===

/// Internal row representation for the share editor form (used during collect from POST).
/// Used by both the (now settings-only) structured save and the dedicated shares save.
#[derive(Debug, Clone)]
struct ShareFormRow {
    idx: usize,
    name: String,
    host: String,
    export_path: Option<String>,
    security: Option<String>,
    rw: bool,
    root_squash: bool,
    sync: bool,
}

/// Template row for server-rendered shares in the structured editor (string values for simple Askama rendering).
#[derive(Debug, Clone)]
struct ShareTemplateRow {
    idx: usize,
    name: String,
    host_path: String,
    export_path: String,
    security: String,
    rw: bool,
    root_squash: bool,
    sync: bool,
}

/// Returns true if `key` is explicitly present in the (raw, pre-derive) TOML source.
/// Used to pre-check the "override" boxes for non-key fields. Key fields (ldap_uri,
/// container_root, bind dn/pw, kllldap_ignored_attributes) are always treated as
/// explicit and have no override flag.
fn has_explicit(doc: &toml_edit::DocumentMut, section: &str, key: &str) -> bool {
    if section.is_empty() {
        doc.get(key).is_some()
    } else {
        doc.get(section)
            .and_then(|i| i.as_table())
            .is_some_and(|t| t.get(key).is_some())
    }
}

/// Return the string value of a key if present in the raw doc (for special prefill logic).
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

/// Export path for the shares editor: only when `export_path` is explicit in raw [[shares]].
/// Derived defaults from validate_and_derive (e.g. `/{name}`) must not appear in the form.
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
    tbl.get("export_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// Build a fully-populated SettingsTemplate by reading the current on-disk config.
/// This is the source of truth for pre-filling the structured editor (including shares).
/// Used for initial page load and after raw/structured save (success or error).
fn build_settings_template(
    current_user: Option<String>,
    config_path: impl AsRef<std::path::Path>,
    message: Option<String>,
    keytab_hostname: String,
    keytab_realm: String,
    keytab_alert: Option<String>,
) -> SettingsTemplate {
    let p = config_path.as_ref();
    let raw_toml = std::fs::read_to_string(p)
        .unwrap_or_else(|_| "# Could not read config file".to_string());

    // Parse raw (un-derived) TOML to detect which fields are *explicit overrides*
    // vs. purely derived at load/validate time. This drives the "override" checkboxes.
    let doc: toml_edit::DocumentMut = raw_toml.parse().unwrap_or_default();

    let cfg = nfs_klldap_config::NfsKlldapConfig::load(p).unwrap_or_default();

    let current_shares: Vec<ShareTemplateRow> = cfg
        .shares
        .iter()
        .enumerate()
        .map(|(idx, s)| ShareTemplateRow {
            idx,
            name: s.name.clone(),
            host_path: s.host_path.display().to_string(),
            export_path: share_export_path_from_raw(&doc, idx),
            security: s.security.clone().unwrap_or_default(),
            rw: s.rw.unwrap_or(true),
            root_squash: s.squash.as_deref() == Some("root_squash"),
            sync: s.sync.unwrap_or(true),
        })
        .collect();
    let next_share_idx = current_shares.len();

    SettingsTemplate {
        current_user,
        raw_toml,
        config_path: p.display().to_string(),
        message,
        effective_hostname: keytab_hostname.clone(),
        effective_realm: keytab_realm.clone(),
        keytab_alert: keytab_alert.clone(),
        keytab_found_principals: get_keytab_info(&keytab_hostname, &keytab_realm)
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
        // Special for ganesha: treat explicit "krb5p" the same as absent (the non-override default state).
        // Only if the source has a non-krb5p value do we consider it an active override.
        // Combined with the writer always ensuring "krb5p" when !override, this keeps the
        // default materialized in the conf without the checkbox appearing "stuck" on for the default.
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
    }
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
                    .filter(|s| !s.trim().is_empty());
                // no auto-fill: leave None so it stays optional/blank in the raw toml
                let security = extra
                    .get(&format!("share_security_{}", idx))
                    .cloned()
                    .filter(|s| !s.trim().is_empty());
                let rw = extra
                    .get(&format!("share_rw_{}", idx))
                    .map(|v| v.trim() == "true")
                    .unwrap_or(true);
                let root_squash = extra.contains_key(&format!("share_root_squash_{}", idx));
                let sync = extra.contains_key(&format!("share_sync_{}", idx));
                share_rows.push(ShareFormRow {
                    idx,
                    name,
                    host,
                    export_path,
                    security,
                    rw,
                    root_squash,
                    sync,
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
                None // omit default so it doesn't get written to raw toml
            },
            sync: Some(r.sync),
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
    // Only overwrite bind pw if a non-empty value was submitted (structured form does not prefill the secret).
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

    // kllldap_ignored_attributes: checkbox absence on submit (for this default-true flag) means explicit false.
    // We always produce Some so structured saves make the value explicit in the TOML.
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
        // Not overriding: materialize the standard default (so ganesha.conf always
        // gets a known SecType, and "go back" from override restores krb5p in source
        // instead of stripping the key entirely).
        cfg.ganesha.default_security = "krb5p".to_string();
    }
}

fn make_settings_error_template(
    current_user: Option<String>,
    config_path: impl AsRef<std::path::Path>,
    message: String,
    keytab_hostname: String,
    keytab_realm: String,
    keytab_alert: Option<String>,
) -> SettingsTemplate {
    // Always re-read current on-disk state for prefilled structured fields + raw.
    // On structured validation error the file on disk is unchanged.
    build_settings_template(
        current_user,
        config_path,
        Some(message),
        keytab_hostname,
        keytab_realm,
        keytab_alert,
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
    keytab_hostname: String,
    keytab_realm: String,
    keytab_alert: Option<String>,
) -> SettingsTemplate {
    // Re-read after successful write so structured pre-fills reflect the just-saved state.
    build_settings_template(
        current_user,
        config_path,
        Some(message),
        keytab_hostname,
        keytab_realm,
        keytab_alert,
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
    // Only write bind pw if non-empty (structured editor never prefills the secret field).
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

    // kllldap_ignored_attributes is always emitted explicitly from the structured path
    // (we treat unchecked as false for this default-true flag).
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
            // override checked but no value submitted (e.g. was disabled before toggle): use default
            let item = doc.entry("ganesha").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["default_security"] = toml_edit::value("krb5p");
            }
        }
    } else {
        // Not overriding ganesha: ensure the default "krb5p" is present in the source
        // (prevents the value from being "removed entirely" when un-overriding; other
        // derived fields intentionally omit their keys to allow dynamic derivation).
        let item = doc.entry("ganesha").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["default_security"] = toml_edit::value("krb5p");
        }
    }
}

/// Write (or replace) only the [[shares]] array in the raw TOML doc.
/// Used exclusively by the dedicated shares-save path so that saving shares
/// never touches [sssd], [server], etc. (and vice-versa for settings save).
/// Mirrors the emission that used to live inside apply_structured_form_to_toml_doc.
fn apply_shares_to_toml_doc(doc: &mut toml_edit::DocumentMut, new_shares: &[nfs_klldap_config::Share]) {
    // Shares: submitted rows (now pre-populated on load) are always authoritative.
    // We replace [[shares]] even if the submitted list is empty (user explicitly removed all rows).
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
        // Only persist non-defaults in the source TOML (keeps conf clean; generator
        // always applies the effective default when the key is absent).
        let rw = s.rw.unwrap_or(true);
        if !rw {
            t["rw"] = toml_edit::value(false);
        }
        if let Some(sq) = &s.squash {
            if sq != "no_root_squash" {
                t["squash"] = toml_edit::value(sq.clone());
            }
        }
        let sync = s.sync.unwrap_or(true);
        if !sync {
            t["sync"] = toml_edit::value(false);
        }
        shares.push(t);
    }
    doc["shares"] = toml_edit::Item::ArrayOfTables(shares);
}

// === Handlers ===

pub(crate) async fn settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    let tpl = build_settings_template(
        Some(user.0),
        &state.config_path,
        None,
        state.keytab_hostname.clone(),
        state.keytab_realm.clone(),
        state.keytab_alert.clone(),
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
        state.keytab_hostname.clone(),
        state.keytab_realm.clone(),
        state.keytab_alert.clone(),
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

    // Note: shares are *not* collected or touched here. The dedicated /settings/save-shares
    // path (and its form) is the only thing that mutates [[shares]]. This ensures a
    // "Save Settings" cannot overwrite custom shares (or their comments) in the raw TOML.
    if let Err(e) = cfg.validate_and_derive() {
        let msg = format!("Validation error: {}", e);
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            &state.config_path,
            msg,
            state.keytab_hostname.clone(),
            state.keytab_realm.clone(),
            state.keytab_alert.clone(),
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
            state.keytab_hostname.clone(),
            state.keytab_realm.clone(),
            state.keytab_alert.clone(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    let tpl = make_settings_success_template(
        Some(user.0),
        &state.config_path,
        "Structured settings saved (shares left untouched in TOML). Container will regenerate configs shortly.".into(),
        state.keytab_hostname.clone(),
        state.keytab_realm.clone(),
        state.keytab_alert.clone(),
    );
    Ok(Html(tpl.render().unwrap()))
}

/// Dedicated handler for the separate Shares form.
/// Only mutates the [[shares]] array in the on-disk TOML (via apply_shares_to_toml_doc);
/// never re-applies or rewrites any [sssd], [server], ldap_uri, etc. keys.
/// Validation is still performed (shares validation lives in validate_and_derive).
pub(crate) async fn settings_save_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<StructuredSettingsForm>,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    // Collect only from the share_* indexed fields in the flatten extra (other form fields absent/None).
    let new_shares = collect_shares_from_structured_form(&form.extra);

    let mut cfg = nfs_klldap_config::NfsKlldapConfig::load(&state.config_path).unwrap_or_default();
    cfg.shares = new_shares.clone();

    if let Err(e) = cfg.validate_and_derive() {
        let msg = format!("Validation error: {}", e);
        let tpl = make_settings_error_template(
            Some(user.0.clone()),
            &state.config_path,
            msg,
            state.keytab_hostname.clone(),
            state.keytab_realm.clone(),
            state.keytab_alert.clone(),
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
            state.keytab_hostname.clone(),
            state.keytab_realm.clone(),
            state.keytab_alert.clone(),
        );
        return Ok(Html(tpl.render().unwrap()));
    }

    let tpl = make_settings_success_template(
        Some(user.0),
        &state.config_path,
        "Shares saved (SSSD and other sections left untouched in TOML). The config watcher (or Restart and apply) will make Ganesha + WebUI see them shortly.".into(),
        state.keytab_hostname.clone(),
        state.keytab_realm.clone(),
        state.keytab_alert.clone(),
    );
    Ok(Html(tpl.render().unwrap()))
}

// === LLDAP / NFS client status + reload (HTMX) ===

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
    html.push_str("<span style='font-size:0.9em;'>Used for live user/group lookups and uid/gid resolution when managing share permissions.</span><br><br>");
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

/// GET /restart-status
/// Public (no auth) lightweight status for the restarting.html poller.
/// Returns 200 only after the entrypoint has completed a full service recycle
/// (i.e. the "Services (Ganesha + SSSD + WebUI) recycled in place for config apply."
/// log has been emitted). This prevents the poller from declaring "up" as soon
/// as the new WebUI process binds (which happens before Ganesha/SSSD are ready
/// and before the shell declares the cycle complete).
pub(crate) async fn restart_status() -> impl IntoResponse {
    const MARKER: &str = "/tmp/.nfs-klldap-services-recycled";
    if std::path::Path::new(MARKER).exists() {
        // Only trust a recent marker (this particular apply, not a leftover
        // from hours/days ago).
        if let Ok(meta) = std::fs::metadata(MARKER) {
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

// === Graceful "Restart and apply" (from System Settings) ===

/// POST /settings/restart
/// Requires auth (like every other settings action).
/// Immediately returns a standalone restarting page (the HTML is delivered before we pull the rug).
/// Then, after a short delay, sends SIGHUP to pid 1. The entrypoint's handle_sighup runs the
/// Rust generator (if needed), fixes permissions, and bounces exactly the services that must
/// see the new config:
///   - Ganesha (to pick up new/changed [[shares]] export fragments + ganesha.conf)
///   - SSSD (to pick up sssd.conf changes: binds, search bases, schema, krb5 bits, etc.)
///   - WebUI (to re-load the central Config + rebuild FsManager with the current shares list
///     so the permission tree / allowed roots / dir editor see new shares)
///
/// Kerberos (krb5.conf) changes are picked up by the freshly-started processes that use the
/// Kerberos libs.
///
/// The supervisor (entrypoint) itself stays alive; only the three children are cycled.
/// This is "restart the services we need" rather than a full container death + runtime
/// restart policy cycle (although a real `docker/podman restart` or TERM to pid 1 still does
/// the full thing for recovery/crash cases).
///
/// A one-shot guard (restart_requested in AppState) ensures that only the first request
/// schedules the delayed HUP; later POSTs (double-click, F5 on the result URL, etc.)
/// just re-serve the restarting page without additional side effects.
pub(crate) async fn system_restart(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;

    // One-shot guard: if a restart was already requested (e.g. rapid re-click or
    // browser refresh of POST result), just return the page again without rescheduling.
    {
        let mut flag = state.restart_requested.lock().await;
        if *flag {
            let tpl = RestartingTemplate;
            return Ok(Html(tpl.render().unwrap()));
        }
        *flag = true;
    }

    // Clear the apply-complete marker (if any) so the JS poller on the restarting
    // page will not see a stale "done" from a prior run. The marker is (re)created
    // by the entrypoint only after the full "Services ... recycled" declaration.
    let _ = std::fs::remove_file("/tmp/.nfs-klldap-services-recycled");

    // Schedule the HUP *after* we have returned the response.
    // The ~1.4 s delay gives the HTTP server time to flush the restarting page + headers
    // to the browser before the current WebUI listener is terminated (as part of the
    // service bounce). The JS in the page then polls for the new UI to come up.
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(1400)).await;
        eprintln!(
            "INFO: 'Restart and apply' requested by '{}' — triggering service bounce (HUP to pid 1)",
            user.0
        );
        // Fire-and-forget a tiny shell snippet. We do not wait for it.
        // The HUP handler in entrypoint does the generate + coordinated bounce of
        // Ganesha/SSSD/WebUI (supervisor stays up; no full container restart).
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 0.25; kill -HUP 1 2>/dev/null || true")
            .spawn();
    });

    let tpl = RestartingTemplate;
    Ok(Html(tpl.render().unwrap()))
}