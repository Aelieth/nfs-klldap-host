use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Json, Redirect},
};
use serde::Deserialize;
use super::setup::{run_bind_probe_blocking, validate_ldap_uri, BindForm, LdapUriForm, SetupTestResponse};
use super::{AppState, require_auth};

mod apply;
mod spec;

pub(crate) use apply::{apply_shares_to_toml_doc, atomic_write_config};
pub(crate) use spec::{apply_structured_form_to_config, apply_structured_form_to_toml_doc};

#[derive(Template)]
#[template(path = "settings.html")]
pub(crate) struct SettingsTemplate {
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
    /// Banner from the ACL re-probe loop: an explicit-ACL share whose backing
    /// filesystem can no longer store ACLs. None hides it.
    acl_alert: Option<String>,
    /// NFS principals from keytab (template underline highlight).
    keytab_found_principals: Vec<String>,
    ldap_uri: String,
    storage_container_root: String,
    server_hostname: String,
    sssd_bind_dn: String,
    /// SSSD pane Auto/Custom text fields, spec-driven (render order).
    sssd_ac_fields: Vec<spec::AcTextView>,
    /// TLS pane Auto/Custom text fields, spec-driven (render order).
    tls_ac_fields: Vec<spec::AcTextView>,
    /// TLS pane Auto/Custom checkboxes, spec-driven (render order).
    tls_ac_bools: Vec<spec::AcBoolView>,
    kerberos_realm: String,
    ganesha_default_security: String,
    kllldap_ignored_attributes: bool,
    probe_user_principal: String,
    probe_client_host: String,
    /// True when no explicit [probe] key exists (auto-pick from directory).
    auto_probe_ldap: bool,
    override_server_hostname: bool,
    override_kerberos_realm: bool,
    override_ganesha_default_security: bool,
    /// Server-rendered shares for edit/delete via row removal.
    current_shares: Vec<ShareTemplateRow>,
    /// Holds the next share row index the client JS uses for Add Share rows.
    next_share_idx: usize,
    /// Reflects HOST_NFS mode where host Ganesha serves exports and WebUI.
    host_nfs_mode: bool,
}
/// One share card; included per row by settings.html and served blank by /settings/share-card.
#[derive(Template)]
#[template(path = "share_card.html")]
struct ShareCardTemplate {
    row: ShareTemplateRow,
}

#[derive(Deserialize)]
pub(crate) struct ShareCardParams {
    idx: usize,
}

/// GET /settings/share-card?idx=N — blank card for the Shares pane "+ Add share" htmx append.
pub(crate) async fn share_card_blank(
    State(state): State<AppState>,
    Query(params): Query<ShareCardParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    let tpl = ShareCardTemplate {
        row: ShareTemplateRow::blank(params.idx),
    };
    Ok(Html(tpl.render().unwrap()))
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
/// A marker mtime at or after `latch_at` means the supervisor completed a
/// recycle since we scheduled this one.
fn recycle_marker_is_fresh(marker: &std::path::Path, latch_at: std::time::SystemTime) -> bool {
    std::fs::metadata(marker)
        .and_then(|m| m.modified())
        .map(|mtime| mtime >= latch_at)
        .unwrap_or(false)
}

/// Clear recycle marker and schedule delayed HUP (pid 1 or test override).
///
/// The `restart_requested` latch means "one HUP is in flight", not "once per
/// process": the spawned task releases it once the supervisor touches the
/// recycle marker (or after a timeout), so a HUP that turns out to be a no-op
/// generate — which never restarts the WebUI — cannot wedge the latch and
/// silently swallow every later save.
pub(crate) async fn try_schedule_service_recycle(state: &super::AppState, log_context: &str) -> bool {
    {
        let mut flag = state.restart_requested.lock().await;
        if *flag {
            return false;
        }
        *flag = true;
    }
    let marker = service_recycle_marker_path();
    let _ = std::fs::remove_file(&marker);
    let latch_at = std::time::SystemTime::now();
    let label = log_context.to_string();
    let hup_pid = std::env::var("NFS_KLLDAP_SUPERVISOR_PID").unwrap_or_else(|_| "1".to_string());
    let delay_ms = std::env::var("NFS_KLLDAP_RECYCLE_DELAY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1400);
    let unlatch_timeout_ms = std::env::var("NFS_KLLDAP_RECYCLE_UNLATCH_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90_000u64);
    let restart_flag = std::sync::Arc::clone(&state.restart_requested);
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        match hup_pid.parse::<u32>() {
            Ok(pid) if pid > 0 => {
                eprintln!("INFO: '{label}' — triggering service bounce (HUP to pid {pid})");
                if let Err(e) = nfs_klldap_config::signal_supervisor_hup(pid) {
                    eprintln!("WARN: '{label}' — SIGHUP failed: {e}");
                }
            }
            _ => {
                eprintln!(
                    "WARN: '{label}' — invalid NFS_KLLDAP_SUPERVISOR_PID '{hup_pid}', skipping HUP"
                );
            }
        }
        // Release the latch once the recycle completes (marker touched) or the
        // timeout elapses, on every path above.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(unlatch_timeout_ms);
        while !recycle_marker_is_fresh(&marker, latch_at) && std::time::Instant::now() < deadline {
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        }
        *restart_flag.lock().await = false;
    });
    true
}
#[derive(Deserialize)]
pub(crate) struct RawSaveForm {
    raw_content: String,
}
/// Flattened name -> value map of the submitted settings form. The scalar
/// field surface is interpreted against spec::FIELDS; share rows and the
/// probe trio read their own keys. Present-vs-absent semantics match the
/// old per-field Option struct: an unsubmitted input leaves state untouched.
#[derive(Deserialize, Debug, Default)]
pub(crate) struct StructuredSettingsForm {
    #[serde(flatten)]
    pub(crate) fields: std::collections::HashMap<String, String>,
}

// Form items from modular settings_form
use super::settings_form::{ShareTemplateRow, collect_shares_from_structured_form, has_explicit, get_explicit_str, share_pseudo_path_explicit_in_raw, share_pseudo_path_from_raw, infer_profile_from_prefs};



// Form logic modularized (settings_form.rs)
/// Share pseudo_path for the editor when explicit in raw TOML.
/// Normalized to an absolute path.
/// Maps legacy pref_read/pref_write pairs to cache profile names.
/// Used to prefill the dropdown.
/// Build SettingsTemplate from on-disk config.
/// Used on page load and post-save re-render.
pub(crate) fn build_settings_template(
    state: &AppState,
    current_user: Option<String>,
    message: Option<String>,
) -> SettingsTemplate {
    let p = state.config_path.as_path();
    let keytab = state.keytab_display();
    let host_nfs_mode = state.host_nfs_mode;
    let snap =
        nfs_klldap_config::MountinfoSnapshot::capture(state.fs_probe_mountinfo_path.as_deref());
    let acl_alert = state.acl_alert.lock().unwrap().clone();
    let raw_toml = std::fs::read_to_string(p)
        .unwrap_or_else(|_| "# Could not read config file".to_string());
    let doc: toml_edit::DocumentMut = raw_toml.parse().unwrap_or_default();
    let cfg = nfs_klldap_config::NfsKlldapConfig::parse_str(&p.display().to_string(), &raw_toml)
        .and_then(|mut c| c.validate_and_derive().map(|_| c))
        .unwrap_or_default();
    let current_shares: Vec<ShareTemplateRow> = cfg
        .shares
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            // One classification for every surface: the same helper drives the
            // Share Permissions cards and the client manifest.
            let status = super::acl_status::share_acl_status(&state.acl_caps, &snap, &cfg, s);
            ShareTemplateRow {
            idx,
            name: s.name.clone(),
            host_path: s.host_path.display().to_string(),
            // For the Pseudo Path input: show the auto-derived value (/{name}) when not explicitly
            // set in the on-disk TOML. This makes the field reflect the correct default instead of
            // a generic placeholder. On save we strip it back to "auto" (not persisted) if it matches derived.
            pseudo_path: if share_pseudo_path_explicit_in_raw(&doc, idx) {
                share_pseudo_path_from_raw(&doc, idx)
            } else {
                nfs_klldap_config::derive_share_pseudo(s)
            },
            pseudo_editable: status.effective_enable_acl,
            effective_pseudo: nfs_klldap_config::derive_share_pseudo(s),
            container_path: s.container_path.clone(),
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
            effective_acl_capable: status.effective_acl_capable,
            // Probe verdict + human label for the card chip and the JS status dot.
            acl_probed: status.probed.to_string(),
            acl_state_label: status.state_label,
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
            manage_gids_expiration: s.manage_gids_expiration,
            warning: nfs_klldap_config::ShareFieldWarning::for_share(
                &cfg.share_warnings,
                idx,
                &s.name,
            )
            .map(|w| w.display_message()),
            // Limited serve root first; otherwise flag ACL-incapable submounts
            // hiding inside an ACL-serving tree (per-share model: a divergent
            // submount is a config-health warning, not a per-directory state).
            fs_warning: nfs_klldap_config::share_fs_warning_message_snapshot(&cfg, s, &snap)
                .or_else(|| {
                    nfs_klldap_config::share_divergent_submount_warning_snapshot(
                        &cfg,
                        s,
                        &snap,
                        status.effective_enable_acl,
                    )
                }),
        }
        })
        .collect();
    let next_share_idx = current_shares.len();
    let sssd_ac_fields = spec::sssd_ac_text_views(&cfg, &doc);
    let tls_ac_fields = spec::tls_ac_text_views(&cfg, &doc);
    let tls_ac_bools = spec::tls_ac_bool_views(&cfg, &doc);
    SettingsTemplate {
        current_user,
        raw_toml,
        config_path: p.display().to_string(),
        message,
        effective_hostname: keytab.hostname.clone(),
        effective_realm: keytab.realm.clone(),
        keytab_alert: keytab.alert.clone(),
        acl_alert,
        keytab_found_principals: nfs_klldap_config::get_keytab_info(&keytab.hostname, &keytab.realm)
            .found_nfs_principals,
        ldap_uri: cfg.ldap_uri,
        storage_container_root: cfg.storage.container_root.clone(),
        server_hostname: cfg.server.hostname.clone().unwrap_or_default(),
        sssd_bind_dn: cfg.sssd.ldap_default_bind_dn.clone(),
        sssd_ac_fields,
        tls_ac_fields,
        tls_ac_bools,
        kerberos_realm: cfg.kerberos.realm.clone().unwrap_or_default(),
        ganesha_default_security: cfg.ganesha.default_security.clone(),
        kllldap_ignored_attributes: cfg.sssd.kllldap_ignored_attributes.unwrap_or(true),
        probe_user_principal: cfg.probe.user_principal.clone().unwrap_or_default(),
        probe_client_host: cfg.probe.client_host.clone().unwrap_or_default(),
        auto_probe_ldap: !(has_explicit(&doc, "probe", "user_principal")
            || has_explicit(&doc, "probe", "client_host")),
        override_server_hostname: has_explicit(&doc, "server", "hostname"),
        override_kerberos_realm: has_explicit(&doc, "kerberos", "realm"),
        override_ganesha_default_security: get_explicit_str(&doc, "ganesha", "default_security")
            .is_some_and(|v| v != "krb5p"),
        current_shares,
        next_share_idx,
        host_nfs_mode,
    }
}
pub(crate) async fn settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;
    let tpl = build_settings_template(&state, Some(user.0), None);
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
    let tpl = build_settings_template(
        &state,
        Some(user.0),
        Some("Raw TOML saved and validated. Container will pick up changes via its watcher (or send SIGHUP).".into()),
    );
    Ok(Html(tpl.render().unwrap()))
}
pub(crate) async fn settings_save_structured(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<StructuredSettingsForm>,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;
    let original_text = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let mut cfg = nfs_klldap_config::NfsKlldapConfig::parse_str(
        &state.config_path.display().to_string(),
        &original_text,
    )
    .and_then(|mut c| c.validate_and_derive().map(|_| c))
    .unwrap_or_default();
    apply_structured_form_to_config(&form, &mut cfg);
    if let Err(e) = cfg.validate_and_derive() {
        let msg = format!("Validation error: {}", e);
        let tpl = build_settings_template(&state, Some(user.0.clone()), Some(msg));
        return Ok(Html(tpl.render().unwrap()));
    }
    let mut doc = original_text
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_default();
    apply_structured_form_to_toml_doc(&form, &mut doc);
    let text = doc.to_string();
    if let Err(msg) = atomic_write_config(&state.config_path, &text) {
        let tpl = build_settings_template(&state, Some(user.0.clone()), Some(msg));
        return Ok(Html(tpl.render().unwrap()));
    }
    let tpl = build_settings_template(
        &state,
        Some(user.0),
        Some("Structured settings saved (shares left untouched in TOML). Container will regenerate configs shortly.".into()),
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
    let original_text = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let doc: toml_edit::DocumentMut = original_text.parse().unwrap_or_default();
    let old_cfg = nfs_klldap_config::NfsKlldapConfig::load(&state.config_path).unwrap_or_default();
    let mut new_shares = collect_shares_from_structured_form(&form.fields);

    // If the pseudo_path submitted matches the auto-derived (/{name}), treat as not-explicit
    // so we don't persist the default value in TOML (keeps it clean/"auto").
    for new_share in &mut new_shares {
        if let Some(p) = &new_share.pseudo_path {
            let auto = format!("/{}", new_share.name);
            let norm = if p.starts_with('/') { p.clone() } else { format!("/{}", p) };
            if norm == auto {
                new_share.pseudo_path = None;
            }
        }
    }

    for (idx, new_share) in new_shares.iter_mut().enumerate() {
        // Raw-TOML-only fields survive a structured save: look the old share
        // up once (index first, then name so reordered rows still match).
        let old = old_cfg
            .shares
            .get(idx)
            .or_else(|| old_cfg.shares.iter().find(|s| s.name == new_share.name));
        let Some(old) = old else { continue };
        if new_share.pseudo_path.is_none() && share_pseudo_path_explicit_in_raw(&doc, idx) {
            new_share.pseudo_path = old.pseudo_path.clone();
        }
        // source_path (ACL staging source) has no structured-form control yet; preserve any
        // value set via raw TOML so a structured save does not silently drop staging.
        if new_share.source_path.is_none() {
            new_share.source_path = old.source_path.clone();
        }
        // attr_expiration_secs likewise rides raw TOML only for now.
        if new_share.attr_expiration_secs.is_none() {
            new_share.attr_expiration_secs = old.attr_expiration_secs;
        }
    }
    let mut cfg = old_cfg;
    cfg.shares = new_shares.clone();
    // Flagging ACL on a share whose serve path provably cannot store POSIX
    // ACLs would only fail later at generate (blocking every export): refuse
    // the save here so the GUI gets immediate feedback.
    let save_snap =
        nfs_klldap_config::MountinfoSnapshot::capture(state.fs_probe_mountinfo_path.as_deref());
    for share in &cfg.shares {
        if share.enable_acl != Some(true) {
            continue;
        }
        let serve = std::path::PathBuf::from(cfg.serve_path_for(share));
        // A save decision must not ride a stale verdict, so force a fresh probe.
        let outcome = state
            .acl_caps
            .verdict_for_snapshot(&save_snap, &serve, &serve, false, true);
        // Only a KNOWN mount may reject the save: pre-deploy configs point at
        // paths that do not exist yet, and generate remains the hard gate.
        if outcome.caps.fstype != "unknown"
            && outcome.verdict == nfs_klldap_config::AclProbeVerdict::Incapable
        {
            let msg = format!(
                "share '{}': enable_acl = true but serve path '{}' (fstype={}) cannot store                  POSIX ACLs — use the staging pattern (source_path) or leave ACL off/auto.",
                share.name,
                serve.display(),
                outcome.caps.fstype
            );
            let tpl = build_settings_template(&state, Some(user.0.clone()), Some(msg));
            return Ok(Html(tpl.render().unwrap()));
        }
    }
    if let Err(e) = cfg.validate_and_derive() {
        let msg = format!("Validation error: {}", e);
        let tpl = build_settings_template(&state, Some(user.0.clone()), Some(msg));
        return Ok(Html(tpl.render().unwrap()));
    }
    let mut doc = doc;
    apply_shares_to_toml_doc(&mut doc, &cfg.shares);
    let text = doc.to_string();
    if let Err(msg) = atomic_write_config(&state.config_path, &text) {
        let tpl = build_settings_template(&state, Some(user.0.clone()), Some(msg));
        return Ok(Html(tpl.render().unwrap()));
    }
    let reload_msg = match state.reload_config_and_fs() {
        Ok(()) => String::new(),
        Err(e) => format!(" (in-memory reload failed: {e})"),
    };
    let _ = try_schedule_service_recycle(
        &state,
        &format!("Shares saved by '{}'", user.0),
    )
    .await;
    let tpl = build_settings_template(
        &state,
        Some(user.0),
        Some(format!(
            "Shares saved (SSSD and other sections left untouched in TOML).{reload_msg} Service recycle scheduled so Ganesha + WebUI pick up the new paths."
        )),
    );
    Ok(Html(tpl.render().unwrap()))
}
pub(crate) async fn lldap_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return Html(
            "<div id='nfs-client-status' class='alert alert-danger'>Unauthorized</div>".to_string(),
        );
    }
    let client = state.lldap.read().await.clone();
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
        "<div id='nfs-client-status' style='border:1px solid var(--border); background:var(--bg-alt); padding:10px; margin:14px 0 0; border-radius:6px;'>"
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
    let pool = if stats.pool_warm { "warm" } else { "cold" };
    html.push_str(&format!(
        r#"<div style='font-size:0.75em;color:var(--text-light);margin-top:6px;'>Cache: {} users, {} groups, {} searches • {}% hit ({} hits / {} misses) • clears: {} • {} LDAP binds since start • pool {}{}</div>"#,
        stats.user_entries, stats.group_entries, stats.recent_search_entries, hit_rate, stats.hits, stats.misses, stats.clears, stats.binds, pool, last_cleared
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
    let (mut new_client, _no_tls_verify) = crate::ldap::LdapClient::from_config(&fresh);
    match new_client.authenticate(&user, &pass).await {
        Ok(()) => {
            {
                *state.lldap.write().await = std::sync::Arc::new(new_client);
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
        let client = state.lldap.read().await.clone();
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
/// Schedules a one-shot HUP recycle and renders the restarting page.
pub(crate) async fn system_restart(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;
    let _ = try_schedule_service_recycle(&state, &format!("Restart and apply by '{}'", user.0)).await;
    Ok(render_restarting_page())
}

/// POST /settings/test-ldap — diagnostic DNS + TCP probe of ldap_uri.
/// Purely informational; a failing test never blocks Save.
pub(crate) async fn settings_test_ldap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LdapUriForm>,
) -> Result<impl IntoResponse, Redirect> {
    require_auth(&state, &headers).await?;
    let uri = match validate_ldap_uri(&form.ldap_uri) {
        Ok(u) => u.to_string(),
        Err(e) => {
            let log = format!(
                "<strong>Command</strong>\n(validation)\n\n<strong>Status</strong>\n{e}"
            );
            return Ok(Json(SetupTestResponse {
                ok: false,
                message: None,
                error: Some(e),
                log: Some(log),
            }));
        }
    };
    let host = nfs_klldap_config::extract_host_from_uri(&uri);
    let host_probe = host.clone();
    let uri_probe = uri.clone();
    let result =
        tokio::task::spawn_blocking(move || {
            nfs_klldap_config::check_ldap_reachability(&host_probe, &uri_probe)
        })
        .await
        .unwrap_or(nfs_klldap_config::LdapReachability::Unreachable {
            detail: "Reachability probe task failed".into(),
        });
    let log = nfs_klldap_config::format_reachability_probe(&host, &uri, &result);
    let ok = result.is_reachable();
    Ok(Json(SetupTestResponse {
        ok,
        message: ok.then(|| "Reachability test passed.".into()),
        error: (!ok).then(|| result.user_message()),
        log: Some(log),
    }))
}

/// POST /settings/test-bind — diagnostic ldapsearch bind with SSSD attributes.
/// Blank password reuses the stored authtok; never blocks Save.
pub(crate) async fn settings_test_bind(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BindForm>,
) -> Result<impl IntoResponse, Redirect> {
    require_auth(&state, &headers).await?;
    if form.ldap_default_bind_dn.trim().is_empty() {
        let log = "<strong>Command</strong>\n(validation)\n\n<strong>Status</strong>\nBind DN is required."
            .to_string();
        return Ok(Json(SetupTestResponse {
            ok: false,
            message: None,
            error: Some("Bind DN is required.".into()),
            log: Some(log),
        }));
    }
    let config_path = state.config_path.clone();
    let dn = form.ldap_default_bind_dn.clone();
    let pw = form.ldap_default_authtok.clone();
    let (result, log) =
        tokio::task::spawn_blocking(move || run_bind_probe_blocking(&config_path, &dn, &pw))
            .await
            .unwrap_or((
                Err("Bind probe task failed".into()),
                "<strong>Status</strong>\nBind probe task failed".to_string(),
            ));
    let (ok, error) = match result {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e)),
    };
    Ok(Json(SetupTestResponse {
        ok,
        message: ok.then(|| "Bind test passed.".into()),
        error,
        log: Some(log),
    }))
}

#[cfg(test)]
mod recycle_tests {
    use super::recycle_marker_is_fresh;
    use std::time::{Duration, SystemTime};

    #[test]
    fn marker_is_fresh_only_when_touched_after_the_latch() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("recycle-marker");
        let latch_at = SystemTime::now();
        // No marker yet: a pending recycle has not completed.
        assert!(!recycle_marker_is_fresh(&marker, latch_at));
        // Supervisor touches it after we latched: fresh.
        std::thread::sleep(Duration::from_millis(5));
        std::fs::write(&marker, "recycled\n").unwrap();
        assert!(recycle_marker_is_fresh(&marker, latch_at));
        // A marker left over from an older recycle (before this latch) is stale.
        let newer_latch = SystemTime::now() + Duration::from_secs(3600);
        assert!(!recycle_marker_is_fresh(&marker, newer_latch));
    }
}
