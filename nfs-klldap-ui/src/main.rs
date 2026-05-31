//! In-container WebUI (Axum + HTMX + rustls) on 9630.
//!
//! Edits the single nfs-klldap.conf. Performs direct chown/chmod (root) on
//! bind-mounted host_path trees via FsManager. Two pages: / (permissions tree)
//! and /settings (raw + structured TOML + LLDAP client reload).

// Enforce that all unsafe code is confined to the ffi module.
#![deny(unsafe_code)]

mod auth;
mod certs;
mod config;
mod ffi;
mod fs;
mod ldap;

mod web;

/// Resolve the runtime hostname using the two-tier consistent API.
/// On inconsistency we print the full actionable diagnostic to the log
/// (this is what surfaces the "d81b4e782f65 vs real name" problem).
fn resolve_runtime_hostname_for_banner() -> String {
    match get_consistent_hostname() {
        Ok(c) => c.hostname,
        Err(e) => {
            // This is the exact path that used to silently print the wrong Docker ID.
            // Now it is impossible to miss.
            eprintln!("\n{}", e);
            eprintln!("WARNING: Using best-effort fallback for keytab reminder because the two hostname sources disagreed.");
            // Best-effort fallback so the UI can still start (the operator can still edit config)
            std::env::var("HOSTNAME").unwrap_or_else(|_| "your-container-hostname".into())
        }
    }
}

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use nfs_klldap_config::get_consistent_hostname;

#[tokio::main]
async fn main() {
    println!("=== nfs-klldap-ui (in-container WebUI) ===\n");

    // Support --config /path or NFS_KLLDAP_CONF env (the shared volume with the container)
    let mut config_path: Option<PathBuf> = std::env::var("NFS_KLLDAP_CONF").ok().map(PathBuf::from);
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if (args[i] == "--config" || args[i] == "-c") && i + 1 < args.len() {
            config_path = Some(PathBuf::from(&args[i + 1]));
            break;
        }
    }
    let config_path = config_path.unwrap_or_else(|| PathBuf::from("nfs-klldap.conf"));

    let config = match crate::config::load_config_from(&config_path) {
        Ok(c) => {
            println!("Loaded central config from {}", config_path.display());
            Arc::new(c)
        }
        Err(e) => {
            eprintln!(
                "Warning: {} — using minimal defaults. Point --config at your nfs-klldap.conf",
                e
            );
            Arc::new(crate::config::Config::default())
        }
    };

    println!("Configured shares: {}", config.shares.len());
    for s in &config.shares {
        let default_ep = format!("/{}", s.name);
        let ep = s.export_path.as_deref().unwrap_or(&default_ep);
        println!("  - {} → {} (host: {})", s.name, ep, s.host_path.display());
    }

    // Startup banner: make the keytab hostname requirement impossible to miss.
    // NEW: Use the two-tier consistent value (hostname command + /proc). Both sources
    // must agree, otherwise we emit the full rich diagnostic before the normal reminder.
    let keytab_host = if let Some(h) = &config.server.hostname {
        if !h.trim().is_empty() {
            h.trim().to_string()
        } else {
            resolve_runtime_hostname_for_banner()
        }
    } else {
        resolve_runtime_hostname_for_banner()
    };

    // Use the authoritative realm from the loaded config (same one that will be written
    // into krb5.conf by the generator). Falls back to a clear placeholder only for the
    // early "no valid config yet" case.
    let keytab_realm = config.display_realm();

    println!("\nKeytab reminder: your krb5.keytab must contain  nfs/{keytab_host}@{keytab_realm}");
    println!("(Set [server] hostname in nfs-klldap.conf or pass --hostname to the container.)");

    // Filesystem manager (real-time, no DB) — now driven by central shares
    let fs = Arc::new(crate::fs::FsManager::new_with_path(
        (*config).clone(),
        config_path.clone(),
    ));

    let posix_attrs = nfs_klldap_config::resolve_posix_attribute_mapping(&config.sssd);
    let realm = config.effective_realm();
    let (user_base, group_base) =
        nfs_klldap_config::effective_ldap_search_bases(&config.sssd, &realm);

    let (no_tls_verify, start_tls) = nfs_klldap_config::ldap_tls_policy(
        &config.ldap_uri,
        config.sssd.ldap_tls_reqcert.as_deref(),
        config.sssd.ldap_tls_cacert.as_deref(),
        config.sssd.ldap_id_use_start_tls,
    );

    if no_tls_verify {
        println!("Outbound LDAPS/StartTLS: verification DISABLED");
    } else {
        println!("Outbound LDAPS/StartTLS: verification ENABLED");
    }

    let cacert = config.sssd.ldap_tls_cacert.clone();
    let mut lldap = crate::ldap::LdapClient::new_with_attributes(
        &config.ldap_uri,
        &user_base,
        &group_base,
        posix_attrs,
        no_tls_verify,
        start_tls,
        cacert,
    );

    // Real credentials from the same nfs-klldap.conf (sssd section) with env override support.
    // The first element is the full bind DN (or verbatim identity). Bare uids are
    // deliberately never produced here — they cause connection drops on LDAPS.
    // Interactive prompt is intentionally avoided for daemon/container use cases.
    let (lldap_user, lldap_pass) = crate::config::ldap_service_creds(&config);
    if lldap_pass.trim().is_empty()
        || lldap_pass == "CHANGE_THIS_TO_A_STRONG_SECRET"
        || lldap_pass == "SET_ME"
    {
        eprintln!(
            "WARNING: LLDAP credentials not configured (see sssd.ldap_default_authtok or NFS_KLLDAP_LLDAP_PW). \
             User/group searches and permission lookups will be non-functional."
        );
    }

    // First bind may emit one-time "unrecognized attr" noise on KLLDAP for non-POSIX fields.
    // All subsequent searches use only the PosixAttributeMapping (same as SSSD).
    if let Err(e) = lldap.authenticate(&lldap_user, &lldap_pass).await {
        eprintln!("Warning: KLLDAP auth failed at startup: {}", e);
    }

    // Prime the client with a narrow POSIX-only self-lookup (SSSD-style query).
    if !lldap_pass.trim().is_empty()
        && lldap_pass != "CHANGE_THIS_TO_A_STRONG_SECRET"
        && lldap_pass != "SET_ME"
    {
        let probe_name = crate::config::short_name_for_service_probe(&lldap_user);
        let _ = lldap.resolve_user(&probe_name).await;
        let _ = lldap.resolve_user_dn(&probe_name).await;
    }

    let lldap = Arc::new(Mutex::new(lldap));

    // Hybrid auth manager (localhost simple-pw sidecar + LLDAP + admin group).
    // The sidecar lives next to the central config file.
    let admin_group = config.management.webui_admin_group.clone();
    let auth = Arc::new(crate::auth::AuthManager::new(&config_path, admin_group));

    let keytab_status_message =
        crate::web::compute_keytab_status_message(&keytab_host, &keytab_realm);

    let state = crate::web::AppState {
        fs,
        lldap,
        config: config.clone(),
        auth,
        config_path: config_path.clone(),
        keytab_hostname: keytab_host,
        keytab_realm,
        keytab_status_message,
    };

    let app = crate::web::router(state);

    // Determine hostname for self-signed certificate SANs (same logic as keytab)
    let cert_hostname = if let Some(h) = &config.server.hostname {
        if !h.trim().is_empty() {
            h.trim().to_string()
        } else {
            resolve_runtime_hostname_for_banner()
        }
    } else {
        resolve_runtime_hostname_for_banner()
    };

    // HTTPS (axum-server + rustls). Self-signed via rcgen unless WEBUI_TLS_* provided.
    let addr = std::env::var("WEBUI_BIND").unwrap_or_else(|_| "0.0.0.0:9630".to_string());

    // Use a stable absolute path inside the container (created in Dockerfile).
    // This avoids polluting / and works under root-only execution model.
    // Full paths can still be overridden via WEBUI_TLS_CERT / WEBUI_TLS_KEY.
    let tls_paths = crate::certs::ensure_webui_tls_certs(
        "/var/lib/nfs-klldap/webui-certs/webui.crt",
        "/var/lib/nfs-klldap/webui-certs/webui.key",
        &cert_hostname,
    )
    .expect("failed to ensure WebUI TLS certificates");

    println!("\nListening on https://{addr} (TLS enabled via axum-server)");
    println!("Certificate: {}", tls_paths.cert.display());

    let config = match axum_server::tls_rustls::RustlsConfig::from_pem_file(
        &tls_paths.cert,
        &tls_paths.key,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FATAL: Failed to load TLS certificate and key:");
            eprintln!("  cert: {}", tls_paths.cert.display());
            eprintln!("  key : {}", tls_paths.key.display());
            eprintln!("  error: {e}");
            eprintln!("The WebUI cannot start without valid TLS material.");
            std::process::exit(1);
        }
    };

    axum_server::bind_rustls(addr.parse().expect("invalid bind address"), config)
        .serve(app.into_make_service())
        .await
        .expect("WebUI HTTPS server failed");
}
