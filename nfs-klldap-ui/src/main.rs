//! In-container WebUI (Axum + HTMX + rustls) on 9630.
//!
//! Edits the single nfs-klldap.conf. Performs direct chown/chmod (root) on
//! bind-mounted host_path trees via FsManager. Two pages: / (permissions tree)
//! and /settings (raw + structured TOML + LLDAP client reload).

#![deny(unsafe_code)]

mod auth;
mod certs;
mod config;
mod fs;
mod ldap;
mod privileged;

mod web;

/// Resolve the runtime hostname using the two-tier consistent API.
/// On inconsistency we print the full actionable diagnostic to the log
/// (this is what surfaces the "d81b4e782f65 vs real name" problem).
fn resolve_runtime_hostname_for_banner() -> String {
    match get_consistent_hostname() {
        Ok(c) => c.hostname,
        Err(e) => {
            // This is the exact path that used to silently print the wrong Docker ID.

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

    // Install the ring CryptoProvider *very early*, before any TLS code runs.
    //
    // This is required for reliable LDAPS handshakes against strict rustls-based
    // servers such as KLLDAP (lldap). The first real outbound LDAPS connections
    // (service account bind + probes) happen during LdapClient initialization,
    // which occurs *before* axum-server starts.
    //
    // Without an early explicit install, some short-lived connections can fail
    // the TLS handshake, manifesting as "[LDAPS] Service Error: tls handshake eof"
    // on the KLLDAP side. We tolerate a second install (the `let _ =`).
    let _ = rustls::crypto::ring::default_provider().install_default();

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

    // Startup banner: keytab hostname requirement.
    // Use the two-tier consistent value (hostname command + /proc). Both sources
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

    let principals = nfs_klldap_config::format_nfs_principal_list(&keytab_host, &keytab_realm);
    println!("\nKeytab reminder: include {principals}");
    println!("(Use --uts=host; optional [server] hostname or --hostname to override.)");

    // Filesystem manager (real-time, no DB) — driven by central shares config.
    let fs = Arc::new(crate::fs::FsManager::new((*config).clone()));

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

    let mut lldap = crate::ldap::LdapClient::new_with_attributes(
        &config.ldap_uri,
        &user_base,
        &group_base,
        posix_attrs,
        no_tls_verify,
        start_tls,
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

    if let Err(e) = lldap.authenticate(&lldap_user, &lldap_pass).await {
        eprintln!("Warning: KLLDAP auth failed at startup: {}", e);
    }

    // Do not extract the RDN value from the bind DN and search using user_name
    // (e.g. uid). This produced filters containing "uid" that triggered KLLDAP
    // warnings when strict ignored_*_attributes are in use.

    let lldap = Arc::new(Mutex::new(lldap));

    // Warm the user/group search caches (and identity caches for the first ~25)
    // at startup. This makes the first visit to Share Permissions + Edit mode fast:
    // focus/click in the UID/GID boxes shows results from cache immediately, without
    // repeated LDAP searches on every interaction.
    {
        let lldap_warm = lldap.clone();
        tokio::spawn(async move {
            let l = lldap_warm.lock().await;
            let _ = l.list_users(None).await;
            let _ = l.list_groups(None).await;
        });
    }

    // Hybrid auth manager (localhost simple-pw sidecar + LLDAP + admin group).
    // The sidecar lives next to the central config file.
    let admin_group = config.management.webui_admin_group.clone();
    let auth = Arc::new(crate::auth::AuthManager::new(&config_path, admin_group));

    let keytab_alert = crate::web::compute_keytab_alert(&keytab_host, &keytab_realm);
    if let Some(ref msg) = keytab_alert {
        eprintln!("WARNING: {}", msg);
    }

    let state = crate::web::AppState {
        fs,
        lldap,
        config: config.clone(),
        auth,
        config_path: config_path.clone(),
        keytab_hostname: keytab_host,
        keytab_realm,
        keytab_alert,
        apply_progress: Arc::new(Mutex::new(None)),
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
