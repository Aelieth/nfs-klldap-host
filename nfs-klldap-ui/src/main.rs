//! nfs-klldap-ui — In-container WebUI (Axum + HTMX).
//!
//! Two-page web UI for the central `nfs-klldap.conf` (the single source of truth):
//! - System Settings (/settings): edit the TOML (raw editor + basic structured)
//! - Share Permissions (/): browse real-time FS trees under shares and apply
//!   POSIX owner/group/mode changes directly + live KLLDAP lookups.
//!
//! Runs inside the container on port 9630 (HTTPS). All services (including this
//! WebUI) run as root and perform direct chown/chmod on bind-mounted paths.
//!
//! TLS certificates are ensured at startup via `crate::certs::ensure_webui_tls_certs`
//! (self-signed generation happens in pure Rust using rcgen when needed).

mod auth;
mod certs;
mod config;
mod fs;
mod llap;

mod web;

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    // Install rustls crypto provider early (required when using axum-server + tls-rustls)
    // This must happen before any TLS code runs.
    let _ = rustls::crypto::ring::default_provider().install_default();

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

    // Startup banner: make the keytab hostname requirement impossible to miss
    let keytab_host = config
        .server
        .hostname
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            std::env::var("HOSTNAME").unwrap_or_else(|_| "your-container-hostname".into())
        });
    println!("\nKeytab reminder: your krb5.keytab must contain  nfs/{keytab_host}@YOUR.REALM");
    println!("(Set [server] hostname in nfs-klldap.conf or pass --hostname to the container.)");

    // Filesystem manager (real-time, no DB) — now driven by central shares
    let fs = Arc::new(crate::fs::FsManager::new_with_path(
        (*config).clone(),
        config_path.clone(),
    ));

    // LLDAP client (GraphQL + POSIX). Derive URL from the central conf when possible.
    let lldap_url = crate::config::derive_lldap_url(&config);
    let mut lldap = crate::llap::LldapClient::new(&lldap_url);

    // Real credentials from the same nfs-klldap.conf (sssd section) with env override support.
    // Interactive prompt is intentionally avoided for daemon/container use cases.
    let (lldap_user, lldap_pass) = crate::config::lldap_login_creds(&config);
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
        eprintln!(
            "Warning: Could not authenticate to KLLDAP at startup: {}",
            e
        );
    }
    let lldap = Arc::new(Mutex::new(lldap));

    // Hybrid auth manager (localhost simple-pw sidecar + LLDAP + admin group).
    // The sidecar lives next to the central config file.
    let admin_group = config.management.webui_admin_group.clone();
    let auth = Arc::new(crate::auth::AuthManager::new(&config_path, admin_group));

    let state = crate::web::AppState {
        fs,
        lldap,
        config: config.clone(),
        auth,
        config_path: config_path.clone(),
    };

    let app = crate::web::router(state);

    // -------------------------------------------------------------------------
    // TLS certificate handling (moved much of the previous shell logic into Rust)
    // -------------------------------------------------------------------------
    // The container launcher (entrypoint + webui-certs script) normally provides
    // WEBUI_TLS_CERT and WEBUI_TLS_KEY. If they are present we use those paths.
    // If the files are missing or the vars are absent (dev mode), we ensure
    // self-signed certificates exist using pure Rust (rcgen).
    let (tls_cert_path, tls_key_path) = if let (Some(c), Some(k)) = (
        std::env::var("WEBUI_TLS_CERT").ok(),
        std::env::var("WEBUI_TLS_KEY").ok(),
    ) {
        (std::path::PathBuf::from(c), std::path::PathBuf::from(k))
    } else {
        // Development / standalone fallback location
        let dir = std::path::PathBuf::from("webui-certs");
        (dir.join("webui.crt"), dir.join("webui.key"))
    };

    // Determine a reasonable hostname for self-signed SANs if we need to generate.
    let cert_hostname = config
        .server
        .hostname
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string()));

    let tls_paths =
        crate::certs::ensure_webui_tls_certs(&tls_cert_path, &tls_key_path, &cert_hostname)
            .expect("failed to ensure WebUI TLS certificates");

    let cert = tls_paths.cert.to_string_lossy().into_owned();
    let key = tls_paths.key.to_string_lossy().into_owned();

    // Default bind for in-container operation (accessible from host and network)
    let addr = std::env::var("WEBUI_BIND").unwrap_or_else(|_| "0.0.0.0:9630".to_string());

    println!("\nListening on https://{addr} (TLS enabled)");
    println!("Certificate: {}", cert);

    let config = match axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FATAL: Failed to load TLS certificate and key:");
            eprintln!("  cert: {cert}");
            eprintln!("  key : {key}");
            eprintln!("  error: {e}");
            eprintln!("The WebUI cannot start without valid TLS material.");
            std::process::exit(1);
        }
    };

    axum_server::bind_rustls(addr.parse().expect("invalid bind address"), config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
