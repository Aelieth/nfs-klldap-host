//! nfs-klldap-ui — In-container WebUI (Axum + HTMX).
//!
//! Two-page web UI for the central `nfs-klldap.conf` (the single source of truth):
//! - System Settings (/settings): edit the TOML (raw editor + basic structured)
//! - Share Permissions (/): browse real-time FS trees under shares and apply
//!   POSIX owner/group/mode changes directly + live KLLDAP lookups.
//!
//! This binary now runs **inside** the `nfs-klldap-host` container on port 9630.
//! The container (using the bundled `nfs-klldap-config` binary) auto-derives
//! sssd.conf, krb5.conf, and all Ganesha EXPORT fragments from the same file.
//! No separate host-side management process is required; the WebUI runs inside the container on port 9630.

mod auth;
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

    println!("=== nfs-klldap-ui (in-container WebUI) — v0.5 central TOML ===\n");

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
    let keytab_host = config.server.hostname.clone().filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_else(|_| "your-container-hostname".into()));
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

    // Default bind for in-container operation (accessible from host and network)
    let addr = std::env::var("WEBUI_BIND")
        .unwrap_or_else(|_| "0.0.0.0:9630".to_string());

    let tls_cert = std::env::var("WEBUI_TLS_CERT").ok();
    let tls_key  = std::env::var("WEBUI_TLS_KEY").ok();

    if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
        println!("\nListening on https://{addr} (TLS enabled)");
        println!("Certificate: {}", cert);

        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
            .await
            .expect("failed to load TLS certificate and key");

        axum_server::bind_rustls(addr.parse().expect("invalid bind address"), config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        println!("\nListening on http://{addr} (no TLS configured)");
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}
