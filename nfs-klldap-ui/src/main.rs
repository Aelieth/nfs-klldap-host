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
    // Install rustls crypto provider early.
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

    // LDAP client (standard RFC searches + simple bind).
    // Uses exactly the same ldap_uri + [sssd] bind credentials + attribute
    // mappings as SSSD. All searches use Subtree scope so child OUs are found.
    let posix_attrs = nfs_klldap_config::resolve_posix_attribute_mapping(&config.sssd);
    let realm = config.effective_realm();
    let (user_base, group_base) =
        nfs_klldap_config::effective_ldap_search_bases(&config.sssd, &realm);
    // TLS policy from sssd section (common "never" for lab self-signed KLLDAP).
    let no_tls_verify = config
        .sssd
        .ldap_tls_reqcert
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("never"))
        .unwrap_or(false);
    let start_tls = config.sssd.ldap_id_use_start_tls.unwrap_or(false);
    let mut lldap = crate::ldap::LdapClient::new_with_attributes(
        &config.ldap_uri,
        &user_base,
        &group_base,
        posix_attrs,
        no_tls_verify,
        start_tls,
    );

    // Real credentials from the same nfs-klldap.conf (sssd section) with env override support.
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

    // Note: This authenticate() performs an LDAP simple bind as the service
    // account (using sssd.ldap_default_bind_* or NFS_KLLDAP_LLDAP_*). The very
    // first bind for that DN can cause KLLDAP to load the user's full entry
    // and emit a one-time burst of "Ignoring unrecognized user attribute"
    // warnings for non-POSIX attributes (krb*, etc.). This is the main source
    // of the single startup burst (the other early bind was the guided
    // startup ldapsearch probe).
    //
    // After this point the client only performs narrow LDAP searches using
    // exactly the attributes from resolve_posix_attribute_mapping (the same
    // set emitted into sssd.conf).
    if let Err(e) = lldap.authenticate(&lldap_user, &lldap_pass).await {
        eprintln!(
            "Warning: Could not authenticate to KLLDAP at startup: {}",
            e
        );
    }

    // Immediately perform one narrow, mapping-respecting self-lookup on the
    // service account itself. This guarantees that the very first post-auth
    // operation the WebUI performs is a "narrow SSSD-style" query (only the
    // admin-declared POSIX attributes), matching the behavior of all later
    // handlers and of SSSD.
    if !lldap_pass.trim().is_empty()
        && lldap_pass != "CHANGE_THIS_TO_A_STRONG_SECRET"
        && lldap_pass != "SET_ME"
    {
        let _ = lldap.resolve_user(&lldap_user).await;
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
    // Prefer the same two-tier confirmed value used for the keytab banner so that
    // the cert and the keytab reminder can never silently disagree.
    let cert_hostname = if let Some(h) = &config.server.hostname {
        if !h.trim().is_empty() {
            h.trim().to_string()
        } else {
            resolve_runtime_hostname_for_banner()
        }
    } else {
        resolve_runtime_hostname_for_banner()
    };

    // When the container launcher provided explicit certs via WEBUI_TLS_CERT/KEY,
    // we never auto-regenerate (even if they look "weak"). For the normal
    // auto-generated self-signed case we *do* want transparent regeneration of
    // old/weak certs after TLS dependency updates.
    let regenerate_weak_certs = std::env::var("WEBUI_TLS_CERT").is_err();

    let tls_paths = crate::certs::ensure_webui_tls_certs(
        &tls_cert_path,
        &tls_key_path,
        &cert_hostname,
        regenerate_weak_certs,
    )
    .expect("failed to ensure WebUI TLS certificates");

    let cert = tls_paths.cert.to_string_lossy().into_owned();

    // Default bind for in-container operation (accessible from host and network)
    let addr = std::env::var("WEBUI_BIND").unwrap_or_else(|_| "0.0.0.0:9630".to_string());

    // Build rustls ServerConfig from the certificate and key we ensured exist on disk.
    let tls_config = crate::certs::load_rustls_server_config(&tls_paths.cert, &tls_paths.key)
        .expect("failed to load TLS certificate and key into rustls config");

    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("failed to bind WebUI address");

    println!("Listening on https://{addr} (TLS enabled)");
    println!("Certificate: {}", cert);

    loop {
        let (stream, _remote_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("Failed to accept connection: {e}");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("TLS handshake failed: {e}");
                    return;
                }
            };

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let hyper_service = hyper_util::service::TowerToHyperService::new(app);

            if let Err(e) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, hyper_service)
                .await
            {
                // Connection errors are common and usually harmless
                let msg = e.to_string();
                if !msg.contains("connection closed") && !msg.contains("broken pipe") {
                    eprintln!("server error: {e}");
                }
            }
        });
    }
}
