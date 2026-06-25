//! In-container WebUI on port 9630 for permissions and nfs-klldap.conf.

#![deny(unsafe_code, dead_code)]

mod auth;
mod certs;
mod config;
mod fs;
mod ldap;
mod privileged;

mod web;

/// Resolves the runtime hostname and logs diagnostics when sources disagree.
fn resolve_runtime_hostname_for_banner() -> String {
    match get_consistent_hostname() {
        Ok(c) => c.hostname,
        Err(e) => {
            eprintln!("\n{}", e);
            eprintln!("WARNING: Using best-effort fallback for keytab reminder because the two hostname sources disagreed.");
            // Best-effort fallback so the UI can still start.
            std::env::var("HOSTNAME").unwrap_or_else(|_| "your-container-hostname".into())
        }
    }
}

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;

use nfs_klldap_config::get_consistent_hostname;

#[tokio::main]
async fn main() {
    println!("=== nfs-klldap-ui (in-container WebUI) ===\n");

    // Install ring CryptoProvider before any LDAPS (KLLDAP/rustls compat).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Support --config /path or NFS_KLLDAP_CONF env. Uses the shared volume.
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
    for (idx, s) in config.shares.iter().enumerate() {
        let default_ep = format!("/{}", s.name);
        let ep = s.export_path.as_deref().unwrap_or(&default_ep);
        println!("  - {} → {} (host: {})", s.name, ep, s.host_path.display());
        if let Some(w) =
            nfs_klldap_config::ShareFieldWarning::for_share(&config.share_warnings, idx, &s.name)
        {
            println!("    WARN: {}", w.display_message());
        }
    }

    // Keytab host: [server] override, else two-tier consistent hostname.
    let keytab_host = if let Some(h) = &config.server.hostname {
        if !h.trim().is_empty() {
            h.trim().to_string()
        } else {
            resolve_runtime_hostname_for_banner()
        }
    } else {
        resolve_runtime_hostname_for_banner()
    };

    // Reads the realm from loaded config for keytab reminders (see krb5.conf).
    let keytab_realm = config.display_realm();

    let principals = nfs_klldap_config::format_nfs_principal_list(&keytab_host, &keytab_realm);
    println!("\nKeytab reminder: include {principals}");
    println!("(Use --uts=host; optional [server] hostname or --hostname to override.)");

    // Filesystem manager (real-time, no DB) — driven by central shares config.
    let fs = Arc::new(crate::fs::FsManager::new((*config).clone()));

    let posix_attrs = nfs_klldap_config::resolve_posix_attribute_mapping(&config.sssd);
    // Display_realm is safe before validate_and_derive. Works for first-run.
    let realm = config.display_realm();
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

    // Loads bind credentials from NFS_KLLDAP_LLDAP_* env or [sssd] verbatim.
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

    // Do not extract the RDN value from the bind DN and search using.

    let lldap = Arc::new(Mutex::new(lldap));

    // Warm caches at startup for fast first / edit interactions.
    {
        let lldap_warm = lldap.clone();
        tokio::spawn(async move {
            let l = lldap_warm.lock().await;
            let _ = l.list_users(None).await;
            let _ = l.list_groups(None).await;
        });
    }

    // Hybrid auth manager (localhost simple-pw sidecar + LLDAP + admin group).
    let admin_group = config.management.webui_admin_group.clone();
    let auth = Arc::new(crate::auth::AuthManager::new(&config_path, admin_group));

    // Keytab banner off-thread so klist cannot block startup.
    let keytab_alert: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
    {
        let alert_slot = keytab_alert.clone();
        let h = keytab_host.clone();
        let r = keytab_realm.clone();
        tokio::spawn(async move {
            let alert = crate::web::compute_keytab_alert(&h, &r);
            if let Some(ref msg) = alert {
                eprintln!("WARNING: {}", msg);
            }
            if let Ok(mut slot) = alert_slot.lock() {
                *slot = alert;
            }
        });
    }

    // NFS_KLLDAP_WEBUI_BIND is used for TLS and plain-http modes. Plain-http.
    let addr = std::env::var("NFS_KLLDAP_WEBUI_BIND").unwrap_or_else(|_| "0.0.0.0:9630".to_string());
    // Enables TLS when NFS_KLLDAP_WEBUI_TLS or [webui].tls requests it.
    let webui_tls_off = if let Ok(v) = std::env::var("NFS_KLLDAP_WEBUI_TLS") {
        let t = v.trim().to_ascii_lowercase();
        t == "off" || t == "false" || t == "0" || t == "no"
    } else if let Some(t) = config.webui.tls {
        !t
    } else {
        crate::certs::webui_tls_disabled()
    };

    let host_nfs_mode = nfs_klldap_config::host_nfs_active(&config);

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
        restart_requested: Arc::new(Mutex::new(false)),
        direct_tls: !webui_tls_off,
        setup_marker_override: None,
        setup_test: Arc::new(std::sync::Mutex::new(crate::web::setup::SetupTestState::default())),
        host_nfs_mode,
        fs_probe_mountinfo_path: None,
    };

    let app = crate::web::router(state);

    if webui_tls_off {
        // Plain HTTP — do not call ensure_webui_tls_certs.
        println!("\nTLS: disabled (reverse proxy mode)");
        println!("Listening on http://{addr}");
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("failed to bind plain HTTP listener");
        axum::serve(listener, app.into_make_service())
            .await
            .expect("WebUI HTTP server failed");
    } else {
        // The existing axum_server is :bind_rustls path (TLS enabled).
        let cert_hostname = if let Some(h) = &config.server.hostname {
            if !h.trim().is_empty() {
                h.trim().to_string()
            } else {
                resolve_runtime_hostname_for_banner()
            }
        } else {
            resolve_runtime_hostname_for_banner()
        };

        // Uses stable absolute cert paths in the container when env is unset.
        let default_cert = "/var/lib/nfs-klldap/webui-certs/webui.crt".to_string();
        let default_key = "/var/lib/nfs-klldap/webui-certs/webui.key".to_string();
        let cert_path = std::env::var("NFS_KLLDAP_WEBUI_TLS_CERT")
            .ok()
            .or_else(|| config.webui.tls_cert.clone())
            .unwrap_or(default_cert);
        let key_path = std::env::var("NFS_KLLDAP_WEBUI_TLS_KEY")
            .ok()
            .or_else(|| config.webui.tls_key.clone())
            .unwrap_or(default_key);
        let tls_paths = crate::certs::ensure_webui_tls_certs(
            &cert_path,
            &key_path,
            &cert_hostname,
        )
        .expect("failed to ensure WebUI TLS certificates");

        println!("\nTLS: enabled (self-signed or custom)");
        println!("Listening on https://{addr} (TLS enabled via axum-server)");
        println!("Certificate: {}", tls_paths.cert.display());
        // Note: if NFS_KLLDAP_WEBUI_TLS_CERT/KEY or [webui] were used they.

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
}
