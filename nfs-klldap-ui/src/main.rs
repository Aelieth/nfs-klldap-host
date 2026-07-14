//! In-container WebUI (default 0.0.0.0:9630): setup, permissions, settings.

#![deny(unsafe_code, dead_code)]

mod auth;
mod certs;
mod config;
mod fs;
mod ldap;
mod privileged;

mod web;

/// True when a periodic refresh should run now: none yet, or the last one is
/// older than half the interval (so a recent login-warm is not duplicated).
fn webui_refresh_tick_due(
    last: Option<std::time::Instant>,
    interval: std::time::Duration,
) -> bool {
    match last {
        None => true,
        Some(t) => t.elapsed() >= interval / 2,
    }
}

/// Spawns the WebUI identity refresher: a bulk resolver reload plus autocomplete
/// list refresh on an interval. `NFS_KLLDAP_WEBUI_LDAP_REFRESH_INTERVAL_SECS = 0`
/// disables it; default 180s (mirrors the idhelper rebulk cadence). The bulk
/// reload rides the pooled connection, so it doubles as a keepalive.
fn spawn_webui_ldap_refresh(
    lldap: std::sync::Arc<tokio::sync::RwLock<std::sync::Arc<crate::ldap::LdapClient>>>,
) {
    let secs = std::env::var("NFS_KLLDAP_WEBUI_LDAP_REFRESH_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(180);
    if secs == 0 {
        eprintln!("INFO: WebUI LDAP refresh disabled (NFS_KLLDAP_WEBUI_LDAP_REFRESH_INTERVAL_SECS=0)");
        return;
    }
    let interval_dur = std::time::Duration::from_secs(secs);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_dur);
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            // Clone the current client Arc under a brief read lock, then run the
            // network refresh without holding the lock — the client is interior-
            // mutable, so live-search and login requests no longer stall behind it.
            let client = lldap.read().await.clone();
            if !webui_refresh_tick_due(client.last_full_refresh(), interval_dur) {
                continue;
            }
            if let Some(n) = client.refresh_identity_data().await {
                eprintln!("INFO: WebUI LDAP refresh reloaded {n} identities");
            }
        }
    });
}

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

    let loaded_config = match crate::config::load_config_from(&config_path) {
        Ok(c) => {
            println!("Loaded central config from {}", config_path.display());
            c
        }
        Err(e) => {
            eprintln!(
                "Warning: {} — using minimal defaults. Point --config at your nfs-klldap.conf",
                e
            );
            crate::config::Config::default()
        }
    };

    println!("Configured shares: {}", loaded_config.shares.len());
    for (idx, s) in loaded_config.shares.iter().enumerate() {
        let default_ep = format!("/{}", s.name);
        let ep = s.pseudo_path.as_deref().unwrap_or(&default_ep);
        println!("  - {} → {} (host: {})", s.name, ep, s.host_path.display());
        if let Some(w) = nfs_klldap_config::ShareFieldWarning::for_share(
            &loaded_config.share_warnings,
            idx,
            &s.name,
        ) {
            println!("    WARN: {}", w.display_message());
        }
        let serve = loaded_config.serve_path_for(s);
        println!("    serve: {} (exists={})", serve, std::path::Path::new(&serve).is_dir());
    }

    let config = std::sync::Arc::new(std::sync::RwLock::new(loaded_config.clone()));

    // Keytab host: [server] override, else two-tier consistent hostname.
    let keytab_host = if let Some(h) = &loaded_config.server.hostname {
        if !h.trim().is_empty() {
            h.trim().to_string()
        } else {
            resolve_runtime_hostname_for_banner()
        }
    } else {
        resolve_runtime_hostname_for_banner()
    };

    // Reads the realm from loaded config for keytab reminders (see krb5.conf).
    let keytab_realm = loaded_config.display_realm();

    let principals = nfs_klldap_config::format_nfs_principal_list(&keytab_host, &keytab_realm);
    println!("\nKeytab reminder: include {principals}");
    println!("(Use --uts=host; optional [server] hostname or --hostname to override.)");

    // Filesystem manager (real-time, no DB) — driven by central shares config.
    let fs = Arc::new(std::sync::RwLock::new(crate::fs::FsManager::new(
        loaded_config.clone(),
    )));

    let (mut lldap, no_tls_verify) = crate::ldap::LdapClient::from_config(&loaded_config);
    if no_tls_verify {
        eprintln!(
            "WARNING: outbound LDAPS/StartTLS certificate verification is DISABLED — \
             the bind and all identity lookups are exposed to man-in-the-middle. This is \
             the self-signed-friendly default when no CA is configured. To verify, set \
             [sssd].ldap_tls_cacert to the LDAP server's CA PEM (see \
             docs/ldap-integration.md#tls)."
        );
    } else {
        println!("Outbound LDAPS/StartTLS: verification ENABLED");
    }

    // Loads bind credentials from NFS_KLLDAP_LLDAP_* env or [sssd] verbatim.
    let (lldap_user, lldap_pass) = crate::config::ldap_service_creds(&loaded_config);
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

    let lldap = Arc::new(tokio::sync::RwLock::new(Arc::new(lldap)));

    // Warm caches at startup for fast first / edit interactions.
    {
        let lldap_warm = lldap.clone();
        tokio::spawn(async move {
            let l = lldap_warm.read().await.clone();
            let _ = l.list_users(None).await;
            let _ = l.list_groups(None).await;
        });
    }

    // Keep identity data fresh without a per-request LDAP burst, and keep the
    // pooled connection alive between user actions.
    spawn_webui_ldap_refresh(lldap.clone());

    // Hybrid auth manager (localhost simple-pw sidecar + LLDAP + admin group).
    let admin_group = loaded_config.management.webui_admin_group.clone();
    let auth = Arc::new(crate::auth::AuthManager::new(&config_path, admin_group));

    // Keytab banner off-thread so klist cannot block startup.
    let keytab_alert: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
    {
        let alert_slot = keytab_alert.clone();
        let h = keytab_host.clone();
        let r = keytab_realm.clone();
        tokio::spawn(async move {
            let alert = nfs_klldap_config::get_keytab_info(&h, &r).alert;
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
    let webui_tls_off =
        nfs_klldap_config::webui_tls_disabled() || loaded_config.webui.tls.is_some_and(|t| !t);

    let host_nfs_mode = nfs_klldap_config::host_nfs_active(&loaded_config);

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
        acl_caps: Arc::new(crate::web::acl_capability::AclCapabilityCache::new_from_env()),
        acl_alert: Arc::new(std::sync::Mutex::new(None)),
    };

    // Reconcile stored ACL/NOACL decisions with live filesystem capability.
    crate::web::acl_watch::spawn_acl_reprobe_loop(state.clone());

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
        let cert_hostname = if let Some(h) = &loaded_config.server.hostname {
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
            .or_else(|| loaded_config.webui.tls_cert.clone())
            .unwrap_or(default_cert);
        let key_path = std::env::var("NFS_KLLDAP_WEBUI_TLS_KEY")
            .ok()
            .or_else(|| loaded_config.webui.tls_key.clone())
            .unwrap_or(default_key);
        let mut tls_paths = crate::certs::ensure_webui_tls_certs(
            &cert_path,
            &key_path,
            &cert_hostname,
        )
        .expect("failed to ensure WebUI TLS certificates");

        println!("\nTLS: enabled (self-signed or custom)");
        println!("Certificate: {}", tls_paths.cert.display());

        let rustls_config =
            match axum_server::tls_rustls::RustlsConfig::from_pem_file(
                &tls_paths.cert,
                &tls_paths.key,
            )
            .await
            {
                Ok(c) => c,
                Err(first_err) => {
                    eprintln!(
                        "WARNING: TLS material at {} failed to load ({first_err}); regenerating self-signed cert",
                        tls_paths.cert.display()
                    );
                    tls_paths = crate::certs::regenerate_webui_tls_certs(
                        &cert_path,
                        &key_path,
                        &cert_hostname,
                    )
                    .expect("failed to regenerate WebUI TLS certificates after load failure");
                    match axum_server::tls_rustls::RustlsConfig::from_pem_file(
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
                    }
                }
            };

        let webui_port = addr
            .split(':')
            .nth(1)
            .unwrap_or("9630");
        let sans = crate::certs::cert_sans_for_host(&cert_hostname);
        println!("Listening on https://{addr} (TLS enabled via axum-server)");
        println!(
            "Open https://{}:{webui_port}/setup (self-signed; accept the browser warning if prompted)",
            cert_hostname
        );
        if sans.len() > 1 {
            println!("Certificate SANs: {}", sans.join(", "));
        }
        println!(
            "If you use a different hostname or IP, ensure it appears in the SAN list above."
        );

        axum_server::bind_rustls(addr.parse().expect("invalid bind address"), rustls_config)
            .serve(app.into_make_service())
            .await
            .expect("WebUI HTTPS server failed");
    }
}

#[cfg(test)]
pub fn create_test_lldap() -> crate::ldap::LdapClient {
    crate::ldap::LdapClient::new_with_attributes(
        "ldaps://localhost:6360",
        "ou=people,dc=test,dc=com",
        "ou=groups,dc=test,dc=com",
        nfs_klldap_config::PosixAttributeMapping {
            user_object_class: "posixAccount".to_string(),
            group_object_class: "posixGroup".to_string(),
            user_name: "uid".to_string(),
            user_uid_number: "uidNumber".to_string(),
            user_gid_number: "gidNumber".to_string(),
            user_home_directory: "homeDirectory".to_string(),
            user_shell: "loginShell".to_string(),
            user_full_name: "displayName".to_string(),
            group_name: "cn".to_string(),
            group_gid_number: "gidNumber".to_string(),
            group_member: "member".to_string(),
            user_principal_name: "krbPrincipalName".to_string(),
        },
        true,
        false,
        None,
    )
}

#[cfg(test)]
mod refresh_tests {
    use super::webui_refresh_tick_due;
    use std::time::{Duration, Instant};

    #[test]
    fn tick_due_when_never_refreshed() {
        assert!(webui_refresh_tick_due(None, Duration::from_secs(180)));
    }

    #[test]
    fn tick_skipped_within_half_interval() {
        // A refresh 10s ago with a 180s interval is well inside the skip window.
        let recent = Instant::now() - Duration::from_secs(10);
        assert!(!webui_refresh_tick_due(Some(recent), Duration::from_secs(180)));
    }

    #[test]
    fn tick_due_after_half_interval() {
        let old = Instant::now() - Duration::from_secs(120);
        assert!(webui_refresh_tick_due(Some(old), Duration::from_secs(180)));
    }
}
