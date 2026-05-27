//! Management tool entry point (visual GUI).
//!
//! Ganesha-only version with native EXPORT blocks and direct management interface calls.
//!
//! Features:
//! - Real-time FS tree per share (no DB)
//! - LLDAP user/group dropdowns with live uidNumber/gidNumber translation
//! - Owner + group + mode + recursive on *any* subfolder under a share
//! - On "save & apply":
//!     1. Resolve names via LLDAP
//!     2. chown/chmod via privileged helper (recursive supported)
//!     3. Write/update native Ganesha EXPORT {} block for the share
//!     4. Speak directly to Ganesha inside the container (ganesha-ctl + DBUS)

mod auth;
mod config;
mod exports;
mod fs;
mod ganesha;
mod llap;

mod web;

use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    println!("=== Starting NFS Kerb Management Tool (Ganesha + LLDAP + Axum/HTMX) ===\n");

    // Load configuration (now with Shares + Ganesha settings)
    let config = match crate::config::Config::load(std::path::Path::new("config.toml")) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Warning: Could not load config.toml ({}). Using defaults.", e);
            Arc::new(crate::config::Config::default())
        }
    };

    println!("Configured shares: {}", config.shares.len());
    for s in &config.shares {
        println!("  - {} → {} (host: {})", s.name, s.export_path, s.host_path.display());
    }

    // Filesystem manager (real-time, no DB)
    let fs = Arc::new(crate::fs::FsManager::new((*config).clone()));

    // Ganesha direct management client (the "speak directly" piece)
    let ganesha = Arc::new(crate::ganesha::GaneshaClient::new(&config.ganesha_container_name));

    // Exports manager that writes native Ganesha blocks + calls the direct interface
    let exports = Arc::new(crate::exports::ExportsManager::new(
        config.ganesha_exports_dir.clone(),
        (*ganesha).clone(),
    ));

    // LLDAP client (GraphQL + POSIX attribute extraction)
    let mut lldap = crate::llap::LldapClient::new(
        config
            .lldap_graphql_url
            .as_deref()
            .unwrap_or("https://lldap.example.com:6360/api/graphql"),
    );

    // TODO: Replace the placeholder credentials below with real configuration
    // (e.g. from environment variables or a secrets file). These will cause
    // LLDAP authentication to fail until you provide valid admin credentials.
    if let Err(e) = lldap
        .authenticate("admin", "your-password-here")
        .await
    {
        eprintln!("Warning: Could not authenticate to LLDAP at startup: {}", e);
    }
    let lldap = Arc::new(Mutex::new(lldap));

    // Local sudo-capable auth manager (root or wheel/sudo users only)
    let auth = Arc::new(crate::auth::AuthManager::new());

    let state = crate::web::AppState {
        fs,
        lldap,
        config: config.clone(),
        ganesha,
        exports,
        auth,
    };

    let app = crate::web::router(state);

    let addr = "127.0.0.1:3000";
    println!("\nListening on http://{addr}");
    println!("Open this URL to manage shares, browse trees, and apply POSIX permissions from LLDAP.");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
