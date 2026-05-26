//! Management tool entry point (visual GUI).
//!
//! This is the beginning of the small Rust program that provides the
//! tree-menu visual interface the user described:
//! - Real-time FS tree (no DB)
//! - LLDAP user/group dropdowns with live ID translation
//! - Owner + group + permissions + recursive
//! - On "save & apply": chown/chmod + touch corresponding *.exports + re-export trigger

mod config;
mod exports;
mod fs;
mod llap;
mod policy;
mod web;

use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    println!("=== Starting NFS Kerb Management Tool (Axum + HTMX UI) ===\n");

    // Load configuration
    let config = match crate::config::Config::load(std::path::Path::new("config.toml")) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Warning: Could not load config.toml ({}). Using defaults.", e);
            Arc::new(crate::config::Config::default())
        }
    };

    // Shared managers (the web handlers will use these)
    let fs = Arc::new(crate::fs::FsManager::new((*config).clone()));

    // LLDAP client (we authenticate once at startup for the demo)
    let mut lldap = crate::llap::LldapClient::new(
        config
            .lldap_graphql_url
            .as_deref()
            .unwrap_or("https://lldap.example.com:6360/api/graphql"),
    );

    if let Err(e) = lldap
        .authenticate("admin", "your-password-here")
        .await
    {
        eprintln!("Warning: Could not authenticate to KLLDAP at startup: {}", e);
    }
    let lldap = Arc::new(Mutex::new(lldap));

    let state = crate::web::AppState {
        fs,
        lldap,
        config: config.clone(),
    };

    let app = crate::web::router(state);

    let addr = "127.0.0.1:3000";
    println!("Listening on http://{addr}");
    println!("Open this URL in your browser to see the lazy-loaded tree UI.");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
