//! Adapter + host-UI helpers around the single source-of-truth `nfs-klldap.conf`.
//!
//! Real structs + validation + generation live in the tiny `nfs-klldap-config` crate
//! (also bundled inside the container). This module only adds the bits the host UI needs
//! (path/env loading, save, root derivation, LLDAP URL fallback).

use std::path::{Path, PathBuf};

pub use nfs_klldap_config::{NfsKlldapConfig as Config, Share};

pub fn load_config_from(path: &Path) -> Result<Config, String> {
    if !path.exists() {
        // Return a minimal default that still lets the UI start and show help text.
        // The user is expected to point --config at the real shared volume.
        return Ok(Config {
            ldap_uri: "ldaps://kllap.example.com:6360".into(),
            sssd: nfs_klldap_config::SssdSection {
                ldap_default_bind_dn: "uid=admin,ou=people,dc=example,dc=com".into(),
                ldap_default_authtok: "SET_ME".into(),
                ..Default::default()
            },
            shares: vec![],
            ..Default::default()
        });
    }

    nfs_klldap_config::NfsKlldapConfig::load(path)
        .map_err(|e| format!("Failed to load {}: {}", path.display(), e))
}

/// Save the config back to disk (used by the System Settings page).
/// Uses toml_edit when possible so comments are best-effort preserved on structured saves.
pub fn save_config(cfg: &Config, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    // Best effort: round-trip through toml_edit Document to keep comments (currently unused,
    // kept for future structured editing that wants to preserve formatting).
    let _doc = std::fs::read_to_string(path)
        .map(|old| old.parse::<toml_edit::DocumentMut>().unwrap_or_default())
        .unwrap_or_default();

    // For maximum simplicity + correctness we serialize via the standard toml crate
    // (the structs are authoritative). Raw textarea mode in the UI is the escape hatch for hand comments.
    let text = toml::to_string_pretty(cfg)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    let tmp = path.with_extension("conf.tmp");
    std::fs::write(&tmp, text.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;

    // Keep secrets safe
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Return the list of host-side paths the UI is allowed to manage (from the shares).
pub fn all_managed_roots(cfg: &Config) -> Vec<PathBuf> {
    cfg.shares.iter().map(|s| s.host_path.clone()).collect()
}

/// Derive a reasonable LLDAP GraphQL URL from ldap_uri if the management section doesn't have one.
pub fn derive_lldap_url(cfg: &Config) -> String {
    if let Some(u) = &cfg.management.lldap_graphql_url {
        return u.clone();
    }
    // ldaps://kllap.example.com:6360 → https://kllap.example.com:6360/api/graphql
    let host = cfg
        .ldap_uri
        .split("://")
        .nth(1)
        .and_then(|s| s.split([':', '/']).next())
        .unwrap_or("localhost");
    format!("https://{}:6360/api/graphql", host)
}
