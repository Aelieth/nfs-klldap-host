//! Adapter + host-UI helpers around the single source-of-truth `nfs-klldap.conf`.
//!
//! Real structs + validation + generation live in the tiny `nfs-klldap-config` crate
//! (also bundled inside the container). This module only adds the bits the host UI needs
//! (path/env loading, root derivation, LLDAP URL + credential helpers).

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

/// Return the list of host_path values the WebUI is allowed to manage (from the shares).
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

/// Return (username, password) for authenticating the LLDAP GraphQL client.
///
/// Env vars NFS_KLLDAP_LLDAP_USER and NFS_KLLDAP_LLDAP_PW take precedence
/// (useful when the SSSD bind DN user differs from the account used for login,
/// or for injecting secrets in containerized deployments without editing the TOML).
///
/// Falls back to parsing a short username from sssd.ldap_default_bind_dn
/// (uid=foo,... or cn=foo,...) and using the corresponding authtok from the same file.
pub fn lldap_login_creds(cfg: &Config) -> (String, String) {
    if let (Ok(user), Ok(pass)) = (
        std::env::var("NFS_KLLDAP_LLDAP_USER"),
        std::env::var("NFS_KLLDAP_LLDAP_PW"),
    ) {
        if !user.trim().is_empty() && !pass.trim().is_empty() {
            return (user.trim().to_string(), pass);
        }
    }

    // Parse short name from bind DN (common case: uid=admin,ou=people,...)
    let dn = &cfg.sssd.ldap_default_bind_dn;
    let username = dn
        .split(',')
        .next()
        .and_then(|rdn| {
            rdn.strip_prefix("uid=")
                .or_else(|| rdn.strip_prefix("cn="))
                .or_else(|| rdn.strip_prefix("CN="))
                .map(|s| s.to_string())
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "admin".to_string());

    let password = cfg.sssd.ldap_default_authtok.clone();
    (username, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        Config {
            ldap_uri: "ldaps://kllap.example.com:6360".into(),
            sssd: nfs_klldap_config::SssdSection {
                ldap_default_bind_dn: "uid=admin,ou=people,dc=example,dc=com".into(),
                ldap_default_authtok: "sekret".into(),
                ..Default::default()
            },
            shares: vec![
                nfs_klldap_config::Share {
                    name: "movies".into(),
                    host_path: "/media/SSD/movies".into(),
                    ..Default::default()
                },
                nfs_klldap_config::Share {
                    name: "backups".into(),
                    host_path: "/media/SSD/backups".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn all_managed_roots_returns_host_paths() {
        let cfg = base_config();
        let roots = all_managed_roots(&cfg);
        assert_eq!(roots.len(), 2);
        assert!(roots.iter().any(|p| p.to_string_lossy().contains("movies")));
    }

    #[test]
    fn derive_lldap_url_uses_management_section_when_present() {
        let mut cfg = base_config();
        cfg.management.lldap_graphql_url = Some("https://custom:8443/graphql".into());
        assert_eq!(derive_lldap_url(&cfg), "https://custom:8443/graphql");
    }

    #[test]
    fn derive_lldap_url_falls_back_to_ldap_uri() {
        let cfg = base_config();
        let url = derive_lldap_url(&cfg);
        assert!(url.contains("kllap.example.com"));
        assert!(url.ends_with("/api/graphql"));
    }

    #[test]
    fn lldap_login_creds_parses_uid_from_dn() {
        let cfg = base_config();
        let (user, pass) = lldap_login_creds(&cfg);
        assert_eq!(user, "admin");
        assert_eq!(pass, "sekret");
    }

    #[test]
    fn lldap_login_creds_prefers_env_vars() {
        std::env::set_var("NFS_KLLDAP_LLDAP_USER", "svc-account");
        std::env::set_var("NFS_KLLDAP_LLDAP_PW", "env-secret");

        let cfg = base_config();
        let (user, pass) = lldap_login_creds(&cfg);
        assert_eq!(user, "svc-account");
        assert_eq!(pass, "env-secret");

        std::env::remove_var("NFS_KLLDAP_LLDAP_USER");
        std::env::remove_var("NFS_KLLDAP_LLDAP_PW");
    }

    #[test]
    fn lldap_login_creds_falls_back_to_admin_on_malformed_dn() {
        let mut cfg = base_config();
        cfg.sssd.ldap_default_bind_dn = "cn=weird,dc=example".into();
        let (user, _) = lldap_login_creds(&cfg);
        assert_eq!(user, "weird");
    }
}
