//! Thin NfsKlldapConfig adapter with env cred overrides for the WebUI.

use std::path::{Path, PathBuf};

pub use nfs_klldap_config::NfsKlldapConfig as Config;

fn minimal_default_config() -> Config {
    Config {
        ldap_uri: "ldaps://klldap.example.com:6360".into(),
        sssd: nfs_klldap_config::SssdSection {
            ldap_default_bind_dn: "uid=admin,ou=people,dc=example,dc=com".into(),
            ldap_default_authtok: "SET_ME".into(),
            ..Default::default()
        },
        shares: vec![],
        ..Default::default()
    }
}

pub fn load_config_from(path: &Path) -> Result<Config, String> {
    if !path.exists() {
        // Return a minimal default that still lets the UI start and show help.
        return Ok(minimal_default_config());
    }

    match nfs_klldap_config::NfsKlldapConfig::load(path) {
        Ok(cfg) => Ok(cfg),
        Err(nfs_klldap_config::ConfigError::Validation(_)) => {
            // First-run template: parse disk without realm/bind validation.
            nfs_klldap_config::NfsKlldapConfig::load_unchecked(path).map_err(|e| {
                format!("Failed to load {}: {}", path.display(), e)
            })
        }
        Err(e) => Err(format!("Failed to load {}: {}", path.display(), e)),
    }
}

/// Return host_path values the WebUI may manage.
/// Values come from configured shares (delegates to central impl).
pub fn all_managed_roots(cfg: &Config) -> Vec<PathBuf> {
    cfg.host_paths()
}

/// Returns LDAP bind identity and password from NFS_KLLDAP_LLDAP_* env.
pub fn ldap_service_creds(cfg: &Config) -> (String, String) {
    if let (Ok(user), Ok(pass)) = (
        std::env::var("NFS_KLLDAP_LLDAP_USER"),
        std::env::var("NFS_KLLDAP_LLDAP_PW"),
    ) {
        if !user.trim().is_empty() && !pass.trim().is_empty() {
            // Verbatim: full DN or acceptable bind name is the operator's.
            return (user.trim().to_string(), pass);
        }
    }

    // Use the bind DN from config *verbatim*. ldap_default_bind_dn is already.
    let bind_identity = cfg.sssd.ldap_default_bind_dn.clone();
    let password = cfg.sssd.ldap_default_authtok.clone();
    (bind_identity, password)
}



