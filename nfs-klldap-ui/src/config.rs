//! Thin adapter around nfs_klldap_config::NfsKlldapConfig for the WebUI.
//! Adds env overrides for creds, all_managed_roots,
//! and short-name probe helper.

use std::path::{Path, PathBuf};

pub use nfs_klldap_config::NfsKlldapConfig as Config;

fn minimal_default_config() -> Config {
    Config {
        ldap_uri: "ldaps://kllap.example.com:6360".into(),
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
        // Return a minimal default that still lets the UI start and show help
        // text.
        // The user is expected to point --config at the real shared volume.
        return Ok(minimal_default_config());
    }

    match nfs_klldap_config::NfsKlldapConfig::load(path) {
        Ok(cfg) => Ok(cfg),
        Err(nfs_klldap_config::ConfigError::Validation(_)) => {
            // First-run template: parse disk content without requiring
            // realm/bind validation.
            nfs_klldap_config::NfsKlldapConfig::load_unchecked(path).map_err(|e| {
                format!("Failed to load {}: {}", path.display(), e)
            })
        }
        Err(e) => Err(format!("Failed to load {}: {}", path.display(), e)),
    }
}

/// Return the list of host_path values the WebUI is allowed to manage .
pub fn all_managed_roots(cfg: &Config) -> Vec<PathBuf> {
    cfg.shares.iter().map(|s| s.host_path.clone()).collect()
}

/// Returns (bind identity, password).
/// Prefers NFS_KLLDAP_LLDAP_* env, falls back
/// to sssd.ldap_default_bind_dn + authtok.
/// Full DN (or verbatim identity) required.
pub fn ldap_service_creds(cfg: &Config) -> (String, String) {
    if let (Ok(user), Ok(pass)) = (
        std::env::var("NFS_KLLDAP_LLDAP_USER"),
        std::env::var("NFS_KLLDAP_LLDAP_PW"),
    ) {
        if !user.trim().is_empty() && !pass.trim().is_empty() {
            // Verbatim: full DN or acceptable bind name is the operator's
            // responsibility.
            return (user.trim().to_string(), pass);
        }
    }

    // Use the bind DN from config *verbatim*.
    // ldap_default_bind_dn is already the
    // full distinguished name in every real deployment and in the documented
    // examples. Passing anything less (bare uid) causes bind failures or
    // connection drops on KLLDAP and other strict LDAPS servers.
    let bind_identity = cfg.sssd.ldap_default_bind_dn.clone();
    let password = cfg.sssd.ldap_default_authtok.clone();
    (bind_identity, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes all tests that touch the NFS_KLLDAP_LLDAP_* env vars.
    /// Without this, parallel test execution (default under cargo) causes
    /// the global process environment to produce flaky results between the
    /// "prefers env" test and the "cfg path" tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard to safely manipulate environment variables in tests without
    /// polluting other tests .
    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        /// Remove the var for the duration of the guard (restores previous
        /// value or absence on drop).
        /// Used by tests that must not see override env vars
        /// even if other concurrent tests are manipulating them.
        fn clear(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

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
    fn ldap_service_creds_returns_full_bind_dn() {
        // Serialize vs other env-manipulating tests (see ENV_LOCK).
        let _serial = ENV_LOCK.lock().unwrap();

        // Force a clean env so parallel tests that set the LLDAP_* overrides
        // cannot affect this result.
        let _c1 = EnvGuard::clear("NFS_KLLDAP_LLDAP_USER");
        let _c2 = EnvGuard::clear("NFS_KLLDAP_LLDAP_PW");

        let cfg = base_config();
        let (bind_id, pass) = ldap_service_creds(&cfg);
        // Must return the full DN verbatim for proper simple_bind .
        assert_eq!(bind_id, "uid=admin,ou=people,dc=example,dc=com");
        assert_eq!(pass, "sekret");
    }

    #[test]
    fn ldap_service_creds_prefers_env_vars() {
        // Serialize vs other env-manipulating tests (see ENV_LOCK).
        let _serial = ENV_LOCK.lock().unwrap();

        let _g1 = EnvGuard::set("NFS_KLLDAP_LLDAP_USER", "svc-account");
        let _g2 = EnvGuard::set("NFS_KLLDAP_LLDAP_PW", "env-secret");

        let cfg = base_config();
        let (user, pass) = ldap_service_creds(&cfg);
        assert_eq!(user, "svc-account");
        assert_eq!(pass, "env-secret");
    }

    #[test]
    fn load_config_from_tolerates_unvalidated_first_run_template() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nfs-klldap.conf");
        std::fs::write(&path, nfs_klldap_config::generate_default_template()).unwrap();

        let cfg = load_config_from(&path).expect("first-run template must load for WebUI");
        assert_eq!(cfg.ldap_uri, "ldaps://kllap.example.com:6360");
        assert_eq!(
            cfg.sssd.ldap_default_bind_dn,
            "uid=admin,ou=people,dc=example,dc=com"
        );
        assert!(cfg.kerberos.realm.is_none());
    }

    #[test]
    fn ldap_service_creds_returns_malformed_bind_dn_verbatim() {
        // Serialize vs other env-manipulating tests (see ENV_LOCK).
        let _serial = ENV_LOCK.lock().unwrap();

        // Force a clean env so parallel tests that set the LLDAP_* overrides
        // cannot affect the cfg-path result.
        let _c1 = EnvGuard::clear("NFS_KLLDAP_LLDAP_USER");
        let _c2 = EnvGuard::clear("NFS_KLLDAP_LLDAP_PW");

        let mut cfg = base_config();
        cfg.sssd.ldap_default_bind_dn = "cn=weird,dc=example".into();
        let (bind_id, _) = ldap_service_creds(&cfg);
        // Verbatim;
        // server rejects bad DN at bind time .
        assert_eq!(bind_id, "cn=weird,dc=example");
    }
}
