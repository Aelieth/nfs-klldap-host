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

/// Return (bind_identity, password) for the long-lived service LDAP bind used by
/// the permission client (LdapClient).
///
/// The first element MUST be a full DN (e.g. "uid=admin,ou=people,dc=...") or
/// another identity string that the remote LDAP server accepts as the bind name
/// for simple_bind. This is the only value that produces reliable connections
/// and avoids the "server dropping connections" / auth errors seen when only a
/// bare uid was passed.
///
/// Env vars NFS_KLLDAP_LLDAP_USER and NFS_KLLDAP_LLDAP_PW take precedence and
/// are passed verbatim (operator may supply a full DN here for remote hosts).
/// Falls back to sssd.ldap_default_bind_dn verbatim (the correct full DN in all
/// normal configs and examples).
pub fn ldap_service_creds(cfg: &Config) -> (String, String) {
    if let (Ok(user), Ok(pass)) = (
        std::env::var("NFS_KLLDAP_LLDAP_USER"),
        std::env::var("NFS_KLLDAP_LLDAP_PW"),
    ) {
        if !user.trim().is_empty() && !pass.trim().is_empty() {
            // Verbatim: full DN or acceptable bind name is the operator's responsibility.
            return (user.trim().to_string(), pass);
        }
    }

    // Use the bind DN from config *verbatim*. ldap_default_bind_dn is already the
    // full distinguished name in every real deployment and in the documented
    // examples. Passing anything less (bare uid) causes bind failures or
    // connection drops on KLLDAP and other strict LDAPS servers.
    let bind_identity = cfg.sssd.ldap_default_bind_dn.clone();
    let password = cfg.sssd.ldap_default_authtok.clone();
    (bind_identity, password)
}

/// Given a service bind identity (full DN preferred, or bare uid/cn), extract
/// only the short value portion for use in name-based filters such as the
/// one-time startup probe that calls resolve_user to exercise the exact
/// PosixAttributeMapping. Never used for simple_bind — binds always use the
/// full identity string returned by ldap_service_creds.
pub fn short_name_for_service_probe(bind_identity: &str) -> String {
    if bind_identity.contains('=') && bind_identity.contains(',') {
        bind_identity
            .split(',')
            .next()
            .and_then(|rdn| rdn.split_once('=').map(|(_, v)| v.trim().to_string()))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| bind_identity.trim().to_string())
    } else {
        bind_identity.trim().to_string()
    }
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
    /// polluting other tests (especially important under `cargo test --workspace`).
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

        /// Remove the var for the duration of the guard (restores previous value
        /// or absence on drop). Used by tests that must not see override env vars
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
        // Must return the full DN verbatim for proper simple_bind (not a stripped uid).
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
        // Still verbatim; the server will reject a truly bad DN at bind time,
        // which is the correct observable error (instead of silently using "weird").
        assert_eq!(bind_id, "cn=weird,dc=example");
    }
}
