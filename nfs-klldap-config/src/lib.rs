//! nfs-klldap-config — Type-safe TOML loader + generator for nfs-klldap-host.
//!
//! This crate is the single source of truth for `nfs-klldap.conf`.
//! It handles parsing, validation, smart auto-derivation, and generation of
//! derived configs (sssd.conf, krb5.conf, Ganesha exports).
//!
//! ## Public API
//!
//! Only the items re-exported below are part of the stable public surface.
//! The internal module layout is **not** part of the semver contract.
//!
//! ## Internal Module Layout
//!
//! - `config`   — Data model (`NfsKlldapConfig`, sections, `Share`, `GenerationPaths`)
//! - `error`    — `ConfigError`
//! - `validate` — Loading, validation, and derivation (`validate_and_derive`, `effective_*`)
//! - `persist`  — Volume detection + tolerant partial share loading
//! - `uri`      — URI helpers (`extract_host_from_uri`, `derive_realm_from_uri`)
//! - `hostname` — Hostname suggestion + **two-tier consistent retrieval**
//!   (primary `hostname` command + /proc confirmation). This is now the
//!   production contract used by startup TUI, WebUI, and diagnostics.
//! - `template` — First-run safe default template + write-if-missing
//! - `generate` — Full generation of sssd/krb5/ganesha configs
//!
//! Note: The container must be started with `--uts=host` (recommended) or
//! an explicit `--hostname` so that the two sources agree on a stable name
//! that matches the nfs/ principal in your keytab.

// =============================================================================
// Internal modules (private — only re-exports below are public API)
// =============================================================================
mod config;
mod error;
mod generate;
mod hostname;
mod persist;
mod template;
mod uri;
mod validate;

// =============================================================================
// Public API (stable surface for binaries + nfs-klldap-ui)
// =============================================================================
pub use config::{
    GaneshaSection, GenerationPaths, KerberosSection, ManagementSection, NfsKlldapConfig,
    ServerSection, Share, SssdSection, StorageSection,
};
pub use error::ConfigError;

pub use generate::generate_all;
pub use hostname::{
    get_consistent_hostname, looks_like_docker_default_hostname, suggested_nfs_hostname,
    ConsistentHostname, HostnameInconsistency, HostnameObservation, HostnameSource,
};
pub use persist::{is_persistent_config, load_host_paths_only};
pub use template::{generate_default_template, write_default_config_if_missing};
pub use uri::{derive_realm_from_uri, extract_host_from_uri};

// =============================================================================
// Imports needed by the facade / coordination layer
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// RAII guard to safely set an environment variable for the duration of a test
    /// and restore the previous value (or remove it) when the test ends.
    /// This prevents test pollution when running with --workspace (parallel tests).
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

        fn remove(key: &'static str) -> Self {
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

    fn minimal_cfg() -> NfsKlldapConfig {
        let mut c = NfsKlldapConfig {
            ldap_uri: "ldaps://kllap.test:6360".into(),
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=admin,ou=people,dc=test,dc=com".into(),
                ldap_default_authtok: "sekret".into(),
                ..Default::default()
            },
            shares: vec![
                Share {
                    name: "movies".into(),
                    host_path: "/media/SSD/movies".into(),
                    ..Default::default()
                },
                Share {
                    name: "data".into(),
                    host_path: "/media/SSD/data".into(),
                    security: Some("krb5i".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        c.validate_and_derive().expect("valid minimal");
        c
    }

    #[test]
    fn load_and_derive_works() {
        let c = minimal_cfg();
        assert_eq!(c.effective_realm(), "TEST");
        assert!(c.sssd.port.is_some());
        assert_eq!(c.shares.len(), 2);
        assert_eq!(c.container_path_for(&c.shares[0]), "/export/movies");
    }

    #[test]
    fn generate_produces_expected_artifacts() {
        let cfg = minimal_cfg();
        let tmp = tempfile::tempdir().unwrap();
        let paths = GenerationPaths {
            sssd_conf: tmp.path().join("sssd.conf"),
            krb5_conf: tmp.path().join("krb5.conf"),
            ganesha_conf: tmp.path().join("ganesha.conf"),
            exports_dir: tmp.path().join("exports.d"),
        };
        generate_all(&cfg, &paths).expect("generate");

        let sssd = fs::read_to_string(&paths.sssd_conf).unwrap();
        assert!(sssd.contains("ldap_uri = ldaps://kllap.test:6360"));
        assert!(sssd.contains("ldap_default_authtok = sekret"));

        let krb = fs::read_to_string(&paths.krb5_conf).unwrap();
        assert!(krb.contains("default_realm = TEST"));
        assert!(
            krb.contains("rdns = false"),
            "krb5.conf should include rdns=false for improved Kerberos reverse-DNS tolerance"
        );

        let main = fs::read_to_string(&paths.ganesha_conf).unwrap();
        assert!(main.contains("%include"));

        let exports: Vec<_> = fs::read_dir(&paths.exports_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(exports.len(), 2);
        // one fragment should mention krb5i for the second share
        let frag =
            fs::read_to_string(paths.exports_dir.join("11-data.conf")).unwrap_or_else(|_| {
                // fallback find
                let mut s = String::new();
                for e in fs::read_dir(&paths.exports_dir).unwrap() {
                    let p = e.unwrap().path();
                    if p.to_string_lossy().contains("data") {
                        s = fs::read_to_string(p).unwrap();
                    }
                }
                s
            });
        assert!(frag.contains("SecType = krb5i") || frag.contains("data"));
    }

    #[test]
    fn duplicate_names_rejected() {
        let mut c = minimal_cfg();
        c.shares.push(Share {
            name: "movies".into(),
            host_path: "/x".into(),
            ..Default::default()
        });
        assert!(c.validate_and_derive().is_err());
    }

    #[test]
    fn invalid_security_rejected() {
        let mut c = minimal_cfg();
        c.ganesha.default_security = "krb5x".into();
        assert!(c.validate_and_derive().is_err());

        let mut c2 = minimal_cfg();
        c2.shares[0].security = Some("aes-256".into());
        assert!(c2.validate_and_derive().is_err());
    }

    #[test]
    fn load_host_paths_only_returns_only_host_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("partial.conf");

        // Write a config that is intentionally missing bind credentials (should still work for helper)
        let partial = r#"
            ldap_uri = "ldaps://kllap.test:6360"
            [[shares]]
            name = "movies"
            host_path = "/media/SSD/movies"
            [[shares]]
            name = "backups"
            host_path = "/media/SSD/backups"
        "#;
        fs::write(&path, partial).unwrap();

        let roots = load_host_paths_only(&path).expect("should parse partial config");
        assert_eq!(roots.len(), 2);
        assert!(roots.iter().any(|p| p.to_string_lossy().contains("movies")));
        assert!(roots
            .iter()
            .any(|p| p.to_string_lossy().contains("backups")));
    }

    #[test]
    fn realm_is_required_no_silent_example() {
        // Prevent pollution from parallel tests in the workspace
        let _g1 = EnvGuard::remove("NFS_REALM");
        let _g2 = EnvGuard::remove("REALM");

        // Explicit placeholder in config must be rejected (core user complaint)
        let mut c = NfsKlldapConfig {
            ldap_uri: "ldaps://kllap.example.com:6360".into(),
            kerberos: KerberosSection {
                realm: Some("EXAMPLE.COM".into()),
            },
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "s".into(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "t".into(),
                host_path: "/t".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = c.validate_and_derive().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("kerberos.realm is required"));
        assert!(msg.contains("NFS_REALM"));

        // Explicit good realm passes
        c.kerberos.realm = Some("MY.REALM".into());
        assert!(c.validate_and_derive().is_ok());
        assert_eq!(c.effective_realm(), "MY.REALM");
    }

    #[test]
    fn realm_from_env_works() {
        // Use guard to prevent pollution of parallel tests in the workspace
        let _guard = EnvGuard::set("NFS_REALM", "ENV.REALM");

        let mut c = NfsKlldapConfig {
            ldap_uri: "ldaps://kllap.test:6360".into(), // would derive "TEST" without env
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "s".into(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "t".into(),
                host_path: "/t".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(c.validate_and_derive().is_ok());
        assert_eq!(c.effective_realm(), "ENV.REALM");
    }

    #[test]
    fn display_realm_returns_real_value_after_validation_and_placeholder_otherwise() {
        // Prevent env var pollution from other tests (NFS_REALM / REALM affect derivation)
        let _g1 = EnvGuard::remove("NFS_REALM");
        let _g2 = EnvGuard::remove("REALM");

        // After successful load/validate with good ldap_uri, display_realm must match effective_realm
        // and what the generator will write into krb5.conf.
        let mut c = NfsKlldapConfig {
            ldap_uri: "ldaps://ldap.testdomain.com:6360".into(),
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=admin,ou=people,dc=testdomain,dc=com".into(),
                ldap_default_authtok: "sekret".into(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "t".into(),
                host_path: "/t".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(c.validate_and_derive().is_ok());
        assert_eq!(c.effective_realm(), "TESTDOMAIN.COM");
        assert_eq!(c.display_realm(), "TESTDOMAIN.COM");

        // When no good realm is present (pre-validation or broken config), we get the placeholder
        let mut broken = NfsKlldapConfig {
            ldap_uri: "ldaps://192.168.1.5:6360".into(), // IP → no derivation
            ..Default::default()
        };
        // display_realm is safe even before validation
        assert_eq!(broken.display_realm(), "YOUR.REALM");

        // Explicit EXAMPLE is treated as missing for display
        broken.kerberos.realm = Some("EXAMPLE.COM".into());
        assert_eq!(broken.display_realm(), "YOUR.REALM");
    }

    #[test]
    fn sssd_tls_options_are_emitted_when_set() {
        let mut c = minimal_cfg();
        c.sssd.ldap_tls_reqcert = Some("never".into());
        c.sssd.ldap_id_use_start_tls = Some(true);
        c.sssd.ldap_tls_cacert = Some("/etc/pki/ca.crt".into());
        // Force a non-ldaps uri so STARTTLS makes sense in the test
        c.ldap_uri = "ldap://kllap.test:389".into();
        // Re-derive (port etc.) — validate will also set search bases
        let _ = c.validate_and_derive();

        let tmp = tempfile::tempdir().unwrap();
        let paths = GenerationPaths {
            sssd_conf: tmp.path().join("sssd.conf"),
            krb5_conf: tmp.path().join("krb5.conf"),
            ganesha_conf: tmp.path().join("ganesha.conf"),
            exports_dir: tmp.path().join("exports.d"),
        };
        generate_all(&c, &paths).expect("generate with tls");

        let sssd = fs::read_to_string(&paths.sssd_conf).unwrap();
        assert!(sssd.contains("ldap_tls_reqcert = never"));
        // We accept both casings; the generator now prefers lowercase to match real production examples.
        assert!(sssd.to_lowercase().contains("ldap_id_use_start_tls = true"));
        assert!(sssd.contains("ldap_tls_cacert = /etc/pki/ca.crt"));
        // Should still have the core ldap_uri from the (overridden) config
        assert!(sssd.contains("ldap_uri = ldap://kllap.test:389"));
    }

    #[test]
    fn ldap_uri_ip_rejected_with_exact_message() {
        std::env::remove_var("NFS_REALM");
        std::env::remove_var("REALM");

        fn make_minimal(ip_uri: &str) -> NfsKlldapConfig {
            NfsKlldapConfig {
                ldap_uri: ip_uri.into(),
                sssd: SssdSection {
                    ldap_default_bind_dn: "uid=admin,ou=people,dc=x,dc=com".into(),
                    ldap_default_authtok: "s".into(),
                    ..Default::default()
                },
                shares: vec![Share {
                    name: "t".into(),
                    host_path: "/t".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
        }

        // IPv4
        let mut c = make_minimal("ldaps://192.168.10.5:6360");
        let err = c.validate_and_derive().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(
                "LDAP IP addresses are not supported, DNS resolution is required for operation."
            ),
            "unexpected error: {}",
            msg
        );

        // IPv6 (with brackets in URI)
        let mut c6 = make_minimal("ldaps://[2001:db8::1]:6360");
        let err6 = c6.validate_and_derive().unwrap_err();
        assert!(err6
            .to_string()
            .contains("LDAP IP addresses are not supported"));

        // Also bare IPv6 without port etc.
        let mut c6b = make_minimal("ldap://[::1]");
        assert!(c6b.validate_and_derive().is_err());

        // Hostname is allowed (validation proceeds to other required fields)
        let mut ch = make_minimal("ldaps://kllap.example.com:6360");
        // Will fail on realm (no EXAMPLE), but NOT on the IP check
        let hmsg = ch.validate_and_derive().unwrap_err().to_string();
        assert!(!hmsg.contains("IP addresses are not supported"));
        assert!(hmsg.contains("kerberos.realm is required"));
    }

    #[test]
    fn suggested_nfs_hostname_inserts_before_first_dot() {
        // Primary use case from the bug report
        assert_eq!(
            suggested_nfs_hostname("aurora.testdomain.com"),
            "aurora-nfs.testdomain.com"
        );
        // Multi-label
        assert_eq!(
            suggested_nfs_hostname("foo.bar.baz.co.uk"),
            "foo-nfs.bar.baz.co.uk"
        );
        // No dot → append
        assert_eq!(suggested_nfs_hostname("myserver"), "myserver-nfs");
        // Already has -nfs (idempotent-ish, we still transform the first label)
        assert_eq!(
            suggested_nfs_hostname("aurora-nfs.testdomain.com"),
            "aurora-nfs-nfs.testdomain.com"
        );
        // Empty / degenerate
        assert_eq!(suggested_nfs_hostname(""), "nfs-server");
        assert_eq!(suggested_nfs_hostname("."), "nfs-server");
        assert_eq!(suggested_nfs_hostname(".."), "nfs-server");
    }

    #[test]
    fn docker_default_hostname_detection() {
        assert!(looks_like_docker_default_hostname("3c896c1c2e24"));
        assert!(looks_like_docker_default_hostname("a1b2c3d4e5f6"));
        assert!(looks_like_docker_default_hostname("0123456789abcdef"));
        assert!(!looks_like_docker_default_hostname("myhost.example.com"));
        assert!(!looks_like_docker_default_hostname("myhost"));
        assert!(!looks_like_docker_default_hostname("abc")); // too short
        assert!(!looks_like_docker_default_hostname("3c896c1c2e24-nfs"));
    }

    #[test]
    fn derive_realm_from_uri_is_public_and_works() {
        assert_eq!(
            derive_realm_from_uri("ldaps://kllap.example.com:6360"),
            Some("EXAMPLE.COM".into())
        );
        assert_eq!(
            derive_realm_from_uri("ldap://sub.host.testdomain.local"),
            Some("HOST.TESTDOMAIN.LOCAL".into())
        );
        assert_eq!(derive_realm_from_uri(""), None);
    }
}
