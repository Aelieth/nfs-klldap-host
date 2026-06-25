#![deny(unsafe_code, dead_code)]

//! TOML validation, derivation, and generation of sssd.conf, krb5.conf, exports.

mod config;
mod constants;
mod error;
mod exports_fingerprint;
mod ganesha_liveness;
mod recycle_plan;
mod runtime;
#[cfg(unix)]
mod signals;
#[cfg(not(unix))]
mod signals_stub;
mod fs_probe;
mod fs_warnings;
mod generate;
mod hook;
mod hostname;
mod network;
mod persist;
mod startup;
mod template;
mod validate;

pub use config::{
    effective_ldap_search_bases, resolve_cache_profile, resolve_posix_attribute_mapping,
    ShareFieldWarning, CACHE_PROFILES, GaneshaSection, GenerationPaths, HostSection,
    KerberosSection, ManagementSection, NfsKlldapConfig, PosixAttributeMapping, ServerSection,
    Share, SssdSection, StorageSection, WebuiSection, SHARE_KNOWN_KEYS,
};
pub use network::{
    container_primary_ipv4, extract_server_addr_from_ganesha_line, is_docker_bridge_ipv4,
};
pub use validate::detect_share_unknown_keys;

pub mod ignored_attributes;
pub use error::ConfigError;
pub use exports_fingerprint::{
    fingerprint_exports_dir, fingerprint_identity_artifacts,
};
pub use ganesha_liveness::{
    discover_ganesha_daemon_pid, ganesha_is_live, pgrep_live_pids, pgrep_pids, process_is_live,
    reconcile_ganesha_pid,
};
pub use recycle_plan::{
    plan_from_changes, ganesha_sighup_failed, GaneshaAction, ServiceRecyclePlan,
};
pub use runtime::{
    host_nfs_active, host_nfs_from_env, parse_host_nfs_env_value, resolve_host_nfs_mode,
    runtime_hostname, runtime_realm, runtime_realm_from_disk, runtime_server_variants,
    runtime_server_variants_from_disk,
};
#[cfg(unix)]
pub use signals::{
    install_signal_handlers, reap_one_child, request_sighup, shutdown_requested,
    signal_process_hup, signal_process_kill, signal_process_term, signal_supervisor_hup,
    take_sighup_requested,
};
#[cfg(not(unix))]
pub use signals_stub::{
    install_signal_handlers, reap_one_child, request_sighup, shutdown_requested,
    signal_process_hup, signal_process_kill, signal_process_term, signal_supervisor_hup,
    take_sighup_requested,
};
pub use constants::PROC_COMM_NAME_MAX;

pub use fs_probe::{
    compute_effective_flags, limited_fs_warning, probe_from_mountinfo, probe_fs_capabilities,
    EffectiveShareFlags, FsCapabilities,
};
pub use fs_warnings::{
    any_share_manage_gids_enabled, collect_fs_warnings, limited_fs_warnings_only,
    share_fs_warning_message, share_fs_warning_message_with_mountinfo, FsShareWarning,
};
pub use hook::{effective_post_generate_hook, run_post_generate_hooks};
pub use generate::generate_all;
pub use hostname::{
    format_nfs_principal_list, get_consistent_hostname, looks_like_docker_default_hostname,
    nfs_keytab_host_matches, nfs_keytab_host_variants, ConsistentHostname, HostnameInconsistency,
    HostnameObservation, HostnameSource,
};
pub use persist::{is_persistent_config, load_host_paths_only};
pub use startup::{
    attempt_realm_from_config, check_ldap_bind, check_ldap_reachability, check_persistent_writable,
    compute_startup_step, compute_wizard_step, config_has_required_startup_fields,
    default_config_path,
    effective_startup_step, format_bind_probe, format_reachability_probe, format_volume_probe,
    is_preconfigured_deployment, is_setup_wizard_complete, resolve_keytab_path,
    is_step_complete, mark_setup_wizard_complete, should_bring_up_services,
    supervisor_loop_tick, startup_step_hint, SupervisorLoopAction,
    setup_wizard_marker_path,
    webui_setup_url, LdapReachability, StartupStep, DEFAULT_KEYTAB_PATH, SETUP_WIZARD_MARKER,
};
#[doc(hidden)]
pub use startup::lock_setup_marker_for_tests;
pub use template::{generate_default_template, write_default_config_if_missing};
pub use nfs_klldap_identity::{derive_realm_from_uri, extract_host_from_uri, host_is_ip};
pub use nfs_klldap_identity::{
    get_keytab_info, parse_klist_nfs_hosts, parse_klist_nfs_principals, read_keytab_nfs_principals,
    KeytabInfo,
};

// Structured LDAP resolution (IdLdapResolver) shared with
// Nfs-klldap-identity / WebUI LDAP client.
pub mod idmap;
pub use idmap::{
    classify_principal, escape_ldap_filter, extract_first_attr_value, from_sssd_section,
    machine_short_name, parse_getent_group, parse_getent_passwd, principal_local_part,
    IdLdapResolver, IdMapSnapshot, PosixGroupEntry, PosixUserEntry,
};

// Centralized constants (Ganesha 9.6 trixie + hybrid
// Principal + POSIX idmapd).
pub use constants::{
    DEFAULT_GROUP_GID_ATTR, DEFAULT_GROUP_NAME_ATTR, DEFAULT_GROUP_OBJECT_CLASS,
    DEFAULT_USER_FULLNAME_ATTR, DEFAULT_USER_GID_ATTR, DEFAULT_USER_HOME_ATTR,
    DEFAULT_USER_NAME_ATTR, DEFAULT_USER_OBJECT_CLASS, DEFAULT_USER_PRINCIPAL_ATTR,
    DEFAULT_USER_SHELL_ATTR, DEFAULT_USER_UID_ATTR, FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID,
    GANESHA_ALLOWED_SECTYPES, GANESHA_ALLOWED_SQUASH, GANESHA_DEFAULT_SECTYPE,
    GANESHA_DEFAULT_SQUASH, GANESHA_PROTOCOLS, GANESHA_PWNAM_IMPL, GANESHA_ROOT_KRB_PRINCIPALS,
    IDMAPD_GSS_METHODS, IDMAPD_NOBODY_GROUP, IDMAPD_NOBODY_USER,
    IDMAPD_TRANSLATION_METHOD, LOG_NOISE_TOKENS, MACHINE_GID, MACHINE_PRINCIPAL_PREFIXES, MACHINE_UID,
    DEFAULT_GROUP_MEMBER_ATTR_KLLDAP, DEFAULT_GROUP_MEMBER_ATTR_LEGACY,
};

/// (no_tls_verify, start_tls) from [sssd] TLS fields and ldap_uri scheme.
pub fn ldap_tls_policy(
    ldap_uri: &str,
    reqcert: Option<&str>,
    cacert: Option<&str>,
    id_use_start_tls: Option<bool>,
) -> (bool, bool) {
    let has_custom = cacert.is_some_and(|s| !s.trim().is_empty());
    let no_verify = if has_custom {
        reqcert.is_some_and(|v| v.eq_ignore_ascii_case("never"))
    } else if ldap_uri.starts_with("ldaps://") {
        reqcert.is_none_or(|v| v.eq_ignore_ascii_case("never"))
    } else {
        reqcert.is_some_and(|v| v.eq_ignore_ascii_case("never"))
    };
    (no_verify, id_use_start_tls.unwrap_or(false))
}

/// Serializes env-mutating tests across modules.
/// Needed because cargo test --workspace runs tests in parallel.
#[cfg(test)]
pub(crate) static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Serializes env-mutating tests under `cargo test --workspace`.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_TEST_LOCK.lock().unwrap()
    }

    /// RAII guard restoring previous env var value on drop.
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

    /// Clear NFS_KLLDAP_* env; hold guards alive across validate under ENV_LOCK.
    fn clean_core_env() -> Vec<EnvGuard> {
        let vars = [
            "NFS_KLLDAP_LDAP_URI",
            "NFS_KLLDAP_SSSD_LDAP_DEFAULT_BIND_DN",
            "NFS_KLLDAP_SSSD_LDAP_DEFAULT_AUTHTOK",
            "NFS_KLLDAP_LLDAP_USER",
            "NFS_KLLDAP_LLDAP_PW",
            "NFS_KLLDAP_KERBEROS_REALM",
            "NFS_KLLDAP_SERVER_HOSTNAME",
            "NFS_KLLDAP_STORAGE_CONTAINER_ROOT",
            "NFS_KLLDAP_GANESHA_DEFAULT_SECURITY",
            "NFS_KLLDAP_MANAGEMENT_WEBUI_ADMIN_GROUP",
            "NFS_KLLDAP_SSSD_KLLLDAP_IGNORED_ATTRIBUTES",
            "NFS_KLLDAP_SSSD_LDAP_TLS_REQCERT",
            "NFS_KLLDAP_SSSD_LDAP_TLS_CACERT",
            "NFS_KLLDAP_SSSD_LDAP_ID_USE_START_TLS",
            "NFS_KLLDAP_WEBUI_TLS",
            "NFS_KLLDAP_WEBUI_TLS_CERT",
            "NFS_KLLDAP_WEBUI_TLS_KEY",
            // Debug toggles (bare names, not under the NFS_KLLDAP_ prefix)
            "GANESHA_DEBUG",
        ];
        vars.iter().map(|&k| EnvGuard::remove(k)).collect()
    }

    fn minimal_cfg() -> NfsKlldapConfig {
        // Clear at construction time so the internal validate sees a clean env
        // Result of clean_core_env() alive for the lifetime of the test (see u
        let _guards = clean_core_env();
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
        let _env = env_lock();
        let _guards = clean_core_env();
        let c = minimal_cfg();
        assert_eq!(c.effective_realm(), "TEST");
        assert!(c.sssd.port.is_some());
        assert_eq!(c.shares.len(), 2);
        assert_eq!(c.container_path_for(&c.shares[0]), "/export/SSD/movies");
    }

    #[test]
    fn generate_produces_expected_artifacts() {
        let _env = env_lock();
        let _guards = clean_core_env();
        let cfg = minimal_cfg();
        let tmp = tempfile::tempdir().unwrap();
        let paths = GenerationPaths {
            sssd_conf: tmp.path().join("sssd.conf"),
            krb5_conf: tmp.path().join("krb5.conf"),
            ganesha_conf: tmp.path().join("ganesha.conf"),
            exports_dir: tmp.path().join("exports.d"),
            idmap_conf: tmp.path().join("idmapd.conf"),
            nfs_conf: tmp.path().join("nfs.conf"),
        };
        generate_all(&cfg, &paths).expect("generate");

        if let Ok(dump_dir) = std::env::var("NFS_KLLDAP_DUMP_DIR") {
            let dump = PathBuf::from(dump_dir);
            let _ = fs::copy(&paths.ganesha_conf, dump.join("ganesha-96.conf"));
            if let Ok(entries) = fs::read_dir(&paths.exports_dir) {
                for e in entries.flatten() {
                    let _ = fs::copy(e.path(), dump.join(e.file_name()));
                }
            }
        }

        let sssd = fs::read_to_string(&paths.sssd_conf).unwrap();
        assert!(sssd.contains("GENERATED by nfs-klldap-config"));
        assert!(sssd.contains("ldap_uri = ldaps://kllap.test:6360"));
        assert!(sssd.contains("ldap_default_authtok = sekret"));
        assert_eq!(
            sssd.matches("ldap_id_mapping = false").count(),
            1,
            "ldap_id_mapping must appear exactly once"
        );
        assert_eq!(sssd.matches("ldap_pwd_policy = none").count(), 1);
        assert!(sssd.contains("ignored_user_attributes"));

        // Auto-derived Kerberos KDC settings (co-located same
        // Host/realm as ldap + krb5.conf).
        assert!(sssd.contains("krb5_realm = TEST"));
        assert!(sssd.contains("krb5_server = kllap.test"));
        assert!(sssd.contains("krb5_kpasswd = kllap.test"));

        let krb = fs::read_to_string(&paths.krb5_conf).unwrap();
        assert!(krb.contains("default_realm = TEST"));
        assert!(
            krb.contains("rdns = false"),
            "krb5.conf should include rdns=false for improved Kerberos reverse-DNS tolerance"
        );

        let main = fs::read_to_string(&paths.ganesha_conf).unwrap();
        assert!(main.contains("%include"));
        // The include is emitted unquoted (no surrounding double quotes).
        assert!(!main.contains("%include \""));
        // Minimal proven-safe NFS_CORE_PARAM block for this Ganesha build.
        assert!(main.contains("Protocols = 4;"));
        assert!(main.contains("Enable_UDP = false"));
        assert!(main.contains("Allow_Set_Io_Flusher_Fail = true"));
        assert!(main.contains("Root_Kerberos_Principal = host, nfs, root;"));
        assert!(
            !main.contains("Manage_Gids_Expiration ="),
            "use idmapped_* in DIRECTORY_SERVICES on Ganesha 9.6 trixie-backports"
        );
        assert!(main.contains("NFS_KRB5 {"));

        assert!(main.contains("idmapped_user_time_validity = 600;"));
        assert!(main.contains("idmapped_group_time_validity = 600;"));
        assert!(main.contains("EXPORT_DEFAULTS {\n    SecType = krb5p;\n    Protocols = 4;"));
        // Ganesha 9.6 trixie-backports: only these blocks are emitted.
        // Classic port/Transports/Idmap keys are fatal at parser time.
        assert!(!main.contains("Transports"));
        assert!(!main.contains("Mountd_Port"));
        assert!(!main.contains("NLM_Port"));
        assert!(!main.contains("Rquota_Port"));
        assert!(!main.contains("IdmapConf"));
        assert!(!main.contains("UseGetpwnam"));
        // Enable_*=false are safe and explicit the dangerous keys
        // Above are omitted.

        // Baseline LOG always emitted (idhelper operators need
        // Visibility on IDMAPPER).
        assert!(
            main.contains("LOG {"),
            "baseline LOG block should be present even without GANESHA_DEBUG"
        );
        assert!(
            !main.contains("IDMAPPER = FULL_DEBUG"),
            "FULL_DEBUG must be absent by default"
        );
        // The lighter components we care about for principal discovery should be present
        assert!(main.contains("CLIENTID = DEBUG") || main.contains("IDMAPPER = EVENT"));
        // Regression guard for CLIENT block parameters
        assert!(!main.contains("Principals ="));

        let exports: Vec<_> = fs::read_dir(&paths.exports_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(exports.len(), 2);
        let frag =
            fs::read_to_string(paths.exports_dir.join("11-data.conf")).unwrap_or_else(|_| {
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
    fn ganesha_debug_log_block_emitted_only_when_env_true() {
        let _env = env_lock();
        let _guards = clean_core_env();

        // 1) Default (no GANESHA_DEBUG) baseline LOG (with CLIENTID etc) is in
        // Now. Only the FULL_DEBUG variant is controlled by the env var.
        let cfg = minimal_cfg();
        let tmp = tempfile::tempdir().unwrap();
        let paths = GenerationPaths {
            sssd_conf: tmp.path().join("sssd.conf"),
            krb5_conf: tmp.path().join("krb5.conf"),
            ganesha_conf: tmp.path().join("ganesha.conf"),
            exports_dir: tmp.path().join("exports.d"),
            idmap_conf: tmp.path().join("idmapd.conf"),
            nfs_conf: tmp.path().join("nfs.conf"),
        };
        generate_all(&cfg, &paths).expect("generate default");
        let main_default = fs::read_to_string(&paths.ganesha_conf).unwrap();
        assert!(
            main_default.contains("LOG {"),
            "baseline LOG must be present (no longer gated behind GANESHA_DEBUG)"
        );
        assert!(
            !main_default.contains("IDMAPPER = FULL_DEBUG"),
            "FULL_DEBUG must be absent without GANESHA_DEBUG=TRUE"
        );

        // 2) With GANESHA_DEBUG=true (any common truthy spelling) -> FULL_DEBUG block
        let _g = EnvGuard::set("GANESHA_DEBUG", "true");
        let cfg2 = minimal_cfg();
        let tmp2 = tempfile::tempdir().unwrap();
        let paths2 = GenerationPaths {
            sssd_conf: tmp2.path().join("sssd.conf"),
            krb5_conf: tmp2.path().join("krb5.conf"),
            ganesha_conf: tmp2.path().join("ganesha.conf"),
            exports_dir: tmp2.path().join("exports.d"),
            idmap_conf: tmp2.path().join("idmapd.conf"),
            nfs_conf: tmp2.path().join("nfs.conf"),
        };
        generate_all(&cfg2, &paths2).expect("generate with debug");

        let main_debug = fs::read_to_string(&paths2.ganesha_conf).unwrap();
        assert!(
            main_debug.contains("LOG {"),
            "LOG block must be present when GANESHA_DEBUG=TRUE"
        );
        assert!(main_debug.contains("Default_Log_Level = DEBUG;"));
        assert!(main_debug.contains("IDMAPPER = FULL_DEBUG;"));
        // FSAL only in fragments top-level NFS4 is DEBUG for
        // Idhelper observer.
        assert!(main_debug.contains("NFS4 = DEBUG;"));
        assert!(
            !main_debug.contains("RECOVERY"),
            "RECOVERY is not a valid LOG component on Ganesha 9.6 trixie-backports"
        );
        // Sanity: core config still there
        assert!(main_debug.contains("Protocols = 4;"));
        assert!(main_debug.contains("%include"));
    }

    #[test]
    fn duplicate_names_rejected() {
        let _env = env_lock();
        let _guards = clean_core_env();
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
        let _env = env_lock();
        let _guards = clean_core_env();
        let mut c = minimal_cfg();
        c.ganesha.default_security = "krb5x".into();
        assert!(c.validate_and_derive().is_err());

        let mut c2 = minimal_cfg();
        c2.shares[0].security = Some("aes-256".into());
        assert!(c2.validate_and_derive().is_err());
    }

    #[test]
    fn invalid_squash_rejected() {
        let _env = env_lock();
        let _guards = clean_core_env();
        let mut c = minimal_cfg();
        c.shares[0].squash = Some("invalid_squash".into());
        assert!(c.validate_and_derive().is_err());

        let mut c2 = minimal_cfg();
        c2.shares[0].squash = Some("root_squash".into());
        assert!(c2.validate_and_derive().is_ok());
    }

    #[test]
    fn invalid_pref_read_rejected() {
        let _env = env_lock();
        let _guards = clean_core_env();
        let mut c = minimal_cfg();
        c.shares[0].pref_read = Some(64 * 1024 * 1024 + 1);
        assert!(c.validate_and_derive().is_err(), "above max must be rejected");

        let mut c2 = minimal_cfg();
        c2.shares[0].pref_read = Some(1);
        assert!(c2.validate_and_derive().is_err(), "below min must be rejected");

        let mut c3 = minimal_cfg();
        c3.shares[0].pref_read = Some(16 * 1024 * 1024);
        assert!(c3.validate_and_derive().is_ok(), "valid 16M streaming value accepted");
    }

    #[test]
    fn invalid_cache_profile_rejected_and_valid_profiles_accepted() {
        let _env = env_lock();
        let _guards = clean_core_env();
        let mut c = minimal_cfg();
        c.shares[0].cache_profile = Some("Turbo".to_string());
        assert!(c.validate_and_derive().is_err(), "unknown profile must be rejected");

        // All 5 official profiles must pass
        for prof in crate::CACHE_PROFILES {
            let mut c_ok = minimal_cfg();
            c_ok.shares[0].cache_profile = Some((*prof).to_string());
            assert!(
                c_ok.validate_and_derive().is_ok(),
                "profile '{}' should be accepted",
                prof
            );
        }
    }

    #[test]
    fn share_unknown_keys_warn_but_config_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("warn.conf");
        let toml = r#"
            ldap_uri = "ldaps://kllap.test:6360"
            [sssd]
            ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
            ldap_default_authtok = "sekret"
            [[shares]]
            name = "movies"
            host_path = "/media/movies"
            disable_acll = true
        "#;
        fs::write(&path, toml).unwrap();

        let cfg = NfsKlldapConfig::load(&path).expect("must load despite unknown key");
        assert_eq!(cfg.shares.len(), 1);
        assert_eq!(cfg.share_warnings.len(), 1);
        assert_eq!(cfg.share_warnings[0].unknown_keys, vec!["disable_acll"]);
        assert_eq!(cfg.share_warnings[0].share_name.as_deref(), Some("movies"));
    }

    #[test]
    fn share_manage_gids_valid_no_warnings() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mg.conf");
        let toml = r#"
            ldap_uri = "ldaps://kllap.test:6360"
            [sssd]
            ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
            ldap_default_authtok = "sekret"
            [[shares]]
            name = "movies"
            host_path = "/media/movies"
            manage_gids = false
        "#;
        fs::write(&path, toml).unwrap();

        let cfg = NfsKlldapConfig::load(&path).expect("load");
        assert!(cfg.share_warnings.is_empty());
        assert_eq!(cfg.shares[0].manage_gids, Some(false));
    }

    #[test]
    fn share_disable_acl_valid_no_warnings() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ok.conf");
        let toml = r#"
            ldap_uri = "ldaps://kllap.test:6360"
            [sssd]
            ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
            ldap_default_authtok = "sekret"
            [[shares]]
            name = "movies"
            host_path = "/media/movies"
            disable_acl = true
        "#;
        fs::write(&path, toml).unwrap();

        let cfg = NfsKlldapConfig::load(&path).expect("load");
        assert!(cfg.share_warnings.is_empty());
        assert_eq!(cfg.shares[0].disable_acl, Some(true));
    }

    #[test]
    fn load_host_paths_only_returns_only_host_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("partial.conf");

        // Partial config (missing bind creds) load_host_paths_only
        // Must still succeed.
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
        let _env = env_lock();
        let _guards = clean_core_env();
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
        assert!(msg.contains("NFS_KLLDAP_KERBEROS_REALM"));

        // Good realm passes.
        c.kerberos.realm = Some("MY.REALM".into());
        assert!(c.validate_and_derive().is_ok());
        assert_eq!(c.effective_realm(), "MY.REALM");
    }

    #[test]
    fn realm_from_env_works() {
        let _env = env_lock();
        let _guards = clean_core_env();
        let _guard = EnvGuard::set("NFS_KLLDAP_KERBEROS_REALM", "ENV.REALM");

        let mut c = NfsKlldapConfig {
            ldap_uri: "ldaps://kllap.test:6360".into(),
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
    fn core_env_overrides_for_ldap_uri_bind_and_webui_work() {
        let _env = env_lock();
        let _guards = clean_core_env(); // clears everything first (under lock)
        let _g1 = EnvGuard::set("NFS_KLLDAP_LDAP_URI", "ldaps://envhost.testdomain.com:6360");
        let _g2 = EnvGuard::set("NFS_KLLDAP_SSSD_LDAP_DEFAULT_BIND_DN", "uid=envadmin,ou=people,dc=example,dc=com");
        let _g3 = EnvGuard::set("NFS_KLLDAP_SSSD_LDAP_DEFAULT_AUTHTOK", "env-secret-123");
        let _g4 = EnvGuard::set("NFS_KLLDAP_WEBUI_TLS", "off");
        let _g5 = EnvGuard::set("NFS_KLLDAP_SSSD_LDAP_TLS_REQCERT", "never");

        let mut c = NfsKlldapConfig {
            // intentionally minimal / placeholder to prove env supplies
            ldap_uri: "ldaps://placeholder:6360".into(),
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=placeholder,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "placeholder".into(),
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
        assert_eq!(c.ldap_uri, "ldaps://envhost.testdomain.com:6360");
        assert_eq!(c.sssd.ldap_default_bind_dn, "uid=envadmin,ou=people,dc=example,dc=com");
        assert_eq!(c.sssd.ldap_default_authtok, "env-secret-123");
        assert_eq!(c.sssd.ldap_tls_reqcert.as_deref(), Some("never"));
        assert_eq!(c.webui.tls, Some(false)); // off -> disabled
    }

    #[test]
    fn display_realm_returns_real_value_after_validation_and_placeholder_otherwise() {
        let _env = env_lock();
        let _guards = clean_core_env();
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

        let mut broken = NfsKlldapConfig {
            ldap_uri: "ldaps://192.168.1.5:6360".into(),
            ..Default::default()
        };
        assert_eq!(broken.display_realm(), "YOUR.REALM");

        // EXAMPLE.COM treated as missing for display.
        broken.kerberos.realm = Some("EXAMPLE.COM".into());
        assert_eq!(broken.display_realm(), "YOUR.REALM");
    }

    #[test]
    fn sssd_tls_options_are_emitted_when_set() {
        let _env = env_lock();
        let _guards = clean_core_env();
        let mut c = minimal_cfg();
        c.sssd.ldap_tls_reqcert = Some("never".into());
        c.sssd.ldap_id_use_start_tls = Some(true);
        c.sssd.ldap_tls_cacert = Some("/etc/pki/ca.crt".into());
        c.ldap_uri = "ldap://kllap.test:389".into();
        let _ = c.validate_and_derive();

        let tmp = tempfile::tempdir().unwrap();
        let paths = GenerationPaths {
            sssd_conf: tmp.path().join("sssd.conf"),
            krb5_conf: tmp.path().join("krb5.conf"),
            ganesha_conf: tmp.path().join("ganesha.conf"),
            exports_dir: tmp.path().join("exports.d"),
            idmap_conf: tmp.path().join("idmapd.conf"),
            nfs_conf: tmp.path().join("nfs.conf"),
        };
        generate_all(&c, &paths).expect("generate with tls");

        let sssd = fs::read_to_string(&paths.sssd_conf).unwrap();
        assert!(sssd.contains("ldap_tls_reqcert = never"));
        assert!(sssd.to_lowercase().contains("ldap_id_use_start_tls = true"));
        assert!(sssd.contains("ldap_tls_cacert = /etc/pki/ca.crt"));
        assert!(sssd.contains("ldap_uri = ldap://kllap.test:389"));
    }

    #[test]
    fn kllldap_ignored_attributes_false_omits_ignore_blocks() {
        let _env = env_lock();
        let _guards = clean_core_env();
        let mut c = minimal_cfg();
        c.sssd.kllldap_ignored_attributes = Some(false);
        let _ = c.validate_and_derive();

        let tmp = tempfile::tempdir().unwrap();
        let paths = GenerationPaths {
            sssd_conf: tmp.path().join("sssd.conf"),
            krb5_conf: tmp.path().join("krb5.conf"),
            ganesha_conf: tmp.path().join("ganesha.conf"),
            exports_dir: tmp.path().join("exports.d"),
            idmap_conf: tmp.path().join("idmapd.conf"),
            nfs_conf: tmp.path().join("nfs.conf"),
        };
        generate_all(&c, &paths).expect("generate with kll=false");

        let sssd = fs::read_to_string(&paths.sssd_conf).unwrap();
        assert!(
            !sssd.contains("ignored_user_attributes"),
            "kll=false must not emit the KLLDAP ignore blocks into sssd.conf"
        );
        assert!(
            !sssd.contains("ignored_group_attributes"),
            "kll=false must not emit the KLLDAP ignore blocks into sssd.conf"
        );
    }

    #[test]
    fn ldap_uri_ip_rejected_with_exact_message() {
        let _env = env_lock();
        let _guards = clean_core_env();

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

        let mut ch = make_minimal("ldaps://kllap.example.com:6360");
        let hmsg = ch.validate_and_derive().unwrap_err().to_string();
        assert!(!hmsg.contains("IP addresses are not supported"));
        assert!(hmsg.contains("kerberos.realm is required"));
    }

    #[test]
    fn docker_default_hostname_detection() {
        assert!(looks_like_docker_default_hostname("3c896c1c2e24"));
        assert!(looks_like_docker_default_hostname("a1b2c3d4e5f6"));
        assert!(looks_like_docker_default_hostname("0123456789abcdef"));
        assert!(!looks_like_docker_default_hostname("myhost.example.com"));
        assert!(!looks_like_docker_default_hostname("myhost"));
        assert!(!looks_like_docker_default_hostname("abc"));
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
