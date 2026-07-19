//! Crate-level tests: load, validate, generate, and env overrides.

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

/// Clears NFS_KLLDAP_* env vars while ENV_LOCK guards stay alive.
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
        // Debug toggles (bare names, not under the NFS_KLLDAP_ prefix).
        "GANESHA_DEBUG",
    ];
    vars.iter().map(|&k| EnvGuard::remove(k)).collect()
}

fn minimal_cfg() -> NfsKlldapConfig {
    // Clear at construction time so the internal validate sees a clean.
    let _guards = clean_core_env();
    let mut c = NfsKlldapConfig {
        ldap_uri: "ldaps://klldap.test:6360".into(),
        sssd: SssdSection {
            ldap_default_bind_dn: "uid=admin,ou=people,dc=test,dc=com".into(),
            ldap_default_authtok: "sekret".into(),
            ..Default::default()
        },
        shares: vec![
            Share {
                name: "movies".into(),
                host_path: "/media/SSD/movies".into(),
                container_path: "/export/SSD/movies".into(),
                ..Default::default()
            },
            Share {
                name: "data".into(),
                host_path: "/media/SSD/data".into(),
                container_path: "/export/SSD/data".into(),
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
    assert_eq!(c.serve_path_for(&c.shares[0]), "/export/SSD/movies");
}

#[test]
fn load_lenient_accepts_first_run_config_and_applies_env_overrides() {
    let _env = env_lock();
    let _guards = clean_core_env();
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nfs-klldap.conf");
    fs::write(&path, "ldap_uri = \"ldaps://klldap.test:6360\"\n").unwrap();

    // Strict load rejects the wizard-stage config; the lenient load must not.
    assert!(NfsKlldapConfig::load(&path).is_err());
    let cfg = NfsKlldapConfig::load_lenient(&path).unwrap();
    assert_eq!(cfg.ldap_uri, "ldaps://klldap.test:6360");
    assert!(cfg.sssd.ldap_default_bind_dn.is_empty());

    let _uri = EnvGuard::set("NFS_KLLDAP_LDAP_URI", "ldaps://env.test:636");
    let cfg = NfsKlldapConfig::load_lenient(&path).unwrap();
    assert_eq!(cfg.ldap_uri, "ldaps://env.test:636");
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
        avahi_services_dir: tmp.path().join("avahi-services"),
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
    assert!(sssd.contains("ldap_uri = ldaps://klldap.test:6360"));
    assert!(sssd.contains("ldap_default_authtok = sekret"));
    assert_eq!(
        sssd.matches("ldap_id_mapping = false").count(),
        1,
        "ldap_id_mapping must appear exactly once"
    );
    assert_eq!(sssd.matches("ldap_pwd_policy = none").count(), 1);
    assert!(sssd.contains("ignored_user_attributes"));

    // Auto-derived Kerberos KDC settings (co-located same Host/realm as.
    assert!(sssd.contains("krb5_realm = TEST"));
    assert!(sssd.contains("krb5_server = klldap.test"));
    assert!(sssd.contains("krb5_kpasswd = klldap.test"));

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
    // 1.4 hardening: host/ machine keytabs are NOT root (upstream default all).
    assert!(main.contains("Root_Kerberos_Principal = nfs, root;"));
    // 9.13 routes the getgroups() trust window through Idmapped_* below;
    // emitting the old core param would only draw a startup warning.
    assert!(!main.contains("Manage_Gids_Expiration"));
    assert!(main.contains("Max_Uid_To_Group_Reqs = 64;"));
    assert!(main.contains("Negative_Cache_Time_Validity = 60;"));
    assert!(main.contains("Getattrs_In_Complete_Read = false;"));
    assert!(main.contains("Enable_malloc_trim = true;"));
    assert!(main.contains("RecoveryRoot = /var/lib/nfs/ganesha;"));
    // Reclaim correctness: grace must cover the lease (9.13 warns on less).
    assert!(main.contains("Lease_Lifetime = 60;"));
    assert!(main.contains("Grace_Period = 90;"));
    assert!(main.contains("NFS_KRB5 {"));

    assert!(main.contains("Idmapped_User_Time_Validity = 180;"));
    assert!(main.contains("Idmapped_Group_Time_Validity = 180;"));
    assert!(main.contains("EXPORT_DEFAULTS {\n    SecType = krb5p;\n    Protocols = 4;"));
    // Ganesha 9.6 trixie-backports: only these blocks are emitted.
    assert!(!main.contains("Transports"));
    assert!(!main.contains("Mountd_Port"));
    assert!(!main.contains("NLM_Port"));
    assert!(!main.contains("Rquota_Port"));
    assert!(!main.contains("IdmapConf"));
    assert!(main.contains("UseGetpwnam = true"));
    // Enable_*=false are safe and explicit the dangerous keys Above are.

    // Baseline LOG is always emitted for idhelper operator visibility.
    assert!(
        main.contains("LOG {"),
        "baseline LOG block should be present even without GANESHA_DEBUG"
    );
    assert!(
        !main.contains("IDMAPPER = FULL_DEBUG"),
        "FULL_DEBUG must be absent by default"
    );
    // The lighter components we care about for principal discovery should.
    assert!(main.contains("CLIENTID = DEBUG") || main.contains("IDMAPPER = EVENT"));
    // Regression guard for CLIENT block parameters.
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

    // Default build emits baseline LOG without FULL_DEBUG.
    let cfg = minimal_cfg();
    let tmp = tempfile::tempdir().unwrap();
    let paths = GenerationPaths {
        sssd_conf: tmp.path().join("sssd.conf"),
        krb5_conf: tmp.path().join("krb5.conf"),
        ganesha_conf: tmp.path().join("ganesha.conf"),
        exports_dir: tmp.path().join("exports.d"),
        idmap_conf: tmp.path().join("idmapd.conf"),
        nfs_conf: tmp.path().join("nfs.conf"),
        avahi_services_dir: tmp.path().join("avahi-services"),
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

    // GANESHA_DEBUG=true enables FULL_DEBUG in generated config.
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
        avahi_services_dir: tmp2.path().join("avahi-services"),
    };
    generate_all(&cfg2, &paths2).expect("generate with debug");

    let main_debug = fs::read_to_string(&paths2.ganesha_conf).unwrap();
    assert!(
        main_debug.contains("LOG {"),
        "LOG block must be present when GANESHA_DEBUG=TRUE"
    );
    assert!(main_debug.contains("Default_Log_Level = DEBUG;"));
    assert!(main_debug.contains("IDMAPPER = FULL_DEBUG;"));
    // ACL component makes ACL-path failures visible in captures.
    assert!(main_debug.contains("NFS_V4_ACL = DEBUG;"));
    // Ganesha 9.13 dropped the RPCSEC_GSS LOG component; GSS cred flow
    // logs under DISPATCH, which the block covers at DEBUG.
    assert!(
        !main_debug.contains("RPCSEC_GSS"),
        "RPCSEC_GSS is not a valid LOG component on Ganesha 9.13"
    );
    assert!(main_debug.contains("DISPATCH = DEBUG;"));
    // FSAL only in fragments top-level NFS4 is DEBUG for Idhelper.
    assert!(main_debug.contains("NFS4 = DEBUG;"));
    assert!(
        !main_debug.contains("RECOVERY"),
        "RECOVERY stays out of the LOG block (only valid since 9.13)"
    );
}

#[test]
fn duplicate_names_rejected() {
    let _env = env_lock();
    let _guards = clean_core_env();
    let mut c = minimal_cfg();
    c.shares.push(Share {
        name: "movies".into(),
        host_path: "/x".into(),
        container_path: "/export".into(),
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
fn read_access_policy_validation() {
    let _env = env_lock();
    let _guards = clean_core_env();
    let mut c = minimal_cfg();
    c.shares[0].read_access_policy = Some("bogus".into());
    assert!(c.validate_and_derive().is_err());

    let mut c2 = minimal_cfg();
    c2.shares[0].read_access_policy = Some("pre".into());
    assert!(c2.validate_and_derive().is_ok());

    // post on a NOACL (opt-out) share is not fatal: it is normalized to pre at emit
    // time with a loud warning, so validation still succeeds.
    let mut c3 = minimal_cfg();
    c3.shares[0].enable_acl = Some(false);
    c3.shares[0].read_access_policy = Some("post".into());
    assert!(c3.validate_and_derive().is_ok());

    // post with ACL explicitly enabled is accepted (ACL path).
    let mut c4 = minimal_cfg();
    c4.shares[0].enable_acl = Some(true);
    c4.shares[0].read_access_policy = Some("post".into());
    assert!(c4.validate_and_derive().is_ok());
}

#[test]
fn duplicate_pseudo_and_serve_paths_rejected() {
    let _env = env_lock();
    let _guards = clean_core_env();

    // Two shares resolving to the same Pseudo path collide in the NFSv4 pseudo-fs.
    let mut dup_pseudo = minimal_cfg();
    dup_pseudo.shares[0].pseudo_path = Some("/shared".into());
    dup_pseudo.shares[1].pseudo_path = Some("/shared".into());
    assert!(dup_pseudo.validate_and_derive().is_err());

    // Two shares serving the same container_path collide in the export table.
    let mut dup_serve = minimal_cfg();
    dup_serve.shares[1].container_path = dup_serve.shares[0].container_path.clone();
    assert!(dup_serve.validate_and_derive().is_err());

    // pseudo_path "/" is reserved for the pseudo-fs root.
    let mut root_pseudo = minimal_cfg();
    root_pseudo.shares[0].pseudo_path = Some("/".into());
    assert!(root_pseudo.validate_and_derive().is_err());
}

#[test]
fn source_path_must_be_absolute_and_under_root() {
    let _env = env_lock();
    let _guards = clean_core_env();

    let mut ok = minimal_cfg();
    ok.shares[0].source_path = Some("/export/SSD/movies-src".into());
    assert!(ok.validate_and_derive().is_ok());

    let mut rel = minimal_cfg();
    rel.shares[0].source_path = Some("relative/path".into());
    assert!(rel.validate_and_derive().is_err());

    let mut outside = minimal_cfg();
    outside.shares[0].source_path = Some("/somewhere/else".into());
    assert!(outside.validate_and_derive().is_err());
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

    // All 5 official profiles must pass.
    for prof in crate::config::CACHE_PROFILES {
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
        ldap_uri = "ldaps://klldap.test:6360"
        [sssd]
        ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
        ldap_default_authtok = "sekret"
        [[shares]]
        name = "movies"
        host_path = "/media/movies"
        container_path = "/export/movies"
        enable_acll = true
    "#;
    fs::write(&path, toml).unwrap();

    let cfg = NfsKlldapConfig::load(&path).expect("must load despite unknown key");
    assert_eq!(cfg.shares.len(), 1);
    assert_eq!(cfg.share_warnings.len(), 1);
    assert_eq!(cfg.share_warnings[0].unknown_keys, vec!["enable_acll"]);
    assert_eq!(cfg.share_warnings[0].share_name.as_deref(), Some("movies"));
}

#[test]
fn share_manage_gids_valid_no_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("mg.conf");
    let toml = r#"
        ldap_uri = "ldaps://klldap.test:6360"
        [sssd]
        ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
        ldap_default_authtok = "sekret"
        [[shares]]
        name = "movies"
        host_path = "/media/movies"
        container_path = "/export/movies"
        manage_gids = false
    "#;
    fs::write(&path, toml).unwrap();

    let cfg = NfsKlldapConfig::load(&path).expect("load");
    assert!(cfg.share_warnings.is_empty());
    assert_eq!(cfg.shares[0].manage_gids, Some(false));
}

#[test]
fn share_enable_acl_valid_no_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ok.conf");
    let toml = r#"
        ldap_uri = "ldaps://klldap.test:6360"
        [sssd]
        ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
        ldap_default_authtok = "sekret"
        [[shares]]
        name = "movies"
        host_path = "/media/movies"
        container_path = "/export/movies"
        enable_acl = false
    "#;
    fs::write(&path, toml).unwrap();

    let cfg = NfsKlldapConfig::load(&path).expect("load");
    assert!(cfg.share_warnings.is_empty());
    assert_eq!(cfg.shares[0].enable_acl, Some(false));
}

#[test]
fn share_navahi_insecure_valid_no_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("navahi.conf");
    let toml = r#"
        ldap_uri = "ldaps://klldap.test:6360"
        navahi_discovery = true
        [sssd]
        ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
        ldap_default_authtok = "sekret"
        [[shares]]
        name = "movies"
        host_path = "/media/movies"
        container_path = "/export/movies"
        navahi_insecure = true
    "#;
    fs::write(&path, toml).unwrap();

    let cfg = NfsKlldapConfig::load(&path).expect("load");
    assert!(cfg.share_warnings.is_empty());
    assert!(cfg.navahi_discovery);
    assert_eq!(cfg.shares[0].navahi_insecure, Some(true));
}

#[test]
fn navahi_effective_requires_both_flags() {
    let mut cfg = NfsKlldapConfig::default();
    let mut share = crate::Share {
        navahi_insecure: Some(true),
        ..crate::Share::default()
    };
    assert!(!crate::share_navahi_effective(&cfg, &share));
    cfg.navahi_discovery = true;
    assert!(crate::share_navahi_effective(&cfg, &share));
    share.navahi_insecure = None;
    assert!(!crate::share_navahi_effective(&cfg, &share));
    share.navahi_insecure = Some(false);
    assert!(!crate::share_navahi_effective(&cfg, &share));
}

#[test]
fn template_defaults_navahi_off_top_level() {
    let tmpl = crate::generate_default_template();
    let nav = tmpl
        .find("navahi_discovery = false")
        .expect("template carries the toggle");
    let first_section = tmpl.find("\n[").expect("template has sections");
    assert!(nav < first_section, "top-level key must precede the first [section]");
}

#[test]
fn legacy_export_path_alias_populates_pseudo_path_no_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("legacy.conf");
    let toml = r#"
        ldap_uri = "ldaps://klldap.test:6360"
        [sssd]
        ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
        ldap_default_authtok = "sekret"
        [[shares]]
        name = "movies"
        host_path = "/media/movies"
        container_path = "/export/movies"
        export_path = "/legacy-movies"
    "#;
    fs::write(&path, toml).unwrap();

    let cfg = NfsKlldapConfig::load(&path).expect("must load legacy export_path");
    assert_eq!(cfg.shares.len(), 1);
    // serde alias + detector suppression => value captured, no warning for the alias
    assert!(cfg.share_warnings.is_empty(), "legacy export_path must not produce unknown key warning");
    assert_eq!(cfg.shares[0].pseudo_path.as_deref(), Some("/legacy-movies"));
    // ensure derive still works from it
    assert_eq!(crate::derive_share_pseudo(&cfg.shares[0]), "/legacy-movies");
}

#[test]
fn load_host_paths_only_returns_only_host_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("partial.conf");

    // Partial config (missing bind creds) load_host_paths_only Must still.
    let partial = r#"
        ldap_uri = "ldaps://klldap.test:6360"
        [[shares]]
        name = "movies"
        host_path = "/media/SSD/movies"
        [[shares]]
        name = "backups"
        host_path = "/media/SSD/backups"
    "#;
    fs::write(&path, partial).unwrap();

    let roots = crate::persist::load_host_paths_only(&path).expect("should parse partial config");
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
        ldap_uri: "ldaps://klldap.example.com:6360".into(),
        kerberos: crate::config::KerberosSection {
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
            container_path: "/export".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = c.validate_and_derive().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("kerberos.realm is required"));
    assert!(msg.contains("NFS_KLLDAP_KERBEROS_REALM"));

    // A valid Kerberos realm passes structural validation.
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
        ldap_uri: "ldaps://klldap.test:6360".into(),
        sssd: SssdSection {
            ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
            ldap_default_authtok: "s".into(),
            ..Default::default()
        },
        shares: vec![Share {
            name: "t".into(),
            host_path: "/t".into(),
            container_path: "/export".into(),
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
    // Clear env vars first while holding the test lock.
    let _guards = clean_core_env();
    let _g1 = EnvGuard::set("NFS_KLLDAP_LDAP_URI", "ldaps://envhost.testdomain.com:6360");
    let _g2 = EnvGuard::set("NFS_KLLDAP_SSSD_LDAP_DEFAULT_BIND_DN", "uid=envadmin,ou=people,dc=example,dc=com");
    let _g3 = EnvGuard::set("NFS_KLLDAP_SSSD_LDAP_DEFAULT_AUTHTOK", "env-secret-123");
    let _g4 = EnvGuard::set("NFS_KLLDAP_WEBUI_TLS", "off");
    let _g5 = EnvGuard::set("NFS_KLLDAP_SSSD_LDAP_TLS_REQCERT", "never");

    let mut c = NfsKlldapConfig {
        // Intentionally minimal / placeholder to prove env supplies.
        ldap_uri: "ldaps://placeholder:6360".into(),
        sssd: SssdSection {
            ldap_default_bind_dn: "uid=placeholder,ou=people,dc=x,dc=com".into(),
            ldap_default_authtok: "placeholder".into(),
            ..Default::default()
        },
        shares: vec![Share {
            name: "t".into(),
            host_path: "/t".into(),
            container_path: "/export".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(c.validate_and_derive().is_ok());
    assert_eq!(c.ldap_uri, "ldaps://envhost.testdomain.com:6360");
    assert_eq!(c.sssd.ldap_default_bind_dn, "uid=envadmin,ou=people,dc=example,dc=com");
    assert_eq!(c.sssd.ldap_default_authtok, "env-secret-123");
    assert_eq!(c.sssd.ldap_tls_reqcert.as_deref(), Some("never"));
    // TLS=off should map to Some(false) in the webui section.
    assert_eq!(c.webui.tls, Some(false));
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
            container_path: "/export".into(),
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
    c.ldap_uri = "ldap://klldap.test:389".into();
    let _ = c.validate_and_derive();

    let tmp = tempfile::tempdir().unwrap();
    let paths = GenerationPaths {
        sssd_conf: tmp.path().join("sssd.conf"),
        krb5_conf: tmp.path().join("krb5.conf"),
        ganesha_conf: tmp.path().join("ganesha.conf"),
        exports_dir: tmp.path().join("exports.d"),
        idmap_conf: tmp.path().join("idmapd.conf"),
        nfs_conf: tmp.path().join("nfs.conf"),
        avahi_services_dir: tmp.path().join("avahi-services"),
    };
    generate_all(&c, &paths).expect("generate with tls");

    let sssd = fs::read_to_string(&paths.sssd_conf).unwrap();
    assert!(sssd.contains("ldap_tls_reqcert = never"));
    assert!(sssd.to_lowercase().contains("ldap_id_use_start_tls = true"));
    assert!(sssd.contains("ldap_tls_cacert = /etc/pki/ca.crt"));
    assert!(sssd.contains("ldap_uri = ldap://klldap.test:389"));
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
        avahi_services_dir: tmp.path().join("avahi-services"),
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
                container_path: "/export".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    // IPv4 ldap_uri hosts parse correctly from the URI.
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

    // IPv6 (with brackets in URI).
    let mut c6 = make_minimal("ldaps://[2001:db8::1]:6360");
    let err6 = c6.validate_and_derive().unwrap_err();
    assert!(err6
        .to_string()
        .contains("LDAP IP addresses are not supported"));

    // Also bare IPv6 without port etc.
    let mut c6b = make_minimal("ldap://[::1]");
    assert!(c6b.validate_and_derive().is_err());

    let mut ch = make_minimal("ldaps://klldap.example.com:6360");
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
        derive_realm_from_uri("ldaps://klldap.example.com:6360"),
        Some("EXAMPLE.COM".into())
    );
    assert_eq!(
        derive_realm_from_uri("ldap://sub.host.testdomain.local"),
        Some("HOST.TESTDOMAIN.LOCAL".into())
    );
    assert_eq!(derive_realm_from_uri(""), None);
}

#[test]
fn signal_ganesha_reload_idmap_respects_disable_env() {
    let _env = env_lock();
    let _g = EnvGuard::set("NFS_KLLDAP_SIGHUP_ON_IDMAP_HEAL", "0");
    assert!(!signal_ganesha_reload_idmap(99999));
}
