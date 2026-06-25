//! Representative nfs-klldap.conf: drives real generate twice and asserts Ganesha 9.6 output.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use nfs_klldap_config::{classify_principal, generate_all, GenerationPaths, NfsKlldapConfig};
use nfs_klldap_identity::nfs_keytab_host_variants;

const REPRESENTATIVE_TOML: &str = r#"
ldap_uri = "ldaps://kllap.test:6360"

[storage]
container_root = "/export"

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "strong-secret"
kllldap_ignored_attributes = true

[ganesha]
default_security = "krb5p"

[[shares]]
name = "movies"
host_path = "/media/NVME-RAID/movies"
export_path = "/movies"
security = "krb5p"
rw = true
cache_profile = "Read - Heavy"
"#;

fn cargo_bin(name: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        return PathBuf::from(path);
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/debug")
        .join(name);
    assert!(
        path.is_file(),
        "binary {name} not built at {} (set {env_key} when available)",
        path.display()
    );
    path
}

fn generation_paths(out: &std::path::Path) -> GenerationPaths {
    GenerationPaths {
        sssd_conf: out.join("sssd.conf"),
        krb5_conf: out.join("krb5.conf"),
        ganesha_conf: out.join("ganesha.conf"),
        exports_dir: out.join("exports.d"),
        idmap_conf: out.join("idmapd.conf"),
        nfs_conf: out.join("nfs.conf"),
    }
}

fn assert_ganesha_96_compliant(ganesha: &str, idmap: &str) {
    for key in [
        "DIRECTORY_SERVICES",
        "DomainName = TEST",
        "Pwnam_Implementation = nsswitch",
        "Root_Kerberos_Principal = host, nfs, root",
        "Idmapped_User_Time_Validity = 600",
        "Idmapped_Group_Time_Validity = 600",
        "NFS_KRB5",
        "PrincipalName = \"nfs\"",
        "Active_krb5 = TRUE",
    ] {
        assert!(ganesha.contains(key), "ganesha.conf missing {key}");
    }
    for forbidden in [
        "Read_Access_Check_Policy =",
        "Manage_Gids_Expiration =",
        "IdmapConf =",
        "UseGetpwnam =",
        "Transports =",
    ] {
        assert!(
            !ganesha.contains(forbidden),
            "ganesha.conf must not emit deprecated key {forbidden}"
        );
    }
    assert!(idmap.contains("Domain = TEST"));
    assert!(idmap.contains("Method = nsswitch"));
}

#[test]
fn representative_config_generate_twice_is_consistent() {
    let tmp = tempfile::tempdir().unwrap();
    let conf_path = tmp.path().join("nfs-klldap.conf");
    fs::write(&conf_path, REPRESENTATIVE_TOML).unwrap();

    let mut cfg = NfsKlldapConfig::load(&conf_path).expect("load");
    cfg.validate_and_derive().expect("validate");

    let out = tmp.path().join("out");
    fs::create_dir_all(out.join("exports.d")).unwrap();
    let paths = generation_paths(&out);

    generate_all(&cfg, &paths).expect("generate run1");
    let g1 = fs::read_to_string(&paths.ganesha_conf).unwrap();
    generate_all(&cfg, &paths).expect("generate run2");
    let g2 = fs::read_to_string(&paths.ganesha_conf).unwrap();
    let i1 = fs::read_to_string(&paths.idmap_conf).unwrap();

    assert_eq!(g1, g2, "two generate runs to the same dir must be identical");
    assert_ganesha_96_compliant(&g1, &i1);

    let variants = nfs_keytab_host_variants("nfs-server.example.com");
    let (m_host, _) = classify_principal("host/client.test@TEST", "TEST", &variants);
    let (m_nfs, _) = classify_principal("nfs/client@TEST", "TEST", &variants);
    let (u_alice, _) = classify_principal("alice@TEST", "TEST", &variants);
    assert!(m_host && m_nfs && !u_alice);
}

#[test]
fn representative_config_cli_generate_exit_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let conf_path = tmp.path().join("nfs-klldap.conf");
    let out = tmp.path().join("out");
    fs::write(&conf_path, REPRESENTATIVE_TOML).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let config_bin = cargo_bin("nfs-klldap-config");
    for run in 1..=2 {
        let output = Command::new(&config_bin)
            .args(["generate", "--config"])
            .arg(&conf_path)
            .env("SSSD_CONF", out.join("sssd.conf"))
            .env("KRB5_CONF", out.join("krb5.conf"))
            .env("GANESHA_CONF", out.join("ganesha.conf"))
            .env("EXPORTS_DIR", out.join("exports.d"))
            .env("IDMAP_CONF", out.join("idmapd.conf"))
            .env("NFS_CONF", out.join("nfs.conf"))
            .output()
            .unwrap_or_else(|e| panic!("cli generate run {run}: {e}"));

        assert!(
            output.status.success(),
            "run {run} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let ganesha = fs::read_to_string(out.join("ganesha.conf")).unwrap();
    let idmap = fs::read_to_string(out.join("idmapd.conf")).unwrap();
    assert_ganesha_96_compliant(&ganesha, &idmap);
}