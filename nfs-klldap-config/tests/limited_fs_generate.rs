//! Drives real generate_all with simulated btrfs+noacl mountinfo and asserts fragment output.

use std::fs;
use std::sync::Mutex;

use nfs_klldap_config::{classify_principal, generate_all, GenerationPaths, NfsKlldapConfig};
use nfs_klldap_identity::nfs_keytab_host_variants;

static MOUNTINFO_ENV_LOCK: Mutex<()> = Mutex::new(());

const LIMITED_TOML: &str = r#"
ldap_uri = "ldaps://kllap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "users"
host_path = "/media/users"
security = "krb5p"
"#;

const MOUNTINFO_BTRFS_NOACL: &str = r#"
36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl
"#;

const MOUNTINFO_EXT4: &str = r#"
37 36 0:60 / /export/movies rw,relatime - ext4 /dev/sdb1 rw
"#;

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

fn read_single_fragment(exports_dir: &std::path::Path) -> String {
    let path = fs::read_dir(exports_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "conf"))
        .expect("export fragment");
    fs::read_to_string(path).unwrap()
}

fn generate_with_mountinfo(mountinfo: &str, toml: &str) -> (tempfile::TempDir, String, String) {
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mountinfo_path = tmp.path().join("mountinfo");
    fs::write(&mountinfo_path, mountinfo).unwrap();
    let conf_path = tmp.path().join("nfs-klldap.conf");
    fs::write(&conf_path, toml).unwrap();
    let out = tmp.path().join("out");
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
    std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mountinfo_path);

    let cfg = NfsKlldapConfig::load(&conf_path).expect("load");
    let paths = generation_paths(&out);
    generate_all(&cfg, &paths).expect("generate_all");

    if let Some(p) = prev {
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p);
    } else {
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
    }

    let frag = read_single_fragment(&out.join("exports.d"));
    let ganesha = fs::read_to_string(out.join("ganesha.conf")).unwrap();
    (tmp, frag, ganesha)
}

#[test]
fn generate_all_limited_btrfs_emits_safe_export_flags() {
    let (_tmp, frag, ganesha) = generate_with_mountinfo(MOUNTINFO_BTRFS_NOACL, LIMITED_TOML);

    assert!(frag.contains("Disable_ACL = true;"), "fragment:\n{frag}");
    assert!(frag.contains("Manage_Gids = false;"), "fragment:\n{frag}");
    assert!(frag.contains("Read_Access_Check_Policy = \"post\";"), "limited must have post policy:\n{frag}");
    assert!(frag.contains("posix-only conservative mode for noacl btrfs (ZimaOS)"), "limited comment:\n{frag}");
    for forbidden in [
        "Manage_Gids_Expiration =",
        "IdmapConf =",
    ] {
        assert!(!frag.contains(forbidden), "forbidden {forbidden} in fragment");
        assert!(!ganesha.contains(forbidden), "forbidden {forbidden} in ganesha.conf");
    }
    assert!(ganesha.contains("Root_Kerberos_Principal = host, nfs, root"));
    assert!(ganesha.contains("Pwnam_Implementation = nsswitch"));

    let variants = nfs_keytab_host_variants("nfs-server.example.com");
    let (m_host, _) = classify_principal("host/client.test@TEST", "TEST", &variants);
    let (m_nfs, _) = classify_principal("nfs/client@TEST", "TEST", &variants);
    let (u_alice, _) = classify_principal("alice@TEST", "TEST", &variants);
    assert!(m_host && m_nfs && !u_alice, "hybrid classify must hold on limited share");
}

#[test]
fn generate_all_capable_ext4_omits_limited_flags() {
    let ext4_toml = r#"
ldap_uri = "ldaps://kllap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "movies"
host_path = "/media/movies"
"#;
    let (_tmp, frag, _) = generate_with_mountinfo(MOUNTINFO_EXT4, ext4_toml);
    assert!(!frag.contains("Disable_ACL = true;"), "capable ext4 omits Disable_ACL");
    assert!(frag.contains("Manage_Gids = true;"));
    assert!(!frag.contains("Auto-detected:"));
}