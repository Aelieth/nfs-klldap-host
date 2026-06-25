//! ganesha_path: probe + EXPORT Path= use staging serve path, not container data path.

use std::fs;
use std::sync::Mutex;

use nfs_klldap_config::{generate_all, GenerationPaths, NfsKlldapConfig};

static MOUNTINFO_ENV_LOCK: Mutex<()> = Mutex::new(());

const MOUNTINFO_MIXED: &str = r#"
40 39 0:70 / /export/movies rw,relatime - btrfs /dev/sda1 rw,noacl
41 40 0:71 / /export/staging/movies rw,relatime - ext4 /dev/sdb1 rw
"#;

fn generate_with_mountinfo(mountinfo: &str, toml: &str) -> String {
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
    assert_eq!(cfg.serve_path_for(&cfg.shares[0]), "/export/staging/movies");
    let paths = GenerationPaths {
        sssd_conf: out.join("sssd.conf"),
        krb5_conf: out.join("krb5.conf"),
        ganesha_conf: out.join("ganesha.conf"),
        exports_dir: out.join("exports.d"),
        idmap_conf: out.join("idmapd.conf"),
        nfs_conf: out.join("nfs.conf"),
    };
    generate_all(&cfg, &paths).expect("generate");

    if let Some(p) = prev {
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p);
    } else {
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
    }

    fs::read_dir(out.join("exports.d"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "conf"))
        .map(|p| fs::read_to_string(p).unwrap())
        .expect("fragment")
}

#[test]
fn ganesha_path_staging_ext4_avoids_disable_acl() {
    let toml = r#"
ldap_uri = "ldaps://kllap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "movies"
host_path = "/media/movies"
ganesha_path = "/export/staging/movies"
"#;
    let frag = generate_with_mountinfo(MOUNTINFO_MIXED, toml);
    assert!(frag.contains("Path = /export/staging/movies;"));
    assert!(!frag.contains("Disable_ACL = true"));
    assert!(!frag.contains("Manage_Gids = false"));
}