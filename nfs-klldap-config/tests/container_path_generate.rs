//! container_path: probe + EXPORT Path= use the configured serve path.

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
    let tmp = tempfile::tempdir().unwrap(); let mp=tmp.path().join("m"); fs::write(&mp,mountinfo).unwrap();
    let cp=tmp.path().join("c"); fs::write(&cp,toml).unwrap(); let out=tmp.path().join("o"); fs::create_dir_all(out.join("e.d")).unwrap();
    let pv = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok(); std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH",&mp);
    let cfg = NfsKlldapConfig::load(&cp).expect("l"); assert_eq!(cfg.serve_path_for(&cfg.shares[0]), "/export/staging/movies");
    let ps=GenerationPaths{sssd_conf:out.join("s"),krb5_conf:out.join("k"),ganesha_conf:out.join("g"),exports_dir:out.join("e.d"),idmap_conf:out.join("i"),nfs_conf:out.join("n")};
    generate_all(&cfg,&ps).expect("g");
    if let Some(p)=pv{std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH",p);}else{std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");}
    fs::read_dir(out.join("e.d")).unwrap().map(|e|e.unwrap().path()).find(|p|p.extension().map_or(false,|x|x=="conf")).map(|p|fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn container_path_staging_ext4_avoids_disable_acl() {
    // ACL is opt-in: a share explicitly requesting ACL (enable_acl = true) whose serve
    // path is on an ACL-capable staging tree keeps the ACL path (no Disable_ACL).
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
container_path = "/export/staging/movies"
enable_acl = true
"#;
    let frag = generate_with_mountinfo(MOUNTINFO_MIXED, toml);
    assert!(frag.contains("Path = /export/staging/movies;"));
    assert!(!frag.contains("Disable_ACL = true;"), "staging ext4 keeps ACL enabled");
    assert!(frag.contains("Manage_Gids = true;"));
}

#[test]
fn container_path_default_is_noacl_even_on_ext4() {
    // Without enable_acl the same ext4 serve path is NOACL (no fail-open onto the ACL
    // path that the packaged Ganesha 9.6 VFS FSAL cannot service).
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
container_path = "/export/staging/movies"
"#;
    let frag = generate_with_mountinfo(MOUNTINFO_MIXED, toml);
    assert!(frag.contains("Path = /export/staging/movies;"));
    assert!(frag.contains("Disable_ACL = true;"), "default (no enable_acl) is NOACL");
    assert!(frag.contains("Read_Access_Check_Policy = pre;"));
}