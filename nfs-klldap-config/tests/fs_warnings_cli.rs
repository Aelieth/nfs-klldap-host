//! fs-warnings CLI output for limited vs capable shares.

use std::fs;
use std::process::Command;
use std::sync::Mutex;

static MOUNTINFO_ENV_LOCK: Mutex<()> = Mutex::new(());

fn cargo_bin(name: &str) -> std::path::PathBuf {
    if let Ok(p)=std::env::var(&format!("CARGO_BIN_EXE_{}",name.replace('-',"_"))) {return std::path::PathBuf::from(p);} std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug").join(name)
}

#[test]
fn fs_warnings_reports_limited_share_only() {
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mountinfo = r#"
36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl
37 36 0:60 / /export/data rw,relatime - ext4 /dev/sdb1 rw
"#;
    let mountinfo_path = tmp.path().join("mountinfo");
    fs::write(&mountinfo_path, mountinfo).unwrap();
    let conf = tmp.path().join("nfs-klldap.conf");
    fs::write(
        &conf,
        r#"
ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "users"
host_path = "/media/users"
container_path = "/export/users"
[[shares]]
name = "data"
host_path = "/media/data"
container_path = "/export/data"
"#,
    )
    .unwrap();

    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
    std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mountinfo_path);

    let out1 = Command::new(cargo_bin("nfs-klldap-config"))
        .args(["fs-warnings", "--config"])
        .arg(&conf)
        .output()
        .expect("fs-warnings");
    let out2 = Command::new(cargo_bin("nfs-klldap-config"))
        .args(["fs-warnings", "--config"])
        .arg(&conf)
        .output()
        .expect("fs-warnings again");

    if let Some(p) = prev {
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p);
    } else {
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
    }

    assert!(out1.status.success());
    let s1 = String::from_utf8_lossy(&out1.stdout);
    let s2 = String::from_utf8_lossy(&out2.stdout);
    assert_eq!(s1, s2, "fs-warnings must be deterministic");
    assert!(s1.contains("users"));
    assert!(s1.contains("acl_capable=false"));
    assert!(!s1.contains("share=data"), "capable share omitted");
}