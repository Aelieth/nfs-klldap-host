//! Shipped CLI gate: `nfs-klldap-config generate --config` twice with GenerationPaths env vars.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use nfs_klldap_config::ganesha_96_has_mode_only_access_knob;

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
container_path = "/export/users"
security = "krb5p"
"#;

const MOUNTINFO_BTRFS_NOACL: &str = r#"
36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl
"#;

fn cargo_bin(name: &str) -> PathBuf {
    if let Ok(p) = std::env::var(&format!("CARGO_BIN_EXE_{}", name.replace('-', "_"))) { return PathBuf::from(p); }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug").join(name)
}
fn write_fixture(d: &Path) -> (PathBuf, PathBuf) { let m = d.join("mi"); fs::write(&m, MOUNTINFO_BTRFS_NOACL).unwrap(); let c = d.join("c.toml"); fs::write(&c, LIMITED_TOML).unwrap(); (c, m) }
fn run_cli_generate(c: &Path, m: &Path, o: &Path) {
    let e = o.join("e.d"); fs::create_dir_all(&e).unwrap();
    let st = Command::new(cargo_bin("nfs-klldap-config")).args(["generate","--config"]).arg(c).env("NFS_KLLDAP_MOUNTINFO_PATH", m).env("NFS_KLLDAP_SKIP_ID_RESOLUTION_CHECK","1").env("EXPORTS_DIR",&e).env("GANESHA_CONF",o.join("g")).env("SSSD_CONF",o.join("s")).env("KRB5_CONF",o.join("k")).env("IDMAP_CONF",o.join("i")).env("NFS_CONF",o.join("n")).status().expect("cli");
    assert!(st.success());
}
fn read_single_fragment(ed: &Path) -> String { fs::read_dir(ed).unwrap().map(|e|e.unwrap().path()).find(|p|p.extension().map_or(false,|x|x=="conf")).map(|p|fs::read_to_string(p).unwrap()).unwrap() }

#[test]
fn cli_generate_limited_btrfs_twice_is_identical() {
    let f = tempfile::tempdir().unwrap(); let (c, mi) = write_fixture(f.path());
    let o1 = tempfile::tempdir().unwrap(); let o2 = tempfile::tempdir().unwrap();
    run_cli_generate(&c, &mi, o1.path()); run_cli_generate(&c, &mi, o2.path());
    let f1 = read_single_fragment(&o1.path().join("e.d")); let f2 = read_single_fragment(&o2.path().join("e.d"));
    assert_eq!(f1, f2);
    assert!(f1.contains("Disable_ACL = true;") && f1.contains("Manage_Gids = true;") && f1.contains("Path = /export/users;") && f1.contains("Pseudo = /users;") && f1.contains("Read_Access_Check_Policy = pre;"));
    assert!(!f1.contains("post;") && !f1.contains("POSIX_ONLY") && !f1.contains("Enable_NLM"));
    assert!(f1.contains("ACL-dependent NFSv4 ops disabled for compatibility"));
    assert!(!ganesha_96_has_mode_only_access_knob());
}

/// Gating: binary generate twice on noacl; capture for verif.
#[test]
fn cli_generate_gate_noacl_binary_twice_pseudo_in_scratch() {
    let sc = std::env::var("NFS_KLLDAP_CAPTURE_SCRATCH").map(PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
    let _ = fs::create_dir_all(&sc);
    let ed = sc.join("noacl-e.d"); let _=fs::remove_dir_all(&ed); fs::create_dir_all(&ed).unwrap();
    let mi = sc.join("mi.txt"); fs::write(&mi, MOUNTINFO_BTRFS_NOACL).unwrap();
    let cp = sc.join("c.toml"); fs::write(&cp, LIMITED_TOML).unwrap();
    let mut rf: Option<String> = None;
    for _r in 1..=2 {
        let st = Command::new(cargo_bin("nfs-klldap-config")).args(["generate","--config"]).arg(&cp).env("NFS_KLLDAP_MOUNTINFO_PATH",&mi).env("NFS_KLLDAP_SKIP_ID_RESOLUTION_CHECK","1").env("EXPORTS_DIR",&ed).env("GANESHA_CONF",sc.join("g")).env("SSSD_CONF",sc.join("s")).env("KRB5_CONF",sc.join("k")).env("IDMAP_CONF",sc.join("i")).env("NFS_CONF",sc.join("n")).status().expect("bin");
        assert!(st.success());
        let f = read_single_fragment(&ed);
        if let Some(p) = &rf { assert_eq!(p, &f); } rf = Some(f);
    }
    let ct = rf.unwrap();
    let _ = fs::write(sc.join("noacl-frag.conf"), &ct);
    assert!(ct.contains("Path = /export/users;") && ct.contains("Disable_ACL = true;") && ct.contains("Pseudo = /users;") && ct.contains("Read_Access_Check_Policy = pre;"));
}

/// Gating verif: binary mixed ACL+NOACL twice; capture.
#[test]
fn cli_generate_gate_mixed_acl_noacl_twice_in_scratch() {
    let sc = std::env::var("NFS_KLLDAP_CAPTURE_SCRATCH").map(PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
    let _ = fs::create_dir_all(&sc); let ed = sc.join("mix-e.d"); let _=fs::remove_dir_all(&ed); fs::create_dir_all(&ed).unwrap();
    let mt = r#"ldap_uri = "ldaps://kllap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "s"
[ganesha]
default_security = "krb5"
[[shares]]
name = "movies-acl"
host_path = "/media/movies"
container_path = "/export/movies"
enable_acl = true
manage_gids = true
[[shares]]
name = "docs-noacl"
host_path = "/media/docs"
container_path = "/export/docs"
enable_acl = false
manage_gids = true
read_access_policy = "pre"
"#;
    let cp = sc.join("acl-test2.toml"); fs::write(&cp, mt).unwrap();
    let mut rf: Option<String> = None;
    for _r in 1..=2 {
        let st = Command::new(cargo_bin("nfs-klldap-config")).args(["generate","--config"]).arg(&cp).env("NFS_KLLDAP_SKIP_ID_RESOLUTION_CHECK","1").env("EXPORTS_DIR",&ed).env("GANESHA_CONF",sc.join("gm")).env("SSSD_CONF",sc.join("sm")).env("KRB5_CONF",sc.join("km")).env("IDMAP_CONF",sc.join("im")).env("NFS_CONF",sc.join("nm")).status().expect("mix");
        assert!(st.success());
        let fs: Vec<_> = fs::read_dir(&ed).unwrap().filter_map(|e|e.ok()).filter(|e|e.path().extension().map_or(false,|x|x=="conf")).map(|e|fs::read_to_string(e.path()).unwrap()).collect();
        let cmb = fs.join("\n---\n");
        if let Some(p)=&rf { assert_eq!(p,&cmb); } rf=Some(cmb);
    }
    let ct = rf.unwrap(); let _ = fs::write(sc.join("mixed-acl-frag.conf"), &ct);
    assert!(!ct.contains("Disable_ACL = true;") || ct.matches("Disable_ACL = true;").count() < 2 );
    assert!(ct.contains("Disable_ACL = true;") && ct.contains("Read_Access_Check_Policy = pre;"));
    assert!(ct.contains("Pseudo = /movies-acl;") || ct.contains("Pseudo = /docs-noacl;"));
}