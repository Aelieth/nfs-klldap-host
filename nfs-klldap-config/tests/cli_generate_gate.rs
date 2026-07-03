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
security = "krb5p"
"#;

const MOUNTINFO_BTRFS_NOACL: &str = r#"
36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl
"#;

fn cargo_bin(name: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/debug")
        .join(name)
}

fn write_fixture(dir: &Path) -> (PathBuf, PathBuf) {
    let mountinfo = dir.join("mountinfo");
    fs::write(&mountinfo, MOUNTINFO_BTRFS_NOACL).unwrap();
    let conf = dir.join("nfs-klldap.conf");
    fs::write(&conf, LIMITED_TOML).unwrap();
    (conf, mountinfo)
}

fn run_cli_generate(conf: &Path, mountinfo: &Path, out: &Path) {
    let exports = out.join("exports.d");
    fs::create_dir_all(&exports).unwrap();
    let status = Command::new(cargo_bin("nfs-klldap-config"))
        .args(["generate", "--config"])
        .arg(conf)
        .env("NFS_KLLDAP_MOUNTINFO_PATH", mountinfo)
        .env("NFS_KLLDAP_SKIP_ID_RESOLUTION_CHECK", "1")
        .env("EXPORTS_DIR", &exports)
        .env("GANESHA_CONF", out.join("ganesha.conf"))
        .env("SSSD_CONF", out.join("sssd.conf"))
        .env("KRB5_CONF", out.join("krb5.conf"))
        .env("IDMAP_CONF", out.join("idmapd.conf"))
        .env("NFS_CONF", out.join("nfs.conf"))
        .status()
        .expect("cli generate spawn");
    assert!(status.success(), "generate failed for {}", out.display());
}

fn read_single_fragment(exports_dir: &Path) -> String {
    let path = fs::read_dir(exports_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "conf"))
        .expect("export fragment");
    fs::read_to_string(path).unwrap()
}

#[test]
fn cli_generate_limited_btrfs_twice_is_identical() {
    let fixture = tempfile::tempdir().unwrap();
    let (conf, mountinfo) = write_fixture(fixture.path());
    let out1 = tempfile::tempdir().unwrap();
    let out2 = tempfile::tempdir().unwrap();
    run_cli_generate(&conf, &mountinfo, out1.path());
    run_cli_generate(&conf, &mountinfo, out2.path());
    let frag1 = read_single_fragment(&out1.path().join("exports.d"));
    let frag2 = read_single_fragment(&out2.path().join("exports.d"));
    assert_eq!(frag1, frag2, "CLI runs must emit identical fragments");
    assert!(frag1.contains("Disable_ACL = true;"));
    assert!(frag1.contains("Manage_Gids = false;"));
    assert!(frag1.contains("Path = /export/users;"), "cli noacl frag must contain Path:\n{frag1}");
    assert!(!frag1.contains("Pseudo = "), "cli noacl generate must omit Pseudo line (twice-identical run):\n{frag1}");
    // NOACL path: 0.9.40 simple + Read_Access_Check_Policy = pre for noacl mount
    assert!(frag1.contains("Read_Access_Check_Policy = pre;"));
    assert!(!frag1.contains("Read_Access_Check_Policy = post;"));
    assert!(!frag1.contains("POSIX_ONLY_EXPORT"));
    assert!(!frag1.contains("Enable_NLM"));
    assert!(frag1.contains("ACL-dependent NFSv4 ops disabled for compatibility"));
    assert!(!ganesha_96_has_mode_only_access_knob());
    if let Ok(scratch) = std::env::var("NFS_KLLDAP_CAPTURE_SCRATCH") {
        let scratch = PathBuf::from(scratch);
        let _ = fs::create_dir_all(&scratch);
        let _ = fs::write(scratch.join("cli-gen-out1.conf"), &frag1);
        let _ = fs::write(scratch.join("cli-gen-out2.conf"), &frag2);
    }
    eprintln!(
        "cli generate gate: identical fragments ({} bytes)",
        frag1.len()
    );
}

/// Gating verification: real binary (not lib) generate twice on noacl fixture.
/// Writes to {SCRATCH}/noacl-exports.d , captures to {SCRATCH}/noacl-frag.conf
/// Asserts Path+Disable present, "Pseudo = " entirely absent, and two runs identical.
#[test]
fn cli_generate_gate_noacl_binary_twice_no_pseudo_in_scratch() {
    let scratch = PathBuf::from("/tmp/grok-goal-e2cc476cb983/implementer");
    let _ = fs::create_dir_all(&scratch);
    let exports_d = scratch.join("noacl-exports.d");
    let _ = fs::remove_dir_all(&exports_d);
    fs::create_dir_all(&exports_d).unwrap();

    let mountinfo_path = scratch.join("gate-noacl-mountinfo.txt");
    fs::write(&mountinfo_path, MOUNTINFO_BTRFS_NOACL).unwrap();
    let conf_path = scratch.join("gate-noacl.toml");
    fs::write(&conf_path, LIMITED_TOML).unwrap();

    let mut run_frag: Option<String> = None;
    for run in 1..=2 {
        let status = Command::new(cargo_bin("nfs-klldap-config"))
            .args(["generate", "--config"])
            .arg(&conf_path)
            .env("NFS_KLLDAP_MOUNTINFO_PATH", &mountinfo_path)
            .env("NFS_KLLDAP_SKIP_ID_RESOLUTION_CHECK", "1")
            .env("EXPORTS_DIR", &exports_d)
            .env("GANESHA_CONF", scratch.join("g.conf"))
            .env("SSSD_CONF", scratch.join("s.conf"))
            .env("KRB5_CONF", scratch.join("k.conf"))
            .env("IDMAP_CONF", scratch.join("i.conf"))
            .env("NFS_CONF", scratch.join("n.conf"))
            .status()
            .expect("binary generate");
        assert!(status.success(), "binary generate run {} failed", run);

        let frag = read_single_fragment(&exports_d);
        if let Some(prev) = &run_frag {
            assert_eq!(prev, &frag, "two binary runs must produce identical noacl frag");
        }
        run_frag = Some(frag);
    }

    let content = run_frag.expect("frag captured");
    // Write captured as per verification plan to {SCRATCH}/noacl-frag.conf
    let captured = scratch.join("noacl-frag.conf");
    fs::write(&captured, &content).expect("write captured noacl frag");
    // Also a copy for run2 consistency proof
    let _ = fs::write(scratch.join("noacl-frag-run2.conf"), &content);

    assert!(content.contains("Path = /export/users;"), "must contain Path:\n{content}");
    assert!(content.contains("Disable_ACL = true;"), "must contain Disable:\n{content}");
    assert!(!content.contains("Pseudo = "), "must NOT contain Pseudo = (nor Pseudo=) on noacl binary gate:\n{content}");
    assert!(!content.contains("Pseudo="), "no Pseudo= substring allowed");
    // Also sanity: Read pre etc still there for syntax
    assert!(content.contains("Read_Access_Check_Policy = pre;"));
    assert!(content.contains("SecType = krb5p;"));
    eprintln!("GATE: real binary twice -> captured noacl-frag.conf ({} bytes) has no Pseudo, has Path+Disable", content.len());
}