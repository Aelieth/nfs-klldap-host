//! Structural audit contract: conservative limited-FS export + main ganesha.conf identity prerequisites.

use std::fs;
use std::sync::Mutex;

use nfs_klldap_config::{generate_all, GenerationPaths, NfsKlldapConfig};

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

const MOUNTINFO_BTRFS_NOACL: &str = "36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl\n";

fn generate_limited(
    mountinfo: &str,
    toml: &str,
) -> (tempfile::TempDir, String, String) {
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
    let paths = GenerationPaths {
        sssd_conf: out.join("sssd.conf"),
        krb5_conf: out.join("krb5.conf"),
        ganesha_conf: out.join("ganesha.conf"),
        exports_dir: out.join("exports.d"),
        idmap_conf: out.join("idmapd.conf"),
        nfs_conf: out.join("nfs.conf"),
    };
    generate_all(&cfg, &paths).expect("generate_all");

    if let Some(p) = prev {
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p);
    } else {
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
    }

    let frag = fs::read_dir(out.join("exports.d"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "conf"))
        .and_then(|p| fs::read_to_string(p).ok())
        .expect("fragment");
    let ganesha = fs::read_to_string(out.join("ganesha.conf")).unwrap();
    (tmp, frag, ganesha)
}

#[test]
fn conservative_limited_export_and_main_conf_emit_identity_prerequisites() {
    let (_tmp, frag, ganesha) = generate_limited(MOUNTINFO_BTRFS_NOACL, LIMITED_TOML);

    for needle in [
        "Disable_ACL = true;",
        "Manage_Gids = false;",
        r#"Read_Access_Check_Policy = "post";"#,
        "SecType = krb5p;",
        "POSIX_ONLY_EXPORT",
    ] {
        assert!(frag.contains(needle), "fragment missing {needle}:\n{frag}");
    }

    for needle in [
        "UseGetpwnam = true;",
        "Pwutils_Use_Fully_Qualified_Names = true;",
        "Only_Numeric_Owners = true;",
        "enable_rpc_cred_fallback = true;",
        "Pwnam_Implementation = nsswitch",
    ] {
        assert!(ganesha.contains(needle), "ganesha.conf missing {needle}:\n{ganesha}");
    }

    let disable = frag.find("Disable_ACL = true;").unwrap();
    let sec = frag.find("SecType =").unwrap();
    assert!(disable < sec, "posix directives must precede SecType");
}