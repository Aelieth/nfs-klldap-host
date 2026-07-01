//! Structural audit contract: conservative limited-FS export + main ganesha.conf identity prerequisites.

use std::fs;
use std::sync::Mutex;

use nfs_klldap_config::{
    evaluate_nss_contract, evaluate_short_name_getgrouplist_contract, generate_all,
    GaneshaNssEnv, GenerationPaths, NfsKlldapConfig,
};

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

#[test]
fn mount_race_structural_empty_nss_fails_contract_seeded_passes() {
    let td = tempfile::tempdir().unwrap();
    let env_empty = GaneshaNssEnv::from_paths(
        &td.path().join("missing_passwd"),
        &td.path().join("missing_group"),
    );
    let (ok_empty, _) =
        evaluate_nss_contract("testuser1@TESTLAB.LOCAL", &env_empty, false);
    assert!(!ok_empty, "empty NSS must fail identity contract (mount-time race)");

    let pw = td.path().join("nss_passwd");
    let gr = td.path().join("nss_group");
    std::fs::write(
        &pw,
        "testuser1@TESTLAB.LOCAL:x:3001:3005:user:/non:/nologin\n",
    )
    .unwrap();
    std::fs::write(
        &gr,
        "root:x:0:\ntestuser1@TESTLAB.LOCAL:x:3005:\nstaff:x:3007:testuser1@TESTLAB.LOCAL\n",
    )
    .unwrap();
    let env_seeded = GaneshaNssEnv::from_paths(&pw, &gr);
    let (ok_seeded, msg) =
        evaluate_nss_contract("testuser1@TESTLAB.LOCAL", &env_seeded, false);
    if env_seeded.wrapper_available() {
        assert!(ok_seeded, "pre-seeded NSS must pass contract: {msg}");
    } else {
        let (file_ok, file_msg) =
            evaluate_nss_contract("testuser1@TESTLAB.LOCAL", &env_seeded, false);
        assert!(file_ok || file_msg.contains("file-ok"), "file-level contract: {file_msg}");
    }
}

#[test]
fn seeded_nss_short_pw_name_getgrouplist_contract_matches_uid2grp_path() {
    let td = tempfile::tempdir().unwrap();
    let pw = td.path().join("nss_passwd");
    let gr = td.path().join("nss_group");
    std::fs::write(
        &pw,
        "root:x:0:0:root:/root:/bin/sh\n\
         testuser1:x:3788:3002:user:/non:/nologin\n\
         testuser1@TESTLAB.LOCAL:x:3788:3002:user:/non:/nologin\n",
    )
    .unwrap();
    std::fs::write(
        &gr,
        "root:x:0:root,daemon,bin\n\
         staff:x:3002:testuser1,testuser1@TESTLAB.LOCAL\n\
         writers:x:3005:testuser1,testuser1@TESTLAB.LOCAL\n\
         aux:x:3007:testuser1,testuser1@TESTLAB.LOCAL\n",
    )
    .unwrap();
    let env = GaneshaNssEnv::from_paths(&pw, &gr);
    let (ok, msg) =
        evaluate_short_name_getgrouplist_contract("testuser1@TESTLAB.LOCAL", &env, 3);
    if env.wrapper_available() {
        assert!(ok, "short-name uid2grp contract: {msg}");
    } else {
        let (file_ok, file_msg) =
            evaluate_short_name_getgrouplist_contract("testuser1@TESTLAB.LOCAL", &env, 1);
        assert!(file_ok, "file-level short passwd row required: {file_msg}");
    }
}

#[test]
fn enable_rpc_cred_fallback_disabled_when_configured() {
    let toml = format!(
        "{LIMITED_TOML}\n[ganesha]\nenable_rpc_cred_fallback = false\n"
    );
    let (_tmp, _frag, ganesha) = generate_limited(MOUNTINFO_BTRFS_NOACL, &toml);
    assert!(
        ganesha.contains("enable_rpc_cred_fallback = false;"),
        "ganesha.conf:\n{ganesha}"
    );
}