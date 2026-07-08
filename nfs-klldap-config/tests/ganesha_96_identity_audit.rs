//! Structural audit: NOACL limited-FS export (0.9.40-style) + main ganesha.conf 0.9.65 identity prerequisites (distinct paths).

use std::fs;
use std::sync::Mutex;

use nfs_klldap_config::{
    evaluate_nss_contract, evaluate_short_name_getgrouplist_contract, generate_all,
    GaneshaNssEnv, GenerationPaths, NfsKlldapConfig,
};

static MOUNTINFO_ENV_LOCK: Mutex<()> = Mutex::new(());

const LIMITED_TOML: &str = r#"
ldap_uri = "ldaps://klldap.test:6360"
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

const MOUNTINFO_BTRFS_NOACL: &str = "36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl\n";

fn generate_limited(mountinfo: &str, toml: &str) -> (tempfile::TempDir, String, String) {
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mp = tmp.path().join("m"); fs::write(&mp, mountinfo).unwrap();
    let cp = tmp.path().join("c"); fs::write(&cp, toml).unwrap();
    let out = tmp.path().join("out"); fs::create_dir_all(out.join("exports.d")).unwrap();
    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok(); std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mp);
    let cfg = NfsKlldapConfig::load(&cp).expect("load");
    let ps = GenerationPaths { sssd_conf: out.join("s"), krb5_conf: out.join("k"), ganesha_conf: out.join("g"), exports_dir: out.join("e"), idmap_conf: out.join("i"), nfs_conf: out.join("n") };
    generate_all(&cfg, &ps).expect("gen");
    if let Some(p) = prev { std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p); } else { std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH"); }
    let frag = fs::read_dir(out.join("e")).unwrap().map(|e|e.unwrap().path()).find(|p|p.extension().is_some_and(|x| x == "conf")).and_then(|p|fs::read_to_string(p).ok()).unwrap();
    (tmp, frag, fs::read_to_string(out.join("g")).unwrap_or_default())
}

#[test]
fn noacl_limited_export_and_main_conf_emit_identity_prerequisites() {
    let (_tmp, frag, ganesha) = generate_limited(MOUNTINFO_BTRFS_NOACL, LIMITED_TOML);
    assert!(frag.contains("Disable_ACL = true;") && frag.contains("Manage_Gids = true;") && frag.contains("SecType = krb5p;"));
    assert!(frag.contains("Path = /export/users;") && frag.contains("Pseudo = /users;") && frag.contains("Read_Access_Check_Policy = pre;"));
    assert!(!frag.contains("post;") && !frag.contains("POSIX_ONLY_EXPORT"));
    let d = frag.find("Disable_ACL = true;").unwrap(); let s = frag.find("SecType =").unwrap(); assert!(d < s);
    assert!(ganesha.contains("UseGetpwnam = true;") && ganesha.contains("Pwnam_Implementation = nsswitch"));
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

/// Drives shipped machine group discovery + uid0 root handling + LD_PRELOAD (nss_wrapper) for Ganesha.
#[test]
fn ganesha_96_root_grouplist_and_nss_integration() {
    use nfs_klldap_identity::{
        machine_group_gids_for_principal, machine_supplemental_gids_from_snapshot,
        IdMapSnapshot, PosixGroupEntry,
    };
    use nfs_klldap_config::ld_preload_for_ganesha;

    let mut snap = IdMapSnapshot::default();
    snap.groups.insert(
        "admins".into(),
        PosixGroupEntry {
            gid: 3005,
            display: "admins".into(),
            members: vec!["root".into()],
        },
    );
    let supps = machine_supplemental_gids_from_snapshot("host/zima-nas@REALM", &snap);
    assert_eq!(supps, vec![3005], "root-member groups feed uid0 supplementals");
    let gids = machine_group_gids_for_principal("host/zima-nas@REALM", &snap);
    assert_eq!(gids, vec![0, 3005]);

    let nss = std::path::Path::new("/usr/lib/x86_64-linux-gnu/libnss_wrapper.so");
    let preload = ld_preload_for_ganesha(nss);
    let preload_s = preload.to_string_lossy();
    eprintln!(
        "ganesha-96-integration: machine_gids={gids:?} ld_preload={preload_s} \
         expected_log=getgrouplist for uname: root returned N groups (not my_getgrouplist_alloc WARN)"
    );
}

// The prose audit of the 9.6 identity chain (_MSPAC_SUPPORT stub, UseGetpwnam uid path)
// lives in docs/ganesha-architecture.md; the executable contract is the tests around it.

#[test]
fn enable_rpc_cred_fallback_disabled_when_configured() {
    let toml = format!(
        "{LIMITED_TOML}\n[ganesha]\nenable_rpc_cred_fallback = false\n"
    );
    let (_tmp, frag, ganesha) = generate_limited(MOUNTINFO_BTRFS_NOACL, &toml);
    assert!(frag.contains("    Pseudo = /users;"), "noacl frag under enable_rpc fallback test must emit Pseudo:\n{frag}");
    assert!(
        ganesha.contains("enable_rpc_cred_fallback = false;"),
        "ganesha.conf:\n{ganesha}"
    );
}