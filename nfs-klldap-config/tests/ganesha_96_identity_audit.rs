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

// ---- Plan 1.4 configuration hardening: declared-not-inherited main conf ----

#[test]
fn main_conf_hardened_defaults_for_identity_and_runtime() {
    let (_tmp, _frag, ganesha) = generate_limited(MOUNTINFO_BTRFS_NOACL, LIMITED_TOML);
    // Root privilege restricted: machine host/ keytabs must not be root (1.4).
    assert!(
        ganesha.contains("Root_Kerberos_Principal = nfs, root;"),
        "hardened default must exclude `host`:\n{ganesha}"
    );
    // Group-trust window rides DS Idmapped_* on 9.13; the old core param
    // would only draw a startup warning and must not be emitted.
    assert!(!ganesha.contains("Manage_Gids_Expiration"), "{ganesha}");
    assert!(ganesha.contains("Idmapped_User_Time_Validity = 180;"), "{ganesha}");
    assert!(ganesha.contains("Idmapped_Group_Time_Validity = 180;"), "{ganesha}");
    assert!(ganesha.contains("Max_Uid_To_Group_Reqs = 64;"), "{ganesha}");
    assert!(ganesha.contains("Negative_Cache_Time_Validity = 60;"), "{ganesha}");
    // Reclaim correctness: grace covers the lease (9.13 warns on 45/60).
    assert!(ganesha.contains("Lease_Lifetime = 60;"), "{ganesha}");
    assert!(ganesha.contains("Grace_Period = 90;"), "{ganesha}");
    // Runtime/perf shaping: no ESXi getattr, malloc trim on, readdir declared.
    assert!(ganesha.contains("Getattrs_In_Complete_Read = false;"), "{ganesha}");
    assert!(ganesha.contains("Enable_malloc_trim = true;"), "{ganesha}");
    assert!(ganesha.contains("Malloc_trim_MinThreshold = 1024;"), "{ganesha}");
    assert!(ganesha.contains("Readdir_Res_Size = 32768;"), "{ganesha}");
    assert!(
        !ganesha.contains("Readdir_Max_Count"),
        "Readdir_Max_Count emitted only when configured:\n{ganesha}"
    );
    // Recovery state contract: fs backend at the volume-backed path.
    assert!(ganesha.contains("RecoveryBackend = fs;"), "{ganesha}");
    assert!(ganesha.contains("RecoveryRoot = /var/lib/nfs/ganesha;"), "{ganesha}");
}

#[test]
fn ganesha_tuning_overrides_and_share_seeded_manage_gids_window() {
    let toml = format!(
        "{LIMITED_TOML}\n[ganesha]\nroot_kerberos_principals = \"root\"\n\
         manage_gids_expiration_secs = 900\nnegative_cache_validity_secs = 120\n\
         max_uid_to_group_reqs = 16\nreaddir_res_size = 65536\nreaddir_max_count = 16384\n\
         getattrs_in_complete_read = true\nmalloc_trim = false\n"
    );
    let (_tmp, _frag, ganesha) = generate_limited(MOUNTINFO_BTRFS_NOACL, &toml);
    assert!(ganesha.contains("Root_Kerberos_Principal = root;"), "{ganesha}");
    // manage_gids_expiration_secs feeds the DS idmapped validity (9.13).
    assert!(ganesha.contains("Idmapped_User_Time_Validity = 900;"), "{ganesha}");
    assert!(ganesha.contains("Idmapped_Group_Time_Validity = 900;"), "{ganesha}");
    assert!(ganesha.contains("Negative_Cache_Time_Validity = 120;"), "{ganesha}");
    assert!(ganesha.contains("Max_Uid_To_Group_Reqs = 16;"), "{ganesha}");
    assert!(ganesha.contains("Readdir_Res_Size = 65536;"), "{ganesha}");
    assert!(ganesha.contains("Readdir_Max_Count = 16384;"), "{ganesha}");
    assert!(ganesha.contains("Getattrs_In_Complete_Read = true;"), "{ganesha}");
    assert!(ganesha.contains("Enable_malloc_trim = false;"), "{ganesha}");

    // Explicit idmapped_validity_secs wins over the manage-gids knob.
    let toml = format!(
        "{LIMITED_TOML}\n[ganesha]\nidmapped_validity_secs = 1200\n\
         manage_gids_expiration_secs = 900\n"
    );
    let (_tmp, _frag, ganesha) = generate_limited(MOUNTINFO_BTRFS_NOACL, &toml);
    assert!(ganesha.contains("Idmapped_User_Time_Validity = 1200;"), "{ganesha}");

    // Deprecated share-level manage_gids_expiration seeds the global (min wins)
    // when [ganesha] manage_gids_expiration_secs is unset.
    let toml = LIMITED_TOML.replace(
        "security = \"krb5p\"",
        "security = \"krb5p\"\nmanage_gids_expiration = 450",
    );
    let (_tmp, frag, ganesha) = generate_limited(MOUNTINFO_BTRFS_NOACL, &toml);
    assert!(ganesha.contains("Idmapped_Group_Time_Validity = 450;"), "{ganesha}");
    assert!(!ganesha.contains("Manage_Gids_Expiration"), "{ganesha}");
    assert!(
        !frag.contains("Manage_Gids_Expiration"),
        "must never land in EXPORT (unknown export param):\n{frag}"
    );
}

#[test]
fn root_kerberos_principals_invalid_token_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let cp = tmp.path().join("c");
    fs::write(
        &cp,
        format!("{LIMITED_TOML}\n[ganesha]\nroot_kerberos_principals = \"nfs, machine\"\n"),
    )
    .unwrap();
    let err = NfsKlldapConfig::load(&cp).expect_err("invalid token must fail validation");
    let msg = err.to_string();
    assert!(
        msg.contains("machine") && msg.contains("none, nfs, root, host, all"),
        "unexpected error: {msg}"
    );
}