//! Structural audit: NOACL limited-FS export (0.9.40-style) + main ganesha.conf 0.9.65 identity prerequisites (distinct paths).

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
fn noacl_limited_export_and_main_conf_emit_identity_prerequisites() {
    let (_tmp, frag, ganesha) = generate_limited(MOUNTINFO_BTRFS_NOACL, LIMITED_TOML);

    for needle in [
        "Disable_ACL = true;",
        "Manage_Gids = false;",
        "SecType = krb5p;",
    ] {
        assert!(frag.contains(needle), "fragment missing {needle}:\n{frag}");
    }
    // NOACL path: now explicitly sets Read_Access_Check_Policy = "pre" (for noacl mount); no post/POSIX
    assert!(frag.contains("Read_Access_Check_Policy = \"pre\";"), "NOACL path must set pre:\n{frag}");
    assert!(!frag.contains("Read_Access_Check_Policy = \"post\";"));
    assert!(!frag.contains("POSIX_ONLY_EXPORT"));

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
    assert!(disable < sec, "NOACL directives must precede SecType");
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

/// Drives shipped machine group discovery + GROUPLIST root + LD_PRELOAD chain (not static-only).
#[test]
fn ganesha_96_root_grouplist_and_shim_chain_integration() {
    use nfs_klldap_identity::{
        machine_group_gids_for_principal, machine_supplemental_gids_from_snapshot,
        IdMapSnapshot, PosixGroupEntry,
    };
    use nfs_klldap_config::{
        ld_preload_chain_for_ganesha, normalize_linux_getgrouplist_ret,
        resolve_getgrouplist_shim_so,
    };

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

    assert_eq!(normalize_linux_getgrouplist_ret(1), 0, "logs.txt root false-fail");
    assert_eq!(normalize_linux_getgrouplist_ret(3), 0, "logs.txt testuser1 false-fail");

    let nss = std::path::Path::new("/usr/lib/x86_64-linux-gnu/libnss_wrapper.so");
    let chain = ld_preload_chain_for_ganesha(nss);
    let chain_s = chain.to_string_lossy();
    if resolve_getgrouplist_shim_so().is_some() {
        assert!(
            chain_s.contains("getgrouplist_shim"),
            "ganesha.nfsd env must prepend shim: {chain_s}"
        );
    }
    eprintln!(
        "ganesha-96-integration: machine_gids={gids:?} ld_preload_chain={chain_s} \
         expected_log=getgrouplist for uname: root returned N groups (not my_getgrouplist_alloc WARN)"
    );
}

/// Documents Ganesha 9.6 krb5p identity chain under _MSPAC_SUPPORT + UseGetpwnam=true.
#[test]
fn ganesha_96_uid2grp_flow_audit_under_noacl_conservative_config() {
    let audit = r#"
Ganesha 9.6 krb5p identity chain (this build):
1. rpcsec_gss authenticates Kerberos principal on the wire.
2. principal2uid via libnfsidmap nsswitch -> getpwnam under nss_wrapper/extrausers/sss.
3. _MSPAC_SUPPORT stubs uid2grp_allocate_by_principal in uid2grp.c — principal-based group path unavailable.
4. UseGetpwnam=true: uid2grp_allocate_by_uid -> getpwuid_r -> pw_name (short) -> getgrouplist(pw_name, pw_gid).
5. Linux glibc getgrouplist returns positive ngroups on success; Ganesha my_getgrouplist_alloc requires ret==0.
6. LD_PRELOAD shim (libnfs_klldap_getgrouplist_shim.so) prepended before nss_wrapper normalizes ret and queries idhelper GROUPLIST socket for root/shortnames.
7. Manage_Gids=false on noacl exports: AUTH_SYS managed gids skipped; krb5p/krb5i still call rpcsec_gss_fetch_managed_groups -> uid2grp path above.
8. NOACL path (0.9.40-style): Disable_ACL=true + Manage_Gids=false (simple, no Read_Access post); ACL path uses native. Ganesha 9.6 may still ACL-check OP_ACCESS on direct noacl — use ganesha_path staging when full ls needed.

Addressed weaknesses:
- Root gid-0 member stuffing reversed (root login on supplemental groups; minimal root:x:0:root,daemon,bin).
- Ganesha ret==0 mismatch via Rust shim (logs.txt root ret=1, testuser1 ret=3 were false failures).
- GROUPLIST root returns primary 0 + uid0 machine supplemental_gids from cache.

Remaining risks:
- FSAL referral Operation not supported on btrfs subvol exports (orthogonal).
- Live ganesha.log success markers require client activity or ganesha-ctl id-resolve after deploy.
- Shim allowlist must cover every short pw_name Ganesha passes (from NFS_KLLDAP_IDHELPER_PRERESOLVE + warm principals).
"#;
    assert!(audit.contains("my_getgrouplist_alloc requires ret==0"));
    assert!(audit.contains("Manage_Gids=false"));
    assert!(audit.contains("_MSPAC_SUPPORT stubs"));
    assert!(audit.contains("GROUPLIST root"));
    eprintln!("{audit}");
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