//! Drives generate_all with btrfs+noacl mountinfo fixtures (determinism, not CLI gate).

use std::fs;
use std::sync::Mutex;

use nfs_klldap_config::{
    classify_principal, collect_fs_warnings, compute_effective_flags, generate_all, GenerationPaths, FsCapabilities, NfsKlldapConfig,
};
use nfs_klldap_identity::nfs_keytab_host_variants;

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

const MOUNTINFO_BTRFS_NOACL: &str = r#"
36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl
"#;

const MOUNTINFO_EXT4: &str = r#"
37 36 0:60 / /export/movies rw,relatime - ext4 /dev/sdb1 rw
"#;

const NOACL_MANAGE_FALSE_TOML: &str = r#"
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
enable_acl = false
manage_gids = false
"#;

fn generation_paths(out: &std::path::Path) -> GenerationPaths {
    GenerationPaths { sssd_conf: out.join("sssd.conf"), krb5_conf: out.join("krb5.conf"), ganesha_conf: out.join("ganesha.conf"), exports_dir: out.join("exports.d"), idmap_conf: out.join("idmapd.conf"), nfs_conf: out.join("nfs.conf"), avahi_services_dir: out.join("avahi-services") }
}
fn read_single_fragment(ed: &std::path::Path) -> String {
    fs::read_dir(ed).unwrap().map(|e| e.unwrap().path()).find(|p| p.extension().is_some_and(|e| e == "conf")).map(|p| fs::read_to_string(p).unwrap()).unwrap()
}
fn generate_with_mountinfo(mountinfo: &str, toml: &str) -> (tempfile::TempDir, String, String) {
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap(); let mi = tmp.path().join("mi"); fs::write(&mi, mountinfo).unwrap();
    let cp = tmp.path().join("c.toml"); fs::write(&cp, toml).unwrap();
    let out = tmp.path().join("out"); fs::create_dir_all(out.join("exports.d")).unwrap();
    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok(); std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mi);
    let cfg = NfsKlldapConfig::load(&cp).expect("load");
    generate_all(&cfg, &generation_paths(&out)).expect("gen");
    if let Some(p) = prev { std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p); } else { std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH"); }
    let frag = read_single_fragment(&out.join("exports.d")); let g = fs::read_to_string(out.join("ganesha.conf")).unwrap_or_default(); (tmp, frag, g)
}

#[test]
fn generate_all_limited_btrfs_emits_safe_export_flags() {
    let (_tmp, frag, ganesha) = generate_with_mountinfo(MOUNTINFO_BTRFS_NOACL, LIMITED_TOML);

    assert!(frag.contains("Disable_ACL = true;"), "fragment:\n{frag}");
    assert!(frag.contains("Manage_Gids = true;"), "fragment:\n{frag}");
    // Default squash is root_squash (0.9.81): a share with no explicit squash
    // must never ship no_root_squash — the 2026-07-11 stress test proved a
    // machine keytab could write to a no_root_squash export.
    assert!(frag.contains("Squash = root_squash;"), "default must be root_squash:\n{frag}");
    assert!(!frag.contains("no_root_squash"), "unset squash must not emit no_root_squash:\n{frag}");
    assert!(frag.contains("Path = /export/users;"), "noacl must still contain Path for location by ganesha-ctl etc:\n{frag}");
    assert!(frag.contains("    Pseudo = /users;"), "noacl must emit 0.9.40-style Pseudo line:\n{frag}");
    let disable_pos = frag.find("Disable_ACL = true;").expect("Disable_ACL");
    let sec_pos = frag.find("SecType =").expect("SecType");
    assert!(
        disable_pos < sec_pos,
        "NOACL directives must precede SecType:\n{frag}"
    );
    // NOACL path uses 0.9.40 simple settings + Read_Access_Check_Policy = pre (explicit for noacl mounts)
    assert!(frag.contains("Read_Access_Check_Policy = pre;"), "NOACL must emit pre policy:\n{frag}");
    assert!(!frag.contains("Read_Access_Check_Policy = post;"), "NOACL must not emit post:\n{frag}");
    assert!(!frag.contains("POSIX_ONLY_EXPORT"), "no legacy posix marker in 0.9.40-style:\n{frag}");
    assert!(!frag.contains("Enable_NLM"), "NOACL omits per-export Enable_NLM:\n{frag}");
    assert!(!frag.contains("Enable_RQUOTA"), "NOACL omits per-export Enable_RQUOTA:\n{frag}");
    assert!(frag.contains("cannot store POSIX ACLs"), "limited-FS auto comment:\n{frag}");
    if let Ok(scratch) = std::env::var("NFS_KLLDAP_CAPTURE_SCRATCH") {
        let dest = std::path::PathBuf::from(scratch).join("10-users-limited.conf");
        let _ = fs::write(&dest, &frag);
    }
    for forbidden in [
        // Superseded on 9.13 by DS Idmapped_*; must appear nowhere.
        "Manage_Gids_Expiration =",
        "IdmapConf =",
    ] {
        assert!(!frag.contains(forbidden), "forbidden {forbidden} in fragment");
    }
    assert!(!ganesha.contains("IdmapConf ="), "forbidden IdmapConf in ganesha.conf");
    // Group-trust window rides the DS idmapped validity (9.13 routing).
    assert!(!ganesha.contains("Manage_Gids_Expiration"));
    assert!(ganesha.contains("Idmapped_Group_Time_Validity = 180;"));
    // Hardened default excludes host/ so machine keytabs are never root.
    assert!(ganesha.contains("Root_Kerberos_Principal = nfs, root;"));
    assert!(ganesha.contains("Pwnam_Implementation = nsswitch"));

    let variants = nfs_keytab_host_variants("nfs-server.example.com");
    let (m_host, _) = classify_principal("host/client.test@TEST", "TEST", &variants);
    let (m_nfs, _) = classify_principal("nfs/client@TEST", "TEST", &variants);
    let (u_alice, _) = classify_principal("alice@TEST", "TEST", &variants);
    assert!(m_host && m_nfs && !u_alice, "hybrid classify must hold on limited share");
}

#[test]
fn generate_all_capable_ext4_omits_limited_flags() {
    // ACL is opt-in: an ACL-capable ext4 share that explicitly enables ACL takes the ACL
    // path (no Disable_ACL, no auto-detect comment).
    let ext4_toml = r#"
ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "movies"
host_path = "/media/movies"
container_path = "/export/movies"
enable_acl = true
"#;
    let (_tmp, frag, _) = generate_with_mountinfo(MOUNTINFO_EXT4, ext4_toml);
    assert!(!frag.contains("Disable_ACL = true;"), "capable ext4 + enable_acl omits Disable_ACL");
    assert!(frag.contains("Manage_Gids = true;"));
    assert!(frag.contains("Path = /export/movies;"), "acl capable must contain Path:\n{frag}");
    assert!(frag.contains("    Pseudo = /movies;"), "acl capable (auto) must include the Pseudo line:\n{frag}");
    assert!(!frag.contains("Pseudo = /users;"), "wrong share name in pseudo");
    assert!(!frag.contains("Auto-detected:"));
}

#[test]
fn generate_all_noacl_with_explicit_manage_gids_false_override() {
    let (_tmp, frag, _g) = generate_with_mountinfo(MOUNTINFO_BTRFS_NOACL, NOACL_MANAGE_FALSE_TOML);
    assert!(frag.contains("Disable_ACL = true;") && frag.contains("Manage_Gids = false;") && !frag.contains("Manage_Gids = true;"));
    assert!(frag.contains("Pseudo = /users;") && frag.contains("Read_Access_Check_Policy = pre;") && !frag.contains("post;"));
    // direct eff + warnings still cover explicit override on NOACL
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let t2 = tempfile::tempdir().unwrap();
    let mi = t2.path().join("mi"); fs::write(&mi, MOUNTINFO_BTRFS_NOACL).unwrap();
    let cp = t2.path().join("c.toml"); fs::write(&cp, NOACL_MANAGE_FALSE_TOML).unwrap();
    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok(); std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mi);
    let cfg = NfsKlldapConfig::load(&cp).unwrap();
    let caps = FsCapabilities { fstype: "btrfs".into(), mount_options: vec!["noacl".into()], acl_capable: false };
    let eff = compute_effective_flags(&cfg.shares[0], &caps);
    assert!(!eff.enable_acl && !eff.manage_gids);
    let out = t2.path().join("o"); fs::create_dir_all(out.join("e.d")).unwrap();
    let ps = GenerationPaths { sssd_conf: out.join("s"), krb5_conf: out.join("k"), ganesha_conf: out.join("g"), exports_dir: out.join("e.d"), idmap_conf: out.join("i"), nfs_conf: out.join("n"), avahi_services_dir: out.join("av") };
    generate_all(&cfg, &ps).unwrap();
    let gf = fs::read_dir(&ps.exports_dir).unwrap().filter_map(|e| e.ok()).find(|e| e.path().extension().is_some_and(|x| x == "conf")).map(|e| fs::read_to_string(e.path()).unwrap()).unwrap_or_default();
    assert!(gf.contains("Manage_Gids = false;"));
    let ws: Vec<_> = collect_fs_warnings(&cfg).into_iter().filter(|w| !w.acl_capable).collect();
    let w = ws.iter().find(|ww| ww.share_name == "users").unwrap();
    assert!(!w.effective_manage_gids && (w.message.contains("manage_gids=false") || w.message.contains("NOACL")));
    if let Some(p) = prev { std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p); } else { std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH"); }
}

#[test]
fn generate_all_limited_btrfs_twice_is_deterministic() {
    let (_a, frag1, _) = generate_with_mountinfo(MOUNTINFO_BTRFS_NOACL, LIMITED_TOML);
    let (_b, frag2, _) = generate_with_mountinfo(MOUNTINFO_BTRFS_NOACL, LIMITED_TOML);
    assert_eq!(frag1, frag2, "NOACL export block must be identical across runs");
    for frag in [&frag1, &frag2] {
        assert!(frag.contains("Disable_ACL = true;"));
        assert!(frag.contains("Manage_Gids = true;"));
        assert!(frag.contains("Path = /export/users;"), "Path must be present even on noacl");
        assert!(frag.contains("    Pseudo = /users;"), "noacl must emit Pseudo line in both runs");
        assert!(frag.contains("Read_Access_Check_Policy = pre;"), "NOACL must set pre");
        assert!(!frag.contains("Read_Access_Check_Policy = post;"));
        assert!(!frag.contains("POSIX_ONLY_EXPORT"));
        let disable = frag.find("Disable_ACL = true;").unwrap();
        let sec = frag.find("SecType =").unwrap();
        assert!(disable < sec);
    }
}
/// WI-2 hard-fail policy: an opted-in ACL share on a filesystem that cannot
/// store POSIX ACLs must refuse to generate (no fail-open), naming the
/// staging pattern as the escape. On the 9.13 VFS backend such an export
/// would break client attribute fetches, not merely ACL ops.
#[test]
fn generate_all_refuses_enable_acl_on_incapable_fs() {
    const ACL_ON_VFAT_TOML: &str = r#"
ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "usb"
host_path = "/media/usb"
container_path = "/export/usb"
enable_acl = true
"#;
    const MOUNTINFO_VFAT: &str = r#"
36 35 0:59 / /export rw,relatime - vfat /dev/sdd1 rw,fmask=0022,dmask=0022
"#;
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mi = tmp.path().join("mi");
    fs::write(&mi, MOUNTINFO_VFAT).unwrap();
    let cp = tmp.path().join("c.toml");
    fs::write(&cp, ACL_ON_VFAT_TOML).unwrap();
    let out = tmp.path().join("out");
    fs::create_dir_all(out.join("exports.d")).unwrap();
    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
    std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mi);
    let cfg = NfsKlldapConfig::load(&cp).expect("load");
    let result = generate_all(&cfg, &generation_paths(&out));
    if let Some(p) = prev {
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p);
    } else {
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
    }
    let err = result.expect_err("enable_acl on vfat must refuse to generate");
    let msg = err.to_string();
    assert!(msg.contains("cannot store POSIX ACLs"), "error names the cause: {msg}");
    assert!(msg.contains("source_path"), "error names the staging escape: {msg}");
    assert!(msg.contains("enable_acl = false"), "error names the opt-out: {msg}");
}

/// The hard-fail must leave exports.d UNTOUCHED: every share validates before
/// any fragment is written. The old mid-loop abort rewrote earlier shares,
/// skipped later ones, and skipped the prune — the next reload served that
/// mixture.
#[test]
fn generate_hard_fail_leaves_exports_dir_untouched() {
    const TWO_SHARE_TOML: &str = r#"
ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "ok1"
host_path = "/media/ok1"
container_path = "/export/ok1"
[[shares]]
name = "usb"
host_path = "/media/usb"
container_path = "/export/usb"
enable_acl = true
"#;
    const MOUNTINFO_VFAT: &str = r#"
36 35 0:59 / /export rw,relatime - vfat /dev/sdd1 rw,fmask=0022,dmask=0022
"#;
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mi = tmp.path().join("mi");
    fs::write(&mi, MOUNTINFO_VFAT).unwrap();
    let cp = tmp.path().join("c.toml");
    fs::write(&cp, TWO_SHARE_TOML).unwrap();
    let out = tmp.path().join("out");
    fs::create_dir_all(out.join("exports.d")).unwrap();
    // Stale fragment from an earlier generation: prune runs only after a
    // fully-validated write pass, so a failed run must not remove it either.
    fs::write(out.join("exports.d/99-stale.conf"), "EXPORT {}\n").unwrap();
    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
    std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mi);
    let cfg = NfsKlldapConfig::load(&cp).expect("load");
    let result = generate_all(&cfg, &generation_paths(&out));
    if let Some(p) = prev {
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p);
    } else {
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
    }
    result.expect_err("second share's enable_acl on vfat must refuse");
    let entries: Vec<String> = fs::read_dir(out.join("exports.d"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        entries,
        vec!["99-stale.conf".to_string()],
        "no fragment for the valid first share, stale fragment untouched"
    );
}

/// Auto ACL (0.9.90): an unset enable_acl share whose serve path passes the
/// write round-trip probe is promoted to the ACL path with an Auto-enabled
/// comment; the mountinfo fixture marks the tree capable and the tempdir
/// serve path provides the real proof.
#[test]
fn generate_all_auto_enables_acl_on_proven_serve_path() {
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let serve = tmp.path().join("export").join("auto");
    fs::create_dir_all(&serve).unwrap();
    let toml = format!(
        r#"
ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{root}"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "auto"
host_path = "/media/auto"
container_path = "{serve}"
"#,
        root = tmp.path().join("export").display(),
        serve = serve.display()
    );
    let mountinfo = format!("36 35 0:59 / {} rw,relatime - btrfs /dev/sda1 rw\n", tmp.path().display());
    let mi = tmp.path().join("mi");
    fs::write(&mi, mountinfo).unwrap();
    let cp = tmp.path().join("c.toml");
    fs::write(&cp, toml).unwrap();
    let out = tmp.path().join("out");
    fs::create_dir_all(out.join("exports.d")).unwrap();
    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
    std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mi);
    let cfg = NfsKlldapConfig::load(&cp).expect("load");
    let res = generate_all(&cfg, &generation_paths(&out));
    if let Some(p) = prev {
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p);
    } else {
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
    }
    res.expect("gen");
    let frag = read_single_fragment(&out.join("exports.d"));
    assert!(frag.contains("Disable_ACL = false;"), "auto must promote to ACL:\n{frag}");
    assert!(frag.contains("Auto-enabled"), "fragment names the auto promotion:\n{frag}");
    assert!(!frag.contains("Read_Access_Check_Policy = pre;"), "ACL path omits pre:\n{frag}");
}

/// WI-8 coherency knobs: EXPORT_DEFAULTS carries an explicit
/// Attr_Expiration_Time (deliberate default 60), and a per-share
/// attr_expiration_secs override lands inside that share's EXPORT block
/// (0 = attribute caching off for coherency-critical shares).
#[test]
fn generate_all_emits_attr_expiration_default_and_share_override() {
    let (_tmp, frag, ganesha) = generate_with_mountinfo(MOUNTINFO_BTRFS_NOACL, LIMITED_TOML);
    assert!(
        ganesha.contains("Attr_Expiration_Time = 60;"),
        "EXPORT_DEFAULTS must declare the 60s attribute-cache window:\n{ganesha}"
    );
    assert!(
        !frag.contains("Attr_Expiration_Time"),
        "no per-share line without an override:\n{frag}"
    );

    const OVERRIDE_TOML: &str = r#"
ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[ganesha]
attr_expiration_secs = 120
[[shares]]
name = "users"
host_path = "/media/users"
container_path = "/export/users"
attr_expiration_secs = 0
"#;
    let (_tmp2, frag2, ganesha2) = generate_with_mountinfo(MOUNTINFO_BTRFS_NOACL, OVERRIDE_TOML);
    assert!(
        ganesha2.contains("Attr_Expiration_Time = 120;"),
        "[ganesha] knob must drive EXPORT_DEFAULTS:\n{ganesha2}"
    );
    assert!(
        frag2.contains("    Attr_Expiration_Time = 0;"),
        "share override must land in the EXPORT block:\n{frag2}"
    );
}
