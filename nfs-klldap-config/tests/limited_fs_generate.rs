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
    GenerationPaths { sssd_conf: out.join("sssd.conf"), krb5_conf: out.join("krb5.conf"), ganesha_conf: out.join("ganesha.conf"), exports_dir: out.join("exports.d"), idmap_conf: out.join("idmapd.conf"), nfs_conf: out.join("nfs.conf") }
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
    assert!(frag.contains("ACL-dependent NFSv4 ops disabled for compatibility"), "0.9.40-style comment:\n{frag}");
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
    assert!(ganesha.contains("Idmapped_Group_Time_Validity = 600;"));
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
    let ps = GenerationPaths { sssd_conf: out.join("s"), krb5_conf: out.join("k"), ganesha_conf: out.join("g"), exports_dir: out.join("e.d"), idmap_conf: out.join("i"), nfs_conf: out.join("n") };
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