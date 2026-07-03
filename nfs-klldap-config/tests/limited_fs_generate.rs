//! Drives generate_all with btrfs+noacl mountinfo fixtures (determinism, not CLI gate).

use std::fs;
use std::sync::Mutex;

use nfs_klldap_config::{
    classify_principal, collect_fs_warnings, compute_effective_flags, generate_all, GenerationPaths, limited_fs_warnings_only, probe_fs_capabilities, FsCapabilities, NfsKlldapConfig,
};
use nfs_klldap_identity::nfs_keytab_host_variants;

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

const MOUNTINFO_BTRFS_NOACL: &str = r#"
36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl
"#;

const MOUNTINFO_EXT4: &str = r#"
37 36 0:60 / /export/movies rw,relatime - ext4 /dev/sdb1 rw
"#;

const NOACL_MANAGE_FALSE_TOML: &str = r#"
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
enable_acl = false
manage_gids = false
"#;

fn generation_paths(out: &std::path::Path) -> GenerationPaths {
    GenerationPaths {
        sssd_conf: out.join("sssd.conf"),
        krb5_conf: out.join("krb5.conf"),
        ganesha_conf: out.join("ganesha.conf"),
        exports_dir: out.join("exports.d"),
        idmap_conf: out.join("idmapd.conf"),
        nfs_conf: out.join("nfs.conf"),
    }
}

fn read_single_fragment(exports_dir: &std::path::Path) -> String {
    let path = fs::read_dir(exports_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "conf"))
        .expect("export fragment");
    fs::read_to_string(path).unwrap()
}

fn generate_to_out(mountinfo: &str, toml: &str, out: &std::path::Path) -> String {
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mountinfo_path = tmp.path().join("mountinfo");
    fs::write(&mountinfo_path, mountinfo).unwrap();
    let conf_path = tmp.path().join("nfs-klldap.conf");
    fs::write(&conf_path, toml).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
    std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mountinfo_path);

    let cfg = NfsKlldapConfig::load(&conf_path).expect("load");
    let paths = generation_paths(out);
    generate_all(&cfg, &paths).expect("generate_all");

    if let Some(p) = prev {
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p);
    } else {
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
    }

    read_single_fragment(&out.join("exports.d"))
}

fn generate_with_mountinfo(mountinfo: &str, toml: &str) -> (tempfile::TempDir, String, String) {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let frag = generate_to_out(mountinfo, toml, &out);
    let ganesha = fs::read_to_string(out.join("ganesha.conf")).unwrap();
    (tmp, frag, ganesha)
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
        "Manage_Gids_Expiration =",
        "IdmapConf =",
    ] {
        assert!(!frag.contains(forbidden), "forbidden {forbidden} in fragment");
        assert!(!ganesha.contains(forbidden), "forbidden {forbidden} in ganesha.conf");
    }
    assert!(ganesha.contains("Root_Kerberos_Principal = host, nfs, root"));
    assert!(ganesha.contains("Pwnam_Implementation = nsswitch"));

    let variants = nfs_keytab_host_variants("nfs-server.example.com");
    let (m_host, _) = classify_principal("host/client.test@TEST", "TEST", &variants);
    let (m_nfs, _) = classify_principal("nfs/client@TEST", "TEST", &variants);
    let (u_alice, _) = classify_principal("alice@TEST", "TEST", &variants);
    assert!(m_host && m_nfs && !u_alice, "hybrid classify must hold on limited share");
}

#[test]
fn generate_all_capable_ext4_omits_limited_flags() {
    let ext4_toml = r#"
ldap_uri = "ldaps://kllap.test:6360"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "movies"
host_path = "/media/movies"
"#;
    let (_tmp, frag, _) = generate_with_mountinfo(MOUNTINFO_EXT4, ext4_toml);
    assert!(!frag.contains("Disable_ACL = true;"), "capable ext4 omits Disable_ACL");
    assert!(frag.contains("Manage_Gids = true;"));
    assert!(frag.contains("Path = /export/movies;"), "acl capable must contain Path:\n{frag}");
    assert!(frag.contains("    Pseudo = /movies;"), "acl capable (auto) must include the Pseudo line:\n{frag}");
    assert!(!frag.contains("Pseudo = /users;"), "wrong share name in pseudo");
    assert!(!frag.contains("Auto-detected:"));
}

#[test]
fn generate_all_noacl_with_explicit_manage_gids_false_override() {
    // Full end-to-end on shipped generate_all + warnings for NOACL + explicit manage=false override.
    // Auto NOACL now defaults manage_gids=true; explicit false must still win.
    let (_tmp, frag, _ganesha) = generate_with_mountinfo(MOUNTINFO_BTRFS_NOACL, NOACL_MANAGE_FALSE_TOML);

    // Frag must have Disable (NOACL path) but Manage_Gids = false (from explicit override)
    assert!(frag.contains("Disable_ACL = true;"), "NOACL path still emits Disable:\n{frag}");
    assert!(frag.contains("Manage_Gids = false;"), "explicit manage_gids=false must win on NOACL:\n{frag}");
    assert!(!frag.contains("Manage_Gids = true;"), "should not force true when overridden false:\n{frag}");
    assert!(frag.contains("Path = /export/users;"), "Path present on overridden noacl:\n{frag}");
    assert!(frag.contains("    Pseudo = /users;"), "noacl with overrides must still emit Pseudo:\n{frag}");
    assert!(frag.contains("Read_Access_Check_Policy = pre;"), "NOACL override must emit pre policy:\n{frag}");
    assert!(!frag.contains("Read_Access_Check_Policy = post;"), "no post on NOACL");

    eprintln!("FRESH_CONSUMER_FULL_CHAIN: override toml load+generate frag has Manage=false on noacl: {}", frag.contains("Manage_Gids = false;"));

    // Now drive warnings path with real share (not dummy)
    // Re-load under same mountinfo to get real cfg + eff
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();
    let mountinfo_path = tmp2.path().join("mountinfo");
    fs::write(&mountinfo_path, MOUNTINFO_BTRFS_NOACL).unwrap();
    let conf_path = tmp2.path().join("nfs-klldap.conf");
    fs::write(&conf_path, NOACL_MANAGE_FALSE_TOML).unwrap();
    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
    std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mountinfo_path);

    // Fresh consumer explicit steps:
    let cfg = NfsKlldapConfig::load(&conf_path).expect("load override toml");
    eprintln!("FRESH_CONSUMER: loaded cfg with 1 share, name={}", cfg.shares[0].name);

    // probe via the serve path (uses env)
    let caps = probe_fs_capabilities(std::path::Path::new("/export/users")).unwrap_or_else(|_| FsCapabilities { fstype:"btrfs".into(), mount_options:vec!["noacl".into()], acl_capable:false });
    eprintln!("FRESH_CONSUMER: probed caps acl_capable={} fstype={}", caps.acl_capable, caps.fstype);

    let eff = compute_effective_flags(&cfg.shares[0], &caps);
    eprintln!("FRESH_CONSUMER: compute_effective_flags enable_acl={} manage_gids={}", eff.enable_acl, eff.manage_gids);
    assert!(!eff.enable_acl);
    assert!(!eff.manage_gids, "override must be visible in eff");

    // full generate_all (exercises export_fs_directives + write internally for the override)
    let out = tmp2.path().join("genout");
    let paths = GenerationPaths {
        sssd_conf: out.join("sssd.conf"),
        krb5_conf: out.join("krb5.conf"),
        ganesha_conf: out.join("ganesha.conf"),
        exports_dir: out.join("exports.d"),
        idmap_conf: out.join("idmapd.conf"),
        nfs_conf: out.join("nfs.conf"),
    };
    std::fs::create_dir_all(&paths.exports_dir).unwrap();
    generate_all(&cfg, &paths).expect("generate_all for override fresh");
    let gen_frag = std::fs::read_dir(&paths.exports_dir).unwrap().filter_map(|e| e.ok()).find(|e| e.path().extension().map_or(false, |x| x=="conf")).map(|e| std::fs::read_to_string(e.path()).unwrap()).unwrap_or_default();
    assert!(gen_frag.contains("Manage_Gids = false;"), "generate_all frag must contain false for override");
    eprintln!("FRESH_CONSUMER: generate_all frag for override has Manage=false: {}", gen_frag.contains("Manage_Gids = false;"));

    let ws = collect_fs_warnings(&cfg);
    let limited_ws: Vec<_> = ws.into_iter().filter(|w| !w.acl_capable).collect();
    assert!(!limited_ws.is_empty());
    let w = limited_ws.iter().find(|w| w.share_name == "users").expect("found users warning");
    assert!(!w.acl_capable);
    assert!(!w.effective_enable_acl);
    assert!(!w.effective_manage_gids, "eff must reflect explicit false override");
    assert!(w.message.contains("manage_gids=false") || w.message.contains("manage_gids = false") || w.message.contains("NOACL mode"), "warning message must reflect override false: {}", w.message);
    eprintln!("FRESH_CONSUMER: warning message for override: {}", w.message);

    let only = limited_fs_warnings_only(&cfg);
    assert!(only.iter().any(|ww| ww.share_name=="users" && !ww.effective_manage_gids));
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