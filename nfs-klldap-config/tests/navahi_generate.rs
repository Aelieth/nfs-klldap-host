//! Navahi generator contract: byte-identical output when off; core v3 +
//! per-share sys/3,4 + avahi XML lifecycle when on.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use nfs_klldap_config::{generate_all, GenerationPaths, NfsKlldapConfig};

static MOUNTINFO_ENV_LOCK: Mutex<()> = Mutex::new(());

const MOUNTINFO_EXT4: &str = "36 35 0:59 / /export rw,relatime - ext4 /dev/sda1 rw\n";

const BASE_TOML: &str = r#"
ldap_uri = "ldaps://klldap.test:6360"
[server]
hostname = "nas.test.example"
[storage]
container_root = "/export"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "movies"
host_path = "/media/movies"
container_path = "/export/movies"
security = "krb5p"
[[shares]]
name = "music"
host_path = "/media/music"
container_path = "/export/music"
"#;

fn on_toml() -> String {
    BASE_TOML
        .replacen("ldap_uri", "navahi_discovery = true\nldap_uri", 1)
        .replacen(
            "security = \"krb5p\"",
            "security = \"krb5p\"\nnavahi_insecure = true",
            1,
        )
}

fn paths_for(out: &Path) -> GenerationPaths {
    GenerationPaths {
        sssd_conf: out.join("sssd.conf"),
        krb5_conf: out.join("krb5.conf"),
        ganesha_conf: out.join("ganesha.conf"),
        exports_dir: out.join("exports.d"),
        idmap_conf: out.join("idmapd.conf"),
        nfs_conf: out.join("nfs.conf"),
        avahi_services_dir: out.join("avahi-services"),
    }
}

/// Generates `toml` into `out` under the shared mountinfo fixture lock.
fn run_generate(tmp: &Path, out: &Path, toml: &str) {
    let _lock = MOUNTINFO_ENV_LOCK.lock().unwrap();
    let mi = tmp.join("mi");
    fs::write(&mi, MOUNTINFO_EXT4).unwrap();
    let cp = tmp.join("c.toml");
    fs::write(&cp, toml).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();
    let prev = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok();
    std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mi);
    let cfg = NfsKlldapConfig::load(&cp).expect("load");
    let res = generate_all(&cfg, &paths_for(out));
    if let Some(p) = prev {
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", p);
    } else {
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
    }
    res.expect("generate");
}

fn fragments_sorted(out: &Path) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = fs::read_dir(out.join("exports.d"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "conf"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn navahi_off_output_is_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let out_a = tmp.path().join("a");
    let out_b = tmp.path().join("b");
    // Same config, once with no navahi keys and once with both spelled false.
    let explicit_off = format!(
        "{}navahi_insecure = false\n",
        BASE_TOML.replacen("ldap_uri", "navahi_discovery = false\nldap_uri", 1)
    );
    run_generate(tmp.path(), &out_a, BASE_TOML);
    run_generate(tmp.path(), &out_b, &explicit_off);

    // %include lines embed the per-run exports dir; everything else must match.
    let strip_includes = |s: &str| -> String {
        s.lines()
            .filter(|l| !l.starts_with("%include"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let main_a = fs::read_to_string(out_a.join("ganesha.conf")).unwrap();
    let main_b = fs::read_to_string(out_b.join("ganesha.conf")).unwrap();
    assert_eq!(
        strip_includes(&main_a),
        strip_includes(&main_b),
        "explicit-false must not change the main conf"
    );
    assert_eq!(fragments_sorted(&out_a), fragments_sorted(&out_b));

    for marker in ["Mount_Path_Pseudo", "MNT_Port", "3,4", ", sys", "Navahi"] {
        assert!(!main_a.contains(marker), "off main conf carries {marker}");
        for (name, frag) in fragments_sorted(&out_a) {
            assert!(!frag.contains(marker), "off fragment {name} carries {marker}");
        }
    }
    assert!(
        !out_a.join("avahi-services").exists(),
        "off-state generate must never create the avahi dir"
    );
}

#[test]
fn navahi_on_emits_core_v3_and_flagged_fragment_only() {
    let tmp = tempfile::tempdir().unwrap();
    let out_off = tmp.path().join("off");
    let out_on = tmp.path().join("on");
    run_generate(tmp.path(), &out_off, BASE_TOML);
    run_generate(tmp.path(), &out_on, &on_toml());

    let main = fs::read_to_string(out_on.join("ganesha.conf")).unwrap();
    let defaults_at = main.find("EXPORT_DEFAULTS").expect("defaults block");
    let core = &main[..defaults_at];
    assert!(core.contains("Protocols = 3,4;"), "core opens v3:\n{main}");
    assert!(core.contains("Mount_Path_Pseudo = true;"));
    assert!(core.contains("MNT_Port = 20048;"));
    let defaults = &main[defaults_at..];
    assert!(
        defaults.contains("Protocols = 4;"),
        "EXPORT_DEFAULTS stays v4-only:\n{defaults}"
    );

    let frags = fragments_sorted(&out_on);
    let movies = &frags.iter().find(|(n, _)| n.contains("movies")).unwrap().1;
    assert!(
        movies.contains("SecType = krb5p, sys;"),
        "flagged export gains sys last:\n{movies}"
    );
    assert!(movies.contains("Protocols = 3,4;"), "flagged export widens:\n{movies}");
    assert!(movies.contains("# Navahi: advertised via mDNS"));

    let music_on = &frags.iter().find(|(n, _)| n.contains("music")).unwrap().1;
    let frags_off = fragments_sorted(&out_off);
    let music_off = &frags_off.iter().find(|(n, _)| n.contains("music")).unwrap().1;
    assert_eq!(
        music_on, music_off,
        "unflagged share must be untouched by the global toggle"
    );
    assert!(!music_on.contains("sys"));
}

#[test]
fn short_hostname_synthesizes_fqdn_host_name_from_realm() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    // Short UTS + multi-label realm → Kerberos DNS FQDN as SRV target.
    // Realm derives from ldap_uri host (klldap.test → TEST).
    let toml = on_toml().replacen("nas.test.example", "shortname", 1);
    run_generate(tmp.path(), &out, &toml);
    let xml =
        fs::read_to_string(out.join("avahi-services/nfs-klldap-movies.service")).unwrap();
    assert!(
        xml.contains("<host-name>shortname.test</host-name>"),
        "short hostname + realm must publish synthesized FQDN:\n{xml}"
    );
}

#[test]
fn avahi_xml_lifecycle_prune_and_content() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let av = out.join("avahi-services");
    fs::create_dir_all(&av).unwrap();
    fs::write(av.join("custom.service"), "<keep/>").unwrap();
    fs::write(av.join("nfs-klldap-old.service"), "<stale/>").unwrap();

    run_generate(tmp.path(), &out, &on_toml());

    let xml = fs::read_to_string(av.join("nfs-klldap-movies.service")).unwrap();
    assert!(xml.contains("<type>_nfs._tcp</type>"), "xml:\n{xml}");
    assert!(xml.contains("<port>2049</port>"));
    assert!(xml.contains("<txt-record>path=/movies</txt-record>"));
    assert!(xml.contains(r#"<name replace-wildcards="yes">movies on %h</name>"#));
    assert!(
        xml.contains("<host-name>nas.test.example</host-name>"),
        "qualified hostname must become the SRV target (not <short>.local):\n{xml}"
    );
    assert!(
        !av.join("nfs-klldap-music.service").exists(),
        "unflagged share never advertised"
    );
    assert!(av.join("custom.service").exists(), "foreign files survive the prune");
    assert!(!av.join("nfs-klldap-old.service").exists(), "stale adverts pruned");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(av.join("nfs-klldap-movies.service"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644, "avahi drops privileges; must stay readable");
    }

    // Global off sweeps ours even though the dir pre-exists.
    run_generate(tmp.path(), &out, BASE_TOML);
    assert!(
        !av.join("nfs-klldap-movies.service").exists(),
        "flip-off withdraws the advert"
    );
    assert!(av.join("custom.service").exists());
}
