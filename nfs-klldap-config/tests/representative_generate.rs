//! Representative nfs-klldap.conf: drives real generate twice and asserts Ganesha 9.6 output.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use nfs_klldap_config::{classify_principal, generate_all, GenerationPaths, NfsKlldapConfig};
use nfs_klldap_identity::nfs_keytab_host_variants;

const REPRESENTATIVE_TOML: &str = r#"
ldap_uri = "ldaps://klldap.test:6360"

[storage]
container_root = "/export"

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "strong-secret"
kllldap_ignored_attributes = true

[ganesha]
default_security = "krb5p"

[[shares]]
name = "movies"
host_path = "/media/NVME-RAID/movies"
container_path = "/export/NVME-RAID/movies"
pseudo_path = "/movies"
security = "krb5p"
rw = true
cache_profile = "Read - Heavy"
"#;

fn cargo_bin(name: &str) -> PathBuf {
    if let Ok(p) = std::env::var(format!("CARGO_BIN_EXE_{}", name.replace('-',"_"))) { return PathBuf::from(p); }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug").join(name);
    assert!(p.is_file(), "bin {name} missing"); p
}
fn generation_paths(out: &std::path::Path) -> GenerationPaths {
    GenerationPaths { sssd_conf: out.join("sssd.conf"), krb5_conf: out.join("krb5.conf"), ganesha_conf: out.join("ganesha.conf"), exports_dir: out.join("exports.d"), idmap_conf: out.join("idmapd.conf"), nfs_conf: out.join("nfs.conf") }
}

fn assert_ganesha_96_compliant(g: &str, i: &str) {
    for k in ["Pwnam_Implementation = nsswitch", "Root_Kerberos_Principal = host, nfs, root", "Only_Numeric_Owners = true", "NFS_KRB5", "UseGetpwnam = true"] { assert!(g.contains(k)); }
    for f in ["Read_Access_Check_Policy =", "Manage_Gids_Expiration =", "IdmapConf =", "Transports ="] { assert!(!g.contains(f)); }
    assert!(i.contains("Domain = TEST") && i.contains("Method = nsswitch"));
}

#[test]
fn representative_config_generate_twice_is_consistent() {
    let tmp = tempfile::tempdir().unwrap(); let cp = tmp.path().join("c.toml"); fs::write(&cp, REPRESENTATIVE_TOML).unwrap();
    let mut cfg = NfsKlldapConfig::load(&cp).unwrap(); cfg.validate_and_derive().unwrap();
    let out = tmp.path().join("out"); fs::create_dir_all(out.join("e.d")).unwrap(); let ps = generation_paths(&out);
    generate_all(&cfg, &ps).expect("r1"); let g1=fs::read_to_string(&ps.ganesha_conf).unwrap();
    generate_all(&cfg, &ps).expect("r2"); let g2=fs::read_to_string(&ps.ganesha_conf).unwrap(); let i1=fs::read_to_string(&ps.idmap_conf).unwrap();
    let fr = fs::read_dir(&ps.exports_dir).unwrap().filter_map(|e|e.ok()).find(|e|e.path().extension().is_some_and(|x| x == "conf")).map(|e|fs::read_to_string(e.path()).unwrap()).unwrap_or_default();
    assert!(fr.contains("Pseudo = /movies;") && fr.contains("Path = /export/NVME-RAID/movies;"));
    assert_eq!(g1,g2); assert_ganesha_96_compliant(&g1,&i1);
    let vs = nfs_keytab_host_variants("nfs-server.example.com");
    let (h,_)=classify_principal("host/client.test@TEST","TEST",&vs); let (n,_)=classify_principal("nfs/client@TEST","TEST",&vs); let (a,_)=classify_principal("alice@TEST","TEST",&vs);
    assert!(h && n && !a);
}

#[test]
fn representative_config_cli_generate_exit_zero() {
    let tmp = tempfile::tempdir().unwrap(); let cp=tmp.path().join("c.toml"); let out=tmp.path().join("out"); fs::write(&cp, REPRESENTATIVE_TOML).unwrap(); fs::create_dir_all(out.join("e.d")).unwrap();
    let bin = cargo_bin("nfs-klldap-config");
    for _r in 1..=2 {
        let o = Command::new(&bin).args(["generate","--config"]).arg(&cp).env("SSSD_CONF",out.join("s")).env("KRB5_CONF",out.join("k")).env("GANESHA_CONF",out.join("g")).env("EXPORTS_DIR",out.join("e.d")).env("IDMAP_CONF",out.join("i")).env("NFS_CONF",out.join("n")).output().unwrap_or_else(|e|panic!("{e}"));
        assert!(o.status.success());
    }
    let g=fs::read_to_string(out.join("g")).unwrap(); let i=fs::read_to_string(out.join("i")).unwrap();
    let fr=fs::read_dir(out.join("e.d")).unwrap().filter_map(|e|e.ok()).find(|e|e.path().extension().is_some_and(|x| x == "conf")).map(|e|fs::read_to_string(e.path()).unwrap()).unwrap_or_default();
    assert!(fr.contains("Pseudo = /movies;") && fr.contains("Path = /export/NVME-RAID/movies;"));
    assert_ganesha_96_compliant(&g,&i);
}