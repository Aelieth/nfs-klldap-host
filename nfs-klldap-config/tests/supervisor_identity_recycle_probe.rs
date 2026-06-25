//! Identity-only config change recycles SSSD without ganesha SIGHUP.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

const COMPLETE_TOML: &str = r#"
ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "data"
host_path = "/media/data"
"#;

fn cargo_bin(name: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        return PathBuf::from(path);
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/debug")
        .join(name);
    assert!(
        path.is_file(),
        "binary {name} not built at {} (set {env_key} when available)",
        path.display()
    );
    path
}

fn write_exe(path: &std::path::Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

#[test]
fn supervise_identity_recycle_probe_sssd_only_change() {
    let tmp = tempfile::tempdir().unwrap();
    let stubs = tmp.path().join("stubs");
    let out = tmp.path().join("out");
    fs::create_dir_all(&stubs).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let conf = tmp.path().join("nfs-klldap.conf");
    let stub_log = tmp.path().join("ganesha-stub.log");
    fs::write(&conf, COMPLETE_TOML).unwrap();

    write_exe(
        &stubs.join("ganesha.nfsd"),
        &format!(
            r#"#!/bin/sh
LOG="{log}"
echo START >> "$LOG"
trap 'echo HUP >> "$LOG"' HUP
trap 'echo TERM >> "$LOG"; exit 0' TERM
while :; do :; done
"#,
            log = stub_log.display()
        ),
    );
    write_exe(
        &stubs.join("sssd"),
        r#"#!/bin/sh
mkdir -p /var/lib/sss/pipes
touch /var/lib/sss/pipes/nss
exec sleep 3600
"#,
    );
    write_exe(
        &stubs.join("nfs-klldap-idhelper"),
        r#"#!/bin/sh
mkdir -p /var/lib/nfs-klldap
echo probe > /var/lib/nfs-klldap/.bulk_seed_done
echo 'root:x:0:0:root:/root:/bin/sh' > /var/lib/nfs-klldap/nss_passwd
exec sleep 3600
"#,
    );
    write_exe(&stubs.join("nfs-klldap-ui"), "#!/bin/sh\nexit 0\n");

    let output = Command::new(cargo_bin("nfs-klldap-startup"))
        .arg("supervise-identity-recycle-probe")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("USE_NSS_WRAPPER", "0")
        .env("CONFIG_BIN", cargo_bin("nfs-klldap-config"))
        .env("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_LOG", &stub_log)
        .env("UI_BIN", stubs.join("nfs-klldap-ui"))
        .env("IDHELPER_BIN", stubs.join("nfs-klldap-idhelper"))
        .env("SSSD_CONF", out.join("sssd.conf"))
        .env("KRB5_CONF", out.join("krb5.conf"))
        .env("GANESHA_CONF", out.join("ganesha.conf"))
        .env("EXPORTS_DIR", out.join("exports.d"))
        .env("IDMAP_CONF", out.join("idmapd.conf"))
        .env("NSS_PASSWD", out.join("nss_passwd"))
        .env("NSS_GROUP", out.join("nss_group"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                stubs.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("supervise-identity-recycle-probe");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output.status.success(),
        "supervise-identity-recycle-probe failed: {combined}"
    );
    assert!(combined.contains("Supervise-identity-recycle-probe mode enabled"));
    assert!(combined.contains("Identity artifacts fingerprint:"));
    assert!(combined.contains("changed=true"));
    assert!(combined.contains("Export fragments fingerprint:"));
    assert!(combined.contains("changed=false"));
    assert!(combined.contains("restart_sssd=true"));
    assert!(combined.contains("ganesha=Skip"));
    assert!(combined.contains("Starting SSSD..."));
    assert!(!combined.contains("Sent SIGHUP to ganesha.nfsd"));
    assert!(combined.contains("Supervise-identity-recycle-probe complete"));

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(
        !stub_log_text.contains("HUP"),
        "ganesha stub must not see SIGHUP on identity-only recycle; log={stub_log_text:?}"
    );
}