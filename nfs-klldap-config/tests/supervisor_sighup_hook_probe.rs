//! Real OS SIGHUP drives handle_sighup (hook + fingerprint) before ganesha recycle.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

const COMPLETE_TOML: &str = r#"
ldap_uri = "ldaps://kllap.test:6360"
[ganesha]
post_generate_hook = "HOOK_PLACEHOLDER"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "data"
host_path = "/media/data"
container_path = "/export/data"
"#;

fn cargo_bin(name: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/debug")
        .join(name)
}

fn write_exe(path: &std::path::Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

#[test]
fn supervise_sighup_hook_probe_real_os_sighup_runs_hook_before_recycle() {
    let tmp = tempfile::tempdir().unwrap();
    let stubs = tmp.path().join("stubs");
    let out = tmp.path().join("out");
    fs::create_dir_all(&stubs).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let hook_log = tmp.path().join("hook.log");
    let hook = stubs.join("post-hook.sh");
    write_exe(
        &hook,
        &format!(
            "#!/bin/sh\necho \"HOOK share=$SHARE_NAME\" >> \"{}\"\n",
            hook_log.display()
        ),
    );

    let conf = tmp.path().join("nfs-klldap.conf");
    let stub_log = tmp.path().join("ganesha-stub.log");
    fs::write(
        &conf,
        COMPLETE_TOML.replace("HOOK_PLACEHOLDER", hook.to_str().unwrap()),
    )
    .unwrap();

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

    let startup_bin = cargo_bin("nfs-klldap-startup");
    let config_bin = cargo_bin("nfs-klldap-config");

    let child = Command::new(&startup_bin)
        .arg("supervise-sighup-hook-probe")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("USE_NSS_WRAPPER", "0")
        .env("CONFIG_BIN", &config_bin)
        .env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "50")
        .env("NFS_KLLDAP_SUPERVISOR_MAX_TICKS", "200")
        .env("SSSD_CONF", out.join("sssd.conf"))
        .env("KRB5_CONF", out.join("krb5.conf"))
        .env("GANESHA_CONF", out.join("ganesha.conf"))
        .env("EXPORTS_DIR", out.join("exports.d"))
        .env("IDMAP_CONF", out.join("idmapd.conf"))
        .env("NFS_CONF", out.join("nfs.conf"))
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
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn supervise-sighup-hook-probe");

    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(
        Command::new("kill")
            .args(["-HUP", &child.id().to_string()])
            .status()
            .expect("kill -HUP")
            .success()
    );

    let output = child.wait_with_output().expect("wait supervise-sighup-hook-probe");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output.status.success(),
        "supervise-sighup-hook-probe failed: {combined}"
    );
    assert!(combined.contains("Supervise-sighup-hook-probe mode enabled"));
    assert!(combined.contains("SIGHUP received — reloading configuration"));
    assert!(combined.contains("Export fragments fingerprint:"));
    assert!(combined.contains("changed=false"));
    assert!(combined.contains("Identity artifacts fingerprint:"));
    assert!(combined.contains("No service recycle required"));
    assert!(!combined.contains("Sent SIGHUP to ganesha.nfsd"));
    assert!(combined.contains("Supervise-sighup-hook-probe complete"));

    let hook_log_text = fs::read_to_string(&hook_log).unwrap_or_default();
    assert!(
        hook_log_text.contains("HOOK share=data"),
        "hook must run on initial generate and OS SIGHUP handle_sighup; log={hook_log_text:?}"
    );
    assert!(
        hook_log_text.matches("HOOK").count() >= 2,
        "hook invoked at least twice (bring-up generate + SIGHUP reload)"
    );

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(
        !stub_log_text.contains("HUP"),
        "unchanged export OS SIGHUP must not signal ganesha; log={stub_log_text:?}"
    );
}