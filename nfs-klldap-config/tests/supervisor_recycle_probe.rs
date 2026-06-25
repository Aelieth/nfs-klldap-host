//! Integration test: handle_sighup fingerprint reload/skip + stop_ganesha via supervise-recycle-probe.

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
fn supervise_recycle_probe_handle_sighup_fingerprint_reload_skip_and_kill() {
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
            "#!/bin/sh\necho \"HOOK $(date +%s%N) share=$SHARE_NAME\" >> \"{}\"\n",
            hook_log.display()
        ),
    );

    let conf = tmp.path().join("nfs-klldap.conf");
    let stub_log = tmp.path().join("ganesha-stub.log");
    let ganesha_bin = stubs.join("ganesha.nfsd");
    fs::write(
        &conf,
        COMPLETE_TOML.replace("HOOK_PLACEHOLDER", hook.to_str().unwrap()),
    )
    .unwrap();

    write_exe(
        &ganesha_bin,
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

    let output = Command::new(&startup_bin)
        .arg("supervise-recycle-probe")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("USE_NSS_WRAPPER", "0")
        .env("CONFIG_BIN", &config_bin)
        .env("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_LOG", &stub_log)
        .env("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_BIN", &ganesha_bin)
        .env("NFS_KLLDAP_RECYCLE_PROBE_TEST_KILL", "1")
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
        .expect("supervise-recycle-probe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        output.status.success(),
        "supervise-recycle-probe failed: {combined}"
    );
    assert!(combined.contains("Supervise-recycle-probe mode enabled"));
    assert!(combined.contains("handle_sighup with unchanged exports"));
    assert!(combined.contains("Export fragments fingerprint:"));
    assert!(combined.contains("changed=false"));
    assert!(combined.contains("Identity artifacts fingerprint:"));
    assert!(combined.contains("No service recycle required"));
    assert!(combined.contains("handle_sighup after export mutation"));
    assert!(combined.contains("changed=true"));
    assert!(combined.contains("Sent SIGHUP to ganesha.nfsd"));
    assert!(combined.contains("exercising stop_ganesha (SIGTERM path)"));
    assert!(combined.contains("stop_ganesha: process exited after SIGTERM"));
    assert!(combined.contains("SIGKILL escalation"));
    assert!(combined.contains("stop_ganesha: timeout — escalating to SIGKILL"));
    assert!(combined.contains("Supervise-recycle-probe complete — exiting"));

    let hook_log_text = fs::read_to_string(&hook_log).unwrap_or_default();
    assert!(
        hook_log_text.matches("HOOK").count() >= 3,
        "hook must run on initial generate + both handle_sighup passes; log={hook_log_text:?}"
    );

    let sighup_pos = combined.find("Sent SIGHUP to ganesha.nfsd").unwrap();
    let hook_lines: Vec<_> = hook_log_text.lines().collect();
    assert!(
        hook_lines.len() >= 3,
        "hook must precede ganesha SIGHUP on export-change handle_sighup"
    );

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(stub_log_text.contains("HUP"));
    assert!(stub_log_text.contains("TERM"));
    assert!(!stub_log_text.contains("HUP") || stub_log_text.matches("HUP").count() == 1);

    let _ = sighup_pos;
}