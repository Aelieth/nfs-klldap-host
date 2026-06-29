//! Supervisor invokes post_generate_hook after generate (supervise-probe path).

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
fn supervise_probe_runs_post_generate_hook() {
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
            "#!/bin/sh\necho \"HOOK share=$SHARE_NAME path=$GANESHA_PATH\" >> \"{}\"\n",
            hook_log.display()
        ),
    );

    let conf = tmp.path().join("nfs-klldap.conf");
    let keytab = tmp.path().join("krb5.keytab");
    let marker = tmp.path().join(".setup_wizard_done");
    fs::write(
        &conf,
        COMPLETE_TOML.replace("HOOK_PLACEHOLDER", hook.to_str().unwrap()),
    )
    .unwrap();
    fs::write(&keytab, b"probe-keytab").unwrap();

    write_exe(&stubs.join("nfs-klldap-ui"), "#!/bin/sh\nexit 0\n");
    write_exe(
        &stubs.join("nfs-klldap-conf-watcher"),
        "#!/bin/sh\nexec sleep 3600\n",
    );
    let idhelper_stub = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/idhelper-probe-stub.sh"),
    )
    .unwrap();
    write_exe(&stubs.join("nfs-klldap-idhelper"), &idhelper_stub);
    write_exe(&stubs.join("healthcheck.sh"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("inotifywait"), "#!/bin/sh\nexit 0\n");

    let output = Command::new(cargo_bin("nfs-klldap-startup"))
        .arg("supervise-probe")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_KEYTAB_PATH", &keytab)
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("NFS_KLLDAP_SETUP_MARKER", &marker)
        .env("USE_NSS_WRAPPER", "0")
        .env("CONFIG_BIN", cargo_bin("nfs-klldap-config"))
        .env("UI_BIN", stubs.join("nfs-klldap-ui"))
        .env("WATCHER_BIN", stubs.join("nfs-klldap-conf-watcher"))
        .env("IDHELPER_BIN", stubs.join("nfs-klldap-idhelper"))
        .env("HEALTHCHECK", stubs.join("healthcheck.sh"))
        .env("SSSD_CONF", out.join("sssd.conf"))
        .env("KRB5_CONF", out.join("krb5.conf"))
        .env("GANESHA_CONF", out.join("ganesha.conf"))
        .env("EXPORTS_DIR", out.join("exports.d"))
        .env("IDMAP_CONF", out.join("idmapd.conf"))
        .env("NFS_CONF", out.join("nfs.conf"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                stubs.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("supervise-probe");

    assert!(output.status.success());
    let log = fs::read_to_string(&hook_log).unwrap_or_default();
    assert!(
        log.contains("HOOK share=data"),
        "hook must run for share; log={log:?}"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("post_generate_hook"));
}

/// Hook must run on each generate inside handle_sighup before ganesha export SIGHUP.
#[test]
fn supervise_recycle_probe_hook_before_ganesha_sighup() {
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
            "#!/bin/sh\necho HOOK >> \"{}\"\n",
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

    let output = Command::new(cargo_bin("nfs-klldap-startup"))
        .arg("supervise-recycle-probe")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("USE_NSS_WRAPPER", "0")
        .env("CONFIG_BIN", cargo_bin("nfs-klldap-config"))
        .env("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_LOG", &stub_log)
        .env("SSSD_CONF", out.join("sssd.conf"))
        .env("KRB5_CONF", out.join("krb5.conf"))
        .env("GANESHA_CONF", out.join("ganesha.conf"))
        .env("EXPORTS_DIR", out.join("exports.d"))
        .env("IDMAP_CONF", out.join("idmapd.conf"))
        .env("NFS_CONF", out.join("nfs.conf"))
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
    assert!(
        output.status.success(),
        "probe failed: {stdout}{stderr}"
    );

    let export_change = stdout
        .split("handle_sighup after export mutation")
        .nth(1)
        .expect("export-mutation handle_sighup section");
    assert!(
        export_change.contains("changed=true"),
        "export mutation must change fingerprint"
    );
    assert!(
        export_change.contains("Sent SIGHUP to ganesha.nfsd"),
        "export change must reload ganesha via SIGHUP"
    );
    assert!(
        stderr.matches("post_generate_hook").count() >= 3,
        "hook must run on initial generate and both handle_sighup passes"
    );

    let hook_log_text = fs::read_to_string(&hook_log).unwrap_or_default();
    assert!(
        hook_log_text.matches("HOOK").count() >= 3,
        "hook script must run before recycle; log={hook_log_text:?}"
    );
}