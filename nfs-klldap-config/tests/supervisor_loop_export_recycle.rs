//! Full supervisor_loop + real OS SIGHUP: export-only change recycles Ganesha + WebUI, not SSSD.

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

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
fn supervisor_loop_real_sighup_export_only_recycles_ganesha_and_webui_not_sssd() {
    let tmp = tempfile::tempdir().unwrap();
    let stubs = tmp.path().join("stubs");
    let out = tmp.path().join("out");
    fs::create_dir_all(&stubs).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let conf = tmp.path().join("nfs-klldap.conf");
    let keytab = tmp.path().join("krb5.keytab");
    let stub_log = tmp.path().join("ganesha-stub.log");
    let recycle_marker = tmp.path().join(".nfs-klldap-services-recycled");
    let _ = fs::remove_file(&recycle_marker);

    fs::write(&conf, COMPLETE_TOML).unwrap();
    fs::write(&keytab, b"probe-keytab\n").unwrap();

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
    let idhelper_stub = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/idhelper-probe-stub.sh"),
    )
    .unwrap();
    write_exe(&stubs.join("nfs-klldap-idhelper"), &idhelper_stub);
    write_exe(&stubs.join("nfs-klldap-ui"), "#!/bin/sh\nexec sleep 3600\n");
    write_exe(
        &stubs.join("nfs-klldap-conf-watcher"),
        "#!/bin/sh\nexec sleep 3600\n",
    );
    write_exe(&stubs.join("healthcheck.sh"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("inotifywait"), "#!/bin/sh\nexec sleep 3600\n");

    let startup_bin = cargo_bin("nfs-klldap-startup");
    let config_bin = cargo_bin("nfs-klldap-config");

    let mut child = Command::new(&startup_bin)
        .arg("supervise")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "100")
        .env("USE_NSS_WRAPPER", "0")
        .env("CONFIG_BIN", &config_bin)
        .env("NFS_KLLDAP_KEYTAB_PATH", &keytab)
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
        .env("NSS_PASSWD", out.join("nss_passwd"))
        .env("NSS_GROUP", out.join("nss_group"))
        .env("NFS_KLLDAP_WEBUI_LOG", out.join("webui.log"))
        .env("NFS_KLLDAP_RECYCLE_MARKER", &recycle_marker)
        .env(
            "PATH",
            format!(
                "{}:{}",
                stubs.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn supervise");

    let log = Arc::new(Mutex::new(String::new()));
    let log_out = Arc::clone(&log);
    let log_err = Arc::clone(&log);
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let out_thread = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let mut buf = log_out.lock().unwrap();
            buf.push_str(&line);
            buf.push('\n');
        }
    });
    let err_thread = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let mut buf = log_err.lock().unwrap();
            buf.push_str(&line);
            buf.push('\n');
        }
    });

    let pid = child.id();
    let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
    loop {
        let combined = log.lock().unwrap().clone();
        if combined.contains("Container is ready (pre-configured path)")
            || combined.contains("Starting nfs-klldap-idhelper")
        {
            break;
        }
        assert!(
            ready_deadline > std::time::Instant::now(),
            "supervisor bring-up did not complete; log={combined:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let conf_text = fs::read_to_string(&conf).unwrap();
    fs::write(
        &conf,
        conf_text.replace(
            "host_path = \"/media/data\"",
            "host_path = \"/media/data2\"",
        ),
    )
    .unwrap();

    assert!(
        Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .expect("kill -HUP")
            .success(),
        "must deliver real OS SIGHUP to running supervisor"
    );

    let sighup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
    loop {
        let combined = log.lock().unwrap().clone();
        if combined.contains("Export fragments fingerprint:")
            && combined.contains("changed=true")
            && combined.contains("Identity artifacts fingerprint:")
            && combined.contains("changed=false")
            && (combined.contains("Services recycled after config apply.")
                || combined.contains("Starting WebUI on 0.0.0.0:9630")
                || combined.contains("restart_webui=true"))
        {
            break;
        }
        assert!(
            sighup_deadline > std::time::Instant::now(),
            "export-only SIGHUP recycle did not complete; log={combined:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let sighup_deadline2 = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let combined = log.lock().unwrap().clone();
        if combined.contains("Services recycled after config apply.") {
            break;
        }
        assert!(
            sighup_deadline2 > std::time::Instant::now(),
            "export-only SIGHUP must finish recycle; log={combined:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = out_thread.join();
    let _ = err_thread.join();
    let combined = log.lock().unwrap().clone();
    let post_sighup = combined
        .split_once("SIGHUP received — reloading configuration")
        .map(|(_, tail)| tail)
        .unwrap_or("");

    assert!(
        !post_sighup.is_empty(),
        "supervisor must process OS SIGHUP; log={combined:?}"
    );
    assert!(
        post_sighup.contains("Export fragments fingerprint:")
            && post_sighup.contains("changed=true"),
        "exports must change on share mutation; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("Identity artifacts fingerprint:")
            && post_sighup.contains("changed=false"),
        "identity artifacts unchanged on export-only reload; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("restart_webui=true"),
        "recycle plan must restart WebUI when exports change; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("Starting WebUI on 0.0.0.0:9630"),
        "export-only reload must spawn a fresh WebUI process; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("Sent SIGHUP to ganesha.nfsd"),
        "export-only reload must SIGHUP ganesha; post_sighup={post_sighup:?}"
    );
    assert!(
        !post_sighup.contains("Starting SSSD..."),
        "export-only reload must not restart SSSD; post_sighup={post_sighup:?}"
    );

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(
        stub_log_text.contains("HUP"),
        "ganesha stub must receive SIGHUP on export change; log={stub_log_text:?}"
    );
}