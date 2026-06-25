//! Full supervisor_loop + real OS SIGHUP: dead ganesha pid escalates to stop_ganesha + restart.

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
    assert!(path.is_file(), "binary {name} not built at {}", path.display());
    path
}

fn write_exe(path: &std::path::Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

#[test]
fn supervisor_loop_export_change_escalates_to_stop_ganesha_and_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let stubs = tmp.path().join("stubs");
    let out = tmp.path().join("out");
    fs::create_dir_all(&stubs).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let conf = tmp.path().join("nfs-klldap.conf");
    let keytab = tmp.path().join("krb5.keytab");
    let stub_log = tmp.path().join("ganesha-stub.log");
    let recycle_marker = std::path::Path::new("/tmp/.nfs-klldap-services-recycled");
    let _ = fs::remove_file(recycle_marker);

    fs::write(&conf, COMPLETE_TOML).unwrap();
    fs::write(&keytab, b"probe-keytab\n").unwrap();

    write_exe(
        &stubs.join("ganesha.nfsd"),
        &format!(
            r#"#!/bin/sh
LOG="{log}"
echo START >> "$LOG"
trap 'echo TERM >> "$LOG"; exit 0' TERM
trap 'echo HUP >> "$LOG"' HUP
while :; do :; done
"#,
            log = stub_log.display()
        ),
    );
    write_exe(
        &stubs.join("sssd"),
        r#"#!/bin/sh
mkdir -p /var/lib/sss/pipes && touch /var/lib/sss/pipes/nss
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
    write_exe(&stubs.join("nfs-klldap-ui"), "#!/bin/sh\nexec sleep 3600\n");
    write_exe(&stubs.join("nfs-klldap-conf-watcher"), "#!/bin/sh\nexec sleep 3600\n");
    write_exe(&stubs.join("healthcheck.sh"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("inotifywait"), "#!/bin/sh\nexec sleep 3600\n");
    let startup_bin = cargo_bin("nfs-klldap-startup");
    let config_bin = cargo_bin("nfs-klldap-config");

    let mut child = Command::new(&startup_bin)
        .arg("supervise")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "100")
        .env("NFS_KLLDAP_STOP_GANESHA_TERM_SECS", "2")
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
        .env("NSS_PASSWD", out.join("nss_passwd"))
        .env("NSS_GROUP", out.join("nss_group"))
        .env("NFS_KLLDAP_WEBUI_LOG", out.join("webui.log"))
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
    let _out_thread = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let mut buf = log_out.lock().unwrap();
            buf.push_str(&line);
            buf.push('\n');
        }
    });
    let _err_thread = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let mut buf = log_err.lock().unwrap();
            buf.push_str(&line);
            buf.push('\n');
        }
    });

    let pid = child.id();
    let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let combined = log.lock().unwrap().clone();
        if combined.contains("Container is ready (pre-configured path)")
            && fs::read_to_string(&stub_log)
                .map(|s| s.contains("START"))
                .unwrap_or(false)
        {
            break;
        }
        assert!(
            ready_deadline > std::time::Instant::now(),
            "bring-up did not complete; log={combined:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    assert!(
        Command::new("pkill")
            .args(["-TERM", "ganesha.nfsd"])
            .status()
            .expect("pkill ganesha")
            .success(),
        "must stop ganesha stub before export-change SIGHUP"
    );
    let term_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !fs::read_to_string(&stub_log)
        .map(|s| s.contains("TERM"))
        .unwrap_or(false)
    {
        assert!(term_deadline > std::time::Instant::now());
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let conf_text = fs::read_to_string(&conf).unwrap();
    fs::write(
        &conf,
        conf_text.replace("host_path = \"/media/data\"", "host_path = \"/media/data2\""),
    )
    .unwrap();

    assert!(
        Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .expect("kill -HUP")
            .success()
    );

    let sighup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
    loop {
        let combined = log.lock().unwrap().clone();
        if combined.contains("Export fragments fingerprint:")
            && combined.contains("changed=true")
            && combined.contains("ganesha=StopStart")
            && combined.contains("stop_ganesha: sending SIGTERM")
            && combined.contains("Starting NFS-Ganesha after recycle")
            && recycle_marker.is_file()
        {
            break;
        }
        assert!(
            sighup_deadline > std::time::Instant::now(),
            "export-change SIGHUP must escalate to stop_ganesha; log={combined:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let _ = child.kill();
    let _ = child.wait();
    let combined = log.lock().unwrap().clone();
    for line in combined.lines() {
        if line.contains("ganesha=StopStart")
            || line.contains("stop_ganesha:")
            || line.contains("Starting NFS-Ganesha after recycle")
        {
            eprintln!("EVIDENCE {line}");
        }
    }
    assert!(
        !combined.contains("Sent SIGHUP to ganesha.nfsd"),
        "export change with ganesha down must use StopStart not SIGHUP; log={combined:?}"
    );
    assert!(
        combined.contains("stop_ganesha: process exited after SIGTERM")
            || combined.contains("stop_ganesha: process exited after SIGKILL")
            || !combined.contains("stop_ganesha: timeout"),
        "stop_ganesha must complete TERM/KILL wait; log={combined:?}"
    );
}