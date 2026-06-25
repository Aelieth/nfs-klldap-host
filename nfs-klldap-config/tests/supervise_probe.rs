//! Integration test: drives the real nfs-klldap-startup supervise-probe path with COMPLETE_TOML defaults.

use std::fs;
use std::io::Read;
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

fn recycle_marker_for(tmp: &tempfile::TempDir) -> PathBuf {
    tmp.path().join(".nfs-klldap-services-recycled")
}

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

fn spin_until(mut ready: impl FnMut() -> bool, max_spins: u64, label: &str) {
    for _ in 0..max_spins {
        if ready() {
            return;
        }
        std::hint::spin_loop();
    }
    panic!("{label}");
}

#[test]
fn supervise_probe_preconf_emits_ready_transcript() {
    let tmp = tempfile::tempdir().unwrap();
    let stubs = tmp.path().join("stubs");
    let out = tmp.path().join("out");
    fs::create_dir_all(&stubs).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let conf = tmp.path().join("nfs-klldap.conf");
    let keytab = tmp.path().join("krb5.keytab");
    let marker = tmp.path().join(".setup_wizard_done");
    fs::write(&conf, COMPLETE_TOML).unwrap();
    fs::write(&keytab, b"probe-keytab").unwrap();

    write_exe(&stubs.join("nfs-klldap-ui"), "#!/bin/sh\nexit 0\n");
    write_exe(
        &stubs.join("nfs-klldap-conf-watcher"),
        "#!/bin/sh\nexec sleep 3600\n",
    );
    write_exe(&stubs.join("nfs-klldap-idhelper"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("healthcheck.sh"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("inotifywait"), "#!/bin/sh\nexit 0\n");

    let startup_bin = cargo_bin("nfs-klldap-startup");
    let config_bin = cargo_bin("nfs-klldap-config");

    let output = Command::new(&startup_bin)
        .arg("supervise-probe")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_KEYTAB_PATH", &keytab)
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("NFS_KLLDAP_SETUP_MARKER", &marker)
        .env("USE_NSS_WRAPPER", "0")
        .env("CONFIG_BIN", &config_bin)
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

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        output.status.success(),
        "supervise-probe failed: {combined}"
    );
    assert!(combined.contains("=== Starting nfs-klldap-host (Rust supervisor) ==="));
    assert!(combined.contains("Pre-configured deployment detected — starting full service stack"));
    assert!(combined.contains("Container is ready (pre-configured path)"));
    assert!(combined.contains("Supervise probe complete — exiting"));
    assert!(out.join("ganesha.conf").is_file(), "generate must write ganesha.conf");
    assert!(marker.is_file(), "wizard marker must be written on preconf bypass");
}

/// Wizard completion path: complete nfs-klldap.conf + marker, then SIGHUP recycle (no keytab).
#[test]
fn supervise_probe_wizard_complete_recycle_touches_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let stubs = tmp.path().join("stubs");
    let out = tmp.path().join("out");
    fs::create_dir_all(&stubs).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let conf = tmp.path().join("nfs-klldap.conf");
    let marker = tmp.path().join(".setup_wizard_done");
    let recycle_marker = recycle_marker_for(&tmp);
    let _ = fs::remove_file(&recycle_marker);

    fs::write(&conf, COMPLETE_TOML).unwrap();
    fs::write(&marker, "ok\n").unwrap();

    write_exe(&stubs.join("nfs-klldap-ui"), "#!/bin/sh\nexit 0\n");
    write_exe(
        &stubs.join("nfs-klldap-conf-watcher"),
        "#!/bin/sh\nexec sleep 3600\n",
    );
    write_exe(&stubs.join("nfs-klldap-idhelper"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("healthcheck.sh"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("inotifywait"), "#!/bin/sh\nexit 0\n");

    let startup_bin = cargo_bin("nfs-klldap-startup");
    let config_bin = cargo_bin("nfs-klldap-config");

    let output = Command::new(&startup_bin)
        .arg("supervise-probe-wizard")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("NFS_KLLDAP_SETUP_MARKER", &marker)
        .env("NFS_KLLDAP_RECYCLE_MARKER", &recycle_marker)
        .env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "0")
        .env("NFS_KLLDAP_SUPERVISOR_MAX_TICKS", "5")
        .env("USE_NSS_WRAPPER", "0")
        .env("CONFIG_BIN", &config_bin)
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
        .expect("supervise-probe-wizard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        output.status.success(),
        "supervise-probe-wizard failed: {combined}"
    );
    assert!(combined.contains("First-run setup required"));
    assert!(combined.contains("Supervise-wizard-probe: posting SIGHUP for bounded loop recycle"));
    assert!(combined.contains("SIGHUP received — reloading configuration"));
    assert!(combined.contains("Supervise-probe: service recycle simulated"));
    assert!(combined.contains("Services recycled after config apply"));
    assert!(combined.contains("Supervise wizard probe complete"));
    assert!(
        !combined.contains("Setup wizard complete — bringing up services"),
        "must not double-bring-up via supervisor_loop after SIGHUP recycle"
    );
    assert!(
        recycle_marker.is_file(),
        "recycle marker must exist after wizard SIGHUP path"
    );
    assert!(out.join("sssd.conf").is_file(), "generate must write sssd.conf");
    let _ = fs::remove_file(&recycle_marker);
}

/// Loop-probe waits for a real OS SIGHUP (not the wizard-probe auto-posted flag).
#[test]
fn supervise_loop_probe_real_sighup_recycle_touches_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let stubs = tmp.path().join("stubs");
    let out = tmp.path().join("out");
    fs::create_dir_all(&stubs).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();

    let conf = tmp.path().join("nfs-klldap.conf");
    let marker = tmp.path().join(".setup_wizard_done");
    let recycle_marker = recycle_marker_for(&tmp);
    let loop_ready = tmp.path().join(".loop_probe_ready");
    let _ = fs::remove_file(&recycle_marker);
    let _ = fs::remove_file(&loop_ready);

    fs::write(&conf, COMPLETE_TOML).unwrap();

    write_exe(&stubs.join("nfs-klldap-ui"), "#!/bin/sh\nexit 0\n");
    write_exe(
        &stubs.join("nfs-klldap-conf-watcher"),
        "#!/bin/sh\nexec sleep 3600\n",
    );
    write_exe(&stubs.join("nfs-klldap-idhelper"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("healthcheck.sh"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("inotifywait"), "#!/bin/sh\nexit 0\n");

    let startup_bin = cargo_bin("nfs-klldap-startup");
    let config_bin = cargo_bin("nfs-klldap-config");

    let mut child = Command::new(&startup_bin)
        .arg("supervise")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_SUPERVISE_PROBE", "1")
        .env("NFS_KLLDAP_SUPERVISE_LOOP_PROBE", "1")
        .env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "100")
        .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
        .env("NFS_KLLDAP_SETUP_MARKER", &marker)
        .env("NFS_KLLDAP_RECYCLE_MARKER", &recycle_marker)
        .env("NFS_KLLDAP_LOOP_PROBE_READY", &loop_ready)
        .env("USE_NSS_WRAPPER", "0")
        .env("CONFIG_BIN", &config_bin)
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
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn supervise loop-probe");

    let mut stdout = child.stdout.take().expect("supervisor stdout pipe");
    let log_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).to_string()
    });

    let pid = child.id();
    spin_until(|| loop_ready.is_file(), 50_000_000, "supervisor never wrote loop-probe ready marker");
    assert!(
        !recycle_marker.is_file(),
        "recycle marker must be absent before SIGHUP"
    );
    assert!(
        Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .expect("kill -HUP")
            .success(),
        "must deliver real SIGHUP to supervisor child"
    );

    spin_until(|| recycle_marker.is_file(), 50_000_000, "recycle marker missing after real SIGHUP");
    assert!(
        fs::metadata(&recycle_marker).map(|m| m.len()).unwrap_or(0) > 0,
        "recycle marker must be non-empty"
    );

    let _ = child.kill();
    let _ = child.wait();
    let combined = log_handle.join().unwrap_or_default();
    assert!(
        combined.contains("SIGHUP received — reloading configuration"),
        "supervisor log missing SIGHUP line; log={combined:?}"
    );
    assert!(
        !combined.contains("Setup wizard complete — bringing up services"),
        "loop must not duplicate bring-up after HUP recycle"
    );
    let _ = fs::remove_file(&recycle_marker);
    let _ = fs::remove_file(&loop_ready);
}