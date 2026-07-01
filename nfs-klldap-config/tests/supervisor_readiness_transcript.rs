//! Integration: supervisor preconf readiness-probe transcript (start_ganesha -F + readiness gate).

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

const COMPLETE_TOML: &str = r#"
ldap_uri = "ldaps://kllap.test:6360"
[server]
hostname = "aurora"
[kerberos]
realm = "TEST"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "data"
host_path = "/media/data"
security = "krb5p"
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

fn mock_idhelper_socket(sock: PathBuf, stop: Arc<AtomicBool>) {
    let _ = fs::remove_file(&sock);
    if let Some(p) = sock.parent() {
        let _ = fs::create_dir_all(p);
    }
    let listener = UnixListener::bind(&sock).expect("bind mock socket");
    listener.set_nonblocking(true).ok();
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    let resp = if line.contains("root") || line.contains("host/") {
                        "OK 0\n"
                    } else if line.contains("testuser1") {
                        "OK 3002|3007|3005\n"
                    } else {
                        "ERR\n"
                    };
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(15));
            }
            Err(_) => break,
        }
    }
}

#[test]
fn supervise_readiness_probe_emits_ganesha_env_and_readiness_transcript() {
    let td = tempfile::tempdir().unwrap();
    let stubs = td.path().join("stubs");
    let out = td.path().join("out");
    let run = td.path().join("run");
    fs::create_dir_all(&stubs).unwrap();
    fs::create_dir_all(out.join("exports.d")).unwrap();
    fs::create_dir_all(&run).unwrap();

    let conf = td.path().join("nfs-klldap.conf");
    let keytab = td.path().join("krb5.keytab");
    let marker = td.path().join(".setup_wizard_done");
    let ganesha_log = td.path().join("ganesha.log");
    let sock = run.join("idhelper.sock");
    fs::write(&conf, COMPLETE_TOML).unwrap();
    fs::write(&keytab, b"probe-keytab").unwrap();
    fs::write(&ganesha_log, "nfs_start :NFS STARTUP :EVENT :ok\n").unwrap();

    write_exe(&stubs.join("nfs-klldap-ui"), "#!/bin/sh\nexit 0\n");
    write_exe(
        &stubs.join("nfs-klldap-conf-watcher"),
        "#!/bin/sh\nexec sleep 3600\n",
    );
    write_exe(&stubs.join("nfs-klldap-idhelper"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("healthcheck.sh"), "#!/bin/sh\nexit 0\n");
    write_exe(&stubs.join("inotifywait"), "#!/bin/sh\nexit 0\n");
    write_exe(
        &stubs.join("ganesha-ctl"),
        "#!/bin/sh\ncase \"$1\" in id-resolve) exit 0;; esac\nexit 0\n",
    );

    let ganesha_stub = stubs.join("ganesha.nfsd");
    write_exe(
        &ganesha_stub,
        "#!/bin/sh\n# stub foreground daemon inheriting supervisor envp\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n",
    );

    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let sock_t = sock.clone();
    let server = thread::spawn(move || mock_idhelper_socket(sock_t, stop_t));

    for _ in 0..100 {
        if UnixStream::connect(&sock).is_ok() {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(20));
    }

    let startup_bin = cargo_bin("nfs-klldap-startup");
    let config_bin = cargo_bin("nfs-klldap-config");
    let nss_passwd = run.join("nss_passwd");
    let nss_group = run.join("nss_group");
    fs::write(
        &nss_passwd,
        "root:x:0:0:root:/root:/bin/sh\ntestuser1:x:3001:3005:user:/non:/nologin\ntestuser1@TEST:x:3001:3005:user:/non:/nologin\nhost/aurora@TEST:x:0:0:host:/non:/nologin\nhost/blue-lt@TEST:x:0:0:host:/non:/nologin\n",
    )
    .unwrap();
    fs::write(
        &nss_group,
        "root:x:0:root,daemon,bin\nstaff:x:3005:testuser1,testuser1@TEST\naux:x:3007:testuser1,testuser1@TEST\n",
    )
    .unwrap();

    let output = Command::new(&startup_bin)
        .arg("supervise-readiness-probe")
        .env("NFS_CONFIG", &conf)
        .env("NFS_KLLDAP_KEYTAB_PATH", &keytab)
        .env("NFS_KLLDAP_SETUP_MARKER", &marker)
        .env("USE_NSS_WRAPPER", "1")
        .env("GANESHA_LOG_PATH", &ganesha_log)
        .env("NFS_KLLDAP_IDHELPER_SOCKET", &sock)
        .env("NSS_PASSWD", &nss_passwd)
        .env("NSS_GROUP", &nss_group)
        .env("GANESHA_CTL_BIN", stubs.join("ganesha-ctl"))
        .env("PATH", format!("{}:{}", stubs.display(), std::env::var("PATH").unwrap_or_default()))
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
        .output()
        .expect("supervise-readiness-probe");

    stop.store(true, Ordering::Relaxed);
    let _ = server.join();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let scratch = std::env::var("GANESHA_READINESS_SCRATCH")
        .unwrap_or_else(|_| "/tmp/grok-goal-25c1e2ddb1b5/implementer".into());
    let _ = fs::create_dir_all(&scratch);
    let transcript = PathBuf::from(&scratch).join("supervisor-readiness-transcript.log");
    fs::write(&transcript, &combined).unwrap();

    assert!(output.status.success(), "probe failed: {combined}");
    let warm_pos = combined
        .find("principal-warm:complete")
        .expect("must log principal-warm:complete");
    let spawned_pos = combined
        .find("Started ganesha.nfsd pid")
        .expect("must log ganesha spawn");
    assert!(
        warm_pos < spawned_pos,
        "principal warm must complete before ganesha.nfsd spawn: {combined}"
    );
    assert!(
        combined.contains("testuser1@TEST"),
        "readiness must probe FQDN user login: {combined}"
    );
    assert!(
        combined.contains("short pw_name testuser1 id -G"),
        "readiness must exercise uid→short-name→getgrouplist chain: {combined}"
    );
    assert!(combined.contains("Starting NFS-Ganesha"));
    assert!(
        combined.contains("Started ganesha.nfsd pid") && combined.contains("foreground + explicit envp"),
        "must show -F direct spawn: {combined}"
    );
    assert!(
        combined.contains("ganesha daemon /proc/") && combined.contains("environ (filtered)"),
        "must log /proc environ diagnostic: {combined}"
    );
    assert!(
        combined.contains("readiness root id -G (under daemon env)"),
        "must exercise id -G: {combined}"
    );
    assert!(
        combined.contains("Ganesha readiness confirmed"),
        "must confirm readiness: {combined}"
    );
    assert!(
        combined.contains("synthetic krb principal getpwuid_r/getgrouplist test: no my_getgrouplist_alloc WARN (clean)"),
        "must pass synthetic krb scan: {combined}"
    );
    assert!(
        combined.contains("Container is ready (pre-configured path)"),
        "ready only after gate: {combined}"
    );
    assert!(
        combined.contains("Supervise readiness probe complete"),
        "one-shot exit: {combined}"
    );
    assert!(
        !combined.contains("Adopted ganesha.nfsd daemon pid") || combined.contains("Recovered"),
        "must not use legacy adopt-after-launcher wording: {combined}"
    );
}