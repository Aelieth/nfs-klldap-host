//! Shared harness for the supervisor integration suites: temp layout,
//! canned service stubs, the common env block, and process runners.
#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Minimal complete config shared by every supervisor suite.
pub const COMPLETE_TOML: &str = r#"
ldap_uri = "ldaps://klldap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "data"
host_path = "/media/data"
container_path = "/export/data"
"#;

/// COMPLETE_TOML plus a [ganesha] post_generate_hook pointing at `hook`.
pub fn complete_toml_with_hook(hook: &Path) -> String {
    COMPLETE_TOML.replacen(
        "[sssd]",
        &format!(
            "[ganesha]\npost_generate_hook = \"{}\"\n[sssd]",
            hook.display()
        ),
        1,
    )
}

pub fn cargo_bin(name: &str) -> PathBuf {
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

pub fn write_exe(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

/// Per-test temp layout: stubs/, out/, out/exports.d, and the config file.
pub struct TestDirs {
    pub tmp: tempfile::TempDir,
    pub stubs: PathBuf,
    pub out: PathBuf,
    pub conf: PathBuf,
}

impl TestDirs {
    pub fn new(conf_text: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let stubs = tmp.path().join("stubs");
        let out = tmp.path().join("out");
        fs::create_dir_all(&stubs).unwrap();
        fs::create_dir_all(out.join("exports.d")).unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        fs::write(&conf, conf_text).unwrap();
        TestDirs {
            tmp,
            stubs,
            out,
            conf,
        }
    }

    /// Write the probe keytab and return its path.
    pub fn keytab(&self) -> PathBuf {
        let keytab = self.tmp.path().join("krb5.keytab");
        fs::write(&keytab, b"probe-keytab\n").unwrap();
        keytab
    }

    /// Recycle-marker path with any stale file removed.
    pub fn recycle_marker(&self) -> PathBuf {
        let marker = self.tmp.path().join(".nfs-klldap-services-recycled");
        let _ = fs::remove_file(&marker);
        marker
    }

    pub fn ganesha_stub_log(&self) -> PathBuf {
        self.tmp.path().join("ganesha-stub.log")
    }

    /// ganesha.nfsd stub logging START/HUP/TERM; returns the log path.
    /// Idle via `sleep & wait` (not a busy loop) so parallel CI runners stay responsive.
    pub fn stub_ganesha_trap_log(&self) -> PathBuf {
        let log = self.ganesha_stub_log();
        write_exe(
            &self.stubs.join("ganesha.nfsd"),
            &format!(
                r#"#!/bin/sh
LOG="{log}"
echo START >> "$LOG"
trap 'echo HUP >> "$LOG"' HUP
trap 'echo TERM >> "$LOG"; exit 0' TERM
while :; do sleep 60 & wait $!; done
"#,
                log = log.display()
            ),
        );
        log
    }

    pub fn webui_stub_log(&self) -> PathBuf {
        self.tmp.path().join("webui-stub.log")
    }

    /// nfs-klldap-ui stub logging START/HUP/TERM; returns the log path. Unlike
    /// `stub_sleeper` (whose `exec sleep` dies on SIGHUP, tripping the
    /// supervisor's reload-escalation respawn), this survives the in-process
    /// reload signal like the real UI does. `sleep & wait` instead of a busy
    /// loop: traps still fire instantly (signals interrupt the `wait`
    /// builtin), but a stub orphaned by the harness SIGKILLing the supervisor
    /// idles instead of burning a core.
    pub fn stub_webui_trap_log(&self) -> PathBuf {
        let log = self.webui_stub_log();
        write_exe(
            &self.stubs.join("nfs-klldap-ui"),
            &format!(
                r#"#!/bin/sh
LOG="{log}"
echo START >> "$LOG"
trap 'echo HUP >> "$LOG"' HUP
trap 'echo TERM >> "$LOG"; exit 0' TERM
while :; do sleep 60 & wait $!; done
"#,
                log = log.display()
            ),
        );
        log
    }

    /// Writable SSSD NSS pipe path for this test (CI cannot write /var/lib/sss).
    pub fn sssd_nss_pipe(&self) -> PathBuf {
        self.tmp.path().join("sss-pipes").join("nss")
    }

    /// sssd stub that creates the NSS pipe then sleeps.
    /// Uses NFS_KLLDAP_SSSD_NSS_PIPE (set by `base_cmd`) so non-root CI works.
    pub fn stub_sssd_pipe(&self) {
        let pipe = self.sssd_nss_pipe();
        write_exe(
            &self.stubs.join("sssd"),
            &format!(
                r#"#!/bin/sh
PIPE="${{NFS_KLLDAP_SSSD_NSS_PIPE:-{pipe}}}"
mkdir -p "$(dirname "$PIPE")"
: > "$PIPE"
exec sleep 3600
"#,
                pipe = pipe.display()
            ),
        );
    }

    /// idhelper stub from the committed probe fixture.
    pub fn stub_idhelper_fixture(&self) {
        let body = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/idhelper-probe-stub.sh"),
        )
        .unwrap();
        write_exe(&self.stubs.join("nfs-klldap-idhelper"), &body);
    }

    pub fn stub_exit0(&self, name: &str) {
        write_exe(&self.stubs.join(name), "#!/bin/sh\nexit 0\n");
    }

    pub fn stub_sleeper(&self, name: &str) {
        write_exe(&self.stubs.join(name), "#!/bin/sh\nexec sleep 3600\n");
    }

    /// Bespoke stub; returns its path.
    pub fn stub_script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.stubs.join(name);
        write_exe(&path, body);
        path
    }

    /// Command with the env block every suite wires: config path, test
    /// persistence, nss_wrapper off, CONFIG_BIN, generated-artifact paths,
    /// and the stub dir prepended to PATH.
    pub fn base_cmd(&self, subcommand: &str) -> Command {
        let mut cmd = Command::new(cargo_bin("nfs-klldap-startup"));
        cmd.arg(subcommand)
            .env("NFS_CONFIG", &self.conf)
            .env("NFS_KLLDAP_TEST_PERSISTENT", "1")
            .env("USE_NSS_WRAPPER", "0")
            .env("CONFIG_BIN", cargo_bin("nfs-klldap-config"))
            .env("SSSD_CONF", self.out.join("sssd.conf"))
            .env("KRB5_CONF", self.out.join("krb5.conf"))
            .env("GANESHA_CONF", self.out.join("ganesha.conf"))
            .env("EXPORTS_DIR", self.out.join("exports.d"))
            .env("IDMAP_CONF", self.out.join("idmapd.conf"))
            .env("NFS_CONF", self.out.join("nfs.conf"))
            .env("AVAHI_SERVICES_DIR", self.out.join("avahi-services"))
            // Writable stand-in for /var/lib/sss/pipes/nss on non-root CI.
            .env("NFS_KLLDAP_SSSD_NSS_PIPE", self.sssd_nss_pipe())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.stubs.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        cmd
    }

    /// Adds the four service-binary env entries used by full-stack suites.
    pub fn service_bins_env(&self, cmd: &mut Command) {
        cmd.env("UI_BIN", self.stubs.join("nfs-klldap-ui"))
            .env("WATCHER_BIN", self.stubs.join("nfs-klldap-conf-watcher"))
            .env("IDHELPER_BIN", self.stubs.join("nfs-klldap-idhelper"))
            .env("HEALTHCHECK", self.stubs.join("healthcheck.sh"));
    }

    /// Adds NSS_PASSWD/NSS_GROUP under out/.
    pub fn nss_env(&self, cmd: &mut Command) {
        cmd.env("NSS_PASSWD", self.out.join("nss_passwd"))
            .env("NSS_GROUP", self.out.join("nss_group"));
    }

    /// Rewrites the config with `from` replaced by `to`.
    pub fn edit_conf(&self, from: &str, to: &str) {
        let text = fs::read_to_string(&self.conf).unwrap();
        fs::write(&self.conf, text.replace(from, to)).unwrap();
    }
}

/// Run a one-shot probe command; returns exit status + combined output.
pub fn run_to_exit(cmd: &mut Command) -> (ExitStatus, String) {
    let output = cmd.output().expect("run startup subcommand");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status, combined)
}

/// Long-running supervisor with piped output captured by reader threads.
pub struct Supervised {
    child: Child,
    log: Arc<Mutex<String>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Supervised {
    pub fn spawn(cmd: &mut Command) -> Self {
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn supervisor");
        let log = Arc::new(Mutex::new(String::new()));
        let mut threads = Vec::new();
        let stdout = child.stdout.take().expect("stdout");
        let stderr = child.stderr.take().expect("stderr");
        let log_out = Arc::clone(&log);
        threads.push(std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let mut buf = log_out.lock().unwrap();
                buf.push_str(&line);
                buf.push('\n');
            }
        }));
        let log_err = Arc::clone(&log);
        threads.push(std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut buf = log_err.lock().unwrap();
                buf.push_str(&line);
                buf.push('\n');
            }
        }));
        Supervised {
            child,
            log,
            threads,
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// Poll the captured log until `pred` matches; panic with the log on timeout.
    pub fn wait_for(&self, timeout: Duration, what: &str, pred: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + timeout;
        loop {
            let combined = self.log();
            if pred(&combined) {
                return;
            }
            assert!(deadline > Instant::now(), "{what}; log={combined:?}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Deliver a real OS SIGHUP to the supervisor process.
    pub fn sighup(&self) {
        assert!(
            Command::new("kill")
                .args(["-HUP", &self.pid().to_string()])
                .status()
                .expect("kill -HUP")
                .success(),
            "must deliver real OS SIGHUP to running supervisor"
        );
    }

    /// Deliver a real OS SIGUSR1 (forced full recycle) to the supervisor.
    pub fn sigusr1(&self) {
        assert!(
            Command::new("kill")
                .args(["-USR1", &self.pid().to_string()])
                .status()
                .expect("kill -USR1")
                .success(),
            "must deliver real OS SIGUSR1 to running supervisor"
        );
    }

    /// Wait for self-termination (probe modes); returns status + log.
    pub fn wait_exit(mut self) -> (ExitStatus, String) {
        let status = self.child.wait().expect("wait supervisor");
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        let log = self.log();
        (status, log)
    }

    /// Kill, reap, join readers; returns the final log.
    pub fn stop_and_log(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        self.log()
    }
}

impl Drop for Supervised {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
