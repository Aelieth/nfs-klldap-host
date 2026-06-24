//! Pid-1 supervisor migrated from entrypoint.sh: preflight, service ordering, SIGHUP recycle.
#![allow(unsafe_code)]

use std::fs::{self, OpenOptions};

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use nfs_klldap_config::{
    compute_startup_step, compute_wizard_step, is_preconfigured_deployment,
    is_setup_wizard_complete, mark_setup_wizard_complete, resolve_keytab_path,
    supervisor_loop_tick, webui_setup_url, NfsKlldapConfig, SupervisorLoopAction,
};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGHUP_REQUESTED: AtomicBool = AtomicBool::new(false);

const BULK_SEED_MARKER: &str = "/var/lib/nfs-klldap/.bulk_seed_done";
const RECYCLE_MARKER: &str = "/tmp/.nfs-klldap-services-recycled";
const NSS_PIPE: &str = "/var/lib/sss/pipes/nss";

/// Runtime paths and binaries (override via env for CI).
struct SupervisorEnv {
    nfs_config: PathBuf,
    sssd_conf: PathBuf,
    krb5_conf: PathBuf,
    ganesha_conf: PathBuf,
    exports_dir: PathBuf,
    idmap_conf: PathBuf,
    config_bin: PathBuf,
    ui_bin: PathBuf,
    watcher_bin: PathBuf,
    idhelper_bin: PathBuf,
    healthcheck: PathBuf,
    nss_passwd: PathBuf,
    nss_group: PathBuf,
    nss_wrapper_so: PathBuf,
    use_nss_wrapper: bool,
    log_format_json: bool,
    /// CI one-shot path: generate + log preconf bring-up, then exit (no daemon loop).
    supervise_probe: bool,
    /// CI one-shot: bounded loop after post-wizard SIGHUP (wizard marker + complete conf).
    supervise_wizard_probe: bool,
    /// CI: run supervisor_loop with probe stubs until a real SIGHUP (no auto-posted HUP).
    supervise_loop_probe: bool,
    /// HOST_NFS sidecar mode: generate fragments for host Ganesha, skip in-container nfsd.
    host_nfs_mode: bool,
    /// Loop sleep override (ms); 0 for wizard-probe bounded ticks.
    supervisor_tick_ms: u64,
    /// Max loop iterations before exit when supervise_wizard_probe is set.
    supervisor_max_ticks: u32,
}

impl SupervisorEnv {
    fn from_env(config_path: &Path) -> Self {
        let env_path = |key: &str, default: &str| -> PathBuf {
            std::env::var(key)
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(default))
        };
        let use_nss = std::env::var("USE_NSS_WRAPPER")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        Self {
            nfs_config: config_path.to_path_buf(),
            sssd_conf: env_path("SSSD_CONF", "/etc/sssd/sssd.conf"),
            krb5_conf: env_path("KRB5_CONF", "/etc/krb5.conf"),
            ganesha_conf: env_path("GANESHA_CONF", "/etc/ganesha/ganesha.conf"),
            exports_dir: env_path("EXPORTS_DIR", "/etc/ganesha/exports.d"),
            idmap_conf: env_path("IDMAP_CONF", "/etc/idmapd.conf"),
            config_bin: env_path("CONFIG_BIN", "/usr/local/bin/nfs-klldap-config"),
            ui_bin: env_path("UI_BIN", "/usr/local/bin/nfs-klldap-ui"),
            watcher_bin: env_path("WATCHER_BIN", "/usr/local/bin/nfs-klldap-conf-watcher"),
            idhelper_bin: env_path("IDHELPER_BIN", "/usr/local/bin/nfs-klldap-idhelper"),
            healthcheck: env_path("HEALTHCHECK", "/container/healthcheck.sh"),
            nss_passwd: env_path("NSS_PASSWD", "/var/lib/nfs-klldap/nss_passwd"),
            nss_group: env_path("NSS_GROUP", "/var/lib/nfs-klldap/nss_group"),
            nss_wrapper_so: resolve_nss_wrapper_so(),
            use_nss_wrapper: use_nss,
            log_format_json: std::env::var("LOG_FORMAT")
                .map(|v| v == "json")
                .unwrap_or(false),
            supervise_probe: std::env::var("NFS_KLLDAP_SUPERVISE_PROBE")
                .is_ok_and(|v| v == "1"),
            supervise_wizard_probe: std::env::var("NFS_KLLDAP_SUPERVISE_WIZARD_PROBE")
                .is_ok_and(|v| v == "1"),
            supervise_loop_probe: std::env::var("NFS_KLLDAP_SUPERVISE_LOOP_PROBE")
                .is_ok_and(|v| v == "1"),
            host_nfs_mode: resolve_host_nfs_mode(config_path),
            supervisor_tick_ms: std::env::var("NFS_KLLDAP_SUPERVISOR_TICK_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2000),
            supervisor_max_ticks: std::env::var("NFS_KLLDAP_SUPERVISOR_MAX_TICKS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(12),
        }
    }
}

fn host_nfs_from_env() -> Option<bool> {
    std::env::var("HOST_NFS")
        .or_else(|_| std::env::var("NFS_KLLDAP_HOST_NFS"))
        .ok()
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            t == "true" || t == "1" || t == "yes" || t == "on"
        })
}

fn resolve_host_nfs_mode(config_path: &Path) -> bool {
    if let Some(val) = host_nfs_from_env() {
        return val;
    }
    NfsKlldapConfig::load(config_path)
        .map(|cfg| cfg.is_host_nfs())
        .unwrap_or(false)
}

#[derive(Default)]
struct ChildPids {
    watcher: Option<u32>,
    sssd: Option<u32>,
    ganesha: Option<u32>,
    webui: Option<u32>,
    dbus: Option<u32>,
    idhelper: Option<u32>,
}

struct Supervisor {
    env: SupervisorEnv,
    pids: ChildPids,
    services_started: bool,
}

/// Entry point for pid-1 supervision (replaces entrypoint.sh main loop).
pub fn run_supervisor(config_path: &Path) -> Result<(), String> {
    install_signal_handlers()?;
    let env = SupervisorEnv::from_env(config_path);
    let mut sup = Supervisor {
        env,
        pids: ChildPids::default(),
        services_started: false,
    };

    sup.log_info("=== Starting nfs-klldap-host (Rust supervisor) ===");
    if sup.env.host_nfs_mode {
        sup.log_info("HOST_NFS mode active — container is management sidecar only.");
        sup.log_info("  Ganesha fragments will be written for the *host* NFS server (e.g. at /etc/ganesha).");
        sup.log_info("  Kerberos (keytab) + LDAP/SSSD identity + WebUI permission management remain in-container.");
    }
    if sup.env.supervise_probe {
        sup.log_info("Supervise-probe mode enabled");
    }
    sup.preflight_checks()?;
    sup.ensure_config_initialized()?;
    sup.start_webui()?;

    let bypass = is_preconfigured_deployment(&sup.env.nfs_config, &resolve_keytab_path());
    if bypass {
        let _ = mark_setup_wizard_complete();
        sup.log_info("Pre-configured deployment detected — starting full service stack");
        sup.bring_up_services()?;
        sup.services_started = true;
        sup.start_watcher()?;
        let _ = fs::remove_file(RECYCLE_MARKER);
        sup.log_info("Container is ready (pre-configured path).");
    } else {
        sup.log_info(&format!(
            "First-run setup required — WebUI wizard at {}",
            webui_setup_url()
        ));
        let _ = fs::remove_file(RECYCLE_MARKER);
        if sup.env.supervise_wizard_probe && is_setup_wizard_complete() {
            sup.log_info("Supervise-wizard-probe: posting SIGHUP for bounded loop recycle");
            SIGHUP_REQUESTED.store(true, Ordering::SeqCst);
            return sup.supervisor_loop();
        }
    }

    sup.supervisor_loop()
}

impl Supervisor {
    fn log_info(&self, msg: &str) {
        log_line("INFO", msg, self.env.log_format_json);
    }

    fn log_warn(&self, msg: &str) {
        log_line("WARN", msg, self.env.log_format_json);
    }

    fn log_error(&self, msg: &str) {
        log_line("ERROR", msg, self.env.log_format_json);
    }

    fn preflight_checks(&self) -> Result<(), String> {
        let mut missing = false;
        for bin in [
            &self.env.config_bin,
            &self.env.ui_bin,
            &self.env.watcher_bin,
            &self.env.idhelper_bin,
            &self.env.healthcheck,
        ] {
            if !is_executable(bin) {
                self.log_error(&format!("Required binary missing: {}", bin.display()));
                missing = true;
            }
        }
        if !self.env.supervise_probe
            && Command::new("which")
                .arg("inotifywait")
                .output()
                .map(|o| !o.status.success())
                .unwrap_or(true)
        {
            self.log_error("inotifywait not found (inotify-tools required)");
            missing = true;
        }
        if self.env.use_nss_wrapper && !self.env.nss_wrapper_so.is_file() {
            self.log_error(&format!(
                "libnss_wrapper.so not found at {}",
                self.env.nss_wrapper_so.display()
            ));
            missing = true;
        }
        if missing {
            return Err("Preflight failed — container image is incomplete".into());
        }
        self.log_info("Preflight checks passed");
        Ok(())
    }

    fn ensure_config_initialized(&self) -> Result<(), String> {
        if self.env.nfs_config.is_file() {
            return Ok(());
        }
        self.log_info(&format!(
            "No config at {} — initializing default",
            self.env.nfs_config.display()
        ));
        let status = Command::new(&self.env.config_bin)
            .args(["init", "--config"])
            .arg(&self.env.nfs_config)
            .status()
            .map_err(|e| format!("config init failed: {e}"))?;
        if !status.success() {
            return Err("Failed to initialize default nfs-klldap.conf".into());
        }
        Ok(())
    }

    fn bring_up_services(&mut self) -> Result<(), String> {
        self.log_info(&format!(
            "Generating derived configuration from {}",
            self.env.nfs_config.display()
        ));
        let status = Command::new(&self.env.config_bin)
            .args(["generate", "--config"])
            .arg(&self.env.nfs_config)
            .status()
            .map_err(|e| format!("generate failed: {e}"))?;
        if !status.success() {
            return Err("Initial config generation failed".into());
        }
        self.fix_derived_permissions();
        for d in [
            "/var/lib/nfs-klldap",
            "/var/run/nfs-klldap",
            "/var/lib/extrausers",
        ] {
            let _ = fs::create_dir_all(d);
        }
        if self.env.supervise_probe {
            self.seed_probe_runtime_state();
            self.log_info("Supervise-probe: derived configs generated; daemon bring-up skipped");
            return Ok(());
        }
        self.restart_sssd_and_wait();
        if !Path::new(NSS_PIPE).exists() {
            return Err("SSSD NSS pipe did not appear — check LLDAP connectivity".into());
        }
        self.restart_idhelper_and_wait_bulk();
        if self.env.host_nfs_mode {
            self.log_info("HOST_NFS mode: skipping in-container ganesha.nfsd (host NFS server will serve the exports).");
        } else {
            self.ensure_ganesha_prereqs();
            self.log_info("Starting NFS-Ganesha...");
            self.start_ganesha();
        }
        self.start_webui()?;
        if self.env.host_nfs_mode {
            self.log_info("HOST_NFS: host NFS server is responsible for 2049; this container provides config, Kerberos material, identity mapping (SSSD), and the WebUI.");
        }
        Ok(())
    }

    /// Touch probe markers so bring-up checks pass without real SSSD/idhelper.
    fn seed_probe_runtime_state(&self) {
        if let Some(parent) = Path::new(NSS_PIPE).parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(NSS_PIPE, b"probe");
        let _ = fs::create_dir_all("/var/lib/nfs-klldap");
        let _ = fs::write(BULK_SEED_MARKER, b"probe\n");
        if let Some(parent) = self.env.nss_passwd.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(
            &self.env.nss_passwd,
            b"root:x:0:0:root:/root:/bin/sh\n",
        );
    }

    fn start_watcher(&mut self) -> Result<(), String> {
        if self.env.supervise_probe {
            self.log_info("Supervise-probe: config watcher start skipped");
            return Ok(());
        }
        self.log_info("Starting config watcher...");
        let child = Command::new(&self.env.watcher_bin)
            .arg(&self.env.nfs_config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("watcher spawn failed: {e}"))?;
        self.pids.watcher = Some(child.id());
        Ok(())
    }

    fn supervisor_loop(&mut self) -> Result<(), String> {
        if self.env.supervise_probe
            && !self.env.supervise_wizard_probe
            && !self.env.supervise_loop_probe
        {
            self.log_info("Supervise probe complete — exiting");
            return Ok(());
        }
        let bounded = self.env.supervise_wizard_probe;
        let max_ticks = if bounded {
            self.env.supervisor_max_ticks
        } else {
            u32::MAX
        };
        let mut ticks = 0u32;
        loop {
            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                self.cleanup("termination signal");
                return Ok(());
            }
            let sighup_pending = SIGHUP_REQUESTED.swap(false, Ordering::SeqCst);
            let wizard_complete = is_setup_wizard_complete();
            let step = if self.env.supervise_probe {
                compute_wizard_step(&self.env.nfs_config)
            } else {
                compute_startup_step(&self.env.nfs_config)
            };
            let (action, _) = supervisor_loop_tick(
                self.services_started,
                sighup_pending,
                wizard_complete,
                step,
            );
            match action {
                SupervisorLoopAction::ProcessSighup => {
                    let need_watcher = self.pids.watcher.is_none();
                    self.handle_sighup()?;
                    self.services_started = true;
                    if need_watcher {
                        let _ = self.start_watcher();
                    }
                }
                SupervisorLoopAction::BringUpServices => {
                    let _ = mark_setup_wizard_complete();
                    self.log_info("Setup wizard complete — bringing up services");
                    if self.bring_up_services().is_ok() {
                        self.services_started = true;
                        let _ = self.start_watcher();
                        self.touch_recycle_marker();
                        self.log_info("Container is ready.");
                    }
                }
                SupervisorLoopAction::Idle => {}
            }
            reap_one_child();
            ticks = ticks.saturating_add(1);
            if bounded && ticks >= max_ticks {
                if !Path::new(RECYCLE_MARKER).is_file() {
                    return Err("wizard probe: recycle marker missing after bounded loop".into());
                }
                self.log_info("Supervise wizard probe complete — exiting");
                return Ok(());
            }
            thread::sleep(Duration::from_millis(self.env.supervisor_tick_ms));
        }
    }

    fn handle_sighup(&mut self) -> Result<(), String> {
        self.log_info("SIGHUP received — reloading configuration...");
        let status = Command::new(&self.env.config_bin)
            .args(["generate", "--config"])
            .arg(&self.env.nfs_config)
            .status()
            .map_err(|e| format!("generate on SIGHUP failed: {e}"))?;
        if !status.success() {
            self.log_error("Config generator failed during SIGHUP reload");
            return Err("SIGHUP generate failed".into());
        }
        self.fix_derived_permissions();
        self.env.host_nfs_mode = resolve_host_nfs_mode(&self.env.nfs_config);
        self.recycle_services_after_config();
        self.log_info("Services recycled after config apply.");
        if !self.services_started {
            self.services_started = true;
            let _ = self.start_watcher();
        }
        self.touch_recycle_marker();
        Ok(())
    }

    /// Signal to the WebUI restart poller that SSSD, idhelper, Ganesha, and WebUI are up.
    fn touch_recycle_marker(&self) {
        if let Ok(mut f) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(RECYCLE_MARKER)
        {
            use std::io::Write;
            let _ = writeln!(f, "ok");
        }
    }

    fn cleanup(&mut self, reason: &str) {
        self.log_info(&format!("Shutting down services (received {reason})..."));
        for pid in [
            self.pids.webui,
            self.pids.ganesha,
            self.pids.sssd,
            self.pids.watcher,
            self.pids.dbus,
            self.pids.idhelper,
        ]
        .into_iter()
        .flatten()
        {
            signal_process(pid, libc::SIGTERM);
        }
        pkill_process("-TERM", "ganesha.nfsd");
        pkill_process("-TERM", "sssd");
        pkill_binary("-TERM", &self.env.watcher_bin);
        pkill_process("-TERM", "dbus-daemon");
        pkill_binary("-TERM", &self.env.idhelper_bin);
        thread::sleep(Duration::from_secs(1));
        self.log_info("Shutdown complete.");
        std::process::exit(0);
    }

    fn fix_derived_permissions(&self) {
        chmod_file(&self.env.sssd_conf, 0o600);
        chmod_file(&self.env.krb5_conf, 0o644);
        chmod_file(&self.env.idmap_conf, 0o644);
        if self.env.ganesha_conf.is_file() {
            chmod_file(&self.env.ganesha_conf, 0o644);
        }
        let _ = Command::new("chmod")
            .args(["-R", "a+rX"])
            .arg(&self.env.exports_dir)
            .status();
    }

    fn stop_ganesha(&mut self) {
        if let Some(pid) = self.pids.ganesha {
            signal_process(pid, libc::SIGTERM);
        }
        pkill_process("-TERM", "ganesha.nfsd");
        thread::sleep(Duration::from_millis(300));
        self.pids.ganesha = None;
    }

    fn recycle_services_after_config(&mut self) {
        let _ = fs::create_dir_all("/var/lib/nfs-klldap");
        let _ = fs::create_dir_all("/var/run/nfs-klldap");
        let _ = fs::create_dir_all("/var/lib/extrausers");
        if self.env.supervise_probe {
            self.seed_probe_runtime_state();
            self.log_info("Supervise-probe: service recycle simulated (SSSD/Ganesha/WebUI)");
            return;
        }
        if !self.env.host_nfs_mode {
            self.stop_ganesha();
        }
        self.restart_sssd_and_wait();
        self.restart_idhelper_and_wait_bulk();
        if self.env.host_nfs_mode {
            self.log_info("HOST_NFS mode: skipping Ganesha restart (host owns the NFS server; fragments were regenerated for it).");
        } else {
            self.ensure_ganesha_prereqs();
            self.log_info("Starting NFS-Ganesha after recycle...");
            self.start_ganesha();
        }
        let _ = self.start_webui();
    }

    fn quiet_winbind(&self) {
        if Command::new("which")
            .arg("wbinfo")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            let _ = std::os::unix::fs::symlink("/bin/false", "/usr/bin/wbinfo");
        }
    }

    // LD_PRELOAD nss_wrapper so Ganesha getpwnam sees idhelper-materialized passwd/group.
    fn start_ganesha(&mut self) {
        self.quiet_winbind();
        let mut cmd = Command::new("ganesha.nfsd");
        cmd.args(["-f"])
            .arg(&self.env.ganesha_conf)
            .args(["-L", "/var/log/ganesha.log"])
            .env("PATH", format!("/usr/local/bin:{}", std::env::var("PATH").unwrap_or_default()));
        if self.env.use_nss_wrapper {
            cmd.env("NSS_WRAPPER_PASSWD", &self.env.nss_passwd)
                .env("NSS_WRAPPER_GROUP", &self.env.nss_group)
                .env("LD_PRELOAD", &self.env.nss_wrapper_so);
        }
        if let Ok(child) = cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
            self.pids.ganesha = Some(child.id());
        }
    }

    fn start_webui(&mut self) -> Result<(), String> {
        if self.env.supervise_probe {
            self.log_info("Supervise-probe: WebUI start skipped (stub binaries)");
            return Ok(());
        }
        if let Some(pid) = self.pids.webui {
            signal_process(pid, libc::SIGTERM);
            thread::sleep(Duration::from_millis(300));
        }
        self.log_info("Starting WebUI on 0.0.0.0:9630...");
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/webui.log")
            .map_err(|e| format!("webui log open: {e}"))?;
        let child = Command::new(&self.env.ui_bin)
            .args(["--config"])
            .arg(&self.env.nfs_config)
            .env("NFS_KLLDAP_CONF", &self.env.nfs_config)
            .stdout(Stdio::from(log_file.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log_file))
            .spawn()
            .map_err(|e| format!("webui spawn failed: {e}"))?;
        self.pids.webui = Some(child.id());
        thread::sleep(Duration::from_millis(800));
        Ok(())
    }

    fn restart_sssd_and_wait(&mut self) {
        if let Some(pid) = self.pids.sssd {
            signal_process(pid, libc::SIGTERM);
        }
        pkill_process("-TERM", "sssd");
        thread::sleep(Duration::from_millis(500));
        self.log_info("Starting SSSD...");
        let mut cmd = Command::new("sssd");
        cmd.args(["-i", "--logger=files"]);
        if let Ok(level) = std::env::var("SSSD_DEBUG_LEVEL") {
            cmd.args(["-d", &level]);
        }
        if let Ok(child) = cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
            self.pids.sssd = Some(child.id());
        }
        self.log_info("Waiting for SSSD NSS responder...");
        for _ in 0..60 {
            if Path::new(NSS_PIPE).exists() {
                self.log_info("SSSD ready");
                return;
            }
            thread::sleep(Duration::from_millis(300));
        }
        self.log_warn("SSSD NSS pipe did not appear — identity mapping may be degraded");
    }

    fn refresh_idhelper_preresolve(&self) {
        let host = Command::new("hostname")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                fs::read_to_string("/proc/sys/kernel/hostname")
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "localhost".into());
        let realm = fs::read_to_string(&self.env.krb5_conf)
            .ok()
            .and_then(|c| {
                c.lines()
                    .find(|l| l.contains("default_realm"))
                    .and_then(|l| l.split_whitespace().nth(2))
                    .map(|s| s.to_string())
            })
            .or_else(|| std::env::var("NFS_KLLDAP_KERBEROS_REALM").ok())
            .unwrap_or_else(|| "EXAMPLE.COM".into());
        let short = host.split('.').next().unwrap_or(&host).to_string();
        let mut pre = std::env::var("NFS_KLLDAP_IDHELPER_PRERESOLVE").unwrap_or_default();
        for v in [&host, &short] {
            let p = format!("host/{v}@{realm}");
            if !pre.split(',').any(|x| x == p) {
                if !pre.is_empty() {
                    pre.push(',');
                }
                pre.push_str(&p);
            }
        }
        std::env::set_var("NFS_KLLDAP_IDHELPER_PRERESOLVE", &pre);
    }

    fn restart_idhelper_and_wait_bulk(&mut self) {
        self.refresh_idhelper_preresolve();
        if let Some(pid) = self.pids.idhelper {
            signal_process(pid, libc::SIGTERM);
            thread::sleep(Duration::from_millis(200));
        }
        pkill_binary("-TERM", &self.env.idhelper_bin);
        thread::sleep(Duration::from_millis(200));
        self.log_info("Starting nfs-klldap-idhelper...");
        let mut cmd = Command::new(&self.env.idhelper_bin);
        cmd.arg("daemon");
        if let Ok(f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/idhelper.log")
        {
            if let Ok(f2) = f.try_clone() {
                cmd.stdout(Stdio::from(f)).stderr(Stdio::from(f2));
            }
        }
        if let Ok(child) = cmd.spawn() {
            self.pids.idhelper = Some(child.id());
        }
        for _ in 0..60 {
            if Path::new(BULK_SEED_MARKER).is_file()
                && fs::read_to_string("/var/lib/nfs-klldap/nss_passwd")
                    .map(|s| s.lines().any(|l| l.starts_with("root:")))
                    .unwrap_or(false)
            {
                self.log_info("idhelper preload ready");
                return;
            }
            thread::sleep(Duration::from_millis(200));
        }
        self.log_warn("idhelper bulk-seed marker missing after reload");
    }

    fn ensure_ganesha_prereqs(&mut self) {
        if Command::new("which")
            .arg("rpcbind")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
            && !pgrep_running("rpcbind")
        {
            self.log_info("Starting rpcbind...");
            let _ = Command::new("rpcbind").arg("-w").status();
            if !pgrep_running("rpcbind") {
                let _ = Command::new("rpcbind").status();
            }
        }
        let _ = fs::create_dir_all("/run/dbus");
        let _ = fs::remove_file("/run/dbus/pid");
        if !pgrep_running("dbus-daemon") {
            self.log_info("Starting dbus-daemon...");
            if let Ok(child) = Command::new("dbus-daemon")
                .args(["--system", "--nofork"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                self.pids.dbus = Some(child.id());
                thread::sleep(Duration::from_millis(500));
            }
        }
        for _ in 0..50 {
            if Path::new("/run/dbus/system_bus_socket").exists()
                && Command::new("dbus-send")
                    .args([
                        "--system",
                        "--print-reply",
                        "--dest=org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus.ListNames",
                    ])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            {
                self.log_info("D-Bus system bus is ready");
                return;
            }
            thread::sleep(Duration::from_millis(200));
        }
        self.log_warn("D-Bus system bus socket did not appear");
    }
}

fn log_line(level: &str, msg: &str, json: bool) {
    let ts = chrono_lite_timestamp();
    if json {
        let escaped = msg.replace('\\', "\\\\").replace('"', "\\\"");
        println!(r#"{{"ts":"{ts}","level":"{level}","msg":"{escaped}"}}"#);
    } else {
        println!("[{ts}] {level:<5} {msg}");
    }
}

fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", dur.as_secs(), dur.subsec_millis())
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn chmod_file(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(mode);
            let _ = fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

fn resolve_nss_wrapper_so() -> PathBuf {
    if let Ok(p) = std::env::var("NSS_WRAPPER_SO") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(out) = Command::new("dpkg-architecture")
        .args(["-qDEB_HOST_MULTIARCH"])
        .output()
    {
        let arch = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !arch.is_empty() {
            let cand = PathBuf::from(format!("/usr/lib/{arch}/libnss_wrapper.so"));
            if cand.is_file() {
                return cand;
            }
        }
    }
    for cand in [
        "/usr/lib/x86_64-linux-gnu/libnss_wrapper.so",
        "/usr/lib/aarch64-linux-gnu/libnss_wrapper.so",
        "/usr/lib/libnss_wrapper.so",
    ] {
        let p = PathBuf::from(cand);
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from("/usr/lib/x86_64-linux-gnu/libnss_wrapper.so")
}

/// Linux TASK_COMM_LEN — names longer than this must use cmdline matching.
const PROC_COMM_NAME_MAX: usize = 15;

fn pkill_process(signal: &str, ident: &str) {
    let mut cmd = Command::new("pkill");
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    if ident.len() > PROC_COMM_NAME_MAX {
        cmd.args([signal, "-f", "--", ident]);
    } else {
        cmd.args([signal, ident]);
    }
    let _ = cmd.status();
}

fn pkill_binary(signal: &str, bin: &Path) {
    pkill_process(signal, &bin.to_string_lossy());
}

fn pgrep_running(name: &str) -> bool {
    let mut cmd = Command::new("pgrep");
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    if name.len() > PROC_COMM_NAME_MAX {
        cmd.args(["-f", "--", name]);
    } else {
        cmd.arg("-x").arg(name);
    }
    cmd.output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod pkill_tests {
    use super::*;

    #[test]
    fn proc_comm_name_max_matches_linux_task_comm_len() {
        assert_eq!(PROC_COMM_NAME_MAX, 15);
        assert!("nfs-klldap-idhelper".len() > PROC_COMM_NAME_MAX);
        assert!("nfs-klldap-conf-watcher".len() > PROC_COMM_NAME_MAX);
        assert!("ganesha.nfsd".len() <= PROC_COMM_NAME_MAX);
    }
}

fn signal_process(pid: u32, sig: i32) {
    unsafe {
        libc::kill(pid as i32, sig);
    }
}

fn reap_one_child() {
    unsafe {
        let mut status: i32 = 0;
        libc::waitpid(-1, &mut status, libc::WNOHANG);
    }
}

fn install_signal_handlers() -> Result<(), String> {
    unsafe {
        libc::signal(libc::SIGTERM, handle_shutdown as *const () as usize);
        libc::signal(libc::SIGINT, handle_shutdown as *const () as usize);
        libc::signal(libc::SIGHUP, handle_sighup as *const () as usize);
        // SIGCHLD left default so Command::status can wait on short-lived children (generate).
        // Long-running daemons are reaped in supervisor_loop via reap_one_child().
    }
    Ok(())
}

extern "C" fn handle_shutdown(_: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

extern "C" fn handle_sighup(_: i32) {
    SIGHUP_REQUESTED.store(true, Ordering::SeqCst);
}

// Minimal libc bindings (no extra crate dependency).
mod libc {
    pub const SIGTERM: i32 = 15;
    pub const SIGINT: i32 = 2;
    pub const SIGHUP: i32 = 1;
    pub const WNOHANG: i32 = 1;

    extern "C" {
        pub fn signal(sig: i32, handler: usize) -> usize;
        pub fn kill(pid: i32, sig: i32) -> i32;
        pub fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    }
}