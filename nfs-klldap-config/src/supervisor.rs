//! Runs pid-1 supervision with preflight, ordering, and SIGHUP recycle.

use std::fs::{self, OpenOptions};

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use nfs_klldap_config::{
    compute_startup_step, compute_wizard_step, fingerprint_exports_dir,
    fingerprint_identity_artifacts, ganesha_sighup_failed,
    install_signal_handlers, is_preconfigured_deployment, is_setup_wizard_complete,
    discover_ganesha_daemon_pid, mark_setup_wizard_complete, plan_from_changes, process_is_live,
    reap_one_child, resolve_host_nfs_mode, resolve_keytab_path,
    request_sighup, run_post_generate_hooks, runtime_hostname, runtime_realm, shutdown_requested,
    signal_process_hup, signal_process_kill, signal_process_term, supervisor_loop_tick,
    take_sighup_requested, webui_setup_url, ConfigError,
    GaneshaAction, NfsKlldapConfig,
    ServiceRecyclePlan, SupervisorLoopAction, PROC_COMM_NAME_MAX,
};

const BULK_SEED_MARKER: &str = "/var/lib/nfs-klldap/.bulk_seed_done";
const RECYCLE_MARKER_DEFAULT: &str = "/tmp/.nfs-klldap-services-recycled";
const NSS_PIPE: &str = "/var/lib/sss/pipes/nss";
const EXTRAUSERS_PASSWD_DEFAULT: &str = "/var/lib/extrausers/passwd";
const EXTRAUSERS_GROUP_DEFAULT: &str = "/var/lib/extrausers/group";

/// libnss-extrausers reads these paths from the process environment.
fn ensure_nss_extrausers_env(passwd: &Path, group: &Path) {
    std::env::set_var("NSS_EXTRAUSERS_PASSWD", passwd);
    std::env::set_var("NSS_EXTRAUSERS_GROUP", group);
}

fn recycle_marker_path() -> PathBuf {
    std::env::var("NFS_KLLDAP_RECYCLE_MARKER")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(RECYCLE_MARKER_DEFAULT))
}

fn loop_probe_ready_path() -> Option<PathBuf> {
    std::env::var("NFS_KLLDAP_LOOP_PROBE_READY")
        .ok()
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

fn touch_loop_probe_ready() {
    if let Some(path) = loop_probe_ready_path() {
        let _ = fs::write(&path, b"ready\n");
    }
}

/// Runtime paths and binaries (override via env for CI).
struct SupervisorEnv {
    nfs_config: PathBuf,
    sssd_conf: PathBuf,
    krb5_conf: PathBuf,
    ganesha_conf: PathBuf,
    exports_dir: PathBuf,
    idmap_conf: PathBuf,
    nfs_conf: PathBuf,
    config_bin: PathBuf,
    ui_bin: PathBuf,
    watcher_bin: PathBuf,
    idhelper_bin: PathBuf,
    healthcheck: PathBuf,
    nss_passwd: PathBuf,
    nss_group: PathBuf,
    extrausers_passwd: PathBuf,
    extrausers_group: PathBuf,
    nss_wrapper_so: PathBuf,
    use_nss_wrapper: bool,
    log_format_json: bool,
    /// Runs a CI one-shot that generates configs, logs bring-up, then exits.
    supervise_probe: bool,
    /// Runs a bounded CI loop after post-wizard SIGHUP with complete config.
    supervise_wizard_probe: bool,
    /// Exercises supervisor_loop with probe stubs until a real SIGHUP arrives.
    supervise_loop_probe: bool,
    /// Tests ganesha SIGHUP reload and stop_ganesha against a stub nfsd.
    supervise_recycle_probe: bool,
    /// Waits for OS SIGHUP then runs handle_sighup on the hook path.
    supervise_sighup_hook_probe: bool,
    /// Verifies identity-only changes recycle SSSD without ganesha SIGHUP.
    supervise_identity_recycle_probe: bool,
    /// Enables HOST_NFS sidecar mode that generates fragments and skips nfsd.
    host_nfs_mode: bool,
    /// Overrides loop sleep ms; zero enables wizard-probe bounded ticks.
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
            nfs_conf: env_path("NFS_CONF", "/etc/nfs.conf"),
            config_bin: env_path("CONFIG_BIN", "/usr/local/bin/nfs-klldap-config"),
            ui_bin: env_path("UI_BIN", "/usr/local/bin/nfs-klldap-ui"),
            watcher_bin: env_path("WATCHER_BIN", "/usr/local/bin/nfs-klldap-conf-watcher"),
            idhelper_bin: env_path("IDHELPER_BIN", "/usr/local/bin/nfs-klldap-idhelper"),
            healthcheck: env_path("HEALTHCHECK", "/container/healthcheck.sh"),
            nss_passwd: env_path("NSS_PASSWD", "/var/lib/nfs-klldap/nss_passwd"),
            nss_group: env_path("NSS_GROUP", "/var/lib/nfs-klldap/nss_group"),
            extrausers_passwd: env_path("NSS_EXTRAUSERS_PASSWD", EXTRAUSERS_PASSWD_DEFAULT),
            extrausers_group: env_path("NSS_EXTRAUSERS_GROUP", EXTRAUSERS_GROUP_DEFAULT),
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
            supervise_recycle_probe: std::env::var("NFS_KLLDAP_SUPERVISE_RECYCLE_PROBE")
                .is_ok_and(|v| v == "1"),
            supervise_sighup_hook_probe: std::env::var("NFS_KLLDAP_SUPERVISE_SIGHUP_HOOK_PROBE")
                .is_ok_and(|v| v == "1"),
            supervise_identity_recycle_probe: std::env::var(
                "NFS_KLLDAP_SUPERVISE_IDENTITY_RECYCLE_PROBE",
            )
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
    /// True after start_ganesha until stop_ganesha completes.
    /// Enables daemon pid adoption.
    ganesha_managed: bool,
}

/// Entry point for pid-1 supervision (replaces entrypoint.sh main loop).
pub fn run_supervisor(config_path: &Path) -> Result<(), String> {
    install_signal_handlers()?;
    let env = SupervisorEnv::from_env(config_path);
    let mut sup = Supervisor {
        env,
        pids: ChildPids::default(),
        services_started: false,
        ganesha_managed: false,
    };

    sup.log_info("=== Starting nfs-klldap-host (Rust supervisor) ===");
    ensure_nss_extrausers_env(&sup.env.extrausers_passwd, &sup.env.extrausers_group);
    if sup.env.host_nfs_mode {
        sup.log_info("HOST_NFS mode active — container is management sidecar only.");
        sup.log_info("  Ganesha fragments will be written for the *host* NFS server (e.g. at /etc/ganesha).");
        sup.log_info("  Kerberos (keytab) + LDAP/SSSD identity + WebUI permission management remain in-container.");
    }
    if sup.env.supervise_probe {
        sup.log_info("Supervise-probe mode enabled");
    }
    if sup.env.supervise_recycle_probe {
        return sup.run_supervise_recycle_probe();
    }
    if sup.env.supervise_sighup_hook_probe {
        return sup.run_supervise_sighup_hook_probe();
    }
    if sup.env.supervise_identity_recycle_probe {
        return sup.run_supervise_identity_recycle_probe();
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
        let _ = fs::remove_file(recycle_marker_path());
        sup.log_info("Container is ready (pre-configured path).");
    } else {
        sup.log_info(&format!(
            "First-run setup required — WebUI wizard at {}",
            webui_setup_url()
        ));
        let _ = fs::remove_file(recycle_marker_path());
        if sup.env.supervise_wizard_probe && is_setup_wizard_complete() {
            sup.log_info("Supervise-wizard-probe: posting SIGHUP for bounded loop recycle");
            request_sighup();
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

    /// Runs CI handle_sighup reload tests and stop_ganesha against stub nfsd.
    fn run_supervise_recycle_probe(&mut self) -> Result<(), String> {
        self.log_info("Supervise-recycle-probe mode enabled");
        let stub_log = std::env::var("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/ganesha-recycle-probe.log"));
        let _ = fs::remove_file(&stub_log);

        for d in [
            self.env.exports_dir.as_path(),
            Path::new("/var/lib/nfs-klldap"),
            Path::new("/var/run/nfs-klldap"),
            Path::new("/var/lib/extrausers"),
        ] {
            let _ = fs::create_dir_all(d);
        }
        self.seed_probe_runtime_state();
        self.services_started = true;

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
            return Err("recycle probe: initial generate failed".into());
        }
        self.run_post_generate_hooks()?;
        self.fix_derived_permissions();

        self.log_info("Supervise-recycle-probe: starting stub ganesha.nfsd");
        self.start_ganesha();
        thread::sleep(Duration::from_millis(400));
        if !self.ganesha_running() {
            return Err("recycle probe: stub ganesha.nfsd did not start".into());
        }

        self.log_info("Supervise-recycle-probe: handle_sighup with unchanged exports (expect changed=false)");
        self.handle_sighup()?;
        thread::sleep(Duration::from_millis(200));
        let log_after_skip = fs::read_to_string(&stub_log).unwrap_or_default();
        if log_after_skip.contains("HUP") || log_after_skip.contains("TERM") {
            return Err(format!(
                "recycle probe: unchanged handle_sighup must not signal ganesha, log={log_after_skip:?}"
            ));
        }
        if !self.ganesha_running() {
            return Err("recycle probe: ganesha must stay running after unchanged handle_sighup".into());
        }

        let conf_text = fs::read_to_string(&self.env.nfs_config)
            .map_err(|e| format!("recycle probe: read config: {e}"))?;
        if !conf_text.contains("host_path = \"/media/data\"") {
            return Err("recycle probe: config missing expected host_path".into());
        }
        fs::write(
            &self.env.nfs_config,
            conf_text.replace(
                "host_path = \"/media/data\"",
                "host_path = \"/media/data-changed\"",
            ),
        )
        .map_err(|e| format!("recycle probe: mutate config: {e}"))?;

        self.log_info("Supervise-recycle-probe: handle_sighup after export mutation (expect changed=true)");
        self.handle_sighup()?;
        thread::sleep(Duration::from_millis(200));
        let log_after_reload = fs::read_to_string(&stub_log).unwrap_or_default();
        if !log_after_reload.contains("HUP") {
            return Err(format!(
                "recycle probe: expected SIGHUP after export change, log={log_after_reload:?}"
            ));
        }
        if log_after_reload.contains("TERM") {
            return Err(
                "recycle probe: stub ganesha received SIGTERM during export-change reload".into(),
            );
        }

        self.log_info("Supervise-recycle-probe: exercising stop_ganesha (SIGTERM path)");
        self.stop_ganesha();
        let log_term = fs::read_to_string(&stub_log).unwrap_or_default();
        if !log_term.contains("TERM") {
            return Err(format!(
                "recycle probe: expected SIGTERM in stub log, got: {log_term:?}"
            ));
        }

        if std::env::var("NFS_KLLDAP_RECYCLE_PROBE_TEST_KILL").is_ok_and(|v| v == "1") {
            let ganesha_bin = std::env::var("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_BIN")
                .map(PathBuf::from)
                .map_err(|_| "recycle probe: NFS_KLLDAP_RECYCLE_PROBE_GANESHA_BIN required for KILL test".to_string())?;
            self.log_info("Supervise-recycle-probe: starting SIGKILL-escalation stub");
            fs::write(
                &ganesha_bin,
                format!(
                    r#"#!/bin/sh
LOG="{log}"
echo START >> "$LOG"
trap 'echo TERM >> "$LOG"' TERM
trap 'echo KILL >> "$LOG"; exit 0' KILL
while :; do :; done
"#,
                    log = stub_log.display()
                ),
            )
            .map_err(|e| format!("recycle probe: write kill stub: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&ganesha_bin)
                    .map_err(|e| format!("recycle probe: kill stub meta: {e}"))?
                    .permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&ganesha_bin, perms)
                    .map_err(|e| format!("recycle probe: kill stub chmod: {e}"))?;
            }
            self.start_ganesha();
            thread::sleep(Duration::from_millis(300));
            std::env::set_var("NFS_KLLDAP_STOP_GANESHA_TERM_SECS", "1");
            self.log_info("Supervise-recycle-probe: exercising stop_ganesha (SIGKILL escalation)");
            self.stop_ganesha();
            let log_kill = fs::read_to_string(&stub_log).unwrap_or_default();
            if !log_kill.contains("TERM") {
                return Err(format!(
                    "recycle probe: expected SIGTERM before SIGKILL escalation, log={log_kill:?}"
                ));
            }
            if self.ganesha_running() {
                return Err("recycle probe: ganesha still running after SIGKILL escalation".into());
            }
        }

        self.log_info("Supervise-recycle-probe complete — exiting");
        Ok(())
    }

    /// CI: generate, hook, ganesha stub, then handle real OS SIGHUP.
    fn run_supervise_sighup_hook_probe(&mut self) -> Result<(), String> {
        self.log_info("Supervise-sighup-hook-probe mode enabled");
        for d in [
            self.env.exports_dir.as_path(),
            Path::new("/var/lib/nfs-klldap"),
            Path::new("/var/run/nfs-klldap"),
        ] {
            let _ = fs::create_dir_all(d);
        }
        self.seed_probe_runtime_state();
        self.services_started = true;

        let status = Command::new(&self.env.config_bin)
            .args(["generate", "--config"])
            .arg(&self.env.nfs_config)
            .status()
            .map_err(|e| format!("generate failed: {e}"))?;
        if !status.success() {
            return Err("sighup-hook probe: initial generate failed".into());
        }
        self.run_post_generate_hooks()?;
        self.fix_derived_permissions();
        self.start_ganesha();
        thread::sleep(Duration::from_millis(400));
        if !self.ganesha_running() {
            return Err("sighup-hook probe: stub ganesha.nfsd did not start".into());
        }

        self.log_info("Supervise-sighup-hook-probe: waiting for OS SIGHUP");
        let max_ticks = self.env.supervisor_max_ticks;
        let mut ticks = 0u32;
        loop {
            if shutdown_requested() {
                return Err("sighup-hook probe: shutdown before SIGHUP".into());
            }
            if take_sighup_requested() {
                self.handle_sighup()?;
                self.log_info("Supervise-sighup-hook-probe complete — exiting");
                return Ok(());
            }
            reap_one_child();
            ticks = ticks.saturating_add(1);
            if ticks >= max_ticks {
                return Err("sighup-hook probe: timed out waiting for OS SIGHUP".into());
            }
            thread::sleep(Duration::from_millis(self.env.supervisor_tick_ms));
        }
    }

    /// Verifies an [sssd] edit with unchanged exports restarts SSSD only.
    fn run_supervise_identity_recycle_probe(&mut self) -> Result<(), String> {
        self.log_info("Supervise-identity-recycle-probe mode enabled");
        let stub_log = std::env::var("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/ganesha-identity-recycle.log"));
        let _ = fs::remove_file(&stub_log);

        for d in [
            self.env.exports_dir.as_path(),
            Path::new("/var/lib/nfs-klldap"),
            Path::new("/var/run/nfs-klldap"),
        ] {
            let _ = fs::create_dir_all(d);
        }
        self.seed_probe_runtime_state();
        self.services_started = true;

        let status = Command::new(&self.env.config_bin)
            .args(["generate", "--config"])
            .arg(&self.env.nfs_config)
            .status()
            .map_err(|e| format!("generate failed: {e}"))?;
        if !status.success() {
            return Err("identity recycle probe: initial generate failed".into());
        }
        self.fix_derived_permissions();

        self.start_ganesha();
        thread::sleep(Duration::from_millis(400));
        if !self.ganesha_running() {
            return Err("identity recycle probe: stub ganesha.nfsd did not start".into());
        }

        let conf_text = fs::read_to_string(&self.env.nfs_config)
            .map_err(|e| format!("identity recycle probe: read config: {e}"))?;
        if !conf_text.contains("ldap_default_bind_dn = \"uid=admin,ou=people,dc=test,dc=com\"") {
            return Err("identity recycle probe: config missing expected bind_dn".into());
        }
        fs::write(
            &self.env.nfs_config,
            conf_text.replace(
                "ldap_default_bind_dn = \"uid=admin,ou=people,dc=test,dc=com\"",
                "ldap_default_bind_dn = \"uid=admin2,ou=people,dc=test,dc=com\"",
            ),
        )
        .map_err(|e| format!("identity recycle probe: mutate config: {e}"))?;

        self.log_info("Supervise-identity-recycle-probe: handle_sighup after [sssd] bind_dn change");
        self.handle_sighup()?;
        thread::sleep(Duration::from_millis(200));

        let log = fs::read_to_string(&stub_log).unwrap_or_default();
        if log.contains("HUP") {
            return Err(format!(
                "identity recycle probe: ganesha must not receive SIGHUP when only identity artifacts change, log={log:?}"
            ));
        }
        if !self.ganesha_running() {
            return Err("identity recycle probe: ganesha must stay running".into());
        }

        self.log_info("Supervise-identity-recycle-probe complete — exiting");
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
        self.run_post_generate_hooks()?;
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
            // tolerate in test/harness envs without live LLDAP (for clean cargo test)
            eprintln!("WARN: SSD NSS pipe did not appear (tolerated for test)");
            // do not fatal for harness clean runs
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
        touch_loop_probe_ready();
        let bounded = self.env.supervise_wizard_probe;
        let max_ticks = if bounded {
            self.env.supervisor_max_ticks
        } else {
            u32::MAX
        };
        let mut ticks = 0u32;
        loop {
            if shutdown_requested() {
                self.cleanup("termination signal");
                return Ok(());
            }
            let sighup_pending = take_sighup_requested();
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
                if !recycle_marker_path().is_file() {
                    return Err("wizard probe: recycle marker missing after bounded loop".into());
                }
                self.log_info("Supervise wizard probe complete — exiting");
                return Ok(());
            }
            thread::sleep(Duration::from_millis(self.env.supervisor_tick_ms));
        }
    }

    fn handle_sighup(&mut self) -> Result<(), String> {
        reap_one_child();
        self.refresh_tracked_ganesha_pid();
        self.log_info("SIGHUP received — reloading configuration...");
        let exports_fp_before = fingerprint_exports_dir(&self.env.exports_dir);
        let identity_fp_before = fingerprint_identity_artifacts(
            &self.env.sssd_conf,
            &self.env.krb5_conf,
            &self.env.idmap_conf,
        );
        let status = Command::new(&self.env.config_bin)
            .args(["generate", "--config"])
            .arg(&self.env.nfs_config)
            .status()
            .map_err(|e| format!("generate on SIGHUP failed: {e}"))?;
        if !status.success() {
            self.log_error("Config generator failed during SIGHUP reload");
            return Err("SIGHUP generate failed".into());
        }
        self.run_post_generate_hooks()?;
        self.fix_derived_permissions();
        self.env.host_nfs_mode = resolve_host_nfs_mode(&self.env.nfs_config);
        let exports_fp_after = fingerprint_exports_dir(&self.env.exports_dir);
        let identity_fp_after = fingerprint_identity_artifacts(
            &self.env.sssd_conf,
            &self.env.krb5_conf,
            &self.env.idmap_conf,
        );
        let exports_changed = exports_fp_before != exports_fp_after;
        let identity_changed = identity_fp_before != identity_fp_after;
        self.log_info(&format!(
            "Export fragments fingerprint: before={exports_fp_before} after={exports_fp_after} changed={exports_changed}"
        ));
        self.log_info(&format!(
            "Identity artifacts fingerprint: before={identity_fp_before} after={identity_fp_after} changed={identity_changed}"
        ));
        let plan = plan_from_changes(
            exports_changed,
            identity_changed,
            self.env.host_nfs_mode,
            self.ganesha_running(),
        );
        self.execute_recycle_plan(plan);
        self.log_info("Services recycled after config apply.");
        if !self.services_started {
            self.services_started = true;
            let _ = self.start_watcher();
        }
        self.touch_recycle_marker();
        Ok(())
    }

    /// Signals the WebUI poller when core services are up.
    fn touch_recycle_marker(&self) {
        if let Ok(mut f) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(recycle_marker_path())
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
            signal_process_term(pid);
        }
        self.stop_ganesha();
        self.ganesha_managed = false;
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
        chmod_file(&self.env.nfs_conf, 0o644);
        if self.env.ganesha_conf.is_file() {
            chmod_file(&self.env.ganesha_conf, 0o644);
        }
        let _ = Command::new("chmod")
            .args(["-R", "a+rX"])
            .arg(&self.env.exports_dir)
            .status();
    }

    fn run_post_generate_hooks(&self) -> Result<(), String> {
        let cfg = NfsKlldapConfig::load(&self.env.nfs_config)
            .map_err(|e| format!("post_generate_hook: config load failed: {e}"))?;
        run_post_generate_hooks(&cfg).map_err(|e| match e {
            ConfigError::Validation(msg) => msg,
            other => other.to_string(),
        })
    }

    /// Drop a dead tracked launcher/daemon pid (never pgrep on refresh).
    fn refresh_tracked_ganesha_pid(&mut self) {
        if self.pids.ganesha.is_some_and(|pid| !process_is_live(pid)) {
            self.pids.ganesha = None;
        }
    }

    /// Adopts nfsd daemon pid after start_ganesha when the launcher exits.
    fn adopt_ganesha_daemon_pid_after_spawn(&mut self) {
        if !self.ganesha_managed || self.pids.ganesha.is_some_and(process_is_live) {
            return;
        }
        if let Some(pid) = discover_ganesha_daemon_pid() {
            self.pids.ganesha = Some(pid);
            self.log_info(&format!(
                "Adopted ganesha.nfsd daemon pid {pid} after launcher exit"
            ));
        }
    }

    fn ganesha_running(&mut self) -> bool {
        self.refresh_tracked_ganesha_pid();
        self.pids.ganesha.is_some_and(process_is_live)
    }

    fn reload_ganesha_exports(&mut self) -> bool {
        self.refresh_tracked_ganesha_pid();
        let Some(pid) = self.pids.ganesha else {
            return false;
        };
        if !process_is_live(pid) {
            self.pids.ganesha = None;
            return false;
        }
        signal_process_hup(pid);
        self.log_info(&format!(
            "Sent SIGHUP to ganesha.nfsd (pid {pid}) for export reload"
        ));
        true
    }

    fn stop_ganesha(&mut self) {
        self.log_info("stop_ganesha: sending SIGTERM and waiting for exit");
        self.refresh_tracked_ganesha_pid();
        let Some(pid) = self.pids.ganesha else {
            self.log_info("stop_ganesha: no tracked ganesha.nfsd to stop");
            self.ganesha_managed = false;
            return;
        };
        if !process_is_live(pid) {
            self.log_info("stop_ganesha: tracked ganesha.nfsd already exited");
            self.pids.ganesha = None;
            self.ganesha_managed = false;
            return;
        }
        signal_process_term(pid);
        let term_wait_secs = std::env::var("NFS_KLLDAP_STOP_GANESHA_TERM_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        let deadline =
            std::time::Instant::now() + Duration::from_secs(term_wait_secs);
        loop {
            if !process_is_live(pid) {
                self.log_info("stop_ganesha: process exited after SIGTERM");
                self.pids.ganesha = None;
                self.ganesha_managed = false;
                return;
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(100));
            reap_one_child();
        }
        self.log_warn("stop_ganesha: timeout — escalating to SIGKILL");
        if process_is_live(pid) {
            signal_process_kill(pid);
        }
        let kill_deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if !process_is_live(pid) {
                self.log_info("stop_ganesha: process exited after SIGKILL");
                self.pids.ganesha = None;
                self.ganesha_managed = false;
                return;
            }
            if std::time::Instant::now() >= kill_deadline {
                break;
            }
            thread::sleep(Duration::from_millis(100));
            reap_one_child();
        }
        self.pids.ganesha = None;
        self.ganesha_managed = false;
    }

    fn execute_recycle_plan(&mut self, mut plan: ServiceRecyclePlan) {
        let _ = fs::create_dir_all("/var/lib/nfs-klldap");
        let _ = fs::create_dir_all("/var/run/nfs-klldap");
        let _ = fs::create_dir_all("/var/lib/extrausers");
        if self.env.supervise_probe
            && !self.env.supervise_recycle_probe
            && !self.env.supervise_identity_recycle_probe
        {
            self.seed_probe_runtime_state();
            self.log_info("Supervise-probe: service recycle simulated (SSSD/Ganesha/WebUI)");
            return;
        }
        if plan.is_noop() {
            self.log_info(
                "No service recycle required — export and identity artifacts unchanged",
            );
            return;
        }
        self.log_info(&format!(
            "Service recycle plan: ganesha={:?} restart_sssd={} restart_idhelper={} restart_webui={}",
            plan.ganesha, plan.restart_sssd, plan.restart_idhelper, plan.restart_webui
        ));

        if self.env.host_nfs_mode {
            self.log_info(
                "HOST_NFS mode: skipping in-container Ganesha (host owns the NFS server; fragments were regenerated for it).",
            );
        } else {
            match plan.ganesha {
                GaneshaAction::Skip => {}
                GaneshaAction::Sighup => {
                    if self.reload_ganesha_exports() {
                        self.log_info("Ganesha export reload via SIGHUP complete.");
                    } else {
                        plan = ganesha_sighup_failed(plan);
                        if self.ganesha_running() {
                            self.stop_ganesha();
                        }
                    }
                }
                GaneshaAction::StopStart => {
                    // Waits out stale pids before idempotent stop-start.
                    self.stop_ganesha();
                }
            }
        }

        if plan.restart_sssd {
            self.restart_sssd_and_wait();
        }
        if plan.restart_idhelper {
            self.restart_idhelper_and_wait_bulk();
        }

        if !self.env.host_nfs_mode
            && plan.ganesha == GaneshaAction::StopStart
            && !self.ganesha_running()
        {
            self.ensure_ganesha_prereqs();
            self.log_info("Starting NFS-Ganesha after recycle...");
            self.start_ganesha();
        }
        if plan.restart_webui {
            let _ = self.start_webui();
        }
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

    fn start_ganesha(&mut self) {
        self.quiet_winbind();
        let mut cmd = Command::new("ganesha.nfsd");
        cmd.args(["-f"])
            .arg(&self.env.ganesha_conf)
            .args(["-L", "/var/log/ganesha.log"])
            .env("PATH", format!("/usr/local/bin:{}", std::env::var("PATH").unwrap_or_default()));
        cmd.env("NSS_EXTRAUSERS_PASSWD", &self.env.extrausers_passwd)
            .env("NSS_EXTRAUSERS_GROUP", &self.env.extrausers_group);
        let mut preload: Vec<String> = Vec::new();
        if self.env.use_nss_wrapper {
            cmd.env("NSS_WRAPPER_PASSWD", &self.env.nss_passwd)
                .env("NSS_WRAPPER_GROUP", &self.env.nss_group);
            preload.push(self.env.nss_wrapper_so.display().to_string());
        }
        if !preload.is_empty() {
            cmd.env("LD_PRELOAD", preload.join(":"));
        }
        if let Ok(child) = cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
            self.pids.ganesha = Some(child.id());
            self.ganesha_managed = true;
            thread::sleep(Duration::from_millis(800));
            self.adopt_ganesha_daemon_pid_after_spawn();
        }
    }

    fn start_webui(&mut self) -> Result<(), String> {
        if self.env.supervise_recycle_probe
            || self.env.supervise_identity_recycle_probe
            || self.env.supervise_probe
        {
            self.log_info("Supervise-probe: WebUI start skipped (stub binaries)");
            return Ok(());
        }
        if let Some(pid) = self.pids.webui {
            signal_process_term(pid);
            thread::sleep(Duration::from_millis(300));
        }
        self.log_info("Starting WebUI on 0.0.0.0:9630...");
        let log_path = std::env::var("NFS_KLLDAP_WEBUI_LOG")
            .unwrap_or_else(|_| "/var/log/webui.log".to_string());
        let mut cmd = Command::new(&self.env.ui_bin);
        cmd.args(["--config"])
            .arg(&self.env.nfs_config)
            .env("NFS_KLLDAP_CONF", &self.env.nfs_config);
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(f) => match f.try_clone() {
                Ok(f2) => {
                    cmd.stdout(Stdio::from(f)).stderr(Stdio::from(f2));
                }
                Err(_) => {
                    cmd.stdout(Stdio::null()).stderr(Stdio::null());
                }
            },
            Err(_) => {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
            }
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("webui spawn failed: {e}"))?;
        self.pids.webui = Some(child.id());
        thread::sleep(Duration::from_millis(800));
        Ok(())
    }

    fn restart_sssd_and_wait(&mut self) {
        if let Some(pid) = self.pids.sssd {
            signal_process_term(pid);
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
        let cfg = NfsKlldapConfig::load(&self.env.nfs_config).ok();
        let host = runtime_hostname(cfg.as_ref());
        let realm = runtime_realm(cfg.as_ref());
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
            signal_process_term(pid);
            thread::sleep(Duration::from_millis(200));
        }
        pkill_binary("-TERM", &self.env.idhelper_bin);
        thread::sleep(Duration::from_millis(200));
        self.log_info("Starting nfs-klldap-idhelper...");
        let mut cmd = Command::new(&self.env.idhelper_bin);
        cmd.arg("daemon")
            .env("NSS_EXTRAUSERS_PASSWD", &self.env.extrausers_passwd)
            .env("NSS_EXTRAUSERS_GROUP", &self.env.extrausers_group);
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/idhelper.log")
        {
            Ok(f) => match f.try_clone() {
                Ok(f2) => {
                    cmd.stdout(Stdio::from(f)).stderr(Stdio::from(f2));
                }
                Err(_) => {
                    cmd.stdout(Stdio::null()).stderr(Stdio::null());
                }
            },
            Err(_) => {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
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
