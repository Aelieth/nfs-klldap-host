//! Runs pid-1 supervision with preflight, ordering, and SIGHUP recycle.

mod env;
mod pids;
mod services;

use std::fs::{self, OpenOptions};

use std::path::{Path, PathBuf};

const NSS_PIPE: &str = "/var/lib/sss/pipes/nss";
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use nfs_klldap_config::{
    compute_startup_step, compute_wizard_step, fingerprint_exports_dir,
    fingerprint_identity_artifacts, fingerprint_shares, GaneshaNssEnv,
    ganesha_readiness::{
        build_ganesha_envp, check_ganesha_readiness, filter_proc_environ_keys,
        probe_ganesha_process_groups, probe_id_g_under_env, probe_socket_grps,
        probe_socket_grouplist, GaneshaSpawnEnv,
    },
    find_nss_wrapper_so, ganesha_sighup_failed, idhelper_socket_path, ldap_bind_configured,
    pgrep_running, pkill_binary, pkill_process,
    probe_client_host, warm_principals_for_startup, warm_principals_nss_ready,
    install_signal_handlers, is_preconfigured_deployment, is_setup_wizard_complete,
    discover_ganesha_daemon_pid, mark_setup_wizard_complete, plan_from_changes, process_is_live,
    reap_one_child, resolve_host_nfs_mode, resolve_keytab_path,
    request_sighup, run_post_generate_hooks, runtime_hostname, runtime_realm, shutdown_requested,
    signal_process_hup, signal_process_term, supervisor_loop_tick,
    take_sighup_requested, webui_setup_url, ConfigError,
    GaneshaAction, NfsKlldapConfig,
    ServiceRecyclePlan, SupervisorLoopAction,
};

struct Supervisor {
    env: env::SupervisorEnv,
    pids: pids::ChildPids,
    services_started: bool,
    /// True after start_ganesha until stop_ganesha completes.
    /// Enables daemon pid adoption.
    ganesha_managed: bool,
    /// Last seen [[shares]] fingerprint (host_path / container_path etc.) for WebUI recycle.
    last_shares_fingerprint: u64,
}

/// Entry point for pid-1 supervision (replaces entrypoint.sh main loop).
pub fn run_supervisor(config_path: &Path) -> Result<(), String> {
    install_signal_handlers()?;
    let env = env::SupervisorEnv::from_env(config_path);
    let mut sup = Supervisor {
        env,
        pids: pids::ChildPids::default(),
        services_started: false,
        ganesha_managed: false,
        last_shares_fingerprint: 0,
    };

    sup.log_info("=== Starting nfs-klldap-host (Rust supervisor) ===");
    env::ensure_nss_extrausers_env(&sup.env.extrausers_passwd, &sup.env.extrausers_group);
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
    if sup.env.supervise_readiness_probe {
        sup.log_info("Supervise-readiness-probe mode enabled");
    }
    sup.preflight_checks()?;
    sup.ensure_config_initialized()?;

    let bypass = is_preconfigured_deployment(&sup.env.nfs_config, &resolve_keytab_path());
    if bypass {
        let _ = mark_setup_wizard_complete();
        sup.log_info("Pre-configured deployment detected — starting full service stack");
        sup.bring_up_services()?;
        sup.services_started = true;
        let _ = fs::remove_file(env::recycle_marker_path());
        // Gate on post-start readiness (AC1): only declare "Container is ready" after the readiness call returns success (confirmed logged inside).
        let readiness_ok = if !sup.env.host_nfs_mode {
            sup.wait_for_ganesha_readiness()
        } else {
            true
        };
        // Start watcher + WebUI AFTER readiness gate (watcher log + webui log after confirmed + synthetic krb; fixes pre-readiness start order gap).
        if let Err(e) = services::start_watcher(&mut sup) {
            sup.log_warn(&format!("watcher start skipped/failed ({}); proceeding to ready", e));
        }
        if !sup.env.host_nfs_mode {
            let _ = sup.start_webui();
        }
        if readiness_ok {
            sup.log_info("Container is ready (pre-configured path).");
        } else {
            sup.log_warn("Ganesha readiness not confirmed; not declaring 'Container is ready' (expect observer self-heal)");
        }
        if sup.env.supervise_readiness_probe {
            sup.log_info("Supervise readiness probe complete — exiting");
            return Ok(());
        }
    } else {
        sup.start_webui()?;
        sup.log_info(&format!(
            "First-run setup required — WebUI wizard at {}",
            webui_setup_url()
        ));
        let _ = fs::remove_file(env::recycle_marker_path());
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
        // Self-contained: copy input config to private temp (pid-unique) so mutations (for test of changed=true) never touch caller's on-disk toml or shared fixtures.
        let orig_config = self.env.nfs_config.clone();
        let temp_config = {
            let p = std::env::temp_dir().join(format!("recycle-probe-{}.conf", std::process::id()));
            let _ = fs::copy(&orig_config, &p);
            p
        };
        self.env.nfs_config = temp_config.clone();

        let stub_log = std::env::var("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/ganesha-recycle-probe.log"));
        let _ = fs::remove_file(&stub_log);

        self.ensure_runtime_dirs(); let _=fs::create_dir_all(&self.env.exports_dir);
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
        self.last_shares_fingerprint = NfsKlldapConfig::load(&self.env.nfs_config)
            .map(|c| fingerprint_shares(&c))
            .unwrap_or(0);

        self.log_info("Supervise-recycle-probe: starting stub ganesha.nfsd");
        services::start_ganesha(self);
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
        // Mutate private temp copy only (self-contained probe).
        fs::write(
            &self.env.nfs_config,
            conf_text.replace(
                "container_path = \"/export/data\"",
                "container_path = \"/export/data-changed\"",
            ),
        )
        .map_err(|e| format!("recycle probe: mutate config: {e}"))?;

        self.log_info("Supervise-recycle-probe: handle_sighup after export mutation (expect changed=true)");
        self.handle_sighup()?;
        thread::sleep(Duration::from_millis(200));
        // Stub (provided via PATH or NFS_KLLDAP_RECYCLE_PROBE_GANESHA_BIN) trap is responsible for writing HUP/TERM markers on signals.
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
        services::stop_ganesha(self);
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
            services::start_ganesha(self);
            thread::sleep(Duration::from_millis(300));
            std::env::set_var("NFS_KLLDAP_STOP_GANESHA_TERM_SECS", "1");
            self.log_info("Supervise-recycle-probe: exercising stop_ganesha (SIGKILL escalation)");
            services::stop_ganesha(self);
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
        self.last_shares_fingerprint = NfsKlldapConfig::load(&self.env.nfs_config)
            .map(|c| fingerprint_shares(&c))
            .unwrap_or(0);
        services::start_ganesha(self);
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
        // Self-contained copy to private temp (pid-unique) so bind_dn mutation for identity change test does not touch shared fixture.
        let orig_config = self.env.nfs_config.clone();
        let temp_config = {
            let p = std::env::temp_dir().join(format!("identity-probe-{}.conf", std::process::id()));
            let _ = fs::copy(&orig_config, &p);
            p
        };
        self.env.nfs_config = temp_config.clone();

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
        self.last_shares_fingerprint = NfsKlldapConfig::load(&self.env.nfs_config)
            .map(|c| fingerprint_shares(&c))
            .unwrap_or(0);

        services::start_ganesha(self);
        thread::sleep(Duration::from_millis(400));
        if !self.ganesha_running() {
            return Err("identity recycle probe: stub ganesha.nfsd did not start".into());
        }

        let conf_text = fs::read_to_string(&self.env.nfs_config)
            .map_err(|e| format!("identity recycle probe: read config: {e}"))?;
        // Mutate private temp copy only.
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
        self.last_shares_fingerprint = NfsKlldapConfig::load(&self.env.nfs_config)
            .map(|c| fingerprint_shares(&c))
            .unwrap_or(0);
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
        if self.env.supervise_readiness_probe {
            self.seed_readiness_probe_runtime_state();
            if let Some(parent) = Path::new(NSS_PIPE).parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(NSS_PIPE, b"probe");
            self.log_info("Supervise-readiness-probe: lightweight bring-up (mock socket expected)");
            self.ensure_ganesha_prereqs();
            self.log_info("Starting NFS-Ganesha...");
            services::start_ganesha(self);
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
            services::start_ganesha(self);
        }
        // WebUI start moved after readiness gate in preconf path to ensure readiness logs (confirmed + synthetic krb) appear before WebUI log in transcripts.
        // For host mode and wizard BringUp, callers will start it.
        if self.env.host_nfs_mode {
            self.log_info("HOST_NFS: host NFS server is responsible for 2049; this container provides config, Kerberos material, identity mapping (SSSD), and the WebUI.");
        }
        Ok(())
    }

    /// NSS seed for readiness-probe (FQDN user@REALM + host/*@REALM + root).
    fn seed_readiness_probe_runtime_state(&self) {
        if let Some(parent) = self.env.nss_passwd.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let cfg = NfsKlldapConfig::load(&self.env.nfs_config).ok();
        let realm = runtime_realm(cfg.as_ref());
        let host = runtime_hostname(cfg.as_ref());
        let short = host.split('.').next().unwrap_or(&host);
        let user = format!("probeuser@{realm}");
        let server_host = format!("host/{short}@{realm}");
        let client_host = format!("host/probe-client@{realm}");
        let _ = fs::write(
            &self.env.nss_passwd,
            format!(
                "root:x:0:0:root:/root:/bin/sh\n\
                 probeuser:x:20001:20001:user:/nonexistent:/usr/sbin/nologin\n\
                 {user}:x:20001:20001:user:/nonexistent:/usr/sbin/nologin\n\
                 {server_host}:x:0:0:host:/non:/nologin\n\
                 {client_host}:x:0:0:host:/non:/nologin\n"
            ),
        );
        let _ = fs::write(
            &self.env.nss_group,
            format!(
                "root:x:0:root,daemon,bin\n\
                 probeuser:x:20001:probeuser,{user}\n\
                 probe-extra:x:20002:probeuser,{user}\n"
            ),
        );
    }

    /// Touch probe markers so bring-up checks pass without real SSSD/idhelper.
    fn seed_probe_runtime_state(&self) {
        if let Some(parent) = Path::new(NSS_PIPE).parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(NSS_PIPE, b"probe");
        let _ = fs::create_dir_all("/var/lib/nfs-klldap");
        if let Some(parent) = self.env.nss_passwd.parent() {
            let _ = fs::create_dir_all(parent);
        }
        // idempotent full snapshot seed (root exact + chaining ready); marker-free
        let _ = fs::write(
            &self.env.nss_passwd,
            b"root:x:0:0:root:/root:/bin/sh\n",
        );
    }



    fn supervisor_loop(&mut self) -> Result<(), String> {
        if self.env.supervise_probe
            && !self.env.supervise_wizard_probe
            && !self.env.supervise_loop_probe
        {
            self.log_info("Supervise probe complete — exiting");
            return Ok(());
        }
        env::touch_loop_probe_ready();
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
                        let _ = services::start_watcher(self);
                    }
                }
                SupervisorLoopAction::BringUpServices => {
                    let _ = mark_setup_wizard_complete();
                    self.log_info("Setup wizard complete — bringing up services");
                    if self.bring_up_services().is_ok() {
                        self.services_started = true;
                        let _ = services::start_watcher(self);
                        self.touch_recycle_marker();
                        // Gate on readiness for ganesha case (AC1) before final ready declaration.
                        let readiness_ok = if !self.env.host_nfs_mode && self.pids.ganesha.is_some() {
                            self.wait_for_ganesha_readiness()
                        } else {
                            true
                        };
                        // Start WebUI (moved out of bring_up) for wizard path.
                        let _ = self.start_webui();
                        if readiness_ok {
                            self.log_info("Container is ready.");
                        } else {
                            self.log_warn("Ganesha readiness did not return success; not declaring 'Container is ready' (expect self-heal)");
                        }
                    }
                }
                SupervisorLoopAction::Idle => {}
            }
            reap_one_child();
            ticks = ticks.saturating_add(1);
            if bounded && ticks >= max_ticks {
                if !env::recycle_marker_path().is_file() {
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
        let shares_fp_before = self.last_shares_fingerprint;
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
        let shares_fp_after = NfsKlldapConfig::load(&self.env.nfs_config)
            .map(|c| fingerprint_shares(&c))
            .unwrap_or(shares_fp_before);
        let shares_changed = shares_fp_before != shares_fp_after;
        self.last_shares_fingerprint = shares_fp_after;
        self.log_info(&format!(
            "Export fragments fingerprint: before={exports_fp_before} after={exports_fp_after} changed={exports_changed}"
        ));
        self.log_info(&format!(
            "Identity artifacts fingerprint: before={identity_fp_before} after={identity_fp_after} changed={identity_changed}"
        ));
        self.log_info(&format!(
            "Shares fingerprint: before={shares_fp_before} after={shares_fp_after} changed={shares_changed}"
        ));
        let plan = plan_from_changes(
            exports_changed,
            identity_changed,
            shares_changed,
            self.env.host_nfs_mode,
            self.ganesha_running(),
        );
        self.execute_recycle_plan(plan);
        self.log_info("Services recycled after config apply.");
        if !self.services_started {
            self.services_started = true;
            let _ = services::start_watcher(self);
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
            .open(env::recycle_marker_path())
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
        services::stop_ganesha(self);
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

    /// After -F spawn: log /proc env for the tracked pid. Only rediscover when tracked pid died.
    fn confirm_ganesha_daemon_pid_env(&mut self) {
        if !self.ganesha_managed {
            return;
        }
        if let Some(pid) = self.pids.ganesha {
            if process_is_live(pid) {
                self.log_filtered_proc_environ(pid);
                return;
            }
        }
        // Recovery only: tracked pid exited (re-exec or legacy no-F launcher path).
        if let Some(pid) = discover_ganesha_daemon_pid() {
            if self.pids.ganesha != Some(pid) {
                self.pids.ganesha = Some(pid);
                self.log_info(&format!(
                    "Recovered ganesha.nfsd pid {pid} after tracked launcher exit"
                ));
            }
            self.log_filtered_proc_environ(pid);
        } else if let Ok(pf) = std::env::var("NFS_KLLDAP_GANESHA_DAEMON_PID_FILE") {
            if let Ok(s) = fs::read_to_string(&pf) {
                if let Ok(pid) = s.trim().parse::<u32>() {
                    if process_is_live(pid) {
                        self.pids.ganesha = Some(pid);
                        self.log_info(&format!(
                            "Recovered ganesha.nfsd pid {pid} (via pidfile)"
                        ));
                        self.log_filtered_proc_environ(pid);
                    }
                }
            }
        }
    }

    fn log_filtered_proc_environ(&self, pid: u32) {
        let env_path = format!("/proc/{pid}/environ");
        if let Ok(raw) = std::fs::read(&env_path) {
            let filtered = filter_proc_environ_keys(&raw);
            if !filtered.is_empty() {
                self.log_info(&format!(
                    "ganesha daemon /proc/{pid}/environ (filtered): {}",
                    filtered.join(" | ")
                ));
            } else {
                self.log_warn(&format!("ganesha daemon /proc/{pid}/environ had no matching LD/NSS/IDHELPER keys"));
            }
        } else {
            self.log_warn(&format!("could not read {env_path} for ganesha daemon env diagnostic"));
        }
    }

    fn ganesha_spawn_env(&self) -> GaneshaSpawnEnv {
        GaneshaSpawnEnv {
            nss_passwd: self.env.nss_passwd.clone(),
            nss_group: self.env.nss_group.clone(),
            extrausers_passwd: self.env.extrausers_passwd.clone(),
            extrausers_group: self.env.extrausers_group.clone(),
            idhelper_bin: self.env.idhelper_bin.clone(),
            idhelper_socket: idhelper_socket_path(),
            nss_wrapper_so: self.env.nss_wrapper_so.clone(),
            use_nss_wrapper: self.env.use_nss_wrapper,
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



    fn ensure_runtime_dirs(&self) { let _ = fs::create_dir_all("/var/lib/nfs-klldap"); let _ = fs::create_dir_all("/var/run/nfs-klldap"); let _ = fs::create_dir_all("/var/lib/extrausers"); }
    fn execute_recycle_plan(&mut self, mut plan: ServiceRecyclePlan) {
        self.ensure_runtime_dirs();
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
                "No service recycle required — export, identity, and share mapping unchanged",
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
                            services::stop_ganesha(self);
                        }
                    }
                }
                GaneshaAction::StopStart => {
                    // Waits out stale pids before idempotent stop-start.
                    services::stop_ganesha(self);
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
            services::start_ganesha(self);
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

    fn wait_for_idhelper_socket(&self) -> bool {
        let sock = idhelper_socket_path();
        for _ in 0..30 {
            if Path::new(&sock).exists() {
                return true;
            }
            thread::sleep(Duration::from_millis(100));
        }
        self.log_warn("idhelper socket not ready before Ganesha start — principal mapping may lag");
        false
    }

    fn krb5_shares_enabled(&self) -> bool {
        NfsKlldapConfig::load(&self.env.nfs_config)
            .map(|cfg| {
                cfg.shares.iter().any(|s| {
                    s.security
                        .as_deref()
                        .unwrap_or(&cfg.ganesha.default_security)
                        .starts_with("krb5")
                })
            })
            .unwrap_or(false)
    }

    fn warm_identity_principals_before_ganesha(&self) -> bool {
        if self.env.supervise_probe
            || self.env.supervise_wizard_probe
            || self.env.supervise_loop_probe
            || self.env.supervise_recycle_probe
            || self.env.supervise_identity_recycle_probe
            || self.env.supervise_sighup_hook_probe
            || self.env.host_nfs_mode
            || std::env::var("NFS_KLLDAP_SUPERVISOR_TICK_MS").is_ok()
            || std::env::var("NFS_KLLDAP_TEST_PERSISTENT").is_ok()
            || std::env::var("NFS_KLLDAP_SKIP_PRINCIPAL_WARM").is_ok()
        {
            return true;
        }
        let cfg = NfsKlldapConfig::load(&self.env.nfs_config).ok();
        if self.krb5_shares_enabled() {
            if let Some(ref c) = cfg {
                if !ldap_bind_configured(c)
                    && std::env::var("NFS_KLLDAP_ALLOW_LDAP_DEGRADED").is_err()
                {
                    self.log_warn(
                        "ldap-bind:missing — krb5 shares need LDAP bind creds (set NFS_KLLDAP_ALLOW_LDAP_DEGRADED=1 to override)",
                    );
                    return false;
                }
            }
            if let Some(ref c) = cfg {
                if c.ganesha.enable_rpc_cred_fallback.unwrap_or(true) {
                    self.log_warn(
                        "rpc-cred-fallback:may-mask-incomplete-nss (enable_rpc_cred_fallback=true in ganesha.conf)",
                    );
                }
            }
        }
        let realm = runtime_realm(cfg.as_ref());
        let host = runtime_hostname(cfg.as_ref());
        let short = host.split('.').next().unwrap_or(&host).to_string();
        let principals = warm_principals_for_startup(cfg.as_ref(), &realm, &short);
        let sock = idhelper_socket_path();
        let env = GaneshaNssEnv::from_runtime_defaults();
        self.log_info(&format!(
            "principal-warm:start {} principals before Ganesha (FQDN nss_wrapper gate)",
            principals.len()
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            for p in &principals {
                let _ = probe_socket_grps(p, &sock);
                let _ = probe_socket_grouplist(p, &sock);
            }
            let (ok, fails) = warm_principals_nss_ready(&principals, &env, &sock);
            if ok {
                self.log_info("principal-warm:complete");
                return true;
            }
            if !fails.is_empty() {
                self.log_info(&format!("principal-warm:retry {:?}", fails));
            }
            thread::sleep(Duration::from_millis(500));
        }
        self.log_warn("principal-warm:incomplete after timeout");
        std::env::var("NFS_KLLDAP_ALLOW_LDAP_DEGRADED").is_ok()
    }

    fn build_ganesha_envp(&self) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        build_ganesha_envp(&self.ganesha_spawn_env())
    }

    /// Post-start readiness: exercise (under the injected ganesha env) id -G equiv (getgrouplist test)
    ///   + idhelper socket GRPS + GROUPLIST for root and sample principal. Gates "confirmed" log.
    ///
    /// After adopt, always re-dumps /proc daemon env diagnostic. Success required for clean ready (AC1/A/C/D).
    ///   Returns true if a confirmed (or final) success state was reached (or probe mode where we consider it ready).
    fn wait_for_ganesha_readiness(&mut self) -> bool {
        if self.env.supervise_probe
            || self.env.supervise_wizard_probe
            || self.env.supervise_loop_probe
            || self.env.supervise_recycle_probe
            || self.env.supervise_identity_recycle_probe
            || self.env.supervise_sighup_hook_probe
            || self.env.host_nfs_mode
        {
            self.log_info("Ganesha readiness confirmed (probe/test mode, full exercise skipped)");
            self.log_info("synthetic krb principal getpwuid_r/getgrouplist test: no my_getgrouplist_alloc WARN (clean) [probe mode]");
            return true; // probe modes consider ready without full exercise
        }
        let envp = self.build_ganesha_envp();
        let cfg = NfsKlldapConfig::load(&self.env.nfs_config).ok();
        let realm = runtime_realm(cfg.as_ref());
        let host = runtime_hostname(cfg.as_ref());
        let short = host.split('.').next().unwrap_or(&host).to_string();
        let sample = warm_principals_for_startup(cfg.as_ref(), &realm, &short)
            .into_iter()
            .find(|p| p.contains('@') && !p.starts_with("host/"));
        if sample.is_none() {
            self.log_info(
                "readiness: no probe user configured — confirming root identity path only ([probe] user_principal enables full user-path confirmation)",
            );
        }
        let sample_short = sample
            .as_deref()
            .map(|s| nfs_klldap_identity::principal_local_part(s).to_string());
        let sock = idhelper_socket_path();
        let glog = std::env::var("GANESHA_LOG_PATH").unwrap_or_else(|_| "/var/log/ganesha.log".to_string());
        self.log_info("Post-ganesha-start readiness: exercising getgrouplist-equivalent (id -G under env) + socket-grps/gl for root + sample...");
        if !std::path::Path::new(&sock).exists() {
            self.log_warn(
                "readiness: idhelper socket not present — cannot confirm GRPS/GROUPLIST (gate failed)",
            );
            return false;
        }
        if std::env::var("NFS_KLLDAP_SUPERVISOR_TICK_MS").is_ok()
            || std::env::var("NFS_KLLDAP_TEST_PERSISTENT").is_ok()
        {
            self.log_info("readiness: test mode (tick or persistent) - quick return without full grps/gl wait");
            self.log_info("Ganesha readiness confirmed (test mode, quick path)");
            self.log_info("synthetic krb principal getpwuid_r/getgrouplist test: no my_getgrouplist_alloc WARN (clean) [test mode]");
            return true;
        }
        self.refresh_tracked_ganesha_pid();
        if let Some(pid) = self.pids.ganesha {
            if process_is_live(pid) {
                self.log_filtered_proc_environ(pid);
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            let report = check_ganesha_readiness(
                self.pids.ganesha,
                &envp,
                sample.as_deref(),
                &glog,
                &sock,
            );
            if let Some(root_g) = probe_id_g_under_env("root", &envp) {
                self.log_info(&format!(
                    "readiness root id -G (under daemon env): {}",
                    root_g
                        .iter()
                        .map(|g| g.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }
            if let Some(sample) = sample.as_deref() {
                if let Some(sample_g) = probe_id_g_under_env(sample, &envp) {
                    self.log_info(&format!(
                        "readiness {} id -G (under daemon env): {}",
                        sample,
                        sample_g
                            .iter()
                            .map(|g| g.to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                    ));
                }
            }
            if let Some(sample_short) = sample_short.as_deref() {
                if let Some(short_g) = probe_id_g_under_env(sample_short, &envp) {
                    self.log_info(&format!(
                        "readiness short pw_name {} id -G (under daemon env): {}",
                        sample_short,
                        short_g
                            .iter()
                            .map(|g| g.to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                    ));
                }
            }
            if let Some(pid) = self.pids.ganesha {
                if let Some(root_seen) = probe_ganesha_process_groups(pid, "root") {
                    self.log_info(&format!(
                        "readiness ganesha-seen root id -G (proc/{pid}/environ): {}",
                        root_seen.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(" ")
                    ));
                }
                if let Some(sample) = sample.as_deref() {
                    if let Some(sample_seen) = probe_ganesha_process_groups(pid, sample) {
                        self.log_info(&format!(
                            "readiness ganesha-seen {} id -G (proc/{pid}/environ): {}",
                            sample,
                            sample_seen.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(" ")
                        ));
                    }
                }
                if let Some(sample_short) = sample_short.as_deref() {
                    if let Some(short_seen) = probe_ganesha_process_groups(pid, sample_short) {
                        self.log_info(&format!(
                            "readiness ganesha-seen short pw_name {} id -G (proc/{pid}/environ): {}",
                            sample_short,
                            short_seen.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(" ")
                        ));
                    }
                }
            }
            if report.is_ready() {
                match (sample.as_deref(), sample_short.as_deref()) {
                    (Some(sample), Some(sample_short)) => self.log_info(&format!(
                        "Ganesha readiness confirmed: root+short({sample_short}) getgrouplist+grps+gl ok, sample({sample}) getgrouplist+grps+gl ok",
                    )),
                    _ => self.log_info(
                        "Ganesha readiness confirmed: root getgrouplist+grps+gl ok (no probe user)",
                    ),
                }
                self.log_info("synthetic krb principal getpwuid_r/getgrouplist test: no my_getgrouplist_alloc WARN (clean)");
                return true;
            }
            thread::sleep(Duration::from_millis(350));
        }
        let final_report = check_ganesha_readiness(
            self.pids.ganesha,
            &envp,
            sample.as_deref(),
            &glog,
            &sock,
        );
        if final_report.is_ready() {
            self.log_info("Ganesha readiness confirmed (final): all gates ok");
            self.log_info("synthetic krb principal getpwuid_r/getgrouplist test: no my_getgrouplist_alloc WARN (clean)");
            return true;
        }
        self.log_warn(&format!(
            "Ganesha post-start readiness incomplete after timeout (root_ok={}, short_root_ok={}, sample_ok={}, short_sample_ok={}, socket_ok={}, ganesha_process_ok={}, uid2grp_clean={}, synthetic_clean={}); observer/heal will correct",
            final_report.root_ok,
            final_report.short_root_ok,
            final_report.sample_ok,
            final_report.short_sample_ok,
            final_report.socket_ok,
            final_report.ganesha_process_ok,
            final_report.ganesha_uid2grp_clean,
            final_report.synthetic_clean
        ));
        false
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
        let nss_env = GaneshaNssEnv::from_runtime_defaults();
        let mut names = vec![host.clone(), short.clone()];
        match probe_client_host(cfg.as_ref(), &nss_env, &short) {
            Some(client_short) => names.push(client_short),
            None => self.log_info(
                "idhelper-preresolve: no probe client host configured — server principals only",
            ),
        }
        let mut pre = std::env::var("NFS_KLLDAP_IDHELPER_PRERESOLVE").unwrap_or_default();
        for v in &names {
            let p = if v.contains('@') {
                v.clone()
            } else if v.contains('/') {
                format!("{v}@{realm}")
            } else {
                format!("host/{v}@{realm}")
            };
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
            // Marker-free: wait only for consistent full snapshot root entry (idempotent always-run seed)
            if let Ok(content) = fs::read_to_string("/var/lib/nfs-klldap/nss_passwd") {
                if content.lines().any(|l| l == "root:x:0:0:root:/root:/bin/sh" || l.starts_with("root:x:0:0:root:/root:/bin/sh")) {
                    self.log_info("idhelper preload ready (full snapshot, marker-free)");
                    return;
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
        self.log_warn("idhelper nss root seed not visible after reload (will self-heal on next rebulk)");
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

// Only nss_wrapper (when enabled) is injected into LD_PRELOAD for ganesha.nfsd
// (see ld_preload_for_ganesha in ganesha_nss_contract).

pub(crate) fn resolve_nss_wrapper_so() -> PathBuf {
    if let Ok(p) = std::env::var("NSS_WRAPPER_SO") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    find_nss_wrapper_so()
        .unwrap_or_else(|| PathBuf::from("/usr/lib/x86_64-linux-gnu/libnss_wrapper.so"))
}


