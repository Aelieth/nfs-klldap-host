//! Ganesha/webui start/stop services extracted for modularization of sup/mod.rs.
//! Keep ACL/NOACL note: none here (pure supervisor).

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use super::Supervisor;

pub(crate) fn stop_ganesha(sup: &mut Supervisor) {
    sup.log_info("stop_ganesha: sending SIGTERM and waiting for exit");
    sup.refresh_tracked_ganesha_pid();
    let Some(pid) = sup.pids.ganesha else {
        sup.log_info("stop_ganesha: no tracked ganesha.nfsd to stop");
        sup.ganesha_managed = false;
        return;
    };
    if !::nfs_klldap_config::process_is_live(pid) {
        sup.log_info("stop_ganesha: tracked ganesha.nfsd already exited");
        sup.pids.ganesha = None;
        sup.ganesha_managed = false;
        return;
    }
    ::nfs_klldap_config::signal_process_term(pid);
    let term_wait_secs = std::env::var("NFS_KLLDAP_STOP_GANESHA_TERM_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let deadline = Instant::now() + Duration::from_secs(term_wait_secs);
    loop {
        if !::nfs_klldap_config::process_is_live(pid) {
            sup.log_info("stop_ganesha: process exited after SIGTERM");
            sup.pids.ganesha = None;
            sup.ganesha_managed = false;
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(100));
        ::nfs_klldap_config::reap_children();
    }
    sup.log_warn("stop_ganesha: timeout — escalating to SIGKILL");
    if ::nfs_klldap_config::process_is_live(pid) {
        ::nfs_klldap_config::signal_process_kill(pid);
    }
    let kill_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if !::nfs_klldap_config::process_is_live(pid) {
            sup.log_info("stop_ganesha: process exited after SIGKILL");
            sup.pids.ganesha = None;
            sup.ganesha_managed = false;
            return;
        }
        if Instant::now() >= kill_deadline {
            break;
        }
        thread::sleep(Duration::from_millis(100));
        ::nfs_klldap_config::reap_children();
    }
    sup.pids.ganesha = None;
    sup.ganesha_managed = false;
}

pub(crate) fn start_ganesha(sup: &mut Supervisor) {
    if !sup.wait_for_idhelper_socket() {
        return;
    }
    if !sup.warm_identity_principals_before_ganesha() {
        sup.log_warn("principal-warm:incomplete — skipping Ganesha start until NSS warm succeeds");
        return;
    }
    sup.quiet_winbind();
    let mut cmd = Command::new("ganesha.nfsd");
    cmd.args(["-F", "-f"])
        .arg(&sup.env.ganesha_conf)
        .args(["-L", "/var/log/ganesha.log"]);
    let envp = sup.build_ganesha_envp();
    cmd.env_clear().envs(envp);
    if let Ok(child) = cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() {
        let launched = child.id();
        sup.pids.ganesha = Some(launched);
        std::env::set_var("NFS_KLLDAP_GANESHA_PID", launched.to_string());
        sup.log_info(&format!("Started ganesha.nfsd pid {launched} (foreground + explicit envp: LD_PRELOAD/NSS_WRAPPER/IDHELPER/socket/nss)"));
        sup.ganesha_managed = true;
        thread::sleep(Duration::from_millis(800));
        sup.confirm_ganesha_daemon_pid_env();
    }
}
pub(crate) fn start_watcher(sup: &mut Supervisor) -> Result<(), String> {
    if sup.env.supervise_probe {
        sup.log_info("Supervise-probe: config watcher start skipped");
        return Ok(());
    }
    sup.log_info("Starting config watcher...");
    let child = Command::new(&sup.env.watcher_bin)
        .arg(&sup.env.nfs_config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("watcher spawn failed: {e}"))?;
    sup.pids.watcher = Some(child.id());
    Ok(())
}
