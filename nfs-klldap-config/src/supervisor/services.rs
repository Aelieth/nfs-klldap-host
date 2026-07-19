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
    // Still alive after SIGKILL = unkillable (D-state on a hung mount).
    // KEEP it tracked: dropping the pid here made the supervisor forget a
    // process that still owns port 2049, and the next start double-spawned
    // against it. It stays managed; a later stop/liveness pass retries once
    // the kernel releases it.
    sup.log_warn(&format!(
        "stop_ganesha: pid {pid} survived SIGKILL (uninterruptible I/O?) — keeping it tracked; will not double-spawn"
    ));
}

pub(crate) fn start_ganesha(sup: &mut Supervisor) {
    // A tracked pid that is still live means stop_ganesha could not kill it
    // (see its SIGKILL-survivor branch) — it still owns 2049; spawning a
    // second daemon against it helps nobody.
    if let Some(pid) = sup.pids.ganesha {
        if ::nfs_klldap_config::process_is_live(pid) {
            sup.log_warn(&format!(
                "start_ganesha: refusing to double-spawn — pid {pid} is still live"
            ));
            return;
        }
        sup.pids.ganesha = None;
    }
    // Soft wait only: missing idhelper must not skip Ganesha entirely. The
    // warn inside wait_for_idhelper_socket documents lag; observer/heal and
    // post-start readiness cover catch-up. Probe suites never start a real
    // idhelper daemon, so a hard return here failed CI with "stub ganesha
    // did not start" while local leftover sockets masked the bug.
    let _ = sup.wait_for_idhelper_socket();
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
pub(crate) fn start_avahi(sup: &mut Supervisor) {
    if !sup.navahi_enabled() {
        return;
    }
    if sup.env.host_nfs_mode {
        sup.log_warn(
            "navahi_discovery is on but HOST_NFS mode has no in-container NFS server — not starting avahi-daemon",
        );
        return;
    }
    if let Some(pid) = sup.pids.avahi {
        if ::nfs_klldap_config::process_is_live(pid) {
            return;
        }
        sup.pids.avahi = None;
    }
    // --no-chroot keeps the Debian chroot helper out of the picture so
    // inotify + SIGHUP re-reads of /etc/avahi/services stay direct (and the
    // daemon stays a single trackable process).
    match Command::new(&sup.env.avahi_bin)
        .arg("--no-chroot")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => {
            let pid = child.id();
            sup.pids.avahi = Some(pid);
            sup.avahi_managed = true;
            sup.log_info(&format!("Started avahi-daemon pid {pid} (Navahi mDNS advertisement)"));
        }
        Err(e) => sup.log_warn(&format!(
            "avahi-daemon start failed: {e} — Navahi advertisement unavailable (NFS service unaffected)"
        )),
    }
}

pub(crate) fn stop_avahi(sup: &mut Supervisor) {
    let Some(pid) = sup.pids.avahi else {
        sup.avahi_managed = false;
        return;
    };
    if ::nfs_klldap_config::process_is_live(pid) {
        ::nfs_klldap_config::signal_process_term(pid);
        let deadline = Instant::now() + Duration::from_secs(3);
        while ::nfs_klldap_config::process_is_live(pid) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
            ::nfs_klldap_config::reap_children();
        }
        if ::nfs_klldap_config::process_is_live(pid) {
            ::nfs_klldap_config::signal_process_kill(pid);
        }
    }
    sup.pids.avahi = None;
    sup.avahi_managed = false;
    sup.log_info("Stopped avahi-daemon");
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
