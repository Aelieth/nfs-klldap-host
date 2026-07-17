//! Steady-state respawn (WI-18, re-opened by the 2026-07-17 audit): a
//! managed child that CRASHES — no recycle in flight — is revived from the
//! Idle tick under the rate-limited budget, instead of leaving the stack
//! silently degraded until the healthcheck flips. Budget math (3 per 10 min,
//! cooldown, exhaustion latch) is unit-tested in supervisor/respawn.rs; this
//! proves the wiring end to end against a real supervise process.

mod common;

use common::{Supervised, TestDirs, COMPLETE_TOML};
use std::time::Duration;

/// The pid the supervisor is TRACKING: the stub launcher backgrounds a
/// daemon and exits, so "Started … pid N" may be superseded by a
/// "Recovered ganesha.nfsd pid M after tracked launcher exit" line — the
/// last mention wins (killing the launcher pid would go unnoticed).
fn parse_tracked_ganesha_pid(log: &str) -> Option<u32> {
    log.lines().rev().find_map(|l| {
        l.split("ganesha.nfsd pid ")
            .nth(1)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

#[test]
fn supervisor_respawns_sigkilled_ganesha_from_idle_tick() {
    let dirs = TestDirs::new(COMPLETE_TOML);
    let keytab = dirs.keytab();
    let recycle_marker = dirs.recycle_marker();
    let _stub_log = dirs.stub_ganesha_trap_log();
    let _webui_log = dirs.stub_webui_trap_log();
    dirs.stub_sssd_pipe();
    dirs.stub_idhelper_fixture();
    dirs.stub_sleeper("nfs-klldap-conf-watcher");
    dirs.stub_exit0("healthcheck.sh");
    dirs.stub_sleeper("inotifywait");

    let mut cmd = dirs.base_cmd("supervise");
    dirs.service_bins_env(&mut cmd);
    dirs.nss_env(&mut cmd);
    cmd.env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "100")
        .env("NFS_KLLDAP_STOP_GANESHA_TERM_SECS", "2")
        .env("NFS_KLLDAP_KEYTAB_PATH", &keytab)
        .env("NFS_KLLDAP_WEBUI_LOG", dirs.out.join("webui.log"))
        .env("NFS_KLLDAP_RECYCLE_MARKER", &recycle_marker);
    let sup = Supervised::spawn(&mut cmd);

    sup.wait_for(
        Duration::from_secs(25),
        "supervisor bring-up did not complete",
        |combined| combined.contains("Container is ready (pre-configured path)"),
    );
    let pid = parse_tracked_ganesha_pid(&sup.log()).expect("tracked ganesha pid in log");

    // A crash, not a recycle: SIGKILL the stub daemon out from under pid 1.
    let killed = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .expect("kill runs");
    assert!(killed.success(), "SIGKILL of stub ganesha pid {pid}");

    sup.wait_for(
        Duration::from_secs(20),
        "Idle tick never noticed the dead ganesha",
        |combined| combined.contains("ganesha is down — respawning (steady-state liveness)"),
    );
    sup.wait_for(
        Duration::from_secs(20),
        "respawn never produced a second ganesha start",
        |combined| combined.matches("Started ganesha.nfsd pid").count() >= 2,
    );

    let combined = sup.stop_and_log();
    let second = parse_tracked_ganesha_pid(&combined).expect("respawned pid in log");
    assert_ne!(second, pid, "respawn must be a fresh process, not the corpse");
    assert!(
        !combined.contains("respawn budget"),
        "a single crash must not exhaust the budget: {combined:?}"
    );
}
