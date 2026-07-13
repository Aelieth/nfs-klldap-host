//! Integration test: drives the real nfs-klldap-startup supervise-probe path with COMPLETE_TOML defaults.

mod common;

use common::{run_to_exit, TestDirs, COMPLETE_TOML};
use std::fs;

#[test]
fn supervise_probe_preconf_emits_ready_transcript() {
    let dirs = TestDirs::new(COMPLETE_TOML);
    let keytab = dirs.keytab();
    let marker = dirs.tmp.path().join(".setup_wizard_done");

    dirs.stub_exit0("nfs-klldap-ui");
    dirs.stub_sleeper("nfs-klldap-conf-watcher");
    dirs.stub_idhelper_fixture();
    dirs.stub_exit0("healthcheck.sh");
    dirs.stub_exit0("inotifywait");

    let mut cmd = dirs.base_cmd("supervise-probe");
    dirs.service_bins_env(&mut cmd);
    cmd.env("NFS_KLLDAP_KEYTAB_PATH", &keytab)
        .env("NFS_KLLDAP_SETUP_MARKER", &marker);
    let (status, combined) = run_to_exit(&mut cmd);

    assert!(status.success(), "supervise-probe failed: {combined}");
    assert!(combined.contains("=== Starting nfs-klldap-host (Rust supervisor) ==="));
    assert!(combined.contains("Pre-configured deployment detected — starting full service stack"));
    assert!(combined.contains("Container is ready (pre-configured path)"));
    assert!(combined.contains("Supervise probe complete — exiting"));
    assert!(dirs.out.join("ganesha.conf").is_file(), "generate must write ganesha.conf");
    assert!(marker.is_file(), "wizard marker must be written on preconf bypass");
}

/// Wizard completion path: complete nfs-klldap.conf + marker, then SIGHUP recycle (no keytab).
#[test]
fn supervise_probe_wizard_complete_recycle_touches_marker() {
    let dirs = TestDirs::new(COMPLETE_TOML);
    let marker = dirs.tmp.path().join(".setup_wizard_done");
    let recycle_marker = dirs.recycle_marker();
    fs::write(&marker, "ok\n").unwrap();

    dirs.stub_exit0("nfs-klldap-ui");
    dirs.stub_sleeper("nfs-klldap-conf-watcher");
    dirs.stub_idhelper_fixture();
    dirs.stub_exit0("healthcheck.sh");
    dirs.stub_exit0("inotifywait");

    let mut cmd = dirs.base_cmd("supervise-probe-wizard");
    dirs.service_bins_env(&mut cmd);
    cmd.env("NFS_KLLDAP_SETUP_MARKER", &marker)
        .env("NFS_KLLDAP_RECYCLE_MARKER", &recycle_marker)
        .env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "0")
        .env("NFS_KLLDAP_SUPERVISOR_MAX_TICKS", "5");
    let (status, combined) = run_to_exit(&mut cmd);

    assert!(status.success(), "supervise-probe-wizard failed: {combined}");
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
    assert!(dirs.out.join("sssd.conf").is_file(), "generate must write sssd.conf");
    let _ = fs::remove_file(&recycle_marker);
}
