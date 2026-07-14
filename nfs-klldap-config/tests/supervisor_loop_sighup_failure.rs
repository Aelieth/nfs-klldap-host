//! Full supervisor_loop + real OS SIGHUP: a failing reload must not kill pid 1.

mod common;

use common::{Supervised, TestDirs, COMPLETE_TOML};
use std::time::Duration;

#[test]
fn supervisor_loop_survives_sighup_generate_failure_and_recovers() {
    let dirs = TestDirs::new(COMPLETE_TOML);
    let keytab = dirs.keytab();
    let recycle_marker = dirs.recycle_marker();

    dirs.stub_ganesha_trap_log();
    dirs.stub_sssd_pipe();
    dirs.stub_idhelper_fixture();
    dirs.stub_sleeper("nfs-klldap-ui");
    dirs.stub_sleeper("nfs-klldap-conf-watcher");
    dirs.stub_exit0("healthcheck.sh");
    dirs.stub_sleeper("inotifywait");

    let mut cmd = dirs.base_cmd("supervise");
    dirs.service_bins_env(&mut cmd);
    dirs.nss_env(&mut cmd);
    cmd.env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "100")
        .env("NFS_KLLDAP_KEYTAB_PATH", &keytab)
        .env("NFS_KLLDAP_WEBUI_LOG", dirs.out.join("webui.log"))
        .env("NFS_KLLDAP_RECYCLE_MARKER", &recycle_marker);
    let sup = Supervised::spawn(&mut cmd);

    sup.wait_for(
        Duration::from_secs(25),
        "supervisor bring-up did not complete",
        |combined| {
            combined.contains("Container is ready (pre-configured path)")
                || combined.contains("Starting nfs-klldap-idhelper")
        },
    );

    // Corrupt the config so `generate` fails on reload.
    dirs.edit_conf("[[shares]]", "[[shares");
    sup.sighup();

    sup.wait_for(
        Duration::from_secs(25),
        "failed reload must be reported without exiting",
        |combined| {
            combined.contains("SIGHUP reload failed")
                && combined.contains("keeping services on the previous configuration")
        },
    );

    // Restore the config; the still-alive loop must complete the next reload.
    dirs.edit_conf("[[shares", "[[shares]]");
    sup.sighup();

    sup.wait_for(
        Duration::from_secs(25),
        "supervisor must recover after a failed reload",
        |combined| combined.contains("Services recycled after config apply."),
    );

    let combined = sup.stop_and_log();
    assert!(
        !combined.contains("FATAL:"),
        "failed reload must not surface as a fatal supervisor exit; log={combined:?}"
    );
}
