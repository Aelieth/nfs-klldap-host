//! Full supervisor_loop + real OS SIGUSR1: the forced full recycle restarts
//! every managed service even when no fingerprint changed — the path behind
//! "Restart and apply" that also covers edits invisible to the fingerprints.

mod common;

use common::{Supervised, TestDirs, COMPLETE_TOML};
use std::fs;
use std::time::Duration;

#[test]
fn supervisor_loop_real_sigusr1_full_recycle_restarts_everything_without_diff() {
    let dirs = TestDirs::new(COMPLETE_TOML);
    let keytab = dirs.keytab();
    let recycle_marker = dirs.recycle_marker();

    let stub_log = dirs.stub_ganesha_trap_log();
    let webui_log = dirs.stub_webui_trap_log();
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
        |combined| {
            combined.contains("Container is ready (pre-configured path)")
                || combined.contains("Starting nfs-klldap-idhelper")
        },
    );

    // Deliberately NO config edit: the forced recycle must act on changed=false.
    sup.sigusr1();

    sup.wait_for(
        Duration::from_secs(35),
        "forced full recycle did not complete",
        |combined| {
            combined.contains("SIGUSR1 received — forced full service recycle")
                && combined.contains("Services recycled after config apply.")
        },
    );

    let combined = sup.stop_and_log();
    let post_usr1 = combined
        .split_once("SIGUSR1 received — forced full service recycle")
        .map(|(_, tail)| tail)
        .unwrap_or("");

    assert!(
        !post_usr1.is_empty(),
        "supervisor must process OS SIGUSR1; log={combined:?}"
    );
    assert!(
        post_usr1.contains("Export fragments fingerprint:")
            && post_usr1.contains("changed=false"),
        "no fingerprint may change in this scenario; post_usr1={post_usr1:?}"
    );
    assert!(
        post_usr1.contains("webui=Restart") && post_usr1.contains("restart_sssd=true"),
        "forced plan must restart everything despite changed=false; post_usr1={post_usr1:?}"
    );
    assert!(
        post_usr1.contains("Starting SSSD..."),
        "forced recycle must restart SSSD; post_usr1={post_usr1:?}"
    );
    assert!(
        post_usr1.contains("Starting NFS-Ganesha after recycle..."),
        "forced recycle must stop/start ganesha; post_usr1={post_usr1:?}"
    );
    assert!(
        post_usr1.contains("Starting WebUI on 0.0.0.0:9630"),
        "forced recycle must restart the WebUI process; post_usr1={post_usr1:?}"
    );
    assert!(
        !post_usr1.contains("Sent SIGHUP to ganesha.nfsd"),
        "forced recycle stop/starts ganesha instead of the graceful reread; post_usr1={post_usr1:?}"
    );
    assert!(
        !post_usr1.contains("Identity changes staged:"),
        "the forced path applies rather than stages; post_usr1={post_usr1:?}"
    );

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(
        stub_log_text.contains("TERM"),
        "ganesha stub must be stopped by the forced recycle; log={stub_log_text:?}"
    );
    assert!(
        stub_log_text.matches("START").count() >= 2,
        "ganesha stub must be started again after the stop; log={stub_log_text:?}"
    );

    let webui_log_text = fs::read_to_string(&webui_log).unwrap_or_default();
    assert!(
        webui_log_text.contains("TERM"),
        "webui stub must be SIGTERMed on the forced recycle; log={webui_log_text:?}"
    );
    assert!(
        !webui_log_text.contains("HUP"),
        "the forced recycle restarts the WebUI rather than reloading it; log={webui_log_text:?}"
    );
    assert!(
        webui_log_text.matches("START").count() >= 2,
        "a fresh webui stub must start after the restart; log={webui_log_text:?}"
    );

    assert!(
        recycle_marker.is_file(),
        "the recycle marker must be touched so the restarting page completes"
    );
}
