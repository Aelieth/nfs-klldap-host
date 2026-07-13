//! Full supervisor_loop + real OS SIGHUP: export-only change recycles Ganesha + WebUI, not SSSD.

mod common;

use common::{Supervised, TestDirs, COMPLETE_TOML};
use std::fs;
use std::time::Duration;

#[test]
fn supervisor_loop_real_sighup_export_only_recycles_ganesha_and_webui_not_sssd() {
    let dirs = TestDirs::new(COMPLETE_TOML);
    let keytab = dirs.keytab();
    let recycle_marker = dirs.recycle_marker();

    let stub_log = dirs.stub_ganesha_trap_log();
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

    dirs.edit_conf(
        "container_path = \"/export/data\"",
        "container_path = \"/export/data2\"",
    );

    sup.sighup();

    sup.wait_for(
        Duration::from_secs(25),
        "export-only SIGHUP recycle did not complete",
        |combined| {
            combined.contains("Export fragments fingerprint:")
                && combined.contains("changed=true")
                && combined.contains("Identity artifacts fingerprint:")
                && combined.contains("changed=false")
                && (combined.contains("Services recycled after config apply.")
                    || combined.contains("Starting WebUI on 0.0.0.0:9630")
                    || combined.contains("restart_webui=true"))
        },
    );

    sup.wait_for(
        Duration::from_secs(5),
        "export-only SIGHUP must finish recycle",
        |combined| combined.contains("Services recycled after config apply."),
    );

    let combined = sup.stop_and_log();
    let post_sighup = combined
        .split_once("SIGHUP received — reloading configuration")
        .map(|(_, tail)| tail)
        .unwrap_or("");

    assert!(
        !post_sighup.is_empty(),
        "supervisor must process OS SIGHUP; log={combined:?}"
    );
    assert!(
        post_sighup.contains("Export fragments fingerprint:")
            && post_sighup.contains("changed=true"),
        "exports must change on share mutation; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("Identity artifacts fingerprint:")
            && post_sighup.contains("changed=false"),
        "identity artifacts unchanged on export-only reload; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("restart_webui=true"),
        "recycle plan must restart WebUI when exports change; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("Starting WebUI on 0.0.0.0:9630"),
        "export-only reload must spawn a fresh WebUI process; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("Sent SIGHUP to ganesha.nfsd"),
        "export-only reload must SIGHUP ganesha; post_sighup={post_sighup:?}"
    );
    assert!(
        !post_sighup.contains("Starting SSSD..."),
        "export-only reload must not restart SSSD; post_sighup={post_sighup:?}"
    );

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(
        stub_log_text.contains("HUP"),
        "ganesha stub must receive SIGHUP on export change; log={stub_log_text:?}"
    );
}
