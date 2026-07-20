//! Full supervisor_loop + real OS SIGHUP: identity-only change is STAGED —
//! artifacts regenerate on disk but no daemon restarts until a forced full
//! recycle.

mod common;

use common::{Supervised, TestDirs, COMPLETE_TOML};
use std::fs;
use std::time::Duration;

#[test]
fn supervisor_loop_real_sighup_identity_only_stages_without_restarts() {
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
        "ldap_default_bind_dn = \"uid=admin,ou=people,dc=test,dc=com\"",
        "ldap_default_bind_dn = \"uid=admin2,ou=people,dc=test,dc=com\"",
    );

    sup.sighup();

    sup.wait_for(
        Duration::from_secs(25),
        "identity-only SIGHUP staging did not complete",
        |combined| {
            combined.contains("Identity artifacts fingerprint:")
                && combined.contains("changed=true")
                && combined.contains("Export fragments fingerprint:")
                && combined.contains("changed=false")
                && combined.contains("Identity changes staged:")
        },
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
            && post_sighup.contains("changed=false"),
        "exports unchanged on identity-only reload; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("Identity artifacts fingerprint:")
            && post_sighup.contains("changed=true"),
        "identity artifacts must change; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("Identity changes staged:"),
        "identity change must be loudly staged; post_sighup={post_sighup:?}"
    );
    assert!(
        !post_sighup.contains("Starting SSSD..."),
        "identity-only reload must NOT restart SSSD (staged); post_sighup={post_sighup:?}"
    );
    assert!(
        !post_sighup.contains("Sent SIGHUP to ganesha.nfsd"),
        "identity-only reload must not SIGHUP ganesha; post_sighup={post_sighup:?}"
    );
    assert!(
        !post_sighup.contains("Sent SIGHUP to WebUI"),
        "identity-only reload must not signal the WebUI; post_sighup={post_sighup:?}"
    );
    assert!(
        !post_sighup.contains("Starting WebUI on 0.0.0.0:9630"),
        "identity-only reload must not restart the WebUI; post_sighup={post_sighup:?}"
    );
    assert!(
        post_sighup.contains("Services recycled after config apply."),
        "the completion line stays unconditional (marker contract); post_sighup={post_sighup:?}"
    );

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(
        !stub_log_text.contains("HUP"),
        "ganesha stub must not receive SIGHUP; log={stub_log_text:?}"
    );
    let webui_log_text = fs::read_to_string(&webui_log).unwrap_or_default();
    assert!(
        !webui_log_text.contains("HUP") && !webui_log_text.contains("TERM"),
        "webui stub must be untouched by a staged identity change; log={webui_log_text:?}"
    );
}
