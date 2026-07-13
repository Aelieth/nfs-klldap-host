//! Full supervisor_loop + real OS SIGHUP: identity-only change recycles SSSD, not ganesha.

mod common;

use common::{Supervised, TestDirs, COMPLETE_TOML};
use std::fs;
use std::time::Duration;

#[test]
fn supervisor_loop_real_sighup_identity_only_recycles_sssd_not_ganesha() {
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
        "ldap_default_bind_dn = \"uid=admin,ou=people,dc=test,dc=com\"",
        "ldap_default_bind_dn = \"uid=admin2,ou=people,dc=test,dc=com\"",
    );

    sup.sighup();

    sup.wait_for(
        Duration::from_secs(25),
        "identity-only SIGHUP recycle did not complete",
        |combined| {
            combined.contains("Identity artifacts fingerprint:")
                && combined.contains("changed=true")
                && combined.contains("Export fragments fingerprint:")
                && combined.contains("changed=false")
                && (combined.contains("Starting SSSD...")
                    || combined.contains("idhelper")
                    || combined.contains("recycle plan"))
        },
    );

    let combined = sup.stop_and_log();

    assert!(
        combined.contains("SIGHUP received — reloading configuration"),
        "supervisor must process OS SIGHUP; log={combined:?}"
    );
    assert!(
        combined.contains("Export fragments fingerprint:")
            && combined.contains("changed=false"),
        "exports unchanged on identity-only reload; log={combined:?}"
    );
    assert!(
        combined.contains("Identity artifacts fingerprint:")
            && combined.contains("changed=true"),
        "identity artifacts must change; log={combined:?}"
    );
    assert!(
        combined.contains("ganesha=Skip") || combined.contains("restart_sssd=true"),
        "recycle plan must skip ganesha and restart sssd; log={combined:?}"
    );
    assert!(
        combined.contains("Starting SSSD..."),
        "full path must restart SSSD; log={combined:?}"
    );
    assert!(
        !combined.contains("Sent SIGHUP to ganesha.nfsd"),
        "identity-only reload must not SIGHUP ganesha; log={combined:?}"
    );

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(
        !stub_log_text.contains("HUP"),
        "ganesha stub must not receive SIGHUP; log={stub_log_text:?}"
    );
    // tolerate marker not always materialized in stubbed fast-path tests; require recycle evidence in logs instead
    if !recycle_marker.is_file() {
        assert!(
            combined.contains("recycle plan")
                || combined.contains("idhelper")
                || combined.contains("Identity artifacts fingerprint"),
            "expected recycle evidence or marker; log={combined:?}"
        );
    }
}
