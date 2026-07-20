//! Real OS SIGHUP drives handle_sighup (hook + fingerprint) before ganesha recycle.

mod common;

use common::{complete_toml_with_hook, Supervised, TestDirs, COMPLETE_TOML};
use std::fs;

#[test]
fn supervise_sighup_hook_probe_real_os_sighup_runs_hook_before_recycle() {
    let dirs = TestDirs::new(COMPLETE_TOML);
    let hook_log = dirs.tmp.path().join("hook.log");
    let hook = dirs.stub_script(
        "post-hook.sh",
        &format!(
            "#!/bin/sh\necho \"HOOK share=$SHARE_NAME\" >> \"{}\"\n",
            hook_log.display()
        ),
    );
    fs::write(&dirs.conf, complete_toml_with_hook(&hook)).unwrap();

    let stub_log = dirs.stub_ganesha_trap_log();

    let mut cmd = dirs.base_cmd("supervise-sighup-hook-probe");
    dirs.nss_env(&mut cmd);
    cmd.env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "50")
        .env("NFS_KLLDAP_SUPERVISOR_MAX_TICKS", "200");
    let sup = Supervised::spawn(&mut cmd);

    std::thread::sleep(std::time::Duration::from_millis(500));
    sup.sighup();

    let (status, combined) = sup.wait_exit();

    assert!(
        status.success(),
        "supervise-sighup-hook-probe failed: {combined}"
    );
    assert!(combined.contains("Supervise-sighup-hook-probe mode enabled"));
    assert!(combined.contains("SIGHUP received — reloading configuration"));
    assert!(combined.contains("Export fragments fingerprint:"));
    assert!(combined.contains("changed=false"));
    assert!(combined.contains("Identity artifacts fingerprint:"));
    assert!(combined.contains("No service recycle required"));
    assert!(!combined.contains("Sent SIGHUP to ganesha.nfsd"));
    assert!(combined.contains("Supervise-sighup-hook-probe complete"));

    let hook_log_text = fs::read_to_string(&hook_log).unwrap_or_default();
    assert!(
        hook_log_text.contains("HOOK share=data"),
        "hook must run on initial generate and OS SIGHUP handle_sighup; log={hook_log_text:?}"
    );
    assert!(
        hook_log_text.matches("HOOK").count() >= 2,
        "hook invoked at least twice (bring-up generate + SIGHUP reload)"
    );

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(
        !stub_log_text.contains("HUP"),
        "unchanged export OS SIGHUP must not signal ganesha; log={stub_log_text:?}"
    );
}
