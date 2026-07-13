//! Integration test: handle_sighup fingerprint reload/skip + stop_ganesha via supervise-recycle-probe.

mod common;

use common::{complete_toml_with_hook, run_to_exit, TestDirs, COMPLETE_TOML};
use std::fs;
use std::path::PathBuf;

#[test]
fn supervise_recycle_probe_handle_sighup_fingerprint_reload_skip_and_kill() {
    let dirs = TestDirs::new(COMPLETE_TOML);
    let hook_log = dirs.tmp.path().join("hook.log");
    let hook = dirs.stub_script(
        "post-hook.sh",
        &format!(
            "#!/bin/sh\necho \"HOOK $(date +%s%N) share=$SHARE_NAME\" >> \"{}\"\n",
            hook_log.display()
        ),
    );
    fs::write(&dirs.conf, complete_toml_with_hook(&hook)).unwrap();

    let stub_log = dirs.stub_ganesha_trap_log();
    let ganesha_bin = dirs.stubs.join("ganesha.nfsd");

    let mut cmd = dirs.base_cmd("supervise-recycle-probe");
    dirs.nss_env(&mut cmd);
    cmd.env("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_LOG", &stub_log)
        .env("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_BIN", &ganesha_bin)
        .env("NFS_KLLDAP_RECYCLE_PROBE_TEST_KILL", "1");
    let (status, combined) = run_to_exit(&mut cmd);

    assert!(status.success(), "supervise-recycle-probe failed: {combined}");
    assert!(combined.contains("Supervise-recycle-probe mode enabled"));
    assert!(combined.contains("handle_sighup with unchanged exports"));
    assert!(combined.contains("Export fragments fingerprint:"));
    assert!(combined.contains("changed=false"));
    assert!(combined.contains("Identity artifacts fingerprint:"));
    assert!(combined.contains("No service recycle required"));
    assert!(combined.contains("handle_sighup after export mutation"));
    assert!(combined.contains("changed=true"));
    assert!(combined.contains("Sent SIGHUP to ganesha.nfsd"));
    assert!(combined.contains("exercising stop_ganesha (SIGTERM path)"));
    assert!(combined.contains("stop_ganesha: process exited after SIGTERM"));
    assert!(combined.contains("SIGKILL escalation"));
    assert!(combined.contains("stop_ganesha: timeout — escalating to SIGKILL"));
    assert!(combined.contains("Supervise-recycle-probe complete — exiting"));

    let hook_log_text = fs::read_to_string(&hook_log).unwrap_or_default();
    assert!(
        hook_log_text.matches("HOOK").count() >= 3,
        "hook must run on initial generate + both handle_sighup passes; log={hook_log_text:?}"
    );

    let sighup_pos = combined.find("Sent SIGHUP to ganesha.nfsd").unwrap();
    let hook_lines: Vec<_> = hook_log_text.lines().collect();
    assert!(
        hook_lines.len() >= 3,
        "hook must precede ganesha SIGHUP on export-change handle_sighup"
    );

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(stub_log_text.contains("HUP"));
    assert!(stub_log_text.contains("TERM"));
    assert!(!stub_log_text.contains("HUP") || stub_log_text.matches("HUP").count() == 1);

    let _ = sighup_pos;

    if let Ok(scratch) = std::env::var("NFS_KLLDAP_CAPTURE_SCRATCH") {
        let scratch = PathBuf::from(scratch);
        let _ = fs::create_dir_all(&scratch);
        let _ = fs::write(scratch.join("supervisor-recycle-probe.log"), &combined);
        // Also capture stub logs for full transcript (tee full when scratch requested).
        let _ = fs::write(scratch.join("recycle-stub.log"), &stub_log_text);
        let _ = fs::write(scratch.join("recycle-hook.log"), &hook_log_text);
    }
}
