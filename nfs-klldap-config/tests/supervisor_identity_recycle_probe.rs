//! Identity-only config change stages artifacts on disk — no SSSD restart, no
//! ganesha SIGHUP; a forced full recycle applies them later.

mod common;

use common::{run_to_exit, TestDirs, COMPLETE_TOML};
use std::fs;
use std::path::PathBuf;

#[test]
fn supervise_identity_recycle_probe_sssd_only_change() {
    let dirs = TestDirs::new(COMPLETE_TOML);
    let stub_log = dirs.stub_ganesha_trap_log();
    dirs.stub_sssd_pipe();
    dirs.stub_idhelper_fixture();
    dirs.stub_exit0("nfs-klldap-ui");

    let mut cmd = dirs.base_cmd("supervise-identity-recycle-probe");
    dirs.nss_env(&mut cmd);
    cmd.env("NFS_KLLDAP_RECYCLE_PROBE_GANESHA_LOG", &stub_log)
        .env("UI_BIN", dirs.stubs.join("nfs-klldap-ui"))
        .env("IDHELPER_BIN", dirs.stubs.join("nfs-klldap-idhelper"));
    let (status, combined) = run_to_exit(&mut cmd);

    assert!(
        status.success(),
        "supervise-identity-recycle-probe failed: {combined}"
    );
    assert!(combined.contains("Supervise-identity-recycle-probe mode enabled"));
    assert!(combined.contains("Identity artifacts fingerprint:"));
    assert!(combined.contains("changed=true"));
    assert!(combined.contains("Export fragments fingerprint:"));
    assert!(combined.contains("changed=false"));
    assert!(
        combined.contains("Identity changes staged:"),
        "identity-only change must be loudly staged; log={combined:?}"
    );
    assert!(
        !combined.contains("Starting SSSD..."),
        "identity-only change must NOT restart SSSD (staged); log={combined:?}"
    );
    assert!(
        !combined.contains("Service recycle plan:"),
        "a staged-only change must not execute a recycle plan; log={combined:?}"
    );
    assert!(!combined.contains("Sent SIGHUP to ganesha.nfsd"));
    assert!(combined.contains("Supervise-identity-recycle-probe complete"));

    let stub_log_text = fs::read_to_string(&stub_log).unwrap_or_default();
    assert!(
        !stub_log_text.contains("HUP"),
        "ganesha stub must not see SIGHUP on a staged identity change; log={stub_log_text:?}"
    );

    if let Ok(scratch) = std::env::var("NFS_KLLDAP_CAPTURE_SCRATCH") {
        let scratch = PathBuf::from(scratch);
        let _ = fs::create_dir_all(&scratch);
        let _ = fs::write(scratch.join("supervisor-identity-recycle-probe.log"), &combined);
        // Capture stub log too for fuller evidence when NFS_KLLDAP_CAPTURE_SCRATCH set.
        let _ = fs::write(scratch.join("identity-stub.log"), &stub_log_text);
    }
}
