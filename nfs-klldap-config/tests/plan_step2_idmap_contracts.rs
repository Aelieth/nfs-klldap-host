//! Verification plan step 2: single gate test that runs named idmap contract suites.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .to_path_buf()
}

fn stream_cargo_test(extra_args: &[&str], label: &str) {
    eprintln!("=== plan_step2: {label} ===");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("nfs-klldap-config");
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.arg("--").arg("--nocapture");
    eprintln!(
        ">>> cargo test -p nfs-klldap-config {} -- --nocapture",
        extra_args.join(" ")
    );
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap_or_else(|e| panic!("spawn cargo test for {label}: {e}"));
    assert!(status.success(), "plan_step2 gate failed: {label}");
}

#[test]
fn plan_step2_named_idmap_contracts() {
    stream_cargo_test(&["--test", "ganesha_96_identity_audit"], "ganesha_96_identity_audit");
    stream_cargo_test(&["--test", "limited_fs_generate"], "limited_fs_generate");
    stream_cargo_test(&["ganesha_readiness"], "ganesha_readiness");
    stream_cargo_test(&["ganesha_identity_pipeline"], "ganesha_identity_pipeline");
    stream_cargo_test(&["ganesha_nss_contract"], "ganesha_nss_contract");
    stream_cargo_test(&["idmap_log_contract"], "idmap_log_contract");
}