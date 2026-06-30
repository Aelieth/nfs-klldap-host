//! Host-side getgrouplist shim contract (Ganesha 9.6 sizing + fill) against fixture nss files.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn write_supplemental_fixtures(base: &std::path::Path) {
    std::fs::create_dir_all(base).unwrap();
    std::fs::write(
        base.join("nss_passwd"),
        "testuser1:x:3001:3005:testuser1@TESTLABBY.LOCAL:/nonexistent:/usr/sbin/nologin\n",
    )
    .unwrap();
    std::fs::write(
        base.join("nss_group"),
        "group-test:x:3005:testuser1\nlldap_sudohost:x:3004:testuser1\n",
    )
    .unwrap();
    std::fs::write(base.join("extrausers_group"), "lldap_sudohost:x:3004:testuser1\n").unwrap();
}

#[test]
fn getgrouplist_shim_fixture_matches_ganesha_96_contract() {
    let td = tempfile::tempdir().unwrap();
    write_supplemental_fixtures(td.path());

    let script = repo_root().join("scripts/test-getgrouplist-shim-fixture.sh");
    assert!(
        script.is_file(),
        "missing shim fixture script at {}",
        script.display()
    );

    let out = Command::new("bash")
        .arg(&script)
        .env("FIXTURE_DIR", td.path())
        .env("ROOT", repo_root())
        .output()
        .expect("run test-getgrouplist-shim-fixture.sh");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "shim fixture probe failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("size ret=-1"), "stdout:\n{stdout}");
    assert!(stdout.contains("fill ret=0"), "stdout:\n{stdout}");
    assert!(stdout.contains("GETGROUPLIST_SHIM_FIXTURE_OK"), "stdout:\n{stdout}");
}