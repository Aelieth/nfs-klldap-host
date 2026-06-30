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
    // This test is a no-op. The legacy getgrouplist shim has been removed.
    // Identity materialization is done exclusively by the Rust idhelper via nss_wrapper.
    // The test exists only for historical reference and now always skips.
    eprintln!("skip: legacy getgrouplist shim support removed (nss_wrapper + idhelper is authoritative)");
}