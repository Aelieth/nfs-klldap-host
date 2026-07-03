//! Integration tests: mountinfo fixtures drive real probe_from_mountinfo + effective flags.

use std::path::Path;

use nfs_klldap_config::{compute_effective_flags, probe_from_mountinfo, Share};

const FIXTURE: &str = r#"
36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl
37 36 0:60 / /export/movies rw,relatime - ext4 /dev/sdb1 rw
38 36 0:61 / /export/data rw,relatime - xfs /dev/sdc1 rw
39 36 0:62 / /export/usb rw,relatime - vfat /dev/sdd1 rw,fmask=0022,dmask=0022
40 36 0:63 / /export/ntfs rw,relatime - fuseblk /dev/sde1 rw,allow_other,default_permissions
"#;

#[test]
fn fixture_btrfs_noacl_limited() {
    let caps = probe_from_mountinfo(FIXTURE, Path::new("/export/users"));
    assert_eq!(caps.fstype, "btrfs");
    assert!(!caps.acl_capable);
    let eff = compute_effective_flags(&Share::default(), &caps);
    assert!(!eff.enable_acl);
    assert!(eff.manage_gids);
}

#[test]
fn fixture_ext4_xfs_capable() {
    for path in ["/export/movies", "/export/data"] {
        let caps = probe_from_mountinfo(FIXTURE, Path::new(path));
        assert!(caps.acl_capable, "{path}");
        let eff = compute_effective_flags(&Share::default(), &caps);
        assert!(eff.enable_acl);
        assert!(eff.manage_gids);
    }
}

#[test]
fn fixture_vfat_ntfs_limited() {
    for path in ["/export/usb", "/export/ntfs"] {
        let caps = probe_from_mountinfo(FIXTURE, Path::new(path));
        assert!(!caps.acl_capable, "{path}");
    }
}

#[test]
fn fixture_unknown_defaults_capable() {
    let caps = probe_from_mountinfo(FIXTURE, Path::new("/other/new"));
    assert_eq!(caps.fstype, "unknown");
    assert!(caps.acl_capable);
}