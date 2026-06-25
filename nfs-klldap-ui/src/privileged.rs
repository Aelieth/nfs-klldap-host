//! Privileged chown/chmod on bind-mounted share trees after allow-list checks.
//! Only called from fs::FsManager::apply_*. WalkDir skips symlinks (see.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn chown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
}

pub fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
}
