//! Direct chown(2)/chmod(2) on bind-mounted host paths (root inside container).

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