//! Direct chown/chmod on bind-mounted host paths .
//!
//! ## Security Boundary
//! This module is the *only* place in the entire application that performs
//! privileged filesystem mutation on user data (the share trees). It is called
//! exclusively from `fs::FsManager::apply_*` after all allow-list and safety
//! checks have passed.
//!
//! chown/chmod follow symlink targets; WalkDir skips symlinks (see fs.rs).

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
