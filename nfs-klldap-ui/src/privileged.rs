//! Direct chown(2)/chmod(2) on bind-mounted host paths (root inside container).
//!
//! ## Security Boundary
//! This module is the *only* place in the entire application that performs
//! privileged filesystem mutation on user data (the share trees). It is called
//! exclusively from `fs::FsManager::apply_*` after all allow-list and safety
//! checks have passed.
//!
//! Symlink policy: WalkDir in `fs::apply_tree_with_progress` skips symlinks; chown/chmod
//! here follow targets on applied entries only (no lchown). See `fs.rs` for traversal rules.

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
