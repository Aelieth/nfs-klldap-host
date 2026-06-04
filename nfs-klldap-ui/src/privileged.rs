//! Direct chown(2)/chmod(2) on bind-mounted host paths (root inside container).
//!
//! ## Security Boundary
//! This module is the *only* place in the entire application that performs
//! privileged filesystem mutation on user data (the share trees). It is called
//! exclusively from `fs::FsManager::apply_*` after all allow-list and safety
//! checks have passed.
//!
//! ## Symlink Policy (see also fs.rs module docs)
//! - `chown` and `chmod` here use the *following* variants (std::os::unix::fs::chown
//!   and set_permissions). This matches historical behavior and the documented
//!   "follow for chown" policy.
//! - Traversal decisions (never descend symlinks) are made by the WalkDir
//!   configuration in `fs::apply_tree`, **not** here.
//! - We deliberately do **not** expose lchown today. Changing ownership of
//!   symlink *inodes themselves* is rarely what an admin intends when they
//!   click "recursive" on a directory tree, and would require a separate
//!   policy flag + careful UX. The current stance (skip symlinks for mutation)
//!   is the safe default that also prevents the old escape vector.
//!
//! If a future requirement needs lchown on links, add a parallel
//! `lchown` / `lchmod` here guarded by an explicit option.

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
