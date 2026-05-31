//! Privileged host filesystem operations.
//!
//! This module is the single place in the crate that performs direct mutations
//! on bind-mounted host paths (chown/chmod as root inside the container).
//!
//! Why this module exists:
//! - The WebUI runs as root and is given bind mounts to the actual host data.
//! - It must be able to change ownership and permissions on those paths so that
//!   the resulting NFS exports have correct POSIX identity for clients.
//! - All such privileged host-mutating operations are intentionally centralized
//!   here for auditability and to make the security boundary obvious.
//!
//! These functions use the safe standard library APIs (`std::os::unix::fs` and
//! `std::fs`). There is no `unsafe` code and no direct `libc` dependency.
//!
//! The crate root uses `#![deny(unsafe_code)]` — any future need for raw
//! syscalls must be justified and added here.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Perform chown(2) on the given path using the safe std API.
///
/// This is the privileged operation used when the WebUI applies permission
/// changes to shares. The path is expected to be inside a bind mount that
/// exposes host filesystem content.
pub fn chown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
}

/// Perform chmod(2) on the given path using the safe std API.
///
/// Matches the historical `chmod` helper.
pub fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
}