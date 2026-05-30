//! FFI / unsafe boundary for low-level filesystem operations.
//!
//! This is the **only** module in the crate that is allowed to contain `unsafe` code.
//! All unsafe usage (primarily direct libc calls for chown inside the container)
//! is sequestered here behind safe, audited wrapper functions.
//!
//! The rest of the crate (fs.rs, web.rs, etc.) must remain entirely safe Rust.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Perform a `chown(2)` syscall on the given path.
///
/// This is the safe wrapper around the unsafe libc call. It is used because
/// the WebUI runs as root inside the container and needs to directly change
/// ownership on bind-mounted host paths (something that cannot be done via
/// pure safe Rust APIs when crossing container boundaries in this model).
pub fn chown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    // Convert to a proper C string (validates no interior NUL bytes).
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let res = unsafe { libc::chown(c_path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) };

    if res == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Set the mode (permissions) on a path.
///
/// This wrapper exists so that all privileged filesystem mutation operations
/// used by the permission editor are funneled through the ffi module, even
/// though the underlying `chmod` can be done safely via std.
pub fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
}
