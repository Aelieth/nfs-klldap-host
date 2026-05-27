//! nfs-perm-helper - Tiny privileged helper for safe chown/chmod operations.
//!
//! This binary is intended to be the *only* thing that ever runs with elevated
//! privileges (via setuid root or a very narrow sudoers rule).
//!
//! Security model:
//! - The main management tool runs as an unprivileged user.
//! - It calls this helper (via sudo or direct exec if setuid) with a JSON request.
//! - This helper performs strict validation before doing any FS mutation.
//!
//! Usage (called by the main tool):
//!   echo '{"path":"/media/SSD-01/datastore","uid":3001,"gid":3002,"mode":504,"recursive":true}' | sudo /usr/local/bin/nfs-perm-helper
//!
//! The helper will only operate on paths under explicitly configured allowed roots
//! (currently hardcoded for safety — can be made configurable via a root-owned config later).

use serde::Deserialize;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process;

#[derive(Deserialize)]
struct Request {
    path: String,
    uid: u32,
    gid: u32,
    mode: u32,
    #[serde(default)]
    recursive: bool,
}

/// Hardcoded allowed roots for now. In production this should come from a
/// root-owned config file that the helper reads.
// On ZimaOS / locked-down appliances only attached/media drives are used.
// System paths such as /srv/nfs do not exist for exports.
const ALLOWED_ROOTS: &[&str] = &["/media/SSD-01", "/media/USB-01", "/mnt"];

fn is_path_allowed(path: &Path) -> bool {
    ALLOWED_ROOTS.iter().any(|root| path.starts_with(root))
}

fn main() {
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Failed to read request: {}", e);
        process::exit(1);
    }

    let req: Request = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Invalid request JSON: {}", e);
            process::exit(1);
        }
    };

    let target = Path::new(&req.path);

    // === Strict validation (this is the important security boundary) ===
    if !is_path_allowed(target) {
        eprintln!("Path not under any allowed root: {}", req.path);
        process::exit(1);
    }

    // Disallow root UID/GID unless explicitly needed (expand whitelist later)
    if req.uid == 0 || req.gid == 0 {
        eprintln!("Refusing to set UID or GID 0");
        process::exit(1);
    }

    // Reasonable mode check (no setuid/setgid bits from the tool for now)
    if req.mode & 0o7000 != 0 {
        eprintln!("Refusing mode with setuid/setgid/sticky bits");
        process::exit(1);
    }

    let uid = req.uid as libc::uid_t;
    let gid = req.gid as libc::gid_t;
    let mode = req.mode;

    if req.recursive {
        // Safe recursive walk with improved symlink/traversal hardening.
        for entry in walkdir::WalkDir::new(target)
            .follow_links(false)           // Never follow symlinks during traversal
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();

            // Basic allow-list check
            if !is_path_allowed(p) {
                eprintln!("Skipping path outside allowed roots: {}", p.display());
                continue;
            }

            // Stronger hardening: canonicalize and re-validate.
            // This catches symlinks that escape the allowed roots.
            match std::fs::canonicalize(p) {
                Ok(canonical) => {
                    if !is_path_allowed(&canonical) {
                        eprintln!("Refusing symlink traversal escape: {} -> {}", p.display(), canonical.display());
                        continue;
                    }
                }
                Err(_) => {
                    // If we can't canonicalize (broken symlink, permission, etc.), be conservative and skip.
                    eprintln!("Skipping unresolvable path during recursion: {}", p.display());
                    continue;
                }
            }

            // Apply chmod
            if let Err(e) = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)) {
                eprintln!("chmod failed on {}: {}", p.display(), e);
                process::exit(1);
            }

            // Apply chown via libc
            unsafe {
                if libc::chown(
                    std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap().as_ptr(),
                    uid,
                    gid,
                ) != 0
                {
                    eprintln!("chown failed on {} with errno {}", p.display(), std::io::Error::last_os_error());
                    process::exit(1);
                }
            }
        }
    } else {
        // Single path
        if let Err(e) = std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode)) {
            eprintln!("chmod failed: {}", e);
            process::exit(1);
        }

        unsafe {
            if libc::chown(
                std::ffi::CString::new(req.path.as_bytes()).unwrap().as_ptr(),
                uid,
                gid,
            ) != 0
            {
                eprintln!("chown failed with errno {}", std::io::Error::last_os_error());
                process::exit(1);
            }
        }
    }

    println!("OK: applied uid={} gid={} mode={:o} on {} (recursive={})", req.uid, req.gid, mode, req.path, req.recursive);
}
