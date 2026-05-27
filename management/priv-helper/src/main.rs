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
//! Allowed roots are derived at runtime from the [[shares]] host_path entries in
//! the central nfs-klldap.conf (same file used by the UI and the container generator).
//! The path is communicated via NFS_KLLDAP_CONF (preferred) or a small set of
//! conventional locations. If the config cannot be read, the helper denies all operations.

use nfs_klldap_config::load_host_paths_only;
use serde::Deserialize;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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

/// Resolve the central config path using the same convention as the UI:
/// 1. NFS_KLLDAP_CONF env (set by caller when spawning helper)
/// 2. Fallback to "nfs-klldap.conf" in current working directory.
fn resolve_config_path() -> PathBuf {
    std::env::var("NFS_KLLDAP_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("nfs-klldap.conf"))
}

/// Load the current set of allowed host roots from the TOML (live on every invocation).
/// Returns empty vec on any error (deny-by-default).
fn load_allowed_roots() -> Vec<PathBuf> {
    let path = resolve_config_path();
    match load_host_paths_only(&path) {
        Ok(roots) => {
            if roots.is_empty() {
                eprintln!(
                    "priv-helper: no shares found in {} (deny all)",
                    path.display()
                );
            }
            roots
        }
        Err(e) => {
            eprintln!(
                "priv-helper: failed to load allowed roots from {}: {} (deny all)",
                path.display(),
                e
            );
            vec![]
        }
    }
}

fn is_path_allowed(path: &Path, allowed: &[PathBuf]) -> bool {
    if allowed.is_empty() {
        return false;
    }
    allowed.iter().any(|root| path.starts_with(root))
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

    // Live allow-list from the central TOML (re-read on every helper invocation so share additions
    // via the UI are immediately effective for subsequent permission operations).
    let allowed_roots = load_allowed_roots();

    // === Strict validation (this is the important security boundary) ===
    if !is_path_allowed(target, &allowed_roots) {
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

    let uid = req.uid; // u32 — matches std::os::unix::fs::chown signature
    let gid = req.gid;
    let mode = req.mode;

    if req.recursive {
        // Safe recursive walk with improved symlink/traversal hardening.
        for entry in walkdir::WalkDir::new(target)
            .follow_links(false) // Never follow symlinks during traversal
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();

            // Basic allow-list check (live from TOML)
            if !is_path_allowed(p, &allowed_roots) {
                eprintln!("Skipping path outside allowed roots: {}", p.display());
                continue;
            }

            // Stronger hardening: canonicalize and re-validate.
            // This catches symlinks that escape the allowed roots.
            match std::fs::canonicalize(p) {
                Ok(canonical) => {
                    if !is_path_allowed(&canonical, &allowed_roots) {
                        eprintln!(
                            "Refusing symlink traversal escape: {} -> {}",
                            p.display(),
                            canonical.display()
                        );
                        continue;
                    }
                }
                Err(_) => {
                    // If we can't canonicalize (broken symlink, permission, etc.), be conservative and skip.
                    eprintln!(
                        "Skipping unresolvable path during recursion: {}",
                        p.display()
                    );
                    continue;
                }
            }

            // Apply chmod
            if let Err(e) = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)) {
                eprintln!("chmod failed on {}: {}", p.display(), e);
                process::exit(1);
            }

            // Apply chown (safe std API since Rust 1.73)
            if let Err(e) = std::os::unix::fs::chown(p, Some(uid), Some(gid)) {
                eprintln!("chown failed on {}: {}", p.display(), e);
                process::exit(1);
            }
        }
    } else {
        // Single path
        if let Err(e) = std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode)) {
            eprintln!("chmod failed: {}", e);
            process::exit(1);
        }

        // Apply chown (safe std API)
        if let Err(e) = std::os::unix::fs::chown(target, Some(uid), Some(gid)) {
            eprintln!("chown failed on {}: {}", target.display(), e);
            process::exit(1);
        }
    }

    println!(
        "OK: applied uid={} gid={} mode={:o} on {} (recursive={})",
        req.uid, req.gid, mode, req.path, req.recursive
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_path_allowed_works_with_empty_and_populated_lists() {
        let empty: Vec<PathBuf> = vec![];
        assert!(!is_path_allowed(Path::new("/media/SSD/foo"), &empty));

        let allowed = vec![PathBuf::from("/media/SSD-01"), PathBuf::from("/mnt/data")];
        assert!(is_path_allowed(Path::new("/media/SSD-01/movies"), &allowed));
        assert!(is_path_allowed(Path::new("/mnt/data/backups"), &allowed));
        assert!(!is_path_allowed(Path::new("/root"), &allowed));
        assert!(!is_path_allowed(Path::new("/media/SSD-02"), &allowed));
    }

    #[test]
    fn resolve_config_path_prefers_env() {
        std::env::set_var("NFS_KLLDAP_CONF", "/etc/nfs/my.conf");
        assert_eq!(resolve_config_path(), PathBuf::from("/etc/nfs/my.conf"));
        std::env::remove_var("NFS_KLLDAP_CONF");
    }

    #[test]
    fn resolve_config_path_defaults_to_local_file() {
        std::env::remove_var("NFS_KLLDAP_CONF");
        assert_eq!(resolve_config_path(), PathBuf::from("nfs-klldap.conf"));
    }
}
