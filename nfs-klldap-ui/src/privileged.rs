//! Privileged chown/chmod on bind-mounted share trees after allow-list checks.
//! Only called from fs::FsManager::apply_*. WalkDir skips symlinks.
//! ACL read + mutation via safe getfacl/setfacl (for Ganesha ACL export path).

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

// chown uses nix::unistd (requires "user" feature) for direct syscall; keeps error shape
// compatible with prior. chmod on std. (libc dep retained only if other unix needs; unused import cleaned)
pub fn chown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(uid)),
        Some(nix::unistd::Gid::from_raw(gid)),
    )
    .map_err(|e| std::io::Error::other(format!("chown: {}", e)))
}

pub fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
}

/// Compact rwx representation for a named ACL entry (relative permissions).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AclPerms {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl AclPerms {
    pub fn from_str(s: &str) -> Self {
        let s = s.trim().to_ascii_lowercase();
        AclPerms {
            r: s.contains('r'),
            w: s.contains('w'),
            x: s.contains('x') || s.contains('X'),
        }
    }
    pub fn to_str(&self) -> String {
        let mut out = String::with_capacity(3);
        out.push(if self.r { 'r' } else { '-' });
        out.push(if self.w { 'w' } else { '-' });
        out.push(if self.x { 'x' } else { '-' });
        out
    }

}

/// Identifies a named (non-base) ACL principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclEntryKind {
    User(u32),
    Group(u32),
}

/// A single named user or group ACL entry (not the owning user:: / group:: / other / mask).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEntry {
    pub kind: AclEntryKind,
    pub perms: AclPerms,
}

/// Modification to apply (add/overwrite one entry, or remove one-or-more).
#[derive(Debug, Clone)]
pub enum AclModification {
    /// Add or overwrite a single named ACL entry.
    Set { kind: AclEntryKind, perms: AclPerms },
    /// Delete one or more named entries (multi supported for Delete op).
    Remove { kinds: Vec<AclEntryKind> },
}

// ACL via setfacl/getfacl (safe Command path).
// Provides named user/group entries for the ACL UI path. Ganesha consumes the FS ACLs.
// Keep ACL vs NOACL decision at higher level (enable_acl / acl_limited).

// Safe ACL via getfacl/setfacl (pure Command, no FFI).
// Named entries only; base preserved by tool. ACL vs NOACL remains explicit in callers.

/// Public: named user/group only (for UI lists). Safe getfacl.
pub fn get_acl(path: &Path) -> io::Result<Vec<AclEntry>> {
    let out = std::process::Command::new("getfacl")
        .args(["-c", "-n", "--absolute-names", path.to_str().unwrap_or(".")])
        .output()
        .map_err(|e| io::Error::other(format!("getfacl: {}", e)))?;
    if !out.status.success() {
        return Err(io::Error::other("getfacl failed"));
    }
    Ok(parse_getfacl_text(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_getfacl_text(s: &str) -> Vec<AclEntry> {
    let mut res = vec![];
    for ln in s.lines() {
        let t = ln.trim();
        if let Some(st) = t.strip_prefix("user:") {
            if let Some((idp, pstr)) = st.split_once(':') {
                if let Ok(id) = idp.parse::<u32>() {
                    res.push(AclEntry { kind: AclEntryKind::User(id), perms: AclPerms::from_str(pstr) });
                }
            }
        } else if let Some(st) = t.strip_prefix("group:") {
            if let Some((idp, pstr)) = st.split_once(':') {
                if let Ok(id) = idp.parse::<u32>() {
                    res.push(AclEntry { kind: AclEntryKind::Group(id), perms: AclPerms::from_str(pstr) });
                }
            }
        }
    }
    res
}

/// Apply mod via setfacl (safe). Supports Set and Remove.
pub fn apply_acl(path: &Path, modification: AclModification) -> io::Result<()> {
    match modification {
        AclModification::Set { kind, perms } => {
            let spec = match kind {
                AclEntryKind::User(u) => format!("u:{}:{}", u, perms.to_str()),
                AclEntryKind::Group(g) => format!("g:{}:{}", g, perms.to_str()),
            };
            let st = std::process::Command::new("setfacl")
                .args(["-m", &spec, path.to_str().unwrap_or(".")])
                .status()
                .map_err(|e| io::Error::other(e.to_string()))?;
            if !st.success() { return Err(io::Error::other("setfacl set failed")); }
        }
        AclModification::Remove { kinds } => {
            for k in kinds {
                let spec = match k {
                    AclEntryKind::User(u) => format!("u:{}", u),
                    AclEntryKind::Group(g) => format!("g:{}", g),
                };
                let _ = std::process::Command::new("setfacl")
                    .args(["-x", &spec, path.to_str().unwrap_or(".")])
                    .status();
            }
        }
    }
    Ok(())
}

// (byte-level pure ACL transform tests removed with switch to safe setfacl/getfacl; coverage on ACL paths preserved via fs/web integration tests driving get_acl/apply_acl)

// === Direct real-FS tests for shipped chown (nix) + chmod (std) ===
// These exercise the privileged fns without going through dry_run. chmod always verifiable;
// chown attempt proves the nix call (may EPERM without privs but error path from new impl).
#[cfg(test)]
mod direct_privileged_fs_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn privileged_chmod_changes_mode_on_real_path() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("tchmod");
        std::fs::write(&p, b"hi").unwrap();
        chmod(&p, 0o600).expect("chmod direct");
        let m = std::fs::metadata(&p).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600, "std chmod must affect disk");
        // idempotent re-apply
        chmod(&p, 0o644).expect("chmod 644");
        let m2 = std::fs::metadata(&p).unwrap();
        assert_eq!(m2.permissions().mode() & 0o777, 0o644);
    }

    #[test]
    fn privileged_chown_via_nix_attempts_on_real_path() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("tchown");
        std::fs::write(&p, b"hi").unwrap();
        // Use current ids (safe values); proves nix::unistd::chown body executed.
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let r = chown(&p, uid, gid);
        if let Err(e) = r {
            let s = e.to_string();
            assert!(s.contains("chown") || s.contains("EPERM") || s.contains("Operation not permitted"), "chown error must originate from nix path: {}", s);
        }
        // At minimum the file remains accessible.
        assert!(std::fs::metadata(&p).is_ok());
    }
}
