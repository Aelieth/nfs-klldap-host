//! Mountinfo probe for POSIX ACL capability on share paths.

use std::io;
use std::path::Path;

use crate::Share;

/// Backing filesystem capabilities for a resolved container share path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsCapabilities {
    pub fstype: String,
    pub mount_options: Vec<String>,
    pub acl_capable: bool,
}

/// Effective EXPORT flags after TOML overrides and probe results.
/// enable_acl=false means emit Disable_ACL=true (conservative on limited FS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveShareFlags {
    pub enable_acl: bool,
    pub manage_gids: bool,
    /// True when probe (not explicit TOML) drove the safe defaults.
    pub auto_applied: bool,
}

#[derive(Debug, Clone)]
struct MountEntry {
    mount_point: String,
    fstype: String,
    mount_source: String,
    super_options: Vec<String>,
}

/// Probes path against live mountinfo.
/// On failure it assumes ACL-capable so generate never aborts.
pub fn probe_fs_capabilities(path: &Path) -> io::Result<FsCapabilities> {
    let mountinfo_path = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH")
        .unwrap_or_else(|_| "/proc/self/mountinfo".to_string());
    let content = std::fs::read_to_string(mountinfo_path)?;
    Ok(probe_from_mountinfo(&content, path))
}

/// Probes path against fixture or live mountinfo (tests).
pub fn probe_from_mountinfo(content: &str, path: &Path) -> FsCapabilities {
    let entries = parse_mountinfo(content);
    let path_str = path.to_string_lossy();
    match resolve_mount_for_path(&entries, path_str.as_ref()) {
        Some(entry) => {
            let acl_capable = acl_capable_from_mount(&entry.fstype, &entry.super_options, &entry.mount_source);
            FsCapabilities {
                fstype: entry.fstype.clone(),
                mount_options: entry.super_options.clone(),
                acl_capable,
            }
        }
        None => FsCapabilities {
            fstype: "unknown".into(),
            mount_options: vec![],
            acl_capable: true,
        },
    }
}

/// Merges explicit share flags with probe results.
/// This is the core of the two distinct mainline paths:
/// - enable_acl=false (probe auto on NTFS/FAT/btrfs+noacl or explicit) → NOACL path (0.9.40 simple disk settings).
/// - enable_acl=true (or auto on capable) → ACL path (full native).
/// manage_gids follows independently (override or default true on all paths).
/// Limited FS defaults: enable_acl=false, manage_gids=true (auto NOACL still fetches managed gids).
/// Capable FS defaults: enable_acl=true, manage_gids=true. First-class modes + overrides preserved.
/// Whether to emit Read_Access_Check_Policy in the EXPORT block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAccessPolicyEmit {
    /// Omit line; Ganesha 9.6 default is pre.
    Omit,
    Pre,
    Post,
}

/// Resolves per-share Read_Access_Check_Policy for fragment emission.
/// Auto: NOACL path emits pre; ACL-capable path omits (native default).
pub fn compute_read_access_policy_emit(
    share: &Share,
    caps: &FsCapabilities,
) -> ReadAccessPolicyEmit {
    if let Some(ref raw) = share.read_access_policy {
        let policy = raw.trim().to_ascii_lowercase();
        if policy == "post" {
            return ReadAccessPolicyEmit::Post;
        }
        return ReadAccessPolicyEmit::Pre;
    }
    let eff = compute_effective_flags(share, caps);
    if eff.enable_acl {
        ReadAccessPolicyEmit::Omit
    } else {
        ReadAccessPolicyEmit::Pre
    }
}

pub fn compute_effective_flags(share: &Share, caps: &FsCapabilities) -> EffectiveShareFlags {
    let probe_limited = !caps.acl_capable;
    let enable_acl = share.enable_acl.unwrap_or(!probe_limited);
    let manage_gids = share.manage_gids.unwrap_or(true);
    let auto_applied =
        probe_limited && share.enable_acl.is_none() && share.manage_gids.is_none();
    EffectiveShareFlags {
        enable_acl,
        manage_gids,
        auto_applied,
    }
}

fn parse_mountinfo(content: &str) -> Vec<MountEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        if let Some(entry) = parse_mountinfo_line(line) {
            entries.push(entry);
        }
    }
    entries
}

fn parse_mountinfo_line(line: &str) -> Option<MountEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    // Parses mountinfo id, parent, root, mount point, fstype, and opts.
    if parts.len() < 10 {
        return None;
    }
    let dash = parts.iter().position(|p| *p == "-")?;
    if dash + 3 >= parts.len() {
        return None;
    }
    let mount_point = parts.get(4)?.to_string();
    let fstype = parts[dash + 1].to_string();
    let mount_source = parts[dash + 2].to_string();
    let super_options: Vec<String> = parts[dash + 3..]
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    Some(MountEntry {
        mount_point,
        fstype,
        mount_source,
        super_options,
    })
}

fn resolve_mount_for_path<'a>(entries: &'a [MountEntry], path: &str) -> Option<&'a MountEntry> {
    let norm = normalize_path(path);
    entries
        .iter()
        .filter(|e| path_under_mount(&norm, &normalize_path(&e.mount_point)))
        .max_by_key(|e| normalize_path(&e.mount_point).len())
}

fn path_under_mount(path: &str, mount_point: &str) -> bool {
    if path == mount_point {
        return true;
    }
    if mount_point == "/" {
        return path.starts_with('/');
    }
    path.starts_with(&format!("{mount_point}/"))
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn acl_capable_from_mount(fstype: &str, options: &[String], mount_source: &str) -> bool {
    if options.iter().any(|o| o.eq_ignore_ascii_case("noacl")) {
        return false;
    }
    let fs = fstype.to_ascii_lowercase();
    match fs.as_str() {
        "vfat" | "fat" | "msdos" | "exfat" => false,
        "ntfs" | "ntfs3" | "fuseblk" => false,
        _ if mount_source.to_ascii_lowercase().contains("ntfs") => false,
        _ => true,
    }
}

// Strings for limited_fs_warning* live in fs_warnings.rs (per Step4/acceptance).
// limited_fs_warning now takes real &Share (not dummy) so explicit manage_gids overrides on NOACL shares are reflected in messages/WARNs from CLI/generate/validate.

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"
36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl
37 36 0:60 / /export/movies rw,relatime - ext4 /dev/sdb1 rw
38 36 0:61 / /export/data rw,relatime - xfs /dev/sdc1 rw
39 36 0:62 / /export/usb rw,relatime - vfat /dev/sdd1 rw,fmask=0022,dmask=0022
40 36 0:63 / /export/ntfs rw,relatime - fuseblk /dev/sde1 rw,allow_other,default_permissions
"#;

    #[test]
    fn btrfs_noacl_not_capable() {
        let caps = probe_from_mountinfo(FIXTURE, Path::new("/export/users"));
        assert_eq!(caps.fstype, "btrfs");
        assert!(!caps.acl_capable);
        assert!(caps.mount_options.iter().any(|o| o == "noacl"));
    }

    #[test]
    fn ext4_xfs_capable() {
        let ext4 = probe_from_mountinfo(FIXTURE, Path::new("/export/movies/sub"));
        assert_eq!(ext4.fstype, "ext4");
        assert!(ext4.acl_capable);
        let xfs = probe_from_mountinfo(FIXTURE, Path::new("/export/data"));
        assert_eq!(xfs.fstype, "xfs");
        assert!(xfs.acl_capable);
    }

    #[test]
    fn vfat_ntfs_not_capable() {
        let vfat = probe_from_mountinfo(FIXTURE, Path::new("/export/usb"));
        assert!(!vfat.acl_capable);
        let ntfs = probe_from_mountinfo(FIXTURE, Path::new("/export/ntfs"));
        assert_eq!(ntfs.fstype, "fuseblk");
        assert!(!ntfs.acl_capable);
    }

    #[test]
    fn unknown_path_assumes_capable() {
        let caps = probe_from_mountinfo(FIXTURE, Path::new("/other/new"));
        assert_eq!(caps.fstype, "unknown");
        assert!(caps.acl_capable);
    }

    #[test]
    fn root_mount_matches_export_subpaths() {
        let fixture = "1 0 0:1 / / rw - btrfs /dev/sda1 rw,noacl\n";
        let caps = probe_from_mountinfo(fixture, Path::new("/export/users"));
        assert_eq!(caps.fstype, "btrfs");
        assert!(!caps.acl_capable);
    }

    #[test]
    fn explicit_noacl_on_ext4_not_capable() {
        let fixture = "37 36 0:60 / /export/movies rw - ext4 /dev/sdb1 rw,noacl\n";
        let caps = probe_from_mountinfo(fixture, Path::new("/export/movies"));
        assert!(!caps.acl_capable);
    }

    #[test]
    fn read_access_policy_auto_noacl_emits_pre() {
        let share = Share::default();
        let caps = FsCapabilities {
            fstype: "btrfs".into(),
            mount_options: vec!["noacl".into()],
            acl_capable: false,
        };
        assert_eq!(
            compute_read_access_policy_emit(&share, &caps),
            ReadAccessPolicyEmit::Pre
        );
    }

    #[test]
    fn read_access_policy_auto_acl_omits() {
        let share = Share::default();
        let caps = FsCapabilities {
            fstype: "ext4".into(),
            mount_options: vec![],
            acl_capable: true,
        };
        assert_eq!(
            compute_read_access_policy_emit(&share, &caps),
            ReadAccessPolicyEmit::Omit
        );
    }

    #[test]
    fn read_access_policy_explicit_post_on_acl() {
        let mut share = Share::default();
        share.read_access_policy = Some("post".into());
        let caps = FsCapabilities {
            fstype: "ext4".into(),
            mount_options: vec![],
            acl_capable: true,
        };
        assert_eq!(
            compute_read_access_policy_emit(&share, &caps),
            ReadAccessPolicyEmit::Post
        );
    }

    #[test]
    fn compute_effective_flags_auto_limited() {
        let share = Share::default();
        let caps = FsCapabilities {
            fstype: "btrfs".into(),
            mount_options: vec!["noacl".into()],
            acl_capable: false,
        };
        let eff = compute_effective_flags(&share, &caps);
        assert!(!eff.enable_acl);
        assert!(eff.manage_gids);
        assert!(eff.auto_applied);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn compute_effective_flags_explicit_override() {
        let mut share = Share::default();
        share.enable_acl = Some(true);
        share.manage_gids = Some(true);
        let caps = FsCapabilities {
            fstype: "btrfs".into(),
            mount_options: vec!["noacl".into()],
            acl_capable: false,
        };
        let eff = compute_effective_flags(&share, &caps);
        assert!(eff.enable_acl);
        assert!(eff.manage_gids);
        assert!(!eff.auto_applied);
    }
}