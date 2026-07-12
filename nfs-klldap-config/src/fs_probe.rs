//! Mountinfo probe for POSIX ACL on share paths.

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
/// Enable_acl=false means emit Disable_ACL=true (conservative on limited FS)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveShareFlags {
    pub enable_acl: bool,
    pub manage_gids: bool,
    /// True when probe (not explicit TOML) drove the safe defaults.
    pub auto_applied: bool,
    /// Resolved umask (e.g. "0022"); inert since 9.13 (no per-export Umask).
    pub umask: Option<String>,
}

#[derive(Debug, Clone)]
struct MountEntry {
    mount_point: String,
    fstype: String,
    mount_source: String,
    super_options: Vec<String>,
}

/// Probes path against live mountinfo.
/// On failure it assumes NOT ACL-capable so generate never emits a broken ACL
/// export (fail-safe). ACL is opt-in via `enable_acl = true` (see
/// `compute_effective_flags`), so a conservative probe never suppresses a share.
pub fn probe_fs_capabilities(path: &Path) -> io::Result<FsCapabilities> {
    let mountinfo_path = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH")
        .unwrap_or_else(|_| "/proc/self/mountinfo".to_string());
    let content = std::fs::read_to_string(mountinfo_path)?;
    Ok(probe_from_mountinfo(&content, path))
}

/// Probes path against fixture or live mountinfo (tests)
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
        // Unresolved path: fail safe. ACL is opt-in and separately verified, so a
        // conservative "not capable" here only affects the auto-detect comment, never
        // whether a share is served.
        None => FsCapabilities {
            fstype: "unknown".into(),
            mount_options: vec![],
            acl_capable: false,
        },
    }
}

/// Core ACL vs NOACL flags (probe + override). manage_gids defaults true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAccessPolicyEmit {
    /// Omit line; Ganesha 9.6 default is pre.
    Omit,
    Pre,
    Post,
}

/// Read policy emit (pre on NOACL, omit on ACL auto)
pub fn compute_read_access_policy_emit(
    share: &Share,
    caps: &FsCapabilities,
) -> ReadAccessPolicyEmit {
    let eff = compute_effective_flags(share, caps);
    if let Some(ref raw) = share.read_access_policy {
        let policy = raw.trim().to_ascii_lowercase();
        if policy == "post" {
            // post is only meaningful on the ACL path. On a NOACL export (the default,
            // or a share not opted into ACL) it is silently normalized to pre so an
            // existing `read_access_policy = post` never blocks generation.
            return if eff.enable_acl {
                ReadAccessPolicyEmit::Post
            } else {
                ReadAccessPolicyEmit::Pre
            };
        }
        return ReadAccessPolicyEmit::Pre;
    }
    if eff.enable_acl {
        ReadAccessPolicyEmit::Omit
    } else {
        ReadAccessPolicyEmit::Pre
    }
}

pub(crate) fn is_valid_umask(s: &str) -> bool {
    let t = s.trim();
    t.len() == 4 && t.starts_with('0') && t[1..].chars().all(|c| matches!(c, '0'..='7'))
}

pub fn compute_effective_flags(share: &Share, caps: &FsCapabilities) -> EffectiveShareFlags {
    let probe_limited = !caps.acl_capable;
    // ACL is opt-in (per-share operator choice). Unset or false => NOACL. This removes
    // the old fail-open where a "capable" probe silently emitted an ACL export that the
    // packaged Ganesha 9.6 VFS FSAL cannot service (NFS4ERR_NOTSUPP). enable_acl = true
    // is separately capability-verified (loud warning) before the ACL path is taken.
    let enable_acl = share.enable_acl == Some(true);
    let manage_gids = share.manage_gids.unwrap_or(true);
    // Auto-detect comment is informational only: it fires when the operator did not opt
    // into ACL and the probe found a genuinely limited FS (vfat/ntfs/noacl mount).
    let auto_applied = probe_limited && share.enable_acl.is_none();
    let umask = share.umask.as_deref().filter(|u| is_valid_umask(u)).map(|u| u.to_string()).or_else(|| {
        if enable_acl { Some("0022".to_string()) } else { None }
    });
    EffectiveShareFlags {
        enable_acl,
        manage_gids,
        auto_applied,
        umask,
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

pub fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Best-effort local check: does the serve path's filesystem support POSIX ACLs at all?
///
/// This is only a partial predictor of whether Ganesha's VFS FSAL can service NFSv4 ACL
/// operations (that also depends on the packaged Ganesha build — see
/// docs/ganesha-architecture.md and `scripts/verify-ganesha.sh` for the authoritative,
/// empirical check). It reliably catches filesystems that cannot do ACLs at all.
///
/// Implemented via `getfacl` (from the already-installed `acl` package) to keep this crate
/// free of raw syscalls. Returns `Some(false)` when the filesystem reports ACLs unsupported,
/// `Some(true)` when ACLs are readable, and `None` when inconclusive (tool or path missing).
pub fn serve_path_posix_acl_supported(path: &Path) -> Option<bool> {
    let out = std::process::Command::new("getfacl")
        .arg("-c") // omit the file-name header
        .arg("--")
        .arg(path)
        .output()
        .ok()?;
    if out.status.success() {
        return Some(true);
    }
    let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
    if stderr.contains("not supported") {
        Some(false)
    } else {
        None
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_umask_accepts_4_digit_octal_with_leading_zero_only() {
        for ok in ["0022", "0027", "0777", " 0002 "] {
            assert!(is_valid_umask(ok), "{ok}");
        }
        for bad in ["022", "999", "0088", "22", "", "00222", "umask"] {
            assert!(!is_valid_umask(bad), "{bad}");
        }
    }

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
    fn unknown_path_assumes_not_capable() {
        // Fail-safe: an unresolved path must not be treated as ACL-capable, so a share
        // is never silently promoted onto the (packaged-VFS-broken) ACL path.
        let caps = probe_from_mountinfo(FIXTURE, Path::new("/other/new"));
        assert_eq!(caps.fstype, "unknown");
        assert!(!caps.acl_capable);
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
    #[allow(clippy::field_reassign_with_default)]
    fn read_access_policy_acl_omits() {
        // ACL is opt-in: enable_acl = true is required to take the ACL path.
        let mut share = Share::default();
        share.enable_acl = Some(true);
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
    #[allow(clippy::field_reassign_with_default)]
    fn read_access_policy_explicit_post_on_acl() {
        let mut share = Share::default();
        share.enable_acl = Some(true);
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
    #[allow(clippy::field_reassign_with_default)]
    fn read_access_policy_post_on_noacl_normalizes_to_pre() {
        // post is meaningless on a NOACL (default/opt-out) share and must normalize to pre
        // rather than emit an invalid post line.
        let mut share = Share::default();
        share.read_access_policy = Some("post".into());
        let caps = FsCapabilities {
            fstype: "ext4".into(),
            mount_options: vec![],
            acl_capable: true,
        };
        assert_eq!(
            compute_read_access_policy_emit(&share, &caps),
            ReadAccessPolicyEmit::Pre
        );
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn enable_acl_is_opt_in_only() {
        // Unset enable_acl => NOACL even on an ACL-capable FS (no fail-open).
        let unset = Share::default();
        let caps = FsCapabilities {
            fstype: "ext4".into(),
            mount_options: vec![],
            acl_capable: true,
        };
        assert!(!compute_effective_flags(&unset, &caps).enable_acl);
        // enable_acl = false => NOACL.
        let mut off = Share::default();
        off.enable_acl = Some(false);
        assert!(!compute_effective_flags(&off, &caps).enable_acl);
        // enable_acl = true => ACL.
        let mut on = Share::default();
        on.enable_acl = Some(true);
        assert!(compute_effective_flags(&on, &caps).enable_acl);
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