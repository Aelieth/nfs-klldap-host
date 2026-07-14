//! Mountinfo + write-probe for POSIX ACL capability on serve paths.

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

/// Effective EXPORT flags after TOML + probe (`enable_acl=false` → Disable_ACL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveShareFlags {
    pub enable_acl: bool,
    pub manage_gids: bool,
    /// Probe (not explicit TOML) drove limited-FS safe defaults.
    pub auto_applied: bool,
    /// Auto mode promoted ACL after a proven write probe.
    pub auto_enabled: bool,
}

/// Layered ACL probe: only write round-trip proves Capable; denylist/failed RT
/// prove Incapable; else Inconclusive (warn, no hard-fail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclProbeVerdict {
    Capable,
    Incapable,
    Inconclusive,
}

#[derive(Debug, Clone)]
struct MountEntry {
    mount_point: String,
    fstype: String,
    mount_source: String,
    super_options: Vec<String>,
}

/// Live mountinfo probe. Fail-safe: errors assume not ACL-capable.
/// Auto ACL still requires write round-trip proof separately.
pub fn probe_fs_capabilities(path: &Path) -> io::Result<FsCapabilities> {
    probe_fs_capabilities_with_root(path).map(|(caps, _)| caps)
}

/// Mountinfo probe plus matched mount root (for per-mount UI cache keys).
pub fn probe_fs_capabilities_with_root(
    path: &Path,
) -> io::Result<(FsCapabilities, Option<String>)> {
    let mountinfo_path = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH")
        .unwrap_or_else(|_| "/proc/self/mountinfo".to_string());
    let content = std::fs::read_to_string(mountinfo_path)?;
    Ok(probe_from_mountinfo_with_root(&content, path))
}

/// Probes path against fixture or live mountinfo (tests)
pub fn probe_from_mountinfo(content: &str, path: &Path) -> FsCapabilities {
    probe_from_mountinfo_with_root(content, path).0
}

/// One ACL-incapable mount discovered strictly below a share serve root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclIncapableMount {
    pub mount_point: String,
    pub fstype: String,
}

/// One mountinfo read shared across a request or reprobe pass.
/// Read precedence per capture matches the per-call probes: an explicit
/// fixture path first, then NFS_KLLDAP_MOUNTINFO_PATH, then
/// /proc/self/mountinfo. `content` stays None when nothing was readable so
/// callers keep their own fail-safe vs display-lenient fallbacks.
pub struct MountinfoSnapshot {
    content: Option<String>,
}

impl MountinfoSnapshot {
    pub fn capture(fixture: Option<&Path>) -> Self {
        if let Some(mp) = fixture {
            if let Ok(content) = std::fs::read_to_string(mp) {
                return MountinfoSnapshot {
                    content: Some(content),
                };
            }
        }
        let live = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH")
            .unwrap_or_else(|_| "/proc/self/mountinfo".to_string());
        MountinfoSnapshot {
            content: std::fs::read_to_string(live).ok(),
        }
    }

    /// Caps plus matched mount point; None when no mountinfo was readable.
    pub fn probe_with_root(&self, path: &Path) -> Option<(FsCapabilities, Option<String>)> {
        self.content
            .as_deref()
            .map(|content| probe_from_mountinfo_with_root(content, path))
    }

    /// Caps only; None when no mountinfo was readable.
    pub fn probe(&self, path: &Path) -> Option<FsCapabilities> {
        self.probe_with_root(path).map(|(caps, _)| caps)
    }

    /// Mounts strictly below `root` whose filesystem cannot store POSIX ACLs.
    /// The root's own mount never matches (its class IS the share verdict), so
    /// any hit means the share tree mixes capability classes. Overmounts
    /// collapse to the last mountinfo entry per mount point (the visible one);
    /// unreadable mountinfo yields an empty list.
    pub fn acl_incapable_mounts_under(&self, root: &Path) -> Vec<AclIncapableMount> {
        let Some(content) = self.content.as_deref() else {
            return Vec::new();
        };
        let root_norm = normalize_path(&root.to_string_lossy());
        let mut visible: std::collections::BTreeMap<String, MountEntry> = Default::default();
        for e in parse_mountinfo(content) {
            visible.insert(normalize_path(&e.mount_point), e);
        }
        visible
            .into_iter()
            .filter(|(mp, e)| {
                mp != &root_norm
                    && path_under_mount(mp, &root_norm)
                    && !acl_capable_from_mount(&e.fstype, &e.super_options, &e.mount_source)
            })
            .map(|(mp, e)| AclIncapableMount {
                mount_point: mp,
                fstype: e.fstype,
            })
            .collect()
    }
}

/// Caps plus the matched mount point. None means the path resolved to no
/// mount, which pairs with the fail-safe "unknown" capabilities.
pub fn probe_from_mountinfo_with_root(
    content: &str,
    path: &Path,
) -> (FsCapabilities, Option<String>) {
    let entries = parse_mountinfo(content);
    let path_str = path.to_string_lossy();
    match resolve_mount_for_path(&entries, path_str.as_ref()) {
        Some(entry) => {
            let acl_capable = acl_capable_from_mount(&entry.fstype, &entry.super_options, &entry.mount_source);
            (
                FsCapabilities {
                    fstype: entry.fstype.clone(),
                    mount_options: entry.super_options.clone(),
                    acl_capable,
                },
                Some(entry.mount_point.clone()),
            )
        }
        // Unresolved path: fail safe. ACL is opt-in and separately verified, so a
        // conservative "not capable" here only affects the auto-detect comment, never
        // whether a share is served.
        None => (
            FsCapabilities {
                fstype: "unknown".into(),
                mount_options: vec![],
                acl_capable: false,
            },
            None,
        ),
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

/// Read policy emit (pre on NOACL, omit on ACL auto). Takes the already
/// resolved flags so auto-ACL shares get the ACL-path emission.
pub fn compute_read_access_policy_emit(
    share: &Share,
    eff: &EffectiveShareFlags,
) -> ReadAccessPolicyEmit {
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

/// Static verdict from mountinfo capabilities alone (no disk access).
/// The denylist is a definitive negative; anything else stays unproven.
pub fn verdict_from_caps(caps: &FsCapabilities) -> AclProbeVerdict {
    if caps.acl_capable {
        AclProbeVerdict::Inconclusive
    } else {
        AclProbeVerdict::Incapable
    }
}

/// Static flags: auto mode resolves to NOACL without a real probe verdict.
/// Warnings, validate, and settings use this fail-safe view; generate and the
/// permissions panel use `compute_effective_flags_probed` with a live verdict.
pub fn compute_effective_flags(share: &Share, caps: &FsCapabilities) -> EffectiveShareFlags {
    compute_effective_flags_probed(share, caps, verdict_from_caps(caps))
}

/// Flags with a real probe verdict (0.9.90 auto-ACL semantics).
/// Explicit true/false always wins; unset = AUTO, which turns ACL on only when
/// the write round-trip proved the filesystem stores POSIX ACLs.
/// Auto never fails generation: unproven degrades to NOACL, the historic rock.
pub fn compute_effective_flags_probed(
    share: &Share,
    caps: &FsCapabilities,
    verdict: AclProbeVerdict,
) -> EffectiveShareFlags {
    let enable_acl = match share.enable_acl {
        Some(v) => v,
        None => verdict == AclProbeVerdict::Capable,
    };
    let manage_gids = share.manage_gids.unwrap_or(true);
    // Auto-detect comment fires when auto lands on a genuinely limited FS.
    let auto_applied = !caps.acl_capable && share.enable_acl.is_none();
    let auto_enabled = enable_acl && share.enable_acl.is_none();
    EffectiveShareFlags {
        enable_acl,
        manage_gids,
        auto_applied,
        auto_enabled,
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
    if stderr_says_not_supported(&String::from_utf8_lossy(&out.stderr)) {
        Some(false)
    } else {
        None
    }
}

/// Shared interpretation of acl-tool failures: the kernel's EOPNOTSUPP
/// surfaces as "Operation not supported" from both getfacl and setfacl.
pub(crate) fn stderr_says_not_supported(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("not supported")
}

/// Definitive write round-trip: prove the serve path's filesystem can STORE
/// POSIX ACLs. The read sniff above is a weak predictor — getfacl happily
/// synthesizes base entries from mode bits on some paths — so only a named
/// entry that survives a setfacl→getfacl round trip counts as proof.
///
/// Creates a transient dot-named probe file under `dir`, sets `u:0:rwx` on it
/// via setfacl, reads it back via getfacl, and always removes the file.
/// `Some(true)` = entry stored and read back; `Some(false)` = the filesystem
/// refused ACL storage; `None` = inconclusive (probe file or tools
/// unavailable) — callers keep the warning path rather than hard-failing.
pub fn serve_path_posix_acl_write_probe(dir: &Path) -> Option<bool> {
    let probe = dir.join(format!(".nfs-klldap-aclprobe-{}", std::process::id()));
    if std::fs::File::create(&probe).is_err() {
        return None;
    }
    let verdict = write_probe_round_trip(&probe);
    let _ = std::fs::remove_file(&probe);
    verdict
}

fn write_probe_round_trip(probe: &Path) -> Option<bool> {
    let set = std::process::Command::new("setfacl")
        .arg("-m")
        .arg("u:0:rwx")
        .arg("--")
        .arg(probe)
        .output()
        .ok()?;
    if !set.status.success() {
        return if stderr_says_not_supported(&String::from_utf8_lossy(&set.stderr)) {
            Some(false)
        } else {
            None
        };
    }
    let get = std::process::Command::new("getfacl")
        .args(["-c", "-n", "--absolute-names", "--"])
        .arg(probe)
        .output()
        .ok()?;
    if !get.status.success() {
        return None;
    }
    let stored = String::from_utf8_lossy(&get.stdout)
        .lines()
        .any(|l| l.trim() == "user:0:rwx");
    if stored {
        Some(true)
    } else {
        None
    }
}

/// Layered capability decision for an `enable_acl = true` serve path:
/// mountinfo denylist (fast definitive negative) → write round-trip
/// (definitive both ways) → read sniff (definitive negative only) →
/// Inconclusive. Generate hard-fails on Incapable and warns on Inconclusive.
pub fn acl_probe_verdict(caps: &FsCapabilities, serve_path: &Path) -> AclProbeVerdict {
    if !caps.acl_capable {
        return AclProbeVerdict::Incapable;
    }
    match serve_path_posix_acl_write_probe(serve_path) {
        Some(true) => AclProbeVerdict::Capable,
        Some(false) => AclProbeVerdict::Incapable,
        None => match serve_path_posix_acl_supported(serve_path) {
            Some(false) => AclProbeVerdict::Incapable,
            _ => AclProbeVerdict::Inconclusive,
        },
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
    fn stderr_not_supported_detection_is_case_insensitive() {
        assert!(stderr_says_not_supported(
            "getfacl: /x: Operation not supported"
        ));
        assert!(stderr_says_not_supported("setfacl: /x: OPERATION NOT SUPPORTED"));
        assert!(!stderr_says_not_supported("setfacl: /x: Permission denied"));
        assert!(!stderr_says_not_supported(""));
    }

    #[test]
    fn write_probe_round_trips_on_acl_capable_tempdir() {
        // tmpfs and the usual dev filesystems store POSIX ACLs, so the round
        // trip proves the happy path end to end with the shipped tools; the
        // probe file must be gone afterwards either way.
        let tmp = tempfile::tempdir().expect("tempdir");
        let verdict = serve_path_posix_acl_write_probe(tmp.path());
        assert_eq!(verdict, Some(true), "tempdir should store POSIX ACLs");
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .collect();
        assert!(leftovers.is_empty(), "probe file must be cleaned up");
    }

    #[test]
    fn write_probe_missing_dir_is_inconclusive() {
        let verdict =
            serve_path_posix_acl_write_probe(Path::new("/nonexistent-nfs-klldap-probe-dir"));
        assert_eq!(verdict, None);
    }

    #[test]
    fn verdict_denylist_is_definitive_negative_without_touching_disk() {
        let caps = FsCapabilities {
            fstype: "vfat".into(),
            mount_options: vec![],
            acl_capable: false,
        };
        // Path deliberately nonexistent: the denylist must decide first.
        let verdict = acl_probe_verdict(&caps, Path::new("/nonexistent-probe-target"));
        assert_eq!(verdict, AclProbeVerdict::Incapable);
    }

    #[test]
    fn verdict_capable_requires_write_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let caps = FsCapabilities {
            fstype: "ext4".into(),
            mount_options: vec![],
            acl_capable: true,
        };
        assert_eq!(acl_probe_verdict(&caps, tmp.path()), AclProbeVerdict::Capable);
    }

    #[test]
    fn verdict_unwritable_path_is_inconclusive_not_incapable() {
        let caps = FsCapabilities {
            fstype: "ext4".into(),
            mount_options: vec![],
            acl_capable: true,
        };
        // Missing dir: probe file creation fails (None) and the read sniff
        // also fails without a "not supported" signature -> Inconclusive.
        let verdict = acl_probe_verdict(&caps, Path::new("/nonexistent-probe-target"));
        assert_eq!(verdict, AclProbeVerdict::Inconclusive);
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
    fn incapable_submounts_exclude_the_root_mount_itself() {
        let snap = MountinfoSnapshot {
            content: Some(FIXTURE.to_string()),
        };
        // /export is itself incapable (btrfs+noacl) but is the root, so only
        // the strictly-below vfat and fuseblk mounts count, sorted by path.
        let got: Vec<(String, String)> = snap
            .acl_incapable_mounts_under(Path::new("/export"))
            .into_iter()
            .map(|m| (m.mount_point, m.fstype))
            .collect();
        assert_eq!(
            got,
            vec![
                ("/export/ntfs".to_string(), "fuseblk".to_string()),
                ("/export/usb".to_string(), "vfat".to_string()),
            ]
        );
        assert!(snap
            .acl_incapable_mounts_under(Path::new("/export/movies"))
            .is_empty());
        let unreadable = MountinfoSnapshot { content: None };
        assert!(unreadable
            .acl_incapable_mounts_under(Path::new("/export"))
            .is_empty());
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
    fn mount_root_longest_prefix_wins() {
        // A path under a submount reports the submount, not /export.
        let (caps, root) =
            probe_from_mountinfo_with_root(FIXTURE, Path::new("/export/movies/sub"));
        assert_eq!(caps.fstype, "ext4");
        assert_eq!(root.as_deref(), Some("/export/movies"));
        let (_, top) = probe_from_mountinfo_with_root(FIXTURE, Path::new("/export/users"));
        assert_eq!(top.as_deref(), Some("/export"));
    }

    #[test]
    fn mount_root_falls_back_to_root_mount() {
        let fixture = "1 0 0:1 / / rw - btrfs /dev/sda1 rw,noacl\n";
        let (_, root) = probe_from_mountinfo_with_root(fixture, Path::new("/export/users"));
        assert_eq!(root.as_deref(), Some("/"));
    }

    #[test]
    fn mount_root_unresolved_is_none_and_unknown() {
        let (caps, root) = probe_from_mountinfo_with_root(FIXTURE, Path::new("/other/new"));
        assert_eq!(caps.fstype, "unknown");
        assert!(!caps.acl_capable);
        assert!(root.is_none());
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
            compute_read_access_policy_emit(&share, &compute_effective_flags(&share, &caps)),
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
            compute_read_access_policy_emit(&share, &compute_effective_flags(&share, &caps)),
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
            compute_read_access_policy_emit(&share, &compute_effective_flags(&share, &caps)),
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
            compute_read_access_policy_emit(&share, &compute_effective_flags(&share, &caps)),
            ReadAccessPolicyEmit::Pre
        );
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn enable_acl_is_opt_in_only() {
        // STATIC view: unset enable_acl => NOACL without a proven write probe
        // (mountinfo capability alone is never promotion-worthy).
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
    fn auto_acl_turns_on_only_with_proven_probe() {
        let caps = FsCapabilities {
            fstype: "btrfs".into(),
            mount_options: vec![],
            acl_capable: true,
        };
        let unset = Share::default();
        // Proven write probe => auto turns ACL on and marks the promotion.
        let eff = compute_effective_flags_probed(&unset, &caps, AclProbeVerdict::Capable);
        assert!(eff.enable_acl && eff.auto_enabled && !eff.auto_applied);
        // Unproven stays NOACL: auto never promotes on guesswork.
        let eff = compute_effective_flags_probed(&unset, &caps, AclProbeVerdict::Inconclusive);
        assert!(!eff.enable_acl && !eff.auto_enabled);
        let eff = compute_effective_flags_probed(&unset, &caps, AclProbeVerdict::Incapable);
        assert!(!eff.enable_acl && !eff.auto_enabled);
        // Explicit false beats a Capable probe; explicit true is never "auto".
        let off = Share { enable_acl: Some(false), ..Share::default() };
        let eff = compute_effective_flags_probed(&off, &caps, AclProbeVerdict::Capable);
        assert!(!eff.enable_acl);
        let on = Share { enable_acl: Some(true), ..Share::default() };
        let eff = compute_effective_flags_probed(&on, &caps, AclProbeVerdict::Capable);
        assert!(eff.enable_acl && !eff.auto_enabled);
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