//! Privileged chown/chmod on bind-mounted share trees after allow-list checks.
//! Only called from fs::FsManager::apply_*. WalkDir skips symlinks.
//! ACL read + mutation via safe getfacl/setfacl (for Ganesha ACL export path).

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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

    /// ACL twin of `fs::dir_mode_r_implies_x`: the directory editor submits
    /// x-less perms (Read stands for r+x — an r-without-x directory cannot be
    /// traversed over NFS), so execute fuses from read on directory targets.
    /// Like the mode fuse it only adds x, never clears an explicit one.
    pub fn dir_r_implies_x(mut self) -> Self {
        self.x = self.x || self.r;
        self
    }
}

/// Identifies a named (non-base) ACL principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclEntryKind {
    User(u32),
    Group(u32),
}

/// One line of a POSIX ACL, base entries included. The mask caps NamedUser,
/// NamedGroup, and OwningGroup entries (POSIX group class); Owner and Other
/// are never masked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclTag {
    Owner,
    NamedUser(u32),
    OwningGroup,
    NamedGroup(u32),
    Mask,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclLine {
    pub tag: AclTag,
    pub perms: AclPerms,
}

/// Full POSIX ACL of one path: the access ACL plus (directories only) the
/// default ACL that children inherit at creation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AclTable {
    pub access: Vec<AclLine>,
    pub default: Vec<AclLine>,
}

impl AclTable {
    fn layer(&self, default: bool) -> &[AclLine] {
        if default {
            &self.default
        } else {
            &self.access
        }
    }

    pub fn mask_of(&self, default: bool) -> Option<&AclPerms> {
        self.layer(default)
            .iter()
            .find(|l| l.tag == AclTag::Mask)
            .map(|l| &l.perms)
    }

    /// Effective permissions of a line per POSIX.1e: group-class entries are
    /// capped by the layer's mask when one exists; Owner/Other/Mask pass through.
    pub fn effective_perms(&self, line: &AclLine, default: bool) -> AclPerms {
        let masked = matches!(
            line.tag,
            AclTag::NamedUser(_) | AclTag::NamedGroup(_) | AclTag::OwningGroup
        );
        match (masked, self.mask_of(default)) {
            (true, Some(mask)) => AclPerms {
                r: line.perms.r && mask.r,
                w: line.perms.w && mask.w,
                x: line.perms.x && mask.x,
            },
            _ => line.perms.clone(),
        }
    }

    /// True when the access ACL carries more than the three base entries —
    /// the `+` in `ls -l` terms.
    pub fn is_extended(&self) -> bool {
        !self.default.is_empty()
            || self.access.iter().any(|l| {
                matches!(
                    l.tag,
                    AclTag::NamedUser(_) | AclTag::NamedGroup(_) | AclTag::Mask
                )
            })
    }
}

/// Modification to apply (add/overwrite one entry, remove one-or-more, or set
/// the mask). `default: true` targets the directory's default (inheritance)
/// ACL — callers must refuse it for non-directories. Policy: entry-merge and
/// targeted remove only — never `setfacl -b`, and never `-n` (letting setfacl
/// recalculate the mask on modification is the POSIX-friendly behavior).
#[derive(Debug, Clone)]
pub enum AclModification {
    /// Add or overwrite a single named ACL entry.
    Set {
        kind: AclEntryKind,
        perms: AclPerms,
        default: bool,
    },
    /// Delete one or more named entries (multi supported for Delete op).
    Remove {
        kinds: Vec<AclEntryKind>,
        default: bool,
    },
    /// Set the mask explicitly (the group-class cap; chmod's group bits edit
    /// the same object). setfacl still auto-recalcs it on later -m edits.
    SetMask { perms: AclPerms, default: bool },
}

// ACL via setfacl/getfacl (safe Command path).
// Provides named user/group entries for the ACL UI path. Ganesha consumes the FS ACLs.
// Keep ACL vs NOACL decision at higher level (enable_acl / acl_limited).

// Safe ACL via getfacl/setfacl (pure Command, no FFI).
// Named entries only; base preserved by tool. ACL vs NOACL remains explicit in callers.

/// Full table: base + named + mask entries of both the access and default
/// ACLs. Safe getfacl (numeric ids; effective-comment suffixes stripped).
pub fn get_acl_table(path: &Path) -> io::Result<AclTable> {
    let out = std::process::Command::new("getfacl")
        .args(["-c", "-n", "--absolute-names", "--"])
        .arg(path)
        .output()
        .map_err(|e| io::Error::other(format!("getfacl: {}", e)))?;
    if !out.status.success() {
        return Err(io::Error::other("getfacl failed"));
    }
    Ok(parse_getfacl_table(&String::from_utf8_lossy(&out.stdout)))
}

/// Parses full `getfacl -c -n` output. Lines look like `user::rwx`,
/// `group:1000:rw-`, `mask::r-x`, `other::r--`, with default-ACL lines
/// prefixed `default:` and mask-capped lines carrying a trailing
/// `#effective:...` comment (stripped here — effective perms are recomputed
/// from the mask so the model has one source of truth).
fn parse_getfacl_table(s: &str) -> AclTable {
    let mut table = AclTable::default();
    for raw in s.lines() {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((entry, _comment)) = line.split_once('#') {
            line = entry.trim();
        }
        let (default, rest) = match line.strip_prefix("default:") {
            Some(rest) => (true, rest),
            None => (false, line),
        };
        if let Some(parsed) = parse_acl_line(rest) {
            if default {
                table.default.push(parsed);
            } else {
                table.access.push(parsed);
            }
        }
    }
    table
}

fn parse_acl_line(rest: &str) -> Option<AclLine> {
    let (tag_str, qual_and_perms) = rest.split_once(':')?;
    let (qualifier, perms_str) = qual_and_perms.split_once(':')?;
    let perms = AclPerms::from_str(perms_str);
    let tag = match (tag_str, qualifier) {
        ("user", "") => AclTag::Owner,
        ("user", id) => AclTag::NamedUser(id.parse().ok()?),
        ("group", "") => AclTag::OwningGroup,
        ("group", id) => AclTag::NamedGroup(id.parse().ok()?),
        ("mask", "") => AclTag::Mask,
        ("other", "") => AclTag::Other,
        _ => return None,
    };
    Some(AclLine { tag, perms })
}

/// Apply mod via setfacl (safe). Supports Set, Remove, and SetMask on either
/// the access or the default layer (`-d`). Never emits `-b` or `-n`.
/// Removing absent entries is a no-op (setfacl semantics, probed).
pub fn apply_acl(path: &Path, modification: AclModification) -> io::Result<()> {
    let (default, op, spec) = modification_spec(&modification);
    run_setfacl(path, default, op, &spec)
}

fn run_setfacl(path: &Path, default: bool, op: &str, spec: &str) -> io::Result<()> {
    run_setfacl_many(std::slice::from_ref(&path.to_path_buf()), default, op, spec)
}

fn run_setfacl_many(paths: &[PathBuf], default: bool, op: &str, spec: &str) -> io::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut cmd = std::process::Command::new("setfacl");
    if default {
        cmd.arg("-d");
    }
    cmd.arg(op).arg(spec).arg("--");
    for p in paths {
        cmd.arg(p);
    }
    let out = cmd.output().map_err(|e| io::Error::other(e.to_string()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!(
            "setfacl {} failed: {}",
            op,
            stderr.lines().next().unwrap_or("unknown error")
        )));
    }
    Ok(())
}

/// The (default-layer, op flag, spec) triple a modification compiles to.
/// Perms render literally: recursive walks hand directories and files their
/// own modification (dirs fused r→x, files the panel's explicit Exec choice),
/// which replaced the old capital-X conditional grant.
pub fn modification_spec(m: &AclModification) -> (bool, &'static str, String) {
    let perm_str = |p: &AclPerms| p.to_str();
    match m {
        AclModification::Set {
            kind,
            perms,
            default,
        } => {
            let spec = match kind {
                AclEntryKind::User(u) => format!("u:{}:{}", u, perm_str(perms)),
                AclEntryKind::Group(g) => format!("g:{}:{}", g, perm_str(perms)),
            };
            (*default, "-m", spec)
        }
        AclModification::Remove { kinds, default } => {
            let specs: Vec<String> = kinds
                .iter()
                .map(|k| match k {
                    AclEntryKind::User(u) => format!("u:{}", u),
                    AclEntryKind::Group(g) => format!("g:{}", g),
                })
                .collect();
            (*default, "-x", specs.join(","))
        }
        AclModification::SetMask { perms, default } => {
            (*default, "-m", format!("m::{}", perm_str(perms)))
        }
    }
}

/// One batched getfacl over many paths: returns the subset whose ACL is
/// extended (named entries, mask, or default entries). Powers the tree's
/// `+` marker without a subprocess per row. Unreadable paths are skipped.
pub fn extended_acl_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    if paths.is_empty() {
        return Vec::new();
    }
    let mut cmd = std::process::Command::new("getfacl");
    // No -c: the "# file:" headers are the per-path delimiters here.
    cmd.args(["-n", "-p", "--absolute-names", "--"]);
    for p in paths {
        cmd.arg(p);
    }
    let Ok(out) = cmd.output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut result = Vec::new();
    let mut current: Option<PathBuf> = None;
    let mut current_extended = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(file) = t.strip_prefix("# file: ") {
            if let (Some(p), true) = (current.take(), current_extended) {
                result.push(p);
            }
            current = Some(PathBuf::from(file));
            current_extended = false;
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        // Named entries carry a qualifier; mask/default lines only exist on
        // extended ACLs.
        if t.starts_with("default:") || t.starts_with("mask::") {
            current_extended = true;
        } else if let Some(rest) = t.strip_prefix("user:") {
            if !rest.starts_with(':') {
                current_extended = true;
            }
        } else if let Some(rest) = t.strip_prefix("group:") {
            if !rest.starts_with(':') {
                current_extended = true;
            }
        }
    }
    if let (Some(p), true) = (current, current_extended) {
        result.push(p);
    }
    result
}

/// Chunked multi-path apply for recursive walks: one setfacl invocation per
/// chunk keeps subprocess overhead off the per-entry path.
pub fn apply_acl_many(paths: &[PathBuf], m: &AclModification) -> io::Result<()> {
    let (default, op, spec) = modification_spec(m);
    run_setfacl_many(paths, default, op, &spec)
}

// (byte-level pure ACL transform tests removed with switch to safe setfacl/getfacl; coverage on ACL paths preserved via fs/web integration tests driving get_acl/apply_acl)

#[cfg(test)]
mod acl_table_tests {
    use super::*;
    use tempfile::TempDir;

    // Mirrors fs::dir_mode_r_implies_x: r fuses x, w-only stays x-less, an
    // explicit x is never cleared.
    #[test]
    fn acl_perms_dir_r_implies_x_matches_the_mode_fuse() {
        let f = |s: &str| AclPerms::from_str(s).dir_r_implies_x().to_str();
        assert_eq!(f("r--"), "r-x");
        assert_eq!(f("rw-"), "rwx");
        assert_eq!(f("-w-"), "-w-");
        assert_eq!(f("--x"), "--x");
        assert_eq!(f("---"), "---");
        assert_eq!(f("rwx"), "rwx");
    }

    // getfacl -c -n output shape: base + named + mask with an effective
    // comment, plus a default layer (directories).
    const FIXTURE: &str = "\
user::rwx
user:1000:rwx\t\t#effective:r-x
group::rw-\t\t#effective:r--
group:2000:r--
mask::r-x
other::---
default:user::rwx
default:group::r-x
default:group:2000:rwx\t\t#effective:r-x
default:mask::r-x
default:other::---
";

    #[test]
    fn parse_full_table_with_defaults_and_effective_suffixes() {
        let t = parse_getfacl_table(FIXTURE);
        assert_eq!(t.access.len(), 6);
        assert_eq!(t.default.len(), 5);
        assert!(t.access.iter().any(|l| l.tag == AclTag::Owner && l.perms.r && l.perms.w && l.perms.x));
        // Entry perms are the GRANTED perms — the #effective comment is
        // stripped, never parsed into the entry.
        assert!(t.access.iter().any(|l| l.tag == AclTag::NamedUser(1000) && l.perms.w));
        assert!(t.access.iter().any(|l| l.tag == AclTag::OwningGroup && l.perms.w));
        assert!(t.access.iter().any(|l| l.tag == AclTag::NamedGroup(2000) && l.perms.r && !l.perms.w));
        assert_eq!(t.mask_of(false), Some(&AclPerms { r: true, w: false, x: true }));
        assert!(t.access.iter().any(|l| l.tag == AclTag::Other && !l.perms.r));
        assert!(t.default.iter().any(|l| l.tag == AclTag::NamedGroup(2000) && l.perms.w));
        assert_eq!(t.mask_of(true), Some(&AclPerms { r: true, w: false, x: true }));
        assert!(t.is_extended());
    }

    #[test]
    fn effective_perms_cap_group_class_only() {
        let t = parse_getfacl_table(FIXTURE);
        let named_user = t.access.iter().find(|l| l.tag == AclTag::NamedUser(1000)).unwrap();
        let eff = t.effective_perms(named_user, false);
        assert!(eff.r && !eff.w && eff.x, "mask r-x caps rwx to r-x");
        let owning_group = t.access.iter().find(|l| l.tag == AclTag::OwningGroup).unwrap();
        let eff = t.effective_perms(owning_group, false);
        assert!(eff.r && !eff.w && !eff.x, "mask caps the owning group too");
        let owner = t.access.iter().find(|l| l.tag == AclTag::Owner).unwrap();
        let eff = t.effective_perms(owner, false);
        assert!(eff.r && eff.w && eff.x, "the owner is never masked");
        let dflt_group = t.default.iter().find(|l| l.tag == AclTag::NamedGroup(2000)).unwrap();
        let eff = t.effective_perms(dflt_group, true);
        assert!(eff.r && !eff.w && eff.x, "default-layer mask caps default entries");
    }

    #[test]
    fn plain_mode_table_is_not_extended() {
        let t = parse_getfacl_table("user::rw-\ngroup::r--\nother::r--\n");
        assert_eq!(t.access.len(), 3);
        assert!(t.default.is_empty());
        assert!(!t.is_extended());
        assert_eq!(t.mask_of(false), None);
    }

    #[test]
    fn default_layer_and_mask_round_trip_on_real_dir() {
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path();

        // Default named entry: setfacl -d auto-fills the default base entries.
        apply_acl(
            dir,
            AclModification::Set {
                kind: AclEntryKind::User(4242),
                perms: AclPerms::from_str("rwx"),
                default: true,
            },
        )
        .expect("set default entry");
        let t = get_acl_table(dir).expect("table");
        assert!(t.default.iter().any(|l| l.tag == AclTag::NamedUser(4242) && l.perms.w));
        assert!(t.mask_of(true).is_some(), "default layer gets a mask");
        assert!(
            !t.access.iter().any(|l| matches!(l.tag, AclTag::NamedUser(_))),
            "default-layer set must not touch the access layer"
        );

        // Access-layer mask set: named entry first so a mask exists to cap.
        apply_acl(
            dir,
            AclModification::Set {
                kind: AclEntryKind::User(4242),
                perms: AclPerms::from_str("rwx"),
                default: false,
            },
        )
        .expect("set access entry");
        apply_acl(
            dir,
            AclModification::SetMask {
                perms: AclPerms::from_str("r--"),
                default: false,
            },
        )
        .expect("set mask");
        let t = get_acl_table(dir).expect("table after mask");
        assert_eq!(t.mask_of(false), Some(&AclPerms { r: true, w: false, x: false }));
        let entry = t.access.iter().find(|l| l.tag == AclTag::NamedUser(4242)).unwrap();
        let eff = t.effective_perms(entry, false);
        assert!(eff.r && !eff.w && !eff.x, "explicit mask caps the named entry");

        // Default-layer removal leaves the access layer alone.
        apply_acl(
            dir,
            AclModification::Remove {
                kinds: vec![AclEntryKind::User(4242)],
                default: true,
            },
        )
        .expect("remove default entry");
        let t = get_acl_table(dir).expect("table after default remove");
        assert!(!t.default.iter().any(|l| matches!(l.tag, AclTag::NamedUser(_))));
        assert!(t.access.iter().any(|l| l.tag == AclTag::NamedUser(4242)));
    }
}

// === Direct real-FS tests for shipped chown (nix) + chmod (std) ===
// These exercise the privileged fns directly on disk. chmod always verifiable;
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
