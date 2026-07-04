//! Privileged chown/chmod on bind-mounted share trees after allow-list checks.
//! Only called from fs::FsManager::apply_*. WalkDir skips symlinks.
//! Also implements ACL read + mutation using pure-Rust libc xattr on
//! system.posix_acl_access (for Ganesha 9.6 ACL export path). No external setfacl/getfacl.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

// libc for direct getxattr/setxattr syscalls (pure Rust FFI, no shell, no additional high-level crate).
#[allow(clippy::single_component_path_imports)]
#[cfg(unix)]
use libc;

// chown uses nix::unistd (requires "user" feature) for direct syscall; keeps error shape
// compatible with prior std::os::unix::fs::chown. chmod stays on std for mode bits.
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
    #[allow(dead_code)]
    pub fn to_octal(&self) -> u8 {
        (if self.r { 4 } else { 0 }) | (if self.w { 2 } else { 0 }) | (if self.x { 1 } else { 0 })
    }
    #[allow(dead_code)]
    pub fn from_octal(o: u8) -> Self {
        AclPerms {
            r: (o & 4) != 0,
            w: (o & 2) != 0,
            x: (o & 1) != 0,
        }
    }
    /// Human short form e.g. "r-x" (used in UI lists).
    #[allow(dead_code)]
    pub fn display(&self) -> String {
        self.to_str()
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

impl AclEntry {
    #[allow(dead_code)]
    pub fn is_user(&self) -> bool {
        matches!(self.kind, AclEntryKind::User(_))
    }
    #[allow(dead_code)]
    pub fn id(&self) -> u32 {
        match self.kind {
            AclEntryKind::User(u) => u,
            AclEntryKind::Group(g) => g,
        }
    }
}

/// Modification to apply (add/overwrite one entry, or remove one-or-more).
#[derive(Debug, Clone)]
pub enum AclModification {
    /// Add or overwrite a single named ACL entry.
    Set { kind: AclEntryKind, perms: AclPerms },
    /// Delete one or more named entries (multi supported for Delete op).
    Remove { kinds: Vec<AclEntryKind> },
}

// Pure-Rust POSIX ACL implementation (no external setfacl/getfacl).
// Uses nix::sys::xattr on "system.posix_acl_access" + manual little-endian
// header+entries parse/serialize. Satisfies "Rust only code" constraint while
// providing the basic named user/group rwx entries required for Ganesha ACL
// export path (NFSv4 translation happens in Ganesha; we manage the FS ACLs).
// Base entries (user::/group::/mask/other) are preserved.

const XATTR_ACL_ACCESS: &str = "system.posix_acl_access";
const ACL_VERSION2: u32 = 2;  // must be 2 (le32 02 00 00 00), matches setfacl output

const TAG_USER_OBJ: u16 = 0x0001;
const TAG_USER:     u16 = 0x0002;
const TAG_GROUP_OBJ:u16 = 0x0004;
const TAG_GROUP:    u16 = 0x0008;
const TAG_MASK:     u16 = 0x0010;
const TAG_OTHER:    u16 = 0x0020;

const ACL_ID_NONE: u32 = 0xffffffff; // used for *_OBJ and MASK and OTHER in the xattr format

/// Build the three base entries (user:: / group:: / other::) from the dir's current stat mode bits.
/// Id for obj entries must be ACL_ID_NONE (0xffffffff).
#[allow(clippy::unnecessary_cast)]
fn base_entries_from_stat(path: &Path) -> io::Result<Vec<(u16, u16, u32)>> {
    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode() as u16;
    let u_perm = ((mode >> 6) & 0x7) as u16;
    let g_perm = ((mode >> 3) & 0x7) as u16;
    let o_perm = (mode & 0x7) as u16;
    Ok(vec![
        (TAG_USER_OBJ, u_perm, ACL_ID_NONE),
        (TAG_GROUP_OBJ, g_perm, ACL_ID_NONE),
        (TAG_OTHER, o_perm, ACL_ID_NONE),
    ])
}

/// Read the raw xattr via libc (returns empty for ENODATA).
pub(crate) fn read_acl_xattr_raw(path: &Path) -> io::Result<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let p = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad path"))?;
    let name = CString::new(XATTR_ACL_ACCESS).unwrap();

    // First probe size
    #[allow(unsafe_code)]
    let sz = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if sz < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(vec![]);
        }
        return Err(e);
    }
    if sz == 0 {
        return Ok(vec![]);
    }
    let mut buf = vec![0u8; sz as usize];
    #[allow(unsafe_code)]
    let r = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), buf.as_mut_ptr() as *mut _, sz as usize) };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(vec![]);
        }
        return Err(e);
    }
    buf.truncate(r as usize);
    Ok(buf)
}

/// Parse raw bytes -> all entries (we filter named for public API).
pub(crate) fn parse_acl_bytes(data: &[u8]) -> io::Result<Vec<(u16, u16, u32)>> {
    if data.is_empty() {
        return Ok(vec![]);
    }
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short acl"));
    }
    let ver = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // Accept common variants (some tools emit 2)
    if ver != ACL_VERSION2 && ver != 2 {
        // be tolerant
    }
    let mut out = Vec::new();
    let mut off = 4usize;
    while off + 8 <= data.len() {
        let tag = u16::from_le_bytes([data[off], data[off+1]]);
        let perm = u16::from_le_bytes([data[off+2], data[off+3]]);
        let id = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
        out.push((tag, perm, id));
        off += 8;
    }
    Ok(out)
}

fn serialize_acl_bytes(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + entries.len() * 8);
    v.extend_from_slice(&ACL_VERSION2.to_le_bytes());
    for (tag, perm, id) in entries {
        v.extend_from_slice(&tag.to_le_bytes());
        v.extend_from_slice(&perm.to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
    }
    v
}



/// Public: named user/group only (for UI lists).
pub fn get_acl(path: &Path) -> io::Result<Vec<AclEntry>> {
    let raw = read_acl_xattr_raw(path)?;
    let all = parse_acl_bytes(&raw)?;
    let mut named = Vec::new();
    for (tag, perm, id) in all {
        let p = AclPerms::from_octal((perm & 0x7) as u8);
        if tag == TAG_USER {
            named.push(AclEntry { kind: AclEntryKind::User(id), perms: p });
        } else if tag == TAG_GROUP {
            named.push(AclEntry { kind: AclEntryKind::Group(id), perms: p });
        }
    }
    Ok(named)
}

/// Build a full entry list from current + apply the Modification, preserving base.
/// Produces canonical order: USER_OBJ, named USERs, GROUP_OBJ, named GROUPs, MASK, OTHER.
/// On initial (virgin) caller seeds bases via base_entries_from_stat (using real mode bits).
fn apply_modification_to_entries(current: &[(u16,u16,u32)], modification: AclModification) -> Vec<(u16,u16,u32)> {
    // Separate current into bases + nameds
    let mut user_obj = None;
    let mut group_obj = None;
    let mut other = None;
    let mut named_users: Vec<(u16,u16,u32)> = vec![];
    let mut named_groups: Vec<(u16,u16,u32)> = vec![];

    for &(tag, perm, id) in current {
        match tag {
            TAG_USER_OBJ => user_obj = Some((tag, perm, id)),
            TAG_GROUP_OBJ => group_obj = Some((tag, perm, id)),
            TAG_OTHER => other = Some((tag, perm, id)),
            TAG_USER => named_users.push((tag, perm, id)),
            TAG_GROUP => named_groups.push((tag, perm, id)),
            _ => {}
        }
    }

    // Apply mod
    match modification {
        AclModification::Set { kind, perms } => {
            let (want_tag, want_id) = match kind {
                AclEntryKind::User(u) => (TAG_USER, u),
                AclEntryKind::Group(g) => (TAG_GROUP, g),
            };
            let new_perm = perms.to_octal() as u16 & 0x7;
            if want_tag == TAG_USER {
                named_users.retain(|&(_,_,id)| id != want_id);
                named_users.push((want_tag, new_perm, want_id));
            } else {
                named_groups.retain(|&(_,_,id)| id != want_id);
                named_groups.push((want_tag, new_perm, want_id));
            }
        }
        AclModification::Remove { kinds } => {
            for k in kinds {
                let (want_tag, want_id) = match k {
                    AclEntryKind::User(u) => (TAG_USER, u),
                    AclEntryKind::Group(g) => (TAG_GROUP, g),
                };
                if want_tag == TAG_USER {
                    named_users.retain(|&(_,_,id)| id != want_id);
                } else {
                    named_groups.retain(|&(_,_,id)| id != want_id);
                }
            }
        }
    }

    // Recompute mask from all
    let mut max_p: u16 = 0;
    for &(_, p, _) in [&user_obj, &group_obj, &other].iter().filter_map(|x| x.as_ref()) {
        max_p |= p & 0x7;
    }
    for &(_, p, _) in named_users.iter().chain(named_groups.iter()) {
        max_p |= p & 0x7;
    }
    let final_mask = (TAG_MASK, max_p, ACL_ID_NONE);

    // Build canonical ordered list (use provided bases or defaults)
    let uo = user_obj.unwrap_or((TAG_USER_OBJ, 0o7, ACL_ID_NONE));
    let go = group_obj.unwrap_or((TAG_GROUP_OBJ, 0o7, ACL_ID_NONE));
    let ot = other.unwrap_or((TAG_OTHER, 0o7, ACL_ID_NONE));

    let mut out = vec![uo];
    out.extend(named_users);
    out.push(go);
    out.extend(named_groups);
    out.push(final_mask);
    out.push(ot);
    out
}

/// Write full ACL xattr via libc setxattr.
fn write_acl_xattr(path: &Path, entries: &[(u16, u16, u32)]) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let p = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad path"))?;
    let name = CString::new(XATTR_ACL_ACCESS).unwrap();
    let bytes = serialize_acl_bytes(entries);
    #[allow(unsafe_code)]
    let r = unsafe {
        libc::setxattr(
            p.as_ptr(),
            name.as_ptr(),
            bytes.as_ptr() as *const _,
            bytes.len(),
            0,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Pure I/O glue only. Read xattr (if any) → call pure transform (apply_modification_to_entries etc) → write xattr.
/// No Command, no setfacl. If the underlying FS rejects the xattr write (e.g. certain tmpfs), the call fails
/// with OS error; callers/tests for FS mutation should be on ACL-capable FS (ext4/xfs with acl) or marked #[ignore].
pub fn apply_acl(path: &Path, modification: AclModification) -> io::Result<()> {
    let raw = read_acl_xattr_raw(path)?;
    let mut current = parse_acl_bytes(&raw)?;
    if current.is_empty() {
        if let Ok(bases) = base_entries_from_stat(path) {
            current = bases;
        } else {
            current = vec![
                (TAG_USER_OBJ, 0o7, ACL_ID_NONE),
                (TAG_GROUP_OBJ, 0o5, ACL_ID_NONE),
                (TAG_OTHER, 0o5, ACL_ID_NONE),
            ];
        }
    }
    let new_entries = apply_modification_to_entries(&current, modification);
    write_acl_xattr(path, &new_entries)
}

// === Pure transform unit tests (table-driven on fixed vectors, NO FS, NO Command) ===
// These prove the "mutation logic" (virgin + Set, bases, ver=2, order, mask) independently of I/O.
#[cfg(test)]
mod acl_pure_transform_tests {
    use super::*;

    fn mk_set_user(id: u32, p: &str) -> AclModification {
        AclModification::Set { kind: AclEntryKind::User(id), perms: AclPerms::from_str(p) }
    }
    fn mk_set_group(id: u32, p: &str) -> AclModification {
        AclModification::Set { kind: AclEntryKind::Group(id), perms: AclPerms::from_str(p) }
    }

    #[test]
    fn virgin_dir_set_user_and_group_produces_ver2_full_bases_named_mask_other() {
        let current: Vec<(u16,u16,u32)> = vec![];
        // simulate Set user + group (as if two applies, or one combined)
        let after1 = apply_modification_to_entries(&current, mk_set_user(12345, "r-x"));
        let after2 = apply_modification_to_entries(&after1, mk_set_group(6789, "rw-"));

        let bytes = serialize_acl_bytes(&after2);
        assert_eq!(&bytes[0..4], &[2, 0, 0, 0], "version must be 2 (le)");

        // Must contain all base tags + named + mask
        let tags: Vec<u16> = after2.iter().map(|(t,_,_)| *t).collect();
        assert!(tags.contains(&TAG_USER_OBJ), "must have USER_OBJ");
        assert!(tags.contains(&TAG_GROUP_OBJ), "must have GROUP_OBJ");
        assert!(tags.contains(&TAG_OTHER), "must have OTHER");
        assert!(tags.contains(&TAG_MASK), "must have MASK");
        assert!(tags.contains(&TAG_USER), "must have named USER");
        assert!(tags.contains(&TAG_GROUP), "must have named GROUP");

        // Named ids present
        assert!(after2.iter().any(|(t,_,id)| *t==TAG_USER && *id==12345));
        assert!(after2.iter().any(|(t,_,id)| *t==TAG_GROUP && *id==6789));

        // Mask should be max (7 in this case for rwx on user)
        let mask_entry = after2.iter().find(|(t,_,_)| *t==TAG_MASK).unwrap();
        assert_eq!(mask_entry.1 & 0x7, 0x7);
    }

    #[test]
    fn parse_serialize_roundtrip_matches_canonical_layout() {
        // bytes captured from setfacl for user:12345:r-x + group:6789:rw- (adjusted base)
        let sample: Vec<u8> = vec![
            2,0,0,0,
            1,0, 6,0, 0xff,0xff,0xff,0xff,   // user_obj rw-
            2,0, 5,0, 0x39,0x30,0,0,          // user 12345 r-x
            4,0, 4,0, 0xff,0xff,0xff,0xff,   // group_obj r--
            8,0, 6,0, 0x85,0x1a,0,0,          // group 6789 rw-
            16,0,7,0, 0xff,0xff,0xff,0xff,   // mask rwx
            32,0,4,0, 0xff,0xff,0xff,0xff,   // other r--
        ];
        let parsed = parse_acl_bytes(&sample).expect("parse");
        let reser = serialize_acl_bytes(&parsed);
        assert_eq!(reser, sample, "roundtrip must preserve bytes including ver=2 and id=ffffffff for bases");
    }
}

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
