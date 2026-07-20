//! Pure directive builders for ACL/NOACL. Explicit branches.

use crate::{
    compute_read_access_policy_emit, EffectiveShareFlags, FsCapabilities, ReadAccessPolicyEmit,
};

pub fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub fn derive_export_id(name: &str, base: u16) -> u16 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        h = h.wrapping_mul(16777619) ^ (*b as u32);
    }
    // Fold the id into range with u32 math so a large base can't overflow u16.
    let floor = base as u32;
    let span = 55000u32.min((u16::MAX as u32).saturating_sub(floor).max(1));
    (floor + (h % span)) as u16
}

pub fn fragment_basename(index: usize, name: &str) -> String {
    format!("{:02}-{}.conf", index + 10, sanitize_name(name))
}

pub fn export_fs_directives(
    _share: &crate::Share,
    caps: &FsCapabilities,
    eff: &EffectiveShareFlags,
) -> (String, String, String, String) {
    let manage_gids_line = if eff.manage_gids {
        "    Manage_Gids = true;\n".to_string()
    } else {
        "    Manage_Gids = false;\n".to_string()
    };

    let (disable_acl_line, auto_comment) = if !eff.enable_acl {
        let disable = "    Disable_ACL = true;\n".to_string();
        let opts = if caps.mount_options.is_empty() {
            String::new()
        } else {
            format!(" ({})", caps.mount_options.join(","))
        };
        let comment = if eff.auto_applied {
            format!(
                "# Auto-detected: {}{opts} — cannot store POSIX ACLs. The 9.13 VFS backend
# fetches ACLs on every attribute refresh, so exports on this filesystem are
# expected to fail attribute fetches regardless of Disable_ACL; stage onto an
# ACL-capable serve tree. See docs/ganesha-architecture.md#acl-and-filesystem-compatibility\n",
                caps.fstype, opts = opts
            )
        } else {
            String::new()
        };
        (disable, comment)
    } else {
        // Auto-enabled fragments name the proof for operators.
        let comment = if eff.auto_enabled {
            format!(
                "# Auto-enabled: enable_acl unset and the ACL write probe passed on {}.
# See docs/ganesha-architecture.md#acl-and-filesystem-compatibility\n",
                caps.fstype
            )
        } else {
            String::new()
        };
        // ACL exports declare Disable_ACL = false explicitly, never inherited.
        ("    Disable_ACL = false;\n".to_string(), comment)
    };

    // No per-export FSAL Umask on 9.13; use Inherit ACLs + setgid.
    let umask_line = String::new();
    (disable_acl_line, manage_gids_line, umask_line, auto_comment)
}

pub fn export_read_access_line(share: &crate::Share, eff: &EffectiveShareFlags) -> String {
    match compute_read_access_policy_emit(share, eff) {
        ReadAccessPolicyEmit::Omit => String::new(),
        ReadAccessPolicyEmit::Pre => "    Read_Access_Check_Policy = pre;\n".to_string(),
        ReadAccessPolicyEmit::Post => "    Read_Access_Check_Policy = post;\n".to_string(),
    }
}

pub fn export_pseudo_line(pseudo: &str) -> String {
    format!("    Pseudo = {};\n", pseudo)
}
