//! Pure directive builders for ACL/NOACL. Explicit branches.

use crate::{
    compute_effective_flags, compute_read_access_policy_emit, ReadAccessPolicyEmit,
    FsCapabilities,
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
    base + (h % 55000) as u16
}

pub fn fragment_basename(index: usize, name: &str) -> String {
    format!("{:02}-{}.conf", index + 10, sanitize_name(name))
}

pub fn export_fs_directives(share: &crate::Share, caps: &FsCapabilities) -> (String, String, String, String) {
    let eff = compute_effective_flags(share, caps);
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
                "# Auto-detected: {}{opts} — ACL-dependent NFSv4 ops disabled for compatibility.
# See docs/ganesha-architecture.md#acl-and-filesystem-compatibility\n",
                caps.fstype, opts = opts
            )
        } else {
            String::new()
        };
        (disable, comment)
    } else {
        let comment = if eff.auto_applied {
            let opts = if caps.mount_options.is_empty() {
                String::new()
            } else {
                format!(" ({})", caps.mount_options.join(","))
            };
            format!(
                "# Auto-detected: {}{opts}
# See docs/ganesha-architecture.md#acl-and-filesystem-compatibility\n",
                caps.fstype, opts = opts
            )
        } else {
            String::new()
        };
        (String::new(), comment)
    };

    let umask_line = if eff.enable_acl {
        let val = eff.umask.as_deref().filter(|u| crate::fs_probe::is_valid_umask(u)).unwrap_or("0022");
        format!("        Umask = {};\n", val)
    } else {
        String::new()
    };
    (disable_acl_line, manage_gids_line, umask_line, auto_comment)
}

pub fn export_read_access_line(share: &crate::Share, caps: &FsCapabilities) -> String {
    match compute_read_access_policy_emit(share, caps) {
        ReadAccessPolicyEmit::Omit => String::new(),
        ReadAccessPolicyEmit::Pre => "    Read_Access_Check_Policy = pre;\n".to_string(),
        ReadAccessPolicyEmit::Post => "    Read_Access_Check_Policy = post;\n".to_string(),
    }
}

pub fn export_pseudo_line(pseudo: &str) -> String {
    format!("    Pseudo = {};\n", pseudo)
}
