//! Limited/NOACL filesystem support (warnings side) for the distinct NOACL path.
//! 0.9.40-style simple directives (Disable_ACL + Manage_Gids=false) are emitted for
//! noacl (btrfs+noacl, vfat, ntfs, ...) via explicit branch in generate; this
//! module supplies the fs_warnings / UI badge text for the NOACL mainline path
//! (ACL path uses native full settings). UID/GID resolution logic is untouched.

use crate::fs_probe::{EffectiveShareFlags, FsCapabilities};
use crate::ganesha_log_contract::ganesha_96_has_mode_only_access_knob;

/// Warning provider for the NOACL/limited path (distinct from ACL-capable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixOnlyPolicy {
    pub fs_warning: String,
    pub settings_ui_warning: String,
    pub staging_recommended: bool,
}

fn mount_opts_suffix(caps: &FsCapabilities) -> String {
    if caps.mount_options.is_empty() {
        String::new()
    } else {
        format!(" ({})", caps.mount_options.join(","))
    }
}

impl PosixOnlyPolicy {
    /// Builds warning info for a share with `enable_acl=false` (probe or explicit).
    /// Directives themselves are handled by the two-path branch in export_fs_directives
    /// (NOACL uses 0.9.40 simple Disable_ACL + Manage_Gids=false).
    pub fn for_share(share_name: &str, caps: &FsCapabilities, eff: &EffectiveShareFlags) -> Option<Self> {
        if eff.enable_acl {
            return None;
        }
        let staging_recommended = !ganesha_96_has_mode_only_access_knob();
        let opts = mount_opts_suffix(caps);
        let fs_warning = format!(
            "share \"{share_name}\": {fstype}{opts} limited filesystem — NOACL mode (enable_acl=false, manage_gids={mg}); ACL-dependent NFSv4 ops disabled for compatibility",
            share_name = share_name,
            fstype = caps.fstype,
            opts = opts,
            mg = eff.manage_gids,
        );
        let settings_ui_warning = format!(
            "share \"{share_name}\": {fstype}{opts} limited filesystem — NOACL (enable_acl={enable_acl}, manage_gids={manage_gids})",
            share_name = share_name,
            fstype = caps.fstype,
            opts = opts,
            enable_acl = eff.enable_acl,
            manage_gids = eff.manage_gids,
        );
        Some(PosixOnlyPolicy {
            fs_warning,
            settings_ui_warning,
            staging_recommended,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Share;

    #[test]
    fn posix_only_policy_noacl_btrfs_warns_without_acl_policy_markers() {
        let caps = FsCapabilities {
            fstype: "btrfs".into(),
            mount_options: vec!["noacl".into()],
            acl_capable: false,
        };
        let eff = crate::compute_effective_flags(&Share::default(), &caps);
        let policy = PosixOnlyPolicy::for_share("users", &caps, &eff).expect("limited policy");
        assert!(policy.staging_recommended);
        assert!(!ganesha_96_has_mode_only_access_knob());
        assert!(policy.fs_warning.contains("NOACL mode"));
        assert!(policy.fs_warning.contains("enable_acl=false"));
        assert!(policy.fs_warning.contains("manage_gids=false"));
        assert!(!policy.fs_warning.contains("Read_Access_Check_Policy"));
        assert!(!policy.fs_warning.contains("POSIX_ONLY"));
        assert!(policy.settings_ui_warning.contains("NOACL"));
        assert!(policy.settings_ui_warning.contains("enable_acl=false"));
    }
}