//! Pure policy for posix-only limited/noacl Ganesha 9.6 exports.

use crate::fs_probe::{EffectiveShareFlags, FsCapabilities};
use crate::ganesha_log_contract::{
    ganesha_96_has_mode_only_access_knob, GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB,
};

/// Consolidated posix-only export emission when `enable_acl` is false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixOnlyPolicy {
    pub directive_lines: String,
    pub export_comment: String,
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
    /// Builds policy for a share with `enable_acl=false` (probe or explicit).
    pub fn for_share(share_name: &str, caps: &FsCapabilities, eff: &EffectiveShareFlags) -> Option<Self> {
        if eff.enable_acl {
            return None;
        }
        debug_assert!(!ganesha_96_has_mode_only_access_knob());
        let staging_recommended = !ganesha_96_has_mode_only_access_knob();
        let opts = mount_opts_suffix(caps);
        let directive_lines = format!(
            "    Disable_ACL = true;\n    Manage_Gids = false;\n    Read_Access_Check_Policy = \"post\";\n    Enable_NLM = false;\n    Enable_RQUOTA = false;\n    # POSIX_ONLY_EXPORT: {knob}\n",
            knob = GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB
        );
        let export_comment = if eff.auto_applied {
            format!(
                "# posix-only conservative mode for noacl btrfs (ZimaOS)\n\
                 # Auto-detected: {}{opts}\n\
                 # {knob}\n\
                 # See docs/ganesha-architecture.md#acl-and-filesystem-compatibility\n",
                caps.fstype,
                opts = opts,
                knob = GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB,
            )
        } else {
            String::new()
        };
        let fs_warning = format!(
            "share \"{share_name}\": {fstype}{opts} limited filesystem — conservative mode (enable_acl=false, manage_gids=false, Read_Access_Check_Policy=post); {knob}",
            knob = GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB,
            share_name = share_name,
            fstype = caps.fstype,
            opts = opts,
        );
        let settings_ui_warning = format!(
            "share \"{share_name}\": {fstype}{opts} limited filesystem — posix-only conservative (enable_acl={enable_acl}, manage_gids={manage_gids}, Read_Access_Check_Policy=post); {knob}",
            knob = GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB,
            share_name = share_name,
            fstype = caps.fstype,
            opts = opts,
            enable_acl = eff.enable_acl,
            manage_gids = eff.manage_gids,
        );
        Some(PosixOnlyPolicy {
            directive_lines,
            export_comment,
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

    const NOACL_BTRFS_SNAPSHOT: &str = r#"    Disable_ACL = true;
    Manage_Gids = false;
    Read_Access_Check_Policy = "post";
    Enable_NLM = false;
    Enable_RQUOTA = false;
    # POSIX_ONLY_EXPORT: Ganesha 9.6: Disable_ACL + Read_Access_Check_Policy=post do not force mode-only OP_ACCESS/GETATTR; nfs_access_op still logs ACL(list_dir,...); use ganesha_path staging on noacl btrfs.
"#;

    #[test]
    fn posix_only_policy_noacl_btrfs_matches_snapshot() {
        let caps = FsCapabilities {
            fstype: "btrfs".into(),
            mount_options: vec!["noacl".into()],
            acl_capable: false,
        };
        let eff = crate::compute_effective_flags(&Share::default(), &caps);
        let policy = PosixOnlyPolicy::for_share("users", &caps, &eff).expect("limited policy");
        assert_eq!(policy.directive_lines, NOACL_BTRFS_SNAPSHOT);
        assert!(policy.staging_recommended);
        assert!(!ganesha_96_has_mode_only_access_knob());
        assert!(policy.export_comment.contains("posix-only conservative mode for noacl btrfs (ZimaOS)"));
        assert!(policy.export_comment.contains(GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB));
        assert!(policy.fs_warning.contains("Read_Access_Check_Policy=post"));
        assert!(policy.settings_ui_warning.contains("enable_acl=false"));
    }
}