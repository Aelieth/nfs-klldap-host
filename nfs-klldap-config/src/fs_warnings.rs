//! FS compatibility warnings for shares.

use std::path::Path;

use crate::ganesha_log_contract::ganesha_96_has_mode_only_access_knob;
use crate::{
    compute_effective_flags, EffectiveShareFlags, FsCapabilities, MountinfoSnapshot,
    NfsKlldapConfig, Share,
};

/// One line of fs-warnings output for a share.
/// Capable shares are omitted unless include_capable is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsShareWarning {
    pub share_name: String,
    pub host_path: String,
    pub serve_path: String,
    pub fstype: String,
    pub acl_capable: bool,
    pub effective_enable_acl: bool,
    pub effective_manage_gids: bool,
    pub message: String,
}

impl FsShareWarning {
    /// Formats a stable single-line report for CLI and healthcheck.
    pub fn format_line(&self) -> String {
        if self.acl_capable {
            format!(
                "share={} host_path={} serve_path={} fstype={} acl_capable=true",
                self.share_name, self.host_path, self.serve_path, self.fstype
            )
        } else {
            format!(
                "share={} host_path={} serve_path={} fstype={} acl_capable=false \
                 effective_enable_acl={} effective_manage_gids={} — {}",
                self.share_name,
                self.host_path,
                self.serve_path,
                self.fstype,
                self.effective_enable_acl,
                self.effective_manage_gids,
                self.message
            )
        }
    }
}

// Display fallback only: an unprobeable path stays quiet here (no badge nag), while the
// generator's emission fallback is acl_capable=false (fail-safe). Intentional asymmetry.
fn default_capable_unknown() -> FsCapabilities {
    FsCapabilities {
        fstype: "unknown".into(),
        mount_options: vec![],
        acl_capable: true,
    }
}

fn limited_fs_opts_suffix(caps: &FsCapabilities) -> String {
    if caps.mount_options.is_empty() {
        String::new()
    } else {
        format!(" ({})", caps.mount_options.join(","))
    }
}

/// Warning provider for the NOACL/limited path (distinct from ACL-capable)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixOnlyPolicy {
    pub fs_warning: String,
    pub settings_ui_warning: String,
    pub staging_recommended: bool,
}

impl PosixOnlyPolicy {
    // Builds warning info for share with enable_acl=false.
    pub fn for_share(
        share_name: &str,
        caps: &FsCapabilities,
        eff: &EffectiveShareFlags,
    ) -> Option<Self> {
        if eff.enable_acl {
            return None;
        }
        let staging_recommended = !ganesha_96_has_mode_only_access_knob();
        let opts = limited_fs_opts_suffix(caps);
        let fs_warning = format!(
            "share \"{share_name}\": {fstype}{opts} limited filesystem — NOACL mode (enable_acl=false, manage_gids={mg}); cannot store POSIX ACLs, and the 9.13 VFS backend is expected to fail attribute fetches on such filesystems — stage onto an ACL-capable serve tree",
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

/// One-line WARN for limited-FS shares. Takes real Share for overrides.
pub fn limited_fs_warning(share: &Share, caps: &FsCapabilities) -> String {
    let eff = compute_effective_flags(share, caps);
    let share_name = &share.name;
    PosixOnlyPolicy::for_share(share_name, caps, &eff)
        .map(|p| p.fs_warning)
        .unwrap_or_else(|| {
            let opts = limited_fs_opts_suffix(caps);
            format!(
                "share \"{share_name}\": {fstype}{opts} limited filesystem",
                share_name = share_name,
                fstype = caps.fstype,
                opts = opts
            )
        })
}

/// Shorter limited-FS line for the WebUI System Settings share badge.
pub fn limited_fs_warning_settings_ui(
    share_name: &str,
    caps: &FsCapabilities,
    eff: &EffectiveShareFlags,
) -> String {
    PosixOnlyPolicy::for_share(share_name, caps, eff)
        .map(|p| p.settings_ui_warning)
        .unwrap_or_else(|| {
            let opts = limited_fs_opts_suffix(caps);
            format!(
                "share \"{share_name}\": {fstype}{opts} limited filesystem",
                share_name = share_name,
                fstype = caps.fstype,
                opts = opts
            )
        })
}

/// Serve-path caps from a shared snapshot; unreadable mountinfo stays lenient.
fn caps_for_share_snapshot(
    cfg: &NfsKlldapConfig,
    share: &Share,
    snap: &MountinfoSnapshot,
) -> FsCapabilities {
    let serve = cfg.serve_path_for(share);
    snap.probe(Path::new(&serve))
        .unwrap_or_else(default_capable_unknown)
}

/// Collect per-share filesystem warnings (probe runs against serve_path)
pub fn collect_fs_warnings(cfg: &NfsKlldapConfig) -> Vec<FsShareWarning> {
    let snap = MountinfoSnapshot::capture(None);
    cfg.shares
        .iter()
        .map(|share| {
            let caps = caps_for_share_snapshot(cfg, share, &snap);
            let eff = compute_effective_flags(share, &caps);
            let message = if caps.acl_capable {
                String::new()
            } else {
                limited_fs_warning(share, &caps)
            };
            FsShareWarning {
                share_name: share.name.clone(),
                host_path: share.host_path.display().to_string(),
                serve_path: cfg.serve_path_for(share),
                fstype: caps.fstype.clone(),
                acl_capable: caps.acl_capable,
                effective_enable_acl: eff.enable_acl,
                effective_manage_gids: eff.manage_gids,
                message,
            }
        })
        .collect()
}

/// Limited-FS warnings only (healthcheck / operator dashboards)
pub fn limited_fs_warnings_only(cfg: &NfsKlldapConfig) -> Vec<FsShareWarning> {
    collect_fs_warnings(cfg)
        .into_iter()
        .filter(|w| !w.acl_capable)
        .collect()
}

/// System Settings badge text when serve path is on a limited filesystem.
pub fn share_fs_warning_message(cfg: &NfsKlldapConfig, share: &Share) -> Option<String> {
    share_fs_warning_message_with_mountinfo(cfg, share, None)
}

/// System Settings badge text using an explicit mountinfo fixture (tests)
pub fn share_fs_warning_message_with_mountinfo(
    cfg: &NfsKlldapConfig,
    share: &Share,
    mountinfo_path: Option<&Path>,
) -> Option<String> {
    share_fs_warning_message_snapshot(cfg, share, &MountinfoSnapshot::capture(mountinfo_path))
}

/// System Settings badge text from a shared per-request snapshot.
pub fn share_fs_warning_message_snapshot(
    cfg: &NfsKlldapConfig,
    share: &Share,
    snap: &MountinfoSnapshot,
) -> Option<String> {
    let caps = caps_for_share_snapshot(cfg, share, snap);
    if caps.acl_capable {
        None
    } else {
        let eff = compute_effective_flags(share, &caps);
        Some(limited_fs_warning_settings_ui(&share.name, &caps, &eff))
    }
}

/// True when the share serve path is on a limited (non-ACL-capable) filesyste.
pub fn share_fs_acl_limited(cfg: &NfsKlldapConfig, share: &Share) -> bool {
    share_fs_acl_limited_with_mountinfo(cfg, share, None)
}

/// Same as [`share_fs_acl_limited`] with an explicit mountinfo fixture (tests.
pub fn share_fs_acl_limited_with_mountinfo(
    cfg: &NfsKlldapConfig,
    share: &Share,
    mountinfo_path: Option<&Path>,
) -> bool {
    share_fs_acl_limited_snapshot(cfg, share, &MountinfoSnapshot::capture(mountinfo_path))
}

/// Limited check from a shared per-request snapshot.
pub fn share_fs_acl_limited_snapshot(
    cfg: &NfsKlldapConfig,
    share: &Share,
    snap: &MountinfoSnapshot,
) -> bool {
    !caps_for_share_snapshot(cfg, share, snap).acl_capable
}

/// True when any share will emit Manage_Gids (explicit or probe default)
pub fn any_share_manage_gids_enabled(cfg: &NfsKlldapConfig) -> bool {
    let snap = MountinfoSnapshot::capture(None);
    cfg.shares.iter().any(|share| {
        let caps = caps_for_share_snapshot(cfg, share, &snap);
        compute_effective_flags(share, &caps).manage_gids
    })
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::{Share, SssdSection};

    #[test]
    fn share_fs_warning_with_mountinfo_fixture_isolated_from_env() {
        let _lock = crate::ENV_TEST_LOCK.lock().unwrap();
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
        let tmp = tempfile::tempdir().unwrap();
        let mountinfo = tmp.path().join("mountinfo");
        std::fs::write(
            &mountinfo,
            "36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl\n",
        )
        .unwrap();
        let mut cfg = NfsKlldapConfig {
            ldap_uri: "ldaps://klldap.test:6360".into(),
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "s".into(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "data".into(),
                host_path: "/media/data".into(),
                container_path: "/export/data".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        cfg.validate_and_derive().expect("valid");
        let msg = share_fs_warning_message_with_mountinfo(&cfg, &cfg.shares[0], Some(&mountinfo))
            .expect("limited fixture must yield warning");
        assert!(msg.contains("limited filesystem"));
        assert!(msg.contains("enable_acl=false"));
        assert!(msg.contains("NOACL mode") || msg.contains("limited filesystem"));
        assert!(share_fs_warning_message(&cfg, &cfg.shares[0]).is_none());
        assert!(share_fs_acl_limited_with_mountinfo(
            &cfg,
            &cfg.shares[0],
            Some(&mountinfo)
        ));
        assert!(!share_fs_acl_limited(&cfg, &cfg.shares[0]));
    }

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
        assert!(policy.fs_warning.contains("manage_gids=true"));
        assert!(!policy.fs_warning.contains("Read_Access_Check_Policy"));
        assert!(!policy.fs_warning.contains("POSIX_ONLY"));
        assert!(policy.settings_ui_warning.contains("NOACL"));
        assert!(policy.settings_ui_warning.contains("enable_acl=false"));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn any_share_manage_gids_false_when_all_limited_auto() {
        let _lock = crate::ENV_TEST_LOCK.lock().unwrap();
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
        let mut cfg = NfsKlldapConfig {
            ldap_uri: "ldaps://klldap.test:6360".into(),
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "s".into(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "t".into(),
                host_path: "/media/t".into(),
                container_path: "/export/t".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        cfg.validate_and_derive().expect("valid");
        assert!(any_share_manage_gids_enabled(&cfg));
        cfg.shares[0].manage_gids = Some(false);
        assert!(!any_share_manage_gids_enabled(&cfg));
    }
}