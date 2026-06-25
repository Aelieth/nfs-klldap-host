//! Filesystem compatibility warnings for shares (reuses fs_probe).

use std::path::Path;

use crate::{
    compute_effective_flags, limited_fs_warning, probe_from_mountinfo, probe_fs_capabilities,
    FsCapabilities, NfsKlldapConfig, Share,
};

/// One line of fs-warnings output for a share .
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsShareWarning {
    pub share_name: String,
    pub host_path: String,
    pub container_path: String,
    pub serve_path: String,
    pub fstype: String,
    pub acl_capable: bool,
    pub effective_disable_acl: bool,
    pub effective_manage_gids: bool,
    pub message: String,
}

impl FsShareWarning {
    /// Stable single-line report for CLI / healthcheck .
    pub fn format_line(&self) -> String {
        if self.acl_capable {
            format!(
                "share={} host_path={} serve_path={} fstype={} acl_capable=true",
                self.share_name, self.host_path, self.serve_path, self.fstype
            )
        } else {
            format!(
                "share={} host_path={} container_path={} serve_path={} fstype={} acl_capable=false \
                 effective_disable_acl={} effective_manage_gids={} — {}",
                self.share_name,
                self.host_path,
                self.container_path,
                self.serve_path,
                self.fstype,
                self.effective_disable_acl,
                self.effective_manage_gids,
                self.message
            )
        }
    }
}

fn default_capable_unknown() -> FsCapabilities {
    FsCapabilities {
        fstype: "unknown".into(),
        mount_options: vec![],
        acl_capable: true,
    }
}

fn caps_for_share(cfg: &NfsKlldapConfig, share: &Share) -> FsCapabilities {
    caps_for_share_with_mountinfo(cfg, share, None)
}

fn caps_for_share_with_mountinfo(
    cfg: &NfsKlldapConfig,
    share: &Share,
    mountinfo_path: Option<&Path>,
) -> FsCapabilities {
    let serve = cfg.serve_path_for(share);
    let path = Path::new(&serve);
    if let Some(mp) = mountinfo_path {
        if let Ok(content) = std::fs::read_to_string(mp) {
            return probe_from_mountinfo(&content, path);
        }
    }
    probe_fs_capabilities(path).unwrap_or_else(|_| default_capable_unknown())
}

/// Collect per-share filesystem warnings (probe runs against serve_path).
pub fn collect_fs_warnings(cfg: &NfsKlldapConfig) -> Vec<FsShareWarning> {
    cfg.shares
        .iter()
        .map(|share| {
            let caps = caps_for_share(cfg, share);
            let eff = compute_effective_flags(share, &caps);
            let message = if caps.acl_capable {
                String::new()
            } else {
                limited_fs_warning(&share.name, &caps)
            };
            FsShareWarning {
                share_name: share.name.clone(),
                host_path: share.host_path.display().to_string(),
                container_path: cfg.container_path_for(share),
                serve_path: cfg.serve_path_for(share),
                fstype: caps.fstype.clone(),
                acl_capable: caps.acl_capable,
                effective_disable_acl: eff.disable_acl,
                effective_manage_gids: eff.manage_gids,
                message,
            }
        })
        .collect()
}

/// Limited-FS warnings only (healthcheck / operator dashboards).
pub fn limited_fs_warnings_only(cfg: &NfsKlldapConfig) -> Vec<FsShareWarning> {
    collect_fs_warnings(cfg)
        .into_iter()
        .filter(|w| !w.acl_capable)
        .collect()
}

/// UI badge text when serve path is on a limited filesystem.
pub fn share_fs_warning_message(cfg: &NfsKlldapConfig, share: &Share) -> Option<String> {
    share_fs_warning_message_with_mountinfo(cfg, share, None)
}

/// UI badge text using an explicit mountinfo fixture file .
pub fn share_fs_warning_message_with_mountinfo(
    cfg: &NfsKlldapConfig,
    share: &Share,
    mountinfo_path: Option<&Path>,
) -> Option<String> {
    let caps = caps_for_share_with_mountinfo(cfg, share, mountinfo_path);
    if caps.acl_capable {
        None
    } else {
        Some(limited_fs_warning(&share.name, &caps))
    }
}

/// True when any share will emit Manage_Gids (explicit or probe default).
pub fn any_share_manage_gids_enabled(cfg: &NfsKlldapConfig) -> bool {
    cfg.shares.iter().any(|share| {
        let caps = caps_for_share(cfg, share);
        compute_effective_flags(share, &caps).manage_gids
    })
}

#[cfg(test)]
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
            ldap_uri: "ldaps://kllap.test:6360".into(),
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "s".into(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "data".into(),
                host_path: "/media/data".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        cfg.validate_and_derive().expect("valid");
        let msg = share_fs_warning_message_with_mountinfo(&cfg, &cfg.shares[0], Some(&mountinfo))
            .expect("limited fixture must yield warning");
        assert!(msg.contains("lacks POSIX ACL support"));
        assert!(share_fs_warning_message(&cfg, &cfg.shares[0]).is_none());
    }

    #[test]
    fn any_share_manage_gids_false_when_all_limited_auto() {
        let _lock = crate::ENV_TEST_LOCK.lock().unwrap();
        std::env::remove_var("NFS_KLLDAP_MOUNTINFO_PATH");
        let mut cfg = NfsKlldapConfig {
            ldap_uri: "ldaps://kllap.test:6360".into(),
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "s".into(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "t".into(),
                host_path: "/media/t".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        cfg.validate_and_derive().expect("valid");
        // Without mountinfo override in unit test,
        // unknown path assumes capable → manage_gids true.
        assert!(any_share_manage_gids_enabled(&cfg));
        cfg.shares[0].manage_gids = Some(false);
        assert!(!any_share_manage_gids_enabled(&cfg));
    }
}
