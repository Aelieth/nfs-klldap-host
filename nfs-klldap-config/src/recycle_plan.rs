//! Pure recycle decision: which services to touch after config regeneration.

/// How Ganesha should be recycled when export fragments change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GaneshaAction {
    /// Leave running (no reload, no stop/start).
    Skip,
    /// In-process export reload via SIGHUP.
    Sighup,
    /// Stop (if running) then start
    /// used when nfsd is down or SIGHUP reload failed.
    StopStart,
}

/// Service recycle plan derived from export vs identity artifact changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRecyclePlan {
    pub ganesha: GaneshaAction,
    pub restart_sssd: bool,
    pub restart_idhelper: bool,
    pub restart_webui: bool,
}

impl ServiceRecyclePlan {
    pub fn is_noop(&self) -> bool {
        self.ganesha == GaneshaAction::Skip
            && !self.restart_sssd
            && !self.restart_idhelper
            && !self.restart_webui
    }
}

/// Compute recycle plan from fingerprint deltas (table-driven
/// see unit tests).
pub fn plan_from_changes(
    exports_changed: bool,
    identity_changed: bool,
    host_nfs_mode: bool,
    ganesha_running: bool,
) -> ServiceRecyclePlan {
    if !exports_changed && !identity_changed {
        return ServiceRecyclePlan {
            ganesha: GaneshaAction::Skip,
            restart_sssd: false,
            restart_idhelper: false,
            restart_webui: false,
        };
    }

    let ganesha = if host_nfs_mode || !exports_changed {
        GaneshaAction::Skip
    } else if ganesha_running {
        GaneshaAction::Sighup
    } else {
        GaneshaAction::StopStart
    };

    ServiceRecyclePlan {
        ganesha,
        restart_sssd: identity_changed,
        restart_idhelper: identity_changed,
        restart_webui: identity_changed,
    }
}

/// After a failed in-process Ganesha reload, escalate to full stop/start.
pub fn ganesha_sighup_failed(plan: ServiceRecyclePlan) -> ServiceRecyclePlan {
    if plan.ganesha == GaneshaAction::Sighup {
        ServiceRecyclePlan {
            ganesha: GaneshaAction::StopStart,
            ..plan
        }
    } else {
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_only_sighup_without_identity_recycle() {
        let plan = plan_from_changes(true, false, false, true);
        assert_eq!(plan.ganesha, GaneshaAction::Sighup);
        assert!(!plan.restart_sssd);
        assert!(!plan.restart_idhelper);
        assert!(!plan.restart_webui);
    }

    #[test]
    fn identity_only_recycles_sssd_idhelper_webui_not_ganesha() {
        let plan = plan_from_changes(false, true, false, true);
        assert_eq!(plan.ganesha, GaneshaAction::Skip);
        assert!(plan.restart_sssd);
        assert!(plan.restart_idhelper);
        assert!(plan.restart_webui);
    }

    #[test]
    fn both_changed_full_recycle_with_ganesha_sighup() {
        let plan = plan_from_changes(true, true, false, true);
        assert_eq!(plan.ganesha, GaneshaAction::Sighup);
        assert!(plan.restart_sssd);
        assert!(plan.restart_idhelper);
        assert!(plan.restart_webui);
    }

    #[test]
    fn neither_changed_is_noop_when_ganesha_running() {
        let plan = plan_from_changes(false, false, false, true);
        assert!(plan.is_noop());
    }

    #[test]
    fn exports_changed_ganesha_down_uses_stop_start() {
        let plan = plan_from_changes(true, false, false, false);
        assert_eq!(plan.ganesha, GaneshaAction::StopStart);
        assert!(!plan.restart_sssd);
    }

    #[test]
    fn host_nfs_skips_ganesha_even_when_exports_change() {
        let plan = plan_from_changes(true, true, true, true);
        assert_eq!(plan.ganesha, GaneshaAction::Skip);
        assert!(plan.restart_sssd);
    }
}
