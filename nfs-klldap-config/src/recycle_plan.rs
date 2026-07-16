//! Recycle plan after config/export/identity fingerprint changes. The auto
//! (SIGHUP) path is shares-scoped and graceful; `plan_full_recycle` is the
//! forced (SIGUSR1) path behind "Restart and apply".

/// How Ganesha should be recycled when export fragments change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GaneshaAction {
    /// Leave running.
    Skip,
    /// In-process export reload via SIGHUP.
    Sighup,
    /// Full stop/start when down, after failed SIGHUP, or on a forced recycle.
    StopStart,
}

/// How the WebUI should pick up a config change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebuiAction {
    /// Leave running.
    Skip,
    /// In-process config reload via SIGHUP to the child (no process bounce, so
    /// live admin connections survive).
    Reload,
    /// Process bounce (SIGTERM + respawn); sessions survive via the
    /// webui-sessions sidecar.
    Restart,
}

/// Services to bounce given fingerprint deltas (see `plan_from_changes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRecyclePlan {
    pub ganesha: GaneshaAction,
    pub restart_sssd: bool,
    pub restart_idhelper: bool,
    pub webui: WebuiAction,
    /// Identity artifacts (sssd.conf/krb5.conf/idmapd.conf) were regenerated
    /// on disk but the running daemons keep the previous settings until a
    /// forced full recycle applies them.
    pub identity_staged: bool,
}

impl ServiceRecyclePlan {
    /// True when no process is signaled or restarted. A staged identity change
    /// can still be pending; the executor logs that separately.
    pub fn is_noop(&self) -> bool {
        self.ganesha == GaneshaAction::Skip
            && !self.restart_sssd
            && !self.restart_idhelper
            && self.webui == WebuiAction::Skip
    }
}

/// Compute the shares-scoped auto plan from fingerprint deltas (see unit
/// tests). Identity changes never restart daemons here — they are staged until
/// `plan_full_recycle` runs; the WebUI is only ever reloaded in place.
pub fn plan_from_changes(
    exports_changed: bool,
    identity_changed: bool,
    shares_changed: bool,
    host_nfs_mode: bool,
    ganesha_running: bool,
) -> ServiceRecyclePlan {
    let ganesha = if host_nfs_mode || !exports_changed {
        GaneshaAction::Skip
    } else if ganesha_running {
        GaneshaAction::Sighup
    } else {
        GaneshaAction::StopStart
    };

    let webui = if exports_changed || shares_changed {
        WebuiAction::Reload
    } else {
        WebuiAction::Skip
    };

    ServiceRecyclePlan {
        ganesha,
        restart_sssd: false,
        restart_idhelper: false,
        webui,
        identity_staged: identity_changed,
    }
}

/// Forced full recycle ("Restart and apply" / SIGUSR1): restart every managed
/// service regardless of fingerprint deltas. This is the only path that
/// applies staged identity changes and edits invisible to the fingerprints
/// (ganesha main conf, nfs.conf, WebUI port/TLS/admin group).
pub fn plan_full_recycle(host_nfs_mode: bool) -> ServiceRecyclePlan {
    ServiceRecyclePlan {
        ganesha: if host_nfs_mode {
            GaneshaAction::Skip
        } else {
            GaneshaAction::StopStart
        },
        restart_sssd: true,
        restart_idhelper: true,
        webui: WebuiAction::Restart,
        identity_staged: false,
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
    fn shares_only_reloads_webui_without_daemon_restarts() {
        let plan = plan_from_changes(false, false, true, false, true);
        assert_eq!(plan.ganesha, GaneshaAction::Skip);
        assert!(!plan.restart_sssd);
        assert!(!plan.restart_idhelper);
        assert_eq!(plan.webui, WebuiAction::Reload);
        assert!(!plan.identity_staged);
    }

    #[test]
    fn exports_only_sighup_ganesha_and_reload_webui() {
        let plan = plan_from_changes(true, false, false, false, true);
        assert_eq!(plan.ganesha, GaneshaAction::Sighup);
        assert!(!plan.restart_sssd);
        assert!(!plan.restart_idhelper);
        assert_eq!(plan.webui, WebuiAction::Reload);
    }

    #[test]
    fn identity_only_stages_without_restarting_anything() {
        let plan = plan_from_changes(false, true, false, false, true);
        assert!(plan.is_noop());
        assert_eq!(plan.ganesha, GaneshaAction::Skip);
        assert!(!plan.restart_sssd);
        assert!(!plan.restart_idhelper);
        assert_eq!(plan.webui, WebuiAction::Skip);
        assert!(plan.identity_staged);
    }

    #[test]
    fn exports_and_identity_reload_webui_and_stage_identity() {
        let plan = plan_from_changes(true, true, false, false, true);
        assert_eq!(plan.ganesha, GaneshaAction::Sighup);
        assert!(!plan.restart_sssd);
        assert!(!plan.restart_idhelper);
        assert_eq!(plan.webui, WebuiAction::Reload);
        assert!(plan.identity_staged);
    }

    #[test]
    fn neither_changed_is_noop_when_ganesha_running() {
        let plan = plan_from_changes(false, false, false, false, true);
        assert!(plan.is_noop());
        assert!(!plan.identity_staged);
    }

    #[test]
    fn exports_changed_ganesha_down_uses_stop_start() {
        let plan = plan_from_changes(true, false, false, false, false);
        assert_eq!(plan.ganesha, GaneshaAction::StopStart);
        assert!(!plan.restart_sssd);
        assert_eq!(plan.webui, WebuiAction::Reload);
    }

    #[test]
    fn host_nfs_skips_ganesha_even_when_exports_change() {
        let plan = plan_from_changes(true, true, false, true, true);
        assert_eq!(plan.ganesha, GaneshaAction::Skip);
        assert!(!plan.restart_sssd);
        assert_eq!(plan.webui, WebuiAction::Reload);
        assert!(plan.identity_staged);
    }

    #[test]
    fn host_nfs_export_only_reloads_webui_not_ganesha() {
        let plan = plan_from_changes(true, false, false, true, true);
        assert_eq!(plan.ganesha, GaneshaAction::Skip);
        assert!(!plan.restart_sssd);
        assert!(!plan.restart_idhelper);
        assert_eq!(plan.webui, WebuiAction::Reload);
    }

    #[test]
    fn full_recycle_stop_starts_ganesha_and_restarts_everything() {
        let plan = plan_full_recycle(false);
        assert_eq!(plan.ganesha, GaneshaAction::StopStart);
        assert!(plan.restart_sssd);
        assert!(plan.restart_idhelper);
        assert_eq!(plan.webui, WebuiAction::Restart);
        assert!(!plan.identity_staged);
        assert!(!plan.is_noop());
    }

    #[test]
    fn full_recycle_host_nfs_skips_ganesha_only() {
        let plan = plan_full_recycle(true);
        assert_eq!(plan.ganesha, GaneshaAction::Skip);
        assert!(plan.restart_sssd);
        assert!(plan.restart_idhelper);
        assert_eq!(plan.webui, WebuiAction::Restart);
    }

    #[test]
    fn sighup_failed_escalation_preserves_webui_action() {
        let plan = plan_from_changes(true, false, true, false, true);
        let escalated = ganesha_sighup_failed(plan);
        assert_eq!(escalated.ganesha, GaneshaAction::StopStart);
        assert_eq!(escalated.webui, WebuiAction::Reload);
        assert!(!escalated.restart_sssd);
    }
}
