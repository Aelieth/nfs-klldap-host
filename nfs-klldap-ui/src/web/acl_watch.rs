//! Background ACL-capability watcher.
//!
//! The stored ACL/NOACL decision is only re-derived when the config changes or
//! Ganesha reloads, so a mount that gains or loses ACL support would otherwise
//! drift from what the exports serve. This loop re-probes each share's serve
//! root on an interval and reconciles:
//!
//! - An **auto** share whose capability flips (with hysteresis) schedules the
//!   normal service recycle; generate then re-probes and flips `Disable_ACL`.
//! - An **explicit `enable_acl = true`** share that loses ACL support never
//!   triggers a recycle (generate would refuse every export). Instead it raises
//!   a persistent banner telling the operator to fix it before the next reload.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nfs_klldap_config::AclProbeVerdict;

use super::AppState;

/// Default re-probe cadence, mirroring the idhelper rebulk interval.
const DEFAULT_INTERVAL_SECS: u64 = 180;
/// A confirmed auto flip must not schedule recycles more often than this, so a
/// flapping mount cannot bounce Ganesha in a tight loop.
const AUTO_HUP_MIN_INTERVAL: Duration = Duration::from_secs(600);
/// Consecutive stable ticks a change must persist before it counts (hysteresis).
const FLIP_STREAK: u8 = 2;

/// Per-auto-share flip state: the capability generate last acted on
/// (`baseline`), the previous tick's reading, and how long the current reading
/// has held.
#[derive(Debug, Clone, Copy)]
struct FlipState {
    baseline: bool,
    last: bool,
    streak: u8,
}

/// Cross-tick state for the watcher.
#[derive(Default)]
pub(crate) struct FlipTracker {
    auto: HashMap<String, FlipState>,
    incap: HashMap<String, u8>,
    last_auto_hup: Option<Instant>,
}

/// What one tick decided, surfaced for tests and logging.
#[derive(Debug, Default)]
pub(crate) struct TickOutcome {
    pub hup_scheduled: bool,
    pub alert: Option<String>,
}

/// Spawns the interval loop. `NFS_KLLDAP_ACL_REPROBE_INTERVAL_SECS = 0` disables
/// it; the default is 180s. The first tick fires after one full interval.
pub(crate) fn spawn_acl_reprobe_loop(state: AppState) {
    let secs = std::env::var("NFS_KLLDAP_ACL_REPROBE_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    if secs == 0 {
        eprintln!("INFO: ACL re-probe loop disabled (NFS_KLLDAP_ACL_REPROBE_INTERVAL_SECS=0)");
        return;
    }
    // Supervised: the inner task IS the loop; if it ever dies (a panic in a
    // probe path), auto-heal must not stay silently dead for process
    // lifetime — respawn with fresh hysteresis state (two stable ticks are
    // re-required before any flip, so a reset is safe).
    tokio::spawn(async move {
        loop {
            let st = state.clone();
            let inner = tokio::spawn(async move {
                let mut tracker = FlipTracker::default();
                let mut interval = tokio::time::interval(Duration::from_secs(secs));
                // The first tick returns immediately; skip it so we probe
                // after a full interval rather than racing startup.
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let outcome = acl_reprobe_tick(&st, &mut tracker).await;
                    if outcome.hup_scheduled {
                        eprintln!("INFO: ACL re-probe scheduled a service recycle");
                    }
                    if let Some(msg) = &outcome.alert {
                        eprintln!("WARN: ACL re-probe: {msg}");
                    }
                }
            });
            let _ = inner.await;
            eprintln!(
                "WARN: ACL re-probe loop terminated unexpectedly — respawning in 30s (hysteresis reset)"
            );
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

/// One re-probe pass. Force-refreshes each share's serve-root verdict, applies
/// hysteresis, schedules at most one recycle for auto flips, and rebuilds the
/// explicit-ACL warning banner.
pub(crate) async fn acl_reprobe_tick(state: &AppState, tracker: &mut FlipTracker) -> TickOutcome {
    // Never probe or fire while a recycle is already in flight.
    if state.restart_requested.lock().await.is_some() {
        return TickOutcome::default();
    }

    // Snapshot the shares so the config lock is not held across the probes.
    // Recover a poisoned lock instead of panicking — a panic here would kill the
    // spawned watcher and silently disable auto-heal for the process lifetime.
    let shares: Vec<(String, Option<bool>, PathBuf)> = {
        let cfg = state.config.read().unwrap_or_else(|p| p.into_inner());
        cfg.shares
            .iter()
            .map(|s| (s.name.clone(), s.enable_acl, PathBuf::from(cfg.serve_path_for(s))))
            .collect()
    };
    let snap =
        nfs_klldap_config::MountinfoSnapshot::capture(state.fs_probe_mountinfo_path.as_deref());

    let mut auto_flip_share: Option<String> = None;
    let mut failing: Vec<String> = Vec::new();

    for (name, enable_acl, serve) in &shares {
        let skip_probe = *enable_acl == Some(false);
        let outcome = state
            .acl_caps
            .verdict_for_snapshot(&snap, serve, serve, skip_probe, true);
        match enable_acl {
            None => {
                let capable = outcome.verdict == AclProbeVerdict::Capable;
                if track_auto_flip(tracker.auto.entry(name.clone()).or_insert(FlipState {
                    baseline: capable,
                    last: capable,
                    streak: 0,
                }), capable)
                {
                    auto_flip_share.get_or_insert_with(|| name.clone());
                }
            }
            Some(true) => {
                let incapable = outcome.verdict == AclProbeVerdict::Incapable;
                let streak = tracker.incap.entry(name.clone()).or_insert(0);
                *streak = if incapable { streak.saturating_add(1) } else { 0 };
                if *streak >= FLIP_STREAK {
                    failing.push(name.clone());
                }
            }
            Some(false) => {}
        }
    }

    // Rebuild the banner from the currently failing shares (clears when healed).
    let alert = build_alert(&failing);
    *state.acl_alert.lock().unwrap_or_else(|p| p.into_inner()) = alert.clone();

    // Schedule at most one recycle per tick; generate re-probes every share.
    let mut hup_scheduled = false;
    if let Some(name) = auto_flip_share {
        let rate_ok = tracker
            .last_auto_hup
            .map(|t| t.elapsed() >= AUTO_HUP_MIN_INTERVAL)
            .unwrap_or(true);
        if rate_ok {
            let reason = format!("ACL capability change on share '{name}'");
            if super::settings::try_schedule_service_recycle(
                state,
                super::RecycleKind::SharesApply,
                &reason,
            )
            .await
            {
                tracker.last_auto_hup = Some(Instant::now());
                hup_scheduled = true;
                // Adopt the new capability as the baseline for every auto share
                // so the recycle is not re-fired next tick.
                for st in tracker.auto.values_mut() {
                    st.baseline = st.last;
                    st.streak = 0;
                }
            }
        }
    }

    TickOutcome { hup_scheduled, alert }
}

/// Updates one auto share's flip state and returns true when a stable change
/// from the baseline has persisted long enough to act on.
fn track_auto_flip(st: &mut FlipState, current: bool) -> bool {
    if current == st.last {
        st.streak = st.streak.saturating_add(1);
    } else {
        st.streak = 1;
        st.last = current;
    }
    current != st.baseline && st.streak >= FLIP_STREAK
}

fn build_alert(failing: &[String]) -> Option<String> {
    if failing.is_empty() {
        return None;
    }
    let list = failing
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "enable_acl = true on {list} but the backing filesystem no longer stores POSIX ACLs — \
         the next config reload will refuse to generate exports. Use the staging pattern \
         (source_path) or set enable_acl = false."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(current: bool) -> FlipState {
        FlipState { baseline: current, last: current, streak: 0 }
    }

    #[test]
    fn flip_requires_two_consecutive_ticks() {
        let mut st = state(true); // baseline capable
        // First divergent reading: not yet acted on.
        assert!(!track_auto_flip(&mut st, false));
        // Second consecutive same reading: now it fires.
        assert!(track_auto_flip(&mut st, false));
    }

    #[test]
    fn flapping_never_fires() {
        let mut st = state(true);
        // Alternate every tick: the streak never reaches two in one direction.
        assert!(!track_auto_flip(&mut st, false));
        assert!(!track_auto_flip(&mut st, true));
        assert!(!track_auto_flip(&mut st, false));
        assert!(!track_auto_flip(&mut st, true));
    }

    #[test]
    fn stable_baseline_never_fires() {
        let mut st = state(true);
        for _ in 0..5 {
            assert!(!track_auto_flip(&mut st, true));
        }
    }

    #[test]
    fn build_alert_lists_all_failing_shares_or_none() {
        assert!(build_alert(&[]).is_none());
        let msg = build_alert(&["a".into(), "b".into()]).unwrap();
        assert!(msg.contains("'a', 'b'"));
        assert!(msg.contains("refuse to generate"));
    }
}
