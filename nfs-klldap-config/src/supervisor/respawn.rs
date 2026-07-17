//! Steady-state respawn budget (WI-18, re-opened by the 2026-07-17 audit).
//!
//! The supervisor used to only reap a crashed child: the stack ran silently
//! degraded until the 30s healthcheck flipped and an orchestrator (maybe)
//! recreated the container. The Idle tick now revives managed children —
//! rate-limited so a crash-looping service cannot become a restart storm:
//! at most `RESPAWN_BUDGET` revivals per sliding `RESPAWN_WINDOW` per
//! service, with a `RESPAWN_COOLDOWN` gap between attempts. Exhaustion logs
//! fatal-degraded once and defers to the healthcheck.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub(crate) const RESPAWN_WINDOW: Duration = Duration::from_secs(600);
pub(crate) const RESPAWN_BUDGET: usize = 3;
pub(crate) const RESPAWN_COOLDOWN: Duration = Duration::from_secs(10);

pub(crate) enum RespawnDecision {
    Go,
    Cooldown,
    Exhausted { first_time: bool },
}

/// Per-service sliding-window budget. Window entries are attempt times;
/// `exhausted_logged` keeps the fatal-degraded line to one per exhaustion
/// episode (a successful later attempt re-arms it).
#[derive(Default)]
pub(crate) struct RespawnBudget {
    attempts: HashMap<&'static str, Vec<Instant>>,
    exhausted_logged: HashMap<&'static str, bool>,
}

impl RespawnBudget {
    pub(crate) fn decide(&mut self, service: &'static str, now: Instant) -> RespawnDecision {
        let hist = self.attempts.entry(service).or_default();
        hist.retain(|t| now.duration_since(*t) < RESPAWN_WINDOW);
        if let Some(last) = hist.last() {
            if now.duration_since(*last) < RESPAWN_COOLDOWN {
                return RespawnDecision::Cooldown;
            }
        }
        if hist.len() >= RESPAWN_BUDGET {
            let logged = self.exhausted_logged.entry(service).or_default();
            let first_time = !*logged;
            *logged = true;
            return RespawnDecision::Exhausted { first_time };
        }
        hist.push(now);
        self.exhausted_logged.insert(service, false);
        RespawnDecision::Go
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_allows_then_exhausts_then_slides() {
        let mut b = RespawnBudget::default();
        let t0 = Instant::now();
        for i in 0..RESPAWN_BUDGET {
            let now = t0 + RESPAWN_COOLDOWN * (i as u32 + 1);
            assert!(
                matches!(b.decide("ganesha", now), RespawnDecision::Go),
                "attempt {i} within budget"
            );
        }
        let after = t0 + RESPAWN_COOLDOWN * (RESPAWN_BUDGET as u32 + 1);
        assert!(
            matches!(
                b.decide("ganesha", after),
                RespawnDecision::Exhausted { first_time: true }
            ),
            "budget exhausted, first notice"
        );
        assert!(
            matches!(
                b.decide("ganesha", after + RESPAWN_COOLDOWN),
                RespawnDecision::Exhausted { first_time: false }
            ),
            "repeat exhaustion is quiet"
        );
        let slid = t0 + RESPAWN_WINDOW + RESPAWN_COOLDOWN * (RESPAWN_BUDGET as u32 + 2);
        assert!(
            matches!(b.decide("ganesha", slid), RespawnDecision::Go),
            "window slid — budget replenishes"
        );
    }

    #[test]
    fn cooldown_gates_consecutive_attempts_and_services_are_independent() {
        let mut b = RespawnBudget::default();
        let t0 = Instant::now();
        assert!(matches!(b.decide("webui", t0), RespawnDecision::Go));
        assert!(
            matches!(
                b.decide("webui", t0 + Duration::from_secs(1)),
                RespawnDecision::Cooldown
            ),
            "second attempt inside the cooldown must wait"
        );
        assert!(
            matches!(b.decide("sssd", t0 + Duration::from_secs(1)), RespawnDecision::Go),
            "another service's budget is untouched"
        );
    }
}
