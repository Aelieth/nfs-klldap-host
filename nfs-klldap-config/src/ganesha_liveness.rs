//! Zombie-aware Ganesha process liveness for recycle planning and reload.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::constants::PROC_COMM_NAME_MAX;

/// True when `pid` exists and is not a zombie (per `/proc/pid/status` State).
pub fn process_is_live(pid: u32) -> bool {
    if !Path::new(&format!("/proc/{pid}")).exists() {
        return false;
    }
    if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("State:") {
                let state = rest.split_whitespace().next().unwrap_or("");
                return state != "Z";
            }
        }
    }
    true
}

/// Pgrep PIDs for `name` (may include zombies).
pub fn pgrep_pids(name: &str) -> Vec<u32> {
    let mut cmd = Command::new("pgrep");
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    if name.len() > PROC_COMM_NAME_MAX {
        cmd.args(["-f", "--", name]);
    } else {
        cmd.args(["-x", name]);
    }
    let Ok(out) = cmd.output() else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .collect()
}

/// Pgrep hits filtered to non-zombie processes only.
pub fn pgrep_live_pids(name: &str) -> Vec<u32> {
    pgrep_pids(name)
        .into_iter()
        .filter(|pid| process_is_live(*pid))
        .collect()
}

/// Reconcile tracked Ganesha pid: keep live tracked pid; when tracked is dead return
/// None (do not pgrep — another host/container nfsd must not masquerade as ours).
/// Pgrep fallback applies only when the supervisor never recorded a pid.
pub fn reconcile_ganesha_pid(tracked: Option<u32>) -> Option<u32> {
    if let Some(pid) = tracked {
        return process_is_live(pid).then_some(pid);
    }
    pgrep_live_pids("ganesha.nfsd").into_iter().next()
}

/// Whether any live ganesha.nfsd exists (tracked or pgrep).
pub fn ganesha_is_live(tracked: Option<u32>) -> bool {
    reconcile_ganesha_pid(tracked).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn live_pid_is_live() {
        let _guard = lock_tests();
        let pid = std::process::id();
        assert!(process_is_live(pid));
        assert!(ganesha_is_live(Some(pid)));
        assert_eq!(reconcile_ganesha_pid(Some(pid)), Some(pid));
    }

    #[test]
    fn zombie_tracked_pid_is_not_live() {
        let _guard = lock_tests();
        let mut child = Command::new("true").spawn().expect("spawn true");
        let pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!process_is_live(pid), "zombie must not count as live");
        let _ = child.wait();
    }

    #[test]
    fn no_pgrep_matches_returns_empty_live_list() {
        let _guard = lock_tests();
        let bogus = "ganesha.nfsd-this-test-name-will-not-exist";
        assert!(pgrep_pids(bogus).is_empty());
        assert!(pgrep_live_pids(bogus).is_empty());
    }

    #[test]
    fn dead_tracked_pid_does_not_pgrep_fallback() {
        let _guard = lock_tests();
        let mut child = Command::new("true").spawn().expect("spawn true");
        let pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!process_is_live(pid));
        assert_eq!(reconcile_ganesha_pid(Some(pid)), None);
        assert!(!ganesha_is_live(Some(pid)));
        let _ = child.wait();
    }

    #[test]
    fn pgrep_live_filters_zombie_pids() {
        let _guard = lock_tests();
        let mut child = Command::new("true").spawn().expect("spawn true");
        let pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!process_is_live(pid));
        let live: Vec<u32> = std::iter::once(pid)
            .filter(|p| process_is_live(*p))
            .collect();
        assert!(live.is_empty(), "zombie pid must be filtered out");
        let _ = child.wait();
    }
}