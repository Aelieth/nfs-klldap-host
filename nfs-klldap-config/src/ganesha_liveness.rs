//! Zombie-aware Ganesha process liveness for recycle planning and reload.
#![allow(unsafe_code)]

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

const PROC_COMM_NAME_MAX: usize = 15;

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

/// Reconcile tracked Ganesha pid: keep live tracked pid, else first live pgrep match.
pub fn reconcile_ganesha_pid(tracked: Option<u32>) -> Option<u32> {
    if tracked.is_some_and(process_is_live) {
        return tracked;
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
        let pid = unsafe {
            let child = libc::fork();
            if child == 0 {
                libc::_exit(0);
            }
            assert!(child > 0);
            child as u32
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!process_is_live(pid), "zombie must not count as live");
        unsafe {
            let mut status = 0;
            libc::waitpid(pid as i32, &mut status, 0);
        }
    }

    #[test]
    fn no_pgrep_matches_returns_empty_live_list() {
        let _guard = lock_tests();
        let bogus = "ganesha.nfsd-this-test-name-will-not-exist";
        assert!(pgrep_pids(bogus).is_empty());
        assert!(pgrep_live_pids(bogus).is_empty());
    }

    #[test]
    fn pgrep_live_filters_zombie_comm_names() {
        let _guard = lock_tests();
        let unique = format!("z{:04}", std::process::id() % 10_000);
        let zombie = unsafe {
            let child = libc::fork();
            if child == 0 {
                let name = std::ffi::CString::new(unique.as_str()).unwrap();
                libc::prctl(libc::PR_SET_NAME, name.as_ptr() as *const libc::c_void);
                libc::_exit(0);
            }
            assert!(child > 0);
            child as u32
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!process_is_live(zombie));
        let all = pgrep_pids(&unique);
        assert!(
            all.contains(&zombie),
            "pgrep must see zombie before filtering; got {all:?}"
        );
        let live = pgrep_live_pids(&unique);
        assert!(
            !live.contains(&zombie),
            "zombie must not appear in pgrep_live_pids; got {live:?}"
        );
        unsafe {
            let mut status = 0;
            libc::waitpid(zombie as i32, &mut status, 0);
        }
    }
}