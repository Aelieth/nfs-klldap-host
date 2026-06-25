//! Safe Unix signal delivery for the pid-1 supervisor.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::Pid;
use signal_hook::consts::{SIGINT, SIGHUP, SIGTERM};
use signal_hook::iterator::Signals;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGHUP_REQUESTED: AtomicBool = AtomicBool::new(false);

pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Take and clear a pending SIGHUP notification.
pub fn take_sighup_requested() -> bool {
    SIGHUP_REQUESTED.swap(false, Ordering::SeqCst)
}

/// Queue a SIGHUP for the supervisor loop (CI wizard-probe path).
pub fn request_sighup() {
    SIGHUP_REQUESTED.store(true, Ordering::SeqCst);
}

/// Send a signal to pid; ignores errors (process may already be gone).
pub fn signal_process(pid: u32, sig: Signal) {
    let _ = kill(Pid::from_raw(pid as i32), sig);
}

/// Non-blocking reap of one child process.
pub fn reap_one_child() {
    let _ = waitpid(Some(Pid::from_raw(-1)), Some(WaitPidFlag::WNOHANG));
}

/// Spawn a signal-hook thread that sets the supervisor atomic flags.
pub fn install_signal_handlers() -> Result<(), String> {
    let mut signals =
        Signals::new([SIGTERM, SIGINT, SIGHUP]).map_err(|e| format!("signal setup failed: {e}"))?;
    thread::spawn(move || {
        for sig in &mut signals {
            match sig {
                SIGTERM | SIGINT => SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst),
                SIGHUP => SIGHUP_REQUESTED.store(true, Ordering::SeqCst),
                _ => {}
            }
        }
    });
    Ok(())
}

/// Validate pid and send SIGHUP (used by WebUI recycle path).
pub fn signal_supervisor_hup(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("invalid supervisor pid 0".to_string());
    }
    kill(Pid::from_raw(pid as i32), Signal::SIGHUP)
        .map_err(|e| format!("SIGHUP to pid {pid} failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn signal_supervisor_hup_rejects_pid_zero() {
        assert!(signal_supervisor_hup(0).is_err());
    }

    #[test]
    fn reap_one_child_does_not_block() {
        reap_one_child();
    }


}