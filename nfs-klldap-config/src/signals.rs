//! Process signal plumbing: shutdown/SIGHUP flags and pid signaling.

use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::sys::wait::{waitpid, WaitPidFlag};
#[cfg(unix)]
use nix::unistd::Pid;
#[cfg(unix)]
use signal_hook::consts::{SIGINT, SIGHUP, SIGTERM};
#[cfg(unix)]
use signal_hook::iterator::Signals;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGHUP_REQUESTED: AtomicBool = AtomicBool::new(false);

pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

pub fn take_sighup_requested() -> bool {
    SIGHUP_REQUESTED.swap(false, Ordering::SeqCst)
}

pub fn request_sighup() {
    SIGHUP_REQUESTED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn signal_process(pid: u32, sig: Signal) {
    let _ = kill(Pid::from_raw(pid as i32), sig);
}

pub fn signal_process_term(pid: u32) {
    #[cfg(unix)]
    signal_process(pid, Signal::SIGTERM);
    #[cfg(not(unix))]
    let _ = pid;
}

pub fn signal_process_hup(pid: u32) {
    #[cfg(unix)]
    signal_process(pid, Signal::SIGHUP);
    #[cfg(not(unix))]
    let _ = pid;
}

pub fn signal_process_kill(pid: u32) {
    #[cfg(unix)]
    signal_process(pid, Signal::SIGKILL);
    #[cfg(not(unix))]
    let _ = pid;
}

pub fn reap_one_child() {
    #[cfg(unix)]
    let _ = waitpid(Some(Pid::from_raw(-1)), Some(WaitPidFlag::WNOHANG));
}

pub fn install_signal_handlers() -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut signals = Signals::new([SIGTERM, SIGINT, SIGHUP])
            .map_err(|e| format!("signal setup failed: {e}"))?;
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
    #[cfg(not(unix))]
    {
        Err("signal handlers require a Unix target".to_string())
    }
}

pub fn signal_supervisor_hup(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("invalid supervisor pid 0".to_string());
    }
    #[cfg(unix)]
    {
        kill(Pid::from_raw(pid as i32), Signal::SIGHUP)
            .map_err(|e| format!("SIGHUP to pid {pid} failed: {e}"))
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err("SIGHUP requires a Unix target".to_string())
    }
}
