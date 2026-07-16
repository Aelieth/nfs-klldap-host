//! Process signal plumbing: shutdown/SIGHUP/SIGUSR1 flags and pid signaling
//! (SIGHUP = scoped graceful apply, SIGUSR1 = forced full service recycle).

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
use signal_hook::consts::{SIGINT, SIGHUP, SIGTERM, SIGUSR1};
#[cfg(unix)]
use signal_hook::iterator::Signals;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGHUP_REQUESTED: AtomicBool = AtomicBool::new(false);
static FULL_RECYCLE_REQUESTED: AtomicBool = AtomicBool::new(false);

pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

pub fn take_sighup_requested() -> bool {
    SIGHUP_REQUESTED.swap(false, Ordering::SeqCst)
}

pub fn request_sighup() {
    SIGHUP_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn take_full_recycle_requested() -> bool {
    FULL_RECYCLE_REQUESTED.swap(false, Ordering::SeqCst)
}

pub fn request_full_recycle() {
    FULL_RECYCLE_REQUESTED.store(true, Ordering::SeqCst);
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

/// Reaps every exited child (pid 1 inherits all reparented orphans). Draining
/// in a loop prevents zombie build-up when several children exit between ticks;
/// a single WNOHANG call per tick would leave N-1 zombies until later ticks.
pub fn reap_children() {
    #[cfg(unix)]
    loop {
        use nix::sys::wait::WaitStatus;
        match waitpid(Some(Pid::from_raw(-1)), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(_) => break,
            Ok(_) => continue,
        }
    }
}

pub fn install_signal_handlers() -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut signals = Signals::new([SIGTERM, SIGINT, SIGHUP, SIGUSR1])
            .map_err(|e| format!("signal setup failed: {e}"))?;
        thread::spawn(move || {
            for sig in &mut signals {
                match sig {
                    SIGTERM | SIGINT => SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst),
                    SIGHUP => SIGHUP_REQUESTED.store(true, Ordering::SeqCst),
                    SIGUSR1 => FULL_RECYCLE_REQUESTED.store(true, Ordering::SeqCst),
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

/// Asks the supervisor for a forced full service recycle (SIGUSR1), as opposed
/// to the scoped graceful apply that SIGHUP performs.
pub fn signal_supervisor_full_recycle(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("invalid supervisor pid 0".to_string());
    }
    #[cfg(unix)]
    {
        kill(Pid::from_raw(pid as i32), Signal::SIGUSR1)
            .map_err(|e| format!("SIGUSR1 to pid {pid} failed: {e}"))
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err("SIGUSR1 requires a Unix target".to_string())
    }
}
