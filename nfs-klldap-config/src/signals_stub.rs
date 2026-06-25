//! Non-Unix stubs so the config crate builds without nix/signal-hook.

use std::sync::atomic::{AtomicBool, Ordering};

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

pub fn reap_one_child() {}

pub fn install_signal_handlers() -> Result<(), String> {
    Err("signal handlers require a Unix target".to_string())
}

pub fn signal_supervisor_hup(_pid: u32) -> Result<(), String> {
    Err("SIGHUP requires a Unix target".to_string())
}