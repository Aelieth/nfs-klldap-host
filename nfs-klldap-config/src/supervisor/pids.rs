//! Pids tracking (extracted submodule for supervisor/mod.rs size reduction).

#[derive(Default)]
pub(crate) struct ChildPids {
    pub watcher: Option<u32>,
    pub sssd: Option<u32>,
    pub ganesha: Option<u32>,
    pub webui: Option<u32>,
    pub dbus: Option<u32>,
    pub idhelper: Option<u32>,
}

impl ChildPids {}