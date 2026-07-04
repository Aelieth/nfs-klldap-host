//! Idhelper socket/probe helpers (moved from lib.rs for modularization).

use crate::{probe_socket_grps, probe_socket_grouplist};

pub(crate) static LAST_IDHELPER_CHECK_MSG: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Unix socket for idhelper GRPS/RESOLVE (overridable via `NFS_KLLDAP_IDHELPER_SOCKET`).
pub fn idhelper_socket_path() -> String {
    std::env::var("NFS_KLLDAP_IDHELPER_SOCKET")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/var/run/nfs-klldap/idhelper.sock".to_string())
}

/// Log idhelper check once per unique message (suppresses supervisor-tick INFO spam).
pub fn emit_idhelper_check_log(ok: bool, msg: &str) {
    let mut last = LAST_IDHELPER_CHECK_MSG.lock().unwrap_or_else(|e| e.into_inner());
    if last.as_deref() == Some(msg) {
        return;
    }
    *last = Some(msg.to_string());
    if ok {
        eprintln!("INFO [nfs-klldap-config] {}", msg);
    } else {
        eprintln!("WARN [nfs-klldap-config] {}", msg);
    }
}

fn parse_grps_output(stdout: &str) -> Vec<u32> {
    let s = stdout.trim();
    let body = s.strip_prefix("OK ").unwrap_or(s);
    body.split(|c: char| "| ,".contains(c))
        .filter_map(|t| t.trim().parse::<u32>().ok())
        .collect()
}

pub(crate) fn probe_grps_via_socket(principal: &str) -> Option<Vec<u32>> {
    probe_socket_grps(principal, &idhelper_socket_path())
}

pub(crate) fn probe_grouplist_via_socket(principal: &str) -> Option<Vec<u32>> {
    probe_socket_grouplist(principal, &idhelper_socket_path())
}

pub(crate) fn probe_grps_via_cli(idh: &str, principal: &str) -> Result<Vec<u32>, String> {
    let mut cmd = std::process::Command::new(idh);
    cmd.args(["grps", principal]);
    if std::path::Path::new("/usr/bin/timeout").exists() {
        cmd = std::process::Command::new("timeout");
        cmd.args(["8", idh, "grps", principal]);
    }
    let o = cmd.output().map_err(|_| "noexec".to_string())?;
    if !o.status.success() {
        return Err("exit".into());
    }
    let gids = parse_grps_output(&String::from_utf8_lossy(&o.stdout));
    if gids.is_empty() {
        Err("empty".into())
    } else {
        Ok(gids)
    }
}

pub(crate) fn resolve_idhelper_bin() -> String {
    if let Ok(p) = std::env::var("IDHELPER_BIN") {
        if !p.trim().is_empty() {
            return p;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            let c = d.join("nfs-klldap-idhelper");
            if c.exists() {
                return c.display().to_string();
            }
        }
    }
    "nfs-klldap-idhelper".into()
}

pub(crate) fn resolve_ganesha_ctl_bin() -> Option<String> {
    if let Ok(p) = std::env::var("GANESHA_CTL_BIN") {
        let p = p.trim().to_string();
        if !p.is_empty() && std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    for cand in [
        "/usr/local/bin/ganesha-ctl",
        "/container/scripts/ganesha-ctl",
    ] {
        if std::path::Path::new(cand).exists() {
            return Some(cand.to_string());
        }
    }
    None
}
