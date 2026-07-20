//! Idhelper resolution preflight: CLI, socket, pipeline, and log probes.
//! Runs from the supervisor loop and the config CLI before serving.

use crate::ganesha_readiness;
use crate::{
    discover_ganesha_daemon_pid, evaluate_nss_contract,
    evaluate_short_name_getgrouplist_contract, identity_principals_for_check,
    proc_environ_map, proc_pid_environ,
    probe_id_g_under_env, probe_socket_grps, probe_socket_grouplist,
    run_identity_pipeline, GaneshaNssEnv, NfsKlldapConfig,
    FALLBACK_NOBODY_GID, MACHINE_GID,
};

static LAST_IDHELPER_CHECK_MSG: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Unix socket for idhelper GRPS/RESOLVE (overridable via `NFS_KLLDAP_IDHELPER_SOCK
pub fn idhelper_socket_path() -> String {
    std::env::var("NFS_KLLDAP_IDHELPER_SOCKET")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/var/run/nfs-klldap/idhelper.sock".to_string())
}

/// Log idhelper check once per unique message (suppresses supervisor-tick INFO spam
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

fn probe_grps_via_socket(principal: &str) -> Option<Vec<u32>> {
    probe_socket_grps(principal, &idhelper_socket_path())
}

fn probe_grouplist_via_socket(principal: &str) -> Option<Vec<u32>> {
    probe_socket_grouplist(principal, &idhelper_socket_path())
}

fn probe_grps_via_cli(idh: &str, principal: &str) -> Result<Vec<u32>, String> {
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

fn resolve_idhelper_bin() -> String {
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

/// ganesha-ctl id-resolve exercises uid2grp/getent group path (shipped Ganesha diag
fn probe_ganesha_id_resolve(principal: &str) -> Option<(bool, String)> {
    let ctl = ganesha_readiness::resolve_ganesha_ctl_bin()?;
    let idh = resolve_idhelper_bin();
    let nss = GaneshaNssEnv::from_runtime_defaults();
    let mut cmd = std::process::Command::new(&ctl);
    cmd.args(["id-resolve", principal]).env("IDHELPER_BIN", &idh);
    cmd.env("NSS_PASSWD", &nss.nss_passwd).env("NSS_GROUP", &nss.nss_group);
    if let Some(ref so) = nss.ld_preload {
        cmd.env("NSS_WRAPPER_SO", so);
    }
    let o = cmd.output().ok()?;
    let out = String::from_utf8_lossy(&o.stdout);
    if o.status.success() && !out.trim().is_empty() {
        Some((true, format!("ganesha-id-resolve:ok:{principal}")))
    } else {
        Some((false, format!("ganesha-id-resolve:exit:{principal}")))
    }
}

/// Trigger idhelper grps into production/runtime nss paths (Ganesha env after super
fn materialize_via_idhelper_grps(idh: &str, principal: &str) {
    let mut base = std::process::Command::new(idh);
    base.args(["grps", principal]);
    for key in [
        "NSS_PASSWD",
        "NSS_GROUP",
        "NSS_EXTRAUSERS_PASSWD",
        "NSS_EXTRAUSERS_GROUP",
    ] {
        if let Ok(v) = std::env::var(key) {
            base.env(key, v);
        }
    }
    let mut cmd = if std::path::Path::new("/usr/bin/timeout").exists() {
        let mut t = std::process::Command::new("timeout");
        t.args(["8"]);
        t.arg(idh).arg("grps").arg(principal);
        for key in [
            "NSS_PASSWD",
            "NSS_GROUP",
            "NSS_EXTRAUSERS_PASSWD",
            "NSS_EXTRAUSERS_GROUP",
        ] {
            if let Ok(v) = std::env::var(key) {
                t.env(key, v);
            }
        }
        t
    } else {
        base
    };
    let _ = cmd.output();
}

fn probe_socket_grps_tag(principal: &str, expect_machine: bool) -> String {
    let sock = idhelper_socket_path();
    if !std::path::Path::new(&sock).exists() {
        return format!("socket-grps:unavailable:{principal}");
    }
    match probe_grps_via_socket(principal) {
        Some(gids) if expect_machine && gids == [MACHINE_GID] => {
            format!("socket-grps:machine-ok:{principal}")
        }
        Some(gids) if !expect_machine && !gids.is_empty()
            && !gids.iter().all(|&g| g == FALLBACK_NOBODY_GID || g == 0) =>
        {
            format!("socket-grps:groups-ok:{principal}:{}gids", gids.len())
        }
        Some(gids) => format!("socket-grps:incomplete:{principal}:{gids:?}"),
        None => format!("socket-grps:connect-fail:{principal}"),
    }
}

/// Surface uid→groups NSS fetch from ganesha.log (getpwuid_r LogInfo from uid2grp.c
fn probe_ganesha_log_uid2grp(principal: &str) -> Option<String> {
    let log = std::path::Path::new("/var/log/ganesha.log");
    if !log.is_file() {
        return Some("ganesha-log:no-file".into());
    }
    let content = std::fs::read_to_string(log).ok()?;
    let short = nfs_klldap_identity::machine_short_name(principal);
    let by_uid = content.lines().any(|ln| {
        ln.contains("getpwuid_r for uid:")
            && (ln.contains(principal) || ln.contains(short) || ln.contains("uname:"))
    });
    let by_principal = content.lines().any(|ln| {
        ln.contains("uid2grp_allocate_by_principal")
            && (ln.contains(principal) || ln.contains(short))
    });
    let unsupported_user = content.lines().any(|ln| {
        ln.contains("Unsupported code path for principal")
            && ln.contains(principal)
            && !principal.to_ascii_lowercase().starts_with("host/")
    });
    if unsupported_user {
        Some(format!("ganesha-log:unsupported-principal:{principal}"))
    } else if by_uid {
        Some(format!("ganesha-log:uid2grp-by-uid:{principal}"))
    } else if by_principal {
        Some(format!("ganesha-log:uid2grp-by-principal:{principal}"))
    } else {
        Some(format!("ganesha-log:no-uid2grp:{principal}"))
    }
}

/// When ganesha.nfsd is live, verify its NSS_WRAPPER/LD_PRELOAD env matches supervi
fn probe_ganesha_runtime_wiring() -> String {
    let Some(pid) = discover_ganesha_daemon_pid() else {
        return "ganesha-runtime:not-running".into();
    };
    let mut tags = vec![format!("ganesha-runtime:live:pid={pid}")];
    let expected = GaneshaNssEnv::from_runtime_defaults();
    let Some(proc_env) = proc_environ_map(pid) else {
        tags.push("ganesha-runtime:environ-unreadable".into());
        return tags.join(" ");
    };
    if proc_env.contains_key("NFS_KLLDAP_IDHELPER_SOCKET") {
        tags.push("ganesha-runtime:idhelper-socket-env".into());
    }
    if proc_env
        .get("NSS_WRAPPER_PASSWD")
        .is_some_and(|p| std::path::Path::new(p) == expected.nss_passwd)
    {
        tags.push("ganesha-runtime:nss_passwd-env".into());
    } else {
        tags.push("ganesha-runtime:nss_passwd-miss".into());
    }
    if let Some(ref so) = expected.ld_preload {
        if proc_env
            .get("LD_PRELOAD")
            .is_some_and(|v| v.contains(&so.to_string_lossy().to_string()))
        {
            tags.push("ganesha-runtime:ld_preload-env".into());
        } else {
            tags.push("ganesha-runtime:ld_preload-miss".into());
        }
    }
    tags.join(" ")
}

/// Preflight: CLI grps + pipeline + runtime nss contract + socket + ganesha-ctl id-
pub fn check_idhelper_sample_resolutions(
    cfg: Option<&NfsKlldapConfig>,
    realm: &str,
    host_short: &str,
) -> (bool, String) {
    if std::env::var("NFS_KLLDAP_SKIP_ID_RESOLUTION_CHECK").is_ok() {
        return (true, "idhelper-check:skip:NFS_KLLDAP_SKIP_ID_RESOLUTION_CHECK".into());
    }
    let sock = idhelper_socket_path();
    if !std::path::Path::new(&sock).exists()
        && std::env::var("NFS_KLLDAP_IDHELPER_SOCKET").is_err()
    {
        return (
            true,
            "idhelper-check:skip:no-live-stack (idhelper socket absent; ganesha-runtime/synthetic-getgrouplist require live container)".into(),
        );
    }
    let idh = resolve_idhelper_bin();
    let nss_env = GaneshaNssEnv::from_runtime_defaults();
    let principals = identity_principals_for_check(cfg, realm, host_short, &nss_env);
    let mut msgs = vec![];
    let mut ok = true;
    if principals.user.is_none() {
        msgs.push(
            "idhelper-check:partial:no-probe-user (user-path checks skipped; set [probe] \
             user_principal or NFS_KLLDAP_PROBE_USER_PRINCIPAL)"
                .to_string(),
        );
    }
    if principals.client_host.is_none() {
        msgs.push(
            "idhelper-check:partial:no-probe-client-host (client-path checks skipped; set \
             [probe] client_host or NFS_KLLDAP_PROBE_CLIENT_HOST)"
                .to_string(),
        );
    }
    let mut probe_list: Vec<(&str, &str, bool)> = Vec::new();
    if let Some(u) = principals.user.as_deref() {
        probe_list.push(("user", u, false));
    }
    probe_list.push(("host-server", principals.server_host.as_str(), true));
    if let Some(c) = principals.client_host.as_deref() {
        probe_list.push(("host-client", c, true));
    }
    for (lab, p, expect_machine) in &probe_list {
        let gids = match probe_grps_via_cli(&idh, p) {
            Ok(g) => g,
            Err(e) => {
                ok = false;
                msgs.push(format!("{}({}):{}", lab, p, e));
                continue;
            }
        };
        if *expect_machine {
            if gids != [MACHINE_GID] {
                ok = false;
                msgs.push(format!(
                    "{}({}): expected gid={}, got {:?}",
                    lab, p, MACHINE_GID, gids
                ));
            } else {
                msgs.push(format!("{}({}):root-gid", lab, p));
            }
        } else if gids.iter().all(|&g| g == FALLBACK_NOBODY_GID || g == 0) {
            ok = false;
            msgs.push(format!("{}({}): incomplete (only fallback {})", lab, p, gids[0]));
        } else {
            msgs.push(format!("{}({}):{}gids", lab, p, gids.len()));
        }
    }
    let (pipe_ok, pipe_msg) = run_identity_pipeline(&principals, &idh);
    if !pipe_ok {
        ok = false;
    }
    msgs.push(pipe_msg);
    for (_, p, _) in &probe_list {
        materialize_via_idhelper_grps(&idh, p);
    }
    let mut socket_probe_list: Vec<(&str, bool)> = Vec::new();
    if let Some(u) = principals.user.as_deref() {
        socket_probe_list.push((u, false));
    }
    if let Some(c) = principals.client_host.as_deref() {
        socket_probe_list.push((c, true));
    }
    for (p, expect_machine) in &socket_probe_list {
        let tag = probe_socket_grps_tag(p, *expect_machine);
        if tag.contains("incomplete") || tag.contains("connect-fail") {
            ok = false;
        }
        msgs.push(tag);
    }
    let sock = idhelper_socket_path();
    let sock_available = std::path::Path::new(&sock).exists();
    let root_gl_ok = probe_grouplist_via_socket("root")
        .as_ref()
        .is_some_and(|g| g.contains(&0));
    let user_short = principals
        .user
        .as_deref()
        .map(|u| nfs_klldap_identity::principal_local_part(u).to_string());
    if let (Some(user), Some(user_short)) = (principals.user.as_deref(), user_short.as_deref()) {
        let user_gl_ok = probe_grouplist_via_socket(user_short).is_some();
        let (short_contract_ok, short_contract_msg) =
            evaluate_short_name_getgrouplist_contract(user, &nss_env, 3);
        msgs.push(format!(
            "synthetic-getgrouplist: root_ok={root_gl_ok} user({user_short})_ok={user_gl_ok} {short_contract_msg}"
        ));
        if sock_available && (!root_gl_ok || !user_gl_ok) {
            ok = false;
        }
        if !short_contract_ok {
            ok = false;
        }
    } else {
        msgs.push(format!(
            "synthetic-getgrouplist: root_ok={root_gl_ok} (no probe user)"
        ));
        if sock_available && !root_gl_ok {
            ok = false;
        }
    }
    for (lab, p, expect_machine) in &probe_list {
        let (contract_ok, contract_msg) = evaluate_nss_contract(p, &nss_env, *expect_machine);
        if !contract_ok {
            ok = false;
        }
        msgs.push(format!("{contract_msg}:{lab}"));
    }
    msgs.push(probe_ganesha_runtime_wiring());
    if let Some(pid) = discover_ganesha_daemon_pid() {
        if let Some(envp) = proc_pid_environ(pid) {
            let root_seen = probe_id_g_under_env("root", &envp);
            if let Some(user_short) = user_short.as_deref() {
                let user_seen = probe_id_g_under_env(user_short, &envp);
                msgs.push(format!(
                    "ganesha-seen-getgrouplist: root={root_seen:?} user({user_short})={user_seen:?}"
                ));
            } else {
                msgs.push(format!(
                    "ganesha-seen-getgrouplist: root={root_seen:?} (no probe user)"
                ));
            }
        }
    }
    for (_, p, _) in &probe_list {
        if let Some((ctl_ok, ctl_msg)) = probe_ganesha_id_resolve(p) {
            if !ctl_ok {
                ok = false;
            }
            msgs.push(ctl_msg);
        }
        if let Some(tag) = probe_ganesha_log_uid2grp(p) {
            msgs.push(tag);
        }
    }
    let m = if ok {
        format!("idhelper check OK: {}", msgs.join(" "))
    } else {
        format!(
            "idhelper resolution incomplete (user+host principals): {}",
            msgs.join("; ")
        )
    };
    (ok, m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_idhelper_check_log_suppresses_repeat_message() {
        let _lock = crate::ENV_TEST_LOCK.lock().unwrap();
        *LAST_IDHELPER_CHECK_MSG.lock().unwrap() = None;
        emit_idhelper_check_log(true, "idhelper check OK: test");
        assert_eq!(
            LAST_IDHELPER_CHECK_MSG.lock().unwrap().as_deref(),
            Some("idhelper check OK: test")
        );
        emit_idhelper_check_log(true, "idhelper check OK: test");
        emit_idhelper_check_log(false, "idhelper resolution incomplete: changed");
        assert_eq!(
            LAST_IDHELPER_CHECK_MSG.lock().unwrap().as_deref(),
            Some("idhelper resolution incomplete: changed")
        );
        *LAST_IDHELPER_CHECK_MSG.lock().unwrap() = None;
    }
}
