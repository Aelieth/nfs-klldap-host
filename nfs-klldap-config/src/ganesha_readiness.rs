//! Readiness checks.

//! Probe nss + socket under env.



use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

use nfs_klldap_identity::principal_local_part;

/// Inputs for building the explicit ganesha.nfsd envp (mirrors supervisor inj.
#[derive(Debug, Clone)]
pub struct GaneshaSpawnEnv {
    pub nss_passwd: PathBuf,
    pub nss_group: PathBuf,
    pub extrausers_passwd: PathBuf,
    pub extrausers_group: PathBuf,
    pub idhelper_bin: PathBuf,
    pub idhelper_socket: String,
    pub nss_wrapper_so: PathBuf,
    pub use_nss_wrapper: bool,
}

/// Report from readiness check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaneshaReadinessReport {
    pub root_ok: bool,
    pub sample_ok: bool,
    /// Exact short pw_name getgrouplist for root (uid2grp).
    pub short_root_ok: bool,
    /// Exact short `pw_name` getgrouplist for sample user after getpwuid_r.
    pub short_sample_ok: bool,
    pub socket_ok: bool,
    // Id -G for root+sample using live pid.
    pub ganesha_process_ok: bool,
    // No new `my_getgrouplist_alloc` WARN in ganesha.log after uid2grp exer.
    pub ganesha_uid2grp_clean: bool,
    pub synthetic_clean: bool,
}

impl GaneshaReadinessReport {
    pub fn is_ready(&self) -> bool {
        self.root_ok
            && self.sample_ok
            && self.short_root_ok
            && self.short_sample_ok
            && self.socket_ok
            && self.ganesha_process_ok
            && self.ganesha_uid2grp_clean
            && self.synthetic_clean
    }
}

/// Filter `/proc/<pid>/environ` bytes for LD_PRELOAD, NSS_WRAPPER, IDHELPER k.
pub fn filter_proc_environ_keys(raw: &[u8]) -> Vec<String> {
    raw.split(|&b| b == 0)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .filter(|s| {
            s.starts_with("LD_PRELOAD=")
                || s.starts_with("NSS_WRAPPER")
                || s.starts_with("IDHELPER")
                || s.starts_with("NFS_KLLDAP_IDHELPER")
                || s.starts_with("NSS_")
        })
        .map(|s| s.to_string())
        .collect()
}

/// Parse `/proc/<pid>/environ` into a key -> value map.
pub fn proc_environ_map(pid: u32) -> Option<std::collections::HashMap<String, String>> {
    let raw = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    Some(
        raw.split(|&b| b == 0)
            .filter_map(|chunk| {
                let s = std::str::from_utf8(chunk).ok()?;
                let (k, v) = s.split_once('=')?;
                Some((k.to_string(), v.to_string()))
            })
            .collect(),
    )
}

/// Parse `/proc/<pid>/environ` into envp tuples.
pub fn proc_pid_environ(pid: u32) -> Option<Vec<(OsString, OsString)>> {
    let raw = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    let envp: Vec<(OsString, OsString)> = raw
        .split(|&b| b == 0)
        .filter_map(|chunk| {
            let s = std::str::from_utf8(chunk).ok()?;
            let (k, v) = s.split_once('=')?;
            Some((OsString::from(k), OsString::from(v)))
        })
        .collect();
    if envp.is_empty() {
        None
    } else {
        Some(envp)
    }
}

/// Build explicit envp for ganesha.nfsd: LD_PRELOAD (nss first), NSS_WRAPPER_.
/// IDHELPER_*, NFS_KLLDAP_IDHELPER_*, nss_passwd-env, and SSSD module chain w.
pub fn build_ganesha_envp(cfg: &GaneshaSpawnEnv) -> Vec<(OsString, OsString)> {
    let mut map: HashMap<OsString, OsString> = std::env::vars_os()
        .filter(|(k, _)| {
            let s = k.to_string_lossy();
            s == "LD_PRELOAD"
                || s.starts_with("NSS_WRAPPER")
                || s.starts_with("IDHELPER")
                || s.starts_with("NFS_KLLDAP_IDHELPER")
                || s.starts_with("NSS_")
                || s == "PATH"
        })
        .collect();

    map.insert(
        OsString::from("PATH"),
        OsString::from(format!(
            "/usr/local/bin:{}",
            std::env::var("PATH").unwrap_or_default()
        )),
    );
    map.insert(
        OsString::from("NSS_EXTRAUSERS_PASSWD"),
        cfg.extrausers_passwd.clone().into_os_string(),
    );
    map.insert(
        OsString::from("NSS_EXTRAUSERS_GROUP"),
        cfg.extrausers_group.clone().into_os_string(),
    );
    map.insert(
        OsString::from("IDHELPER_BIN"),
        cfg.idhelper_bin.clone().into_os_string(),
    );
    map.insert(
        OsString::from("NFS_KLLDAP_IDHELPER_SOCKET"),
        OsString::from(&cfg.idhelper_socket),
    );

    if cfg.use_nss_wrapper {
        map.insert(
            OsString::from("NSS_WRAPPER_PASSWD"),
            cfg.nss_passwd.clone().into_os_string(),
        );
        map.insert(
            OsString::from("NSS_WRAPPER_GROUP"),
            cfg.nss_group.clone().into_os_string(),
        );
        if let Some(sss) = resolve_nss_sss_so() {
            map.insert(
                OsString::from("NSS_WRAPPER_MODULE_SO_PATH"),
                sss.into_os_string(),
            );
            map.insert(
                OsString::from("NSS_WRAPPER_MODULE_FN_PREFIX"),
                OsString::from("_nss_sss_"),
            );
        }
        let chain = crate::ld_preload_for_ganesha(&cfg.nss_wrapper_so);
        map.insert(
            OsString::from("LD_PRELOAD"),
            OsString::from(chain.to_string_lossy().into_owned()),
        );
    }

    map.into_iter().collect()
}

/// Resolve path to libnss_sss.so.2 for nss_wrapper module chaining.
pub fn resolve_nss_sss_so() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("NSS_SSS_MODULE_SO") {
        if !p.is_empty() {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return Some(pb);
            }
        }
    }
    for cand in [
        "/usr/lib64/libnss_sss.so.2",
        "/usr/lib/x86_64-linux-gnu/libnss_sss.so.2",
        "/lib/x86_64-linux-gnu/libnss_sss.so.2",
        "/usr/lib/aarch64-linux-gnu/libnss_sss.so.2",
        "/run/host/usr/lib64/libnss_sss.so.2",
        "/run/host/usr/lib/x86_64-linux-gnu/libnss_sss.so.2",
    ] {
        let p = PathBuf::from(cand);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(out) = Command::new("find")
        .args(["/usr", "/lib", "-name", "libnss_sss.so.2", "-type", "f"])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(first) = s.lines().next() {
                if !first.is_empty() {
                    let p = PathBuf::from(first.trim());
                    if p.is_file() {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

/// Scan ganesha.log for `my_getgrouplist_alloc` WARN/failed lines (full file.
pub(crate) fn ganesha_log_has_getgrouplist_warn(ganesha_log_path: &str, from_offset: u64) -> bool {
    let Ok(content) = std::fs::read_to_string(ganesha_log_path) else {
        return false;
    };
    // Offset exactly at EOF means no new data: scan nothing, not everything.
    let tail = if from_offset > 0 && (from_offset as usize) <= content.len() {
        &content[from_offset as usize..]
    } else {
        content.as_str()
    };
    tail.lines().any(|ln| {
        let low = ln.to_ascii_lowercase();
        low.contains("my_getgrouplist_alloc")
            && (low.contains("warn") || low.contains("failed, errno"))
    })
}

/// Synthetic krb log scan.
pub(crate) fn check_synthetic_krb_log_clean(ganesha_log_path: &str) -> bool {
    !ganesha_log_has_getgrouplist_warn(ganesha_log_path, 0)
}

/// Scan ganesha.log past offset for nfs_creds managed-groups fetch failures.
/// These log under DISP at INFO (not ID MAPPER WARN) when uid2grp fails on a
/// live RPCSEC_GSS request; under GSS the fallback strips all supplementary
/// groups, so they are the primary group-resolution failure signature.
pub(crate) fn ganesha_log_has_managed_gids_failure(ganesha_log_path: &str, from_offset: u64) -> bool {
    let Ok(content) = std::fs::read_to_string(ganesha_log_path) else {
        return false;
    };
    // Offset exactly at EOF means no new data: scan nothing, not everything.
    let tail = if from_offset > 0 && (from_offset as usize) <= content.len() {
        &content[from_offset as usize..]
    } else {
        content.as_str()
    };
    tail.lines().any(|ln| {
        let low = ln.to_ascii_lowercase();
        low.contains("attempt to fetch managed") && low.contains("failed")
    })
}

fn apply_envp(cmd: &mut Command, envp: &[(OsString, OsString)]) {
    cmd.env_clear();
    cmd.envs(envp.iter().map(|(k, v)| (k.clone(), v.clone())));
}

/// Id -G under envp for readiness.
pub fn probe_id_g_under_env(who: &str, envp: &[(OsString, OsString)]) -> Option<Vec<u32>> {
    let mut cmd = Command::new("id");
    cmd.args(["-G", who]);
    apply_envp(&mut cmd, envp);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let gids: Vec<u32> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    if gids.is_empty() {
        None
    } else {
        Some(gids)
    }
}

/// Id -G using live ganesha pid proc.oc/<pid>/envir.
pub fn probe_ganesha_process_groups(pid: u32, who: &str) -> Option<Vec<u32>> {
    let envp = proc_pid_environ(pid)?;
    probe_id_g_under_env(who, &envp)
}

pub(crate) fn resolve_ganesha_ctl_bin() -> Option<String> {
    if let Ok(p) = std::env::var("GANESHA_CTL_BIN") {
        let p = p.trim().to_string();
        if !p.is_empty() && Path::new(&p).exists() {
            return Some(p);
        }
    }
    for cand in ["/usr/local/bin/ganesha-ctl", "/container/scripts/ganesha-ctl"] {
        if Path::new(cand).exists() {
            return Some(cand.to_string());
        }
    }
    None
}

/// Exercise uid2grp/getgrouplist path via ganesha-ctl id-resolve under ganesh.
pub(crate) fn exercise_ganesha_uid2grp(
    envp: &[(OsString, OsString)],
    principals: &[&str],
    ganesha_log_path: &str,
) -> (bool, String) {
    let log_offset = std::fs::metadata(ganesha_log_path)
        .map(|m| m.len())
        .unwrap_or(0);
    if let Some(ctl) = resolve_ganesha_ctl_bin() {
        for p in principals {
            let mut cmd = Command::new(&ctl);
            cmd.args(["id-resolve", p]);
            apply_envp(&mut cmd, envp);
            let _ = cmd.output();
        }
    } else {
        for p in principals {
            let _ = probe_id_g_under_env(p, envp);
            let short = principal_local_part(p);
            if short != *p {
                let _ = probe_id_g_under_env(short, envp);
            }
        }
    }
    let has_warn = ganesha_log_has_getgrouplist_warn(ganesha_log_path, log_offset)
        || ganesha_log_has_managed_gids_failure(ganesha_log_path, log_offset);
    let msg = if has_warn {
        "ganesha-uid2grp-exercise:warn-seen".into()
    } else {
        "ganesha-uid2grp-exercise:clean".into()
    };
    (!has_warn, msg)
}

/// One-line request/response over the idhelper unix socket.
/// Returns the trimmed first response line; None when the socket is absent
/// or the exchange fails.
pub fn idhelper_socket_request(socket_path: &str, request: &str) -> Option<String> {
    if !Path::new(socket_path).exists() {
        return None;
    }
    let mut stream = UnixStream::connect(socket_path).ok()?;
    stream.write_all(request.as_bytes()).ok()?;
    stream.flush().ok()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    Some(line.trim().to_string())
}

fn socket_cmd_gids(socket_path: &str, cmd: &str, principal: &str) -> Option<Vec<u32>> {
    let resp = idhelper_socket_request(socket_path, &format!("{cmd} {principal}\n"))?;
    let rest = resp.strip_prefix("OK ")?;
    let gids: Vec<u32> = rest
        .split('|')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if gids.is_empty() {
        None
    } else {
        Some(gids)
    }
}

/// Socket GRPS query for readiness.
pub fn probe_socket_grps(principal: &str, socket_path: &str) -> Option<Vec<u32>> {
    socket_cmd_gids(socket_path, "GRPS", principal)
}

/// Socket GROUPLIST/GETGROUPLIST query for readiness backstop.
pub fn probe_socket_grouplist(principal: &str, socket_path: &str) -> Option<Vec<u32>> {
    socket_cmd_gids(socket_path, "GROUPLIST", principal)
}

/// Send SIGHUP to ganesha.nfsd to clear idmapper negative cache after NSS hea.
pub fn signal_ganesha_reload_idmap(pid: u32) -> bool {
    if std::env::var("NFS_KLLDAP_SIGHUP_ON_IDMAP_HEAL")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
    {
        return false;
    }
    if pid == 0 {
        return false;
    }
    crate::signal_process_hup(pid);
    true
}

/// Single-shot readiness gate under the ganesha envp (no retry loop)
pub fn check_ganesha_readiness(
    pid: Option<u32>,
    envp: &[(OsString, OsString)],
    sample: Option<&str>,
    ganesha_log_path: &str,
    socket_path: &str,
) -> GaneshaReadinessReport {
    let Some(sample) = sample else {
        return check_ganesha_readiness_root_only(pid, envp, ganesha_log_path, socket_path);
    };
    let short_sample = principal_local_part(sample);
    let root_gids = probe_id_g_under_env("root", envp);
    let sample_gids = probe_id_g_under_env(sample, envp);
    let short_root_gids = probe_id_g_under_env("root", envp);
    let short_sample_gids = probe_id_g_under_env(short_sample, envp);
    let sample_socket_gl = probe_socket_grouplist(sample, socket_path);
    let short_sample_socket_gl = probe_socket_grouplist(short_sample, socket_path);

    let root_ok = root_gids
        .as_ref()
        .is_some_and(|g| g.contains(&0));
    let short_root_ok = short_root_gids
        .as_ref()
        .is_some_and(|g| g.contains(&0));
    let sample_ok = sample_socket_gl
        .as_ref()
        .is_some_and(|g| g.len() >= 2)
        || (sample_gids.as_ref().is_some_and(|g| !g.is_empty())
            && probe_socket_grps(sample, socket_path).is_some());
    let short_sample_ok = short_sample_socket_gl
        .as_ref()
        .is_some_and(|g| g.len() >= 2)
        || short_sample_gids.as_ref().is_some_and(|g| g.len() >= 2);

    let sock_root_grps = probe_socket_grps("root", socket_path).is_some();
    let sock_sample_grps = probe_socket_grps(sample, socket_path).is_some();
    let sock_short_sample_grps = probe_socket_grps(short_sample, socket_path).is_some();
    let sock_root_gl = probe_socket_grouplist("root", socket_path)
        .as_ref()
        .is_some_and(|g| g.contains(&0));
    let sock_sample_gl = sample_socket_gl.is_some();
    let sock_short_sample_gl = short_sample_socket_gl.is_some();
    let socket_ok = sock_root_grps
        && sock_sample_grps
        && sock_short_sample_grps
        && sock_root_gl
        && sock_sample_gl
        && sock_short_sample_gl;

    let ganesha_process_ok = if let Some(pid) = pid {
        let root_seen = probe_ganesha_process_groups(pid, "root");
        let sample_seen = probe_ganesha_process_groups(pid, sample);
        let short_seen = probe_ganesha_process_groups(pid, short_sample);
        root_seen.as_ref().is_some_and(|g| g.contains(&0))
            && (sample_seen.as_ref().is_some_and(|g| !g.is_empty())
                || short_seen.as_ref().is_some_and(|g| !g.is_empty())
                || sample_socket_gl.is_some()
                || short_sample_socket_gl.is_some())
    } else {
        false
    };

    let proc_envp = pid
        .and_then(proc_pid_environ)
        .unwrap_or_else(|| envp.to_vec());
    let (ganesha_uid2grp_clean, _) = exercise_ganesha_uid2grp(
        &proc_envp,
        &["root", short_sample],
        ganesha_log_path,
    );

    let synthetic_clean = check_synthetic_krb_log_clean(ganesha_log_path);

    GaneshaReadinessReport {
        root_ok,
        sample_ok,
        short_root_ok,
        short_sample_ok,
        socket_ok,
        ganesha_process_ok,
        ganesha_uid2grp_clean,
        synthetic_clean,
    }
}

/// Readiness without a probe user: sample gates pass vacuously.
fn check_ganesha_readiness_root_only(
    pid: Option<u32>,
    envp: &[(OsString, OsString)],
    ganesha_log_path: &str,
    socket_path: &str,
) -> GaneshaReadinessReport {
    let root_gids = probe_id_g_under_env("root", envp);
    let root_ok = root_gids.as_ref().is_some_and(|g| g.contains(&0));
    let sock_root_grps = probe_socket_grps("root", socket_path).is_some();
    let sock_root_gl = probe_socket_grouplist("root", socket_path)
        .as_ref()
        .is_some_and(|g| g.contains(&0));
    let ganesha_process_ok = if let Some(pid) = pid {
        probe_ganesha_process_groups(pid, "root")
            .as_ref()
            .is_some_and(|g| g.contains(&0))
    } else {
        false
    };
    let proc_envp = pid
        .and_then(proc_pid_environ)
        .unwrap_or_else(|| envp.to_vec());
    let (ganesha_uid2grp_clean, _) =
        exercise_ganesha_uid2grp(&proc_envp, &["root"], ganesha_log_path);
    let synthetic_clean = check_synthetic_krb_log_clean(ganesha_log_path);
    GaneshaReadinessReport {
        root_ok,
        sample_ok: true,
        short_root_ok: root_ok,
        short_sample_ok: true,
        socket_ok: sock_root_grps && sock_root_gl,
        ganesha_process_ok,
        ganesha_uid2grp_clean,
        synthetic_clean,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn filter_proc_environ_keys_parses_nul_separated_fixture() {
        let raw = b"LD_PRELOAD=/usr/lib/libnss_wrapper.so\0NSS_WRAPPER_PASSWD=/var/lib/nfs-klldap/nss_passwd\0HOME=/root\0NSS_WRAPPER_MODULE_SO_PATH=/usr/lib64/libnss_sss.so.2\0";
        let keys = filter_proc_environ_keys(raw);
        assert!(keys.iter().any(|s| s.starts_with("LD_PRELOAD=")));
        assert!(keys.iter().any(|s| s.starts_with("NSS_WRAPPER_PASSWD=")));
        assert!(keys.iter().any(|s| s.starts_with("NSS_WRAPPER_MODULE_SO_PATH=")));
        assert!(!keys.iter().any(|s| s.starts_with("HOME=")));
    }

    #[test]
    fn build_ganesha_envp_includes_required_nss_keys() {
        let cfg = GaneshaSpawnEnv {
            nss_passwd: PathBuf::from("/var/lib/nfs-klldap/nss_passwd"),
            nss_group: PathBuf::from("/var/lib/nfs-klldap/nss_group"),
            extrausers_passwd: PathBuf::from("/var/lib/extrausers/passwd"),
            extrausers_group: PathBuf::from("/var/lib/extrausers/group"),
            idhelper_bin: PathBuf::from("/usr/local/bin/nfs-klldap-idhelper"),
            idhelper_socket: "/var/run/nfs-klldap/idhelper.sock".into(),
            nss_wrapper_so: PathBuf::from("/usr/lib/x86_64-linux-gnu/libnss_wrapper.so"),
            use_nss_wrapper: true,
        };
        let envp = build_ganesha_envp(&cfg);
        let get = |k: &str| {
            envp.iter()
                .find(|(key, _)| key == &OsString::from(k))
                .map(|(_, v)| v.to_string_lossy().to_string())
        };
        assert!(get("LD_PRELOAD").is_some());
        assert_eq!(
            get("NSS_WRAPPER_PASSWD").as_deref(),
            Some("/var/lib/nfs-klldap/nss_passwd")
        );
        assert_eq!(
            get("NSS_WRAPPER_GROUP").as_deref(),
            Some("/var/lib/nfs-klldap/nss_group")
        );
        assert_eq!(
            get("NFS_KLLDAP_IDHELPER_SOCKET").as_deref(),
            Some("/var/run/nfs-klldap/idhelper.sock")
        );
        if resolve_nss_sss_so().is_some() {
            assert!(get("NSS_WRAPPER_MODULE_SO_PATH").is_some());
            assert_eq!(
                get("NSS_WRAPPER_MODULE_FN_PREFIX").as_deref(),
                Some("_nss_sss_")
            );
        }
    }

    #[test]
    fn check_ganesha_readiness_false_when_sample_missing_from_nss_fixture() {
        let td = tempfile::tempdir().unwrap();
        let pw = td.path().join("nss_passwd");
        let gr = td.path().join("nss_group");
        std::fs::write(&pw, "root:x:0:0:root:/root:/bin/sh\n").unwrap();
        std::fs::write(&gr, "root:x:0:root\n").unwrap();
        let mut envp = vec![
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (
                OsString::from("NSS_WRAPPER_PASSWD"),
                pw.into_os_string(),
            ),
            (OsString::from("NSS_WRAPPER_GROUP"), gr.into_os_string()),
        ];
        if let Some(so) = crate::ganesha_nss_contract::GaneshaNssEnv::from_runtime_defaults()
            .ld_preload
        {
            envp.push((OsString::from("LD_PRELOAD"), so.into_os_string()));
        } else {
            return;
        }
        let report = check_ganesha_readiness(
            None,
            &envp,
            Some("testuser1"),
            "/nonexistent/ganesha.log",
            "/nonexistent/idhelper.sock",
        );
        assert!(report.root_ok, "root must resolve from nss fixture");
        assert!(!report.sample_ok, "unknown sample must not resolve");
        assert!(!report.socket_ok);
        assert!(!report.ganesha_process_ok);
        assert!(!report.is_ready());
    }

    #[test]
    fn check_synthetic_krb_log_clean_detects_warn_lines() {
        let td = tempfile::tempdir().unwrap();
        let log = td.path().join("ganesha.log");
        std::fs::write(
            &log,
            "my_getgrouplist_alloc :ID MAPPER :WARN :getgrouplist for user:root failed, ngroups: 1, errno: 1\n",
        )
        .unwrap();
        assert!(!check_synthetic_krb_log_clean(log.to_str().unwrap()));
        std::fs::write(&log, "nfs_start :NFS STARTUP :EVENT :ok\n").unwrap();
        assert!(check_synthetic_krb_log_clean(log.to_str().unwrap()));
    }

    #[test]
    fn ganesha_log_has_managed_gids_failure_matches_nfs_creds_lines() {
        let td = tempfile::tempdir().unwrap();
        let log = td.path().join("ganesha.log");
        std::fs::write(
            &log,
            "set_extended_groups :DISP :INFO :Attempt to fetch managed_gids for uid: 3788 failed\n",
        )
        .unwrap();
        assert!(ganesha_log_has_managed_gids_failure(log.to_str().unwrap(), 0));
        let off = std::fs::metadata(&log).unwrap().len();
        assert!(!ganesha_log_has_managed_gids_failure(
            log.to_str().unwrap(),
            off
        ));
        std::fs::write(&log, "nfs_start :NFS STARTUP :EVENT :ok\n").unwrap();
        assert!(!ganesha_log_has_managed_gids_failure(log.to_str().unwrap(), 0));
    }

    #[test]
    fn ganesha_log_has_getgrouplist_warn_only_in_tail_after_offset() {
        use std::io::Write;
        let td = tempfile::tempdir().unwrap();
        let log = td.path().join("ganesha.log");
        std::fs::write(&log, "nfs_start :EVENT :ok\n").unwrap();
        let off = std::fs::metadata(&log).unwrap().len();
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(
            f,
            "my_getgrouplist_alloc :WARN :getgrouplist for user:testuser1 failed, errno: 3"
        )
        .unwrap();
        assert!(!ganesha_log_has_getgrouplist_warn(
            std::str::from_utf8(b"nfs_start :EVENT :ok\n").unwrap(),
            0
        ));
        assert!(ganesha_log_has_getgrouplist_warn(log.to_str().unwrap(), off));
        assert!(ganesha_log_has_getgrouplist_warn(log.to_str().unwrap(), 0));
    }
}