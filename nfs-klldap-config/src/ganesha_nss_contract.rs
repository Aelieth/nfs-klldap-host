//! Ganesha request-time identity contract: libnfsidmap getpwnam/getgrouplist under nss_wrapper.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{parse_getent_passwd, FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID, MACHINE_GID, MACHINE_UID};
use nfs_klldap_identity::{machine_short_name, principal_local_part};

/// NSS env Ganesha receives from supervisor `start_ganesha` (nss_wrapper LD_PRELOAD path).
#[derive(Clone, Debug)]
pub struct GaneshaNssEnv {
    pub nss_passwd: PathBuf,
    pub nss_group: PathBuf,
    pub ld_preload: Option<PathBuf>,
    pub extrausers_passwd: Option<PathBuf>,
    pub extrausers_group: Option<PathBuf>,
}

impl GaneshaNssEnv {
    /// Same defaults as `supervisor.rs:start_ganesha` env injection.
    pub fn from_runtime_defaults() -> Self {
        let env_path = |key: &str, default: &str| -> PathBuf {
            std::env::var(key)
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(default))
        };
        let use_nss = std::env::var("USE_NSS_WRAPPER")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let ld_preload = if use_nss {
            let chain = ld_preload_for_ganesha_nss();
            if chain.as_os_str().is_empty() {
                None
            } else {
                Some(chain)
            }
        } else {
            None
        };
        Self {
            nss_passwd: env_path("NSS_PASSWD", "/var/lib/nfs-klldap/nss_passwd"),
            nss_group: env_path("NSS_GROUP", "/var/lib/nfs-klldap/nss_group"),
            ld_preload,
            extrausers_passwd: Some(env_path(
                "NSS_EXTRAUSERS_PASSWD",
                "/var/lib/extrausers/passwd",
            )),
            extrausers_group: Some(env_path(
                "NSS_EXTRAUSERS_GROUP",
                "/var/lib/extrausers/group",
            )),
        }
    }

    pub fn from_paths(nss_passwd: &Path, nss_group: &Path) -> Self {
        Self {
            nss_passwd: nss_passwd.to_path_buf(),
            nss_group: nss_group.to_path_buf(),
            ld_preload: Some(ld_preload_for_ganesha_nss()),
            extrausers_passwd: None,
            extrausers_group: None,
        }
    }

    pub fn wrapper_available(&self) -> bool {
        self.ld_preload
            .as_ref()
            .is_some_and(|p| !p.as_os_str().is_empty())
            && resolve_nss_wrapper_so().is_some()
            && self.nss_passwd.is_file()
            && self.nss_group.is_file()
    }

    fn apply_to_cmd(&self, cmd: &mut Command) {
        cmd.env("NSS_WRAPPER_PASSWD", &self.nss_passwd)
            .env("NSS_WRAPPER_GROUP", &self.nss_group);
        if let Some(ref p) = self.extrausers_passwd {
            cmd.env("NSS_EXTRAUSERS_PASSWD", p);
        }
        if let Some(ref p) = self.extrausers_group {
            cmd.env("NSS_EXTRAUSERS_GROUP", p);
        }
        if let Some(so) = self.ld_preload.as_ref() {
            cmd.env("LD_PRELOAD", so);
        }
        if let Some(sss) = crate::ganesha_readiness::resolve_nss_sss_so() {
            cmd.env("NSS_WRAPPER_MODULE_SO_PATH", &sss)
                .env("NSS_WRAPPER_MODULE_FN_PREFIX", "_nss_sss_");
        }
    }
}

/// Lookup names Ganesha/libnfsidmap may pass to getpwnam (full principal, short, host segment).
pub fn nss_lookup_names(principal: &str) -> Vec<String> {
    let mut names = vec![principal.to_string()];
    let short = principal_local_part(principal);
    if short != principal {
        names.push(short.to_string());
    }
    let host_seg = machine_short_name(principal);
    if host_seg != short && host_seg != principal {
        names.push(host_seg.to_string());
    }
    names.sort();
    names.dedup();
    names
}

fn getent_passwd(name: &str, env: &GaneshaNssEnv) -> Option<(u32, u32)> {
    let mut cmd = Command::new("getent");
    cmd.args(["passwd", name]);
    env.apply_to_cmd(&mut cmd);
    let o = cmd.output().ok()?;
    if !o.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&o.stdout);
    line.lines().find_map(parse_getent_passwd)
}

/// Direct nss_passwd file lookup (fallback when LD_PRELOAD unavailable).
pub fn probe_nss_passwd_from_file(name: &str, env: &GaneshaNssEnv) -> Option<(u32, u32)> {
    let content = std::fs::read_to_string(&env.nss_passwd).ok()?;
    for candidate in nss_lookup_names(name) {
        for line in content.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let login = line.split(':').next()?;
            if login == candidate {
                return parse_getent_passwd(line);
            }
        }
    }
    None
}

/// getpwnam contract under Ganesha nss_wrapper env (live getent when wrapper present).
pub fn probe_nss_passwd(name: &str, env: &GaneshaNssEnv) -> Option<(u32, u32)> {
    if env.wrapper_available() {
        for candidate in nss_lookup_names(name) {
            if let Some(ids) = getent_passwd(&candidate, env) {
                return Some(ids);
            }
        }
    }
    probe_nss_passwd_from_file(name, env)
}

/// Strict exact probe: query *only* the literal name (no nss_lookup_names expansion).
/// Used by gate tests to prove the precise principal string Ganesha passes is present.
pub fn probe_nss_passwd_exact(name: &str, env: &GaneshaNssEnv) -> Option<(u32, u32)> {
    if env.wrapper_available() {
        let mut cmd = Command::new("getent");
        cmd.args(["passwd", name]);
        env.apply_to_cmd(&mut cmd);
        if let Ok(o) = cmd.output() {
            if o.status.success() {
                let line = String::from_utf8_lossy(&o.stdout);
                if let Some((uid, gid)) = line.lines().next().and_then(parse_getent_passwd) {
                    return Some((uid, gid));
                }
            }
        }
    }
    probe_nss_passwd_from_file_exact(name, env)
}

pub fn probe_nss_passwd_from_file_exact(name: &str, env: &GaneshaNssEnv) -> Option<(u32, u32)> {
    let content = std::fs::read_to_string(&env.nss_passwd).ok()?;
    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let login = line.split(':').next()?;
        if login == name {
            return parse_getent_passwd(line);
        }
    }
    None
}

/// getgrouplist contract (via `id -G` numeric gids under same env).
pub fn probe_nss_groups(name: &str, env: &GaneshaNssEnv) -> Vec<u32> {
    if !env.wrapper_available() {
        return vec![];
    }
    for candidate in nss_lookup_names(name) {
        if let Some(gids) = probe_nss_groups_exact(&candidate, env) {
            if !gids.is_empty() {
                return gids;
            }
        }
    }
    vec![]
}

/// Strict exact probe: query *only* the literal login (no nss_lookup_names expansion).
/// Mirrors Ganesha uid2grp.c: getpwuid_r → pw_name → getgrouplist(short_name, …).
pub fn probe_nss_groups_exact(name: &str, env: &GaneshaNssEnv) -> Option<Vec<u32>> {
    if !env.wrapper_available() {
        return None;
    }
    let mut cmd = Command::new("id");
    cmd.args(["-G", name]);
    env.apply_to_cmd(&mut cmd);
    let o = cmd.output().ok()?;
    if !o.status.success() {
        return None;
    }
    let gids: Vec<u32> = String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    if gids.is_empty() {
        None
    } else {
        Some(gids)
    }
}

/// Short passwd login Ganesha passes to getgrouplist after getpwuid_r (not the krb principal).
pub fn short_pw_name_for_principal(principal: &str) -> String {
    principal_local_part(principal).to_string()
}

/// uid2grp short-name chain: exact short passwd row + exact short getgrouplist (no principal alias expansion).
/// `min_total_gids` is the minimum number of gids `id -G <short>` must return (primary + supplementals).
pub fn evaluate_short_name_getgrouplist_contract(
    principal: &str,
    env: &GaneshaNssEnv,
    min_total_gids: usize,
) -> (bool, String) {
    let short = short_pw_name_for_principal(principal);
    let Some((uid, gid)) = probe_nss_passwd_exact(&short, env)
        .or_else(|| probe_nss_passwd_from_file_exact(&short, env))
    else {
        return (
            false,
            format!("short-getgrouplist:passwd-miss:{short}"),
        );
    };
    let gids = if env.wrapper_available() {
        probe_nss_groups_exact(&short, env).unwrap_or_default()
    } else {
        vec![gid]
    };
    if gids.is_empty() && env.wrapper_available() {
        return (
            false,
            format!("short-getgrouplist:no-groups:{short}:uid={uid}"),
        );
    }
    if uid == FALLBACK_NOBODY_UID || gid == FALLBACK_NOBODY_GID {
        return (
            false,
            format!("short-getgrouplist:fallback uid={uid} gid={gid}"),
        );
    }
    if !gids.contains(&gid) && env.wrapper_available() {
        return (
            false,
            format!("short-getgrouplist:missing-primary:{short}:gid={gid}:gids={gids:?}"),
        );
    }
    let min_want = min_total_gids.max(1);
    if gids.len() < min_want && env.wrapper_available() {
        return (
            false,
            format!(
                "short-getgrouplist:insufficient:{short}:{}gids want>={min_want} have={gids:?}",
                gids.len()
            ),
        );
    }
    (
        true,
        format!("short-getgrouplist:ok:{short}:{uid}:{gid}:{}gids:{gids:?}", gids.len()),
    )
}

/// B2/B3 gate: principal visible in nss_wrapper after idhelper materialize.
pub fn evaluate_nss_contract(
    principal: &str,
    env: &GaneshaNssEnv,
    expect_machine: bool,
) -> (bool, String) {
    if !env.nss_passwd.is_file() {
        return (false, "nss-contract:nss-passwd-missing".into());
    }
    let live = env.wrapper_available();
    let Some((uid, gid)) = probe_nss_passwd(principal, env) else {
        return (false, format!("nss-contract:passwd-miss:{principal}"));
    };
    let gids = if live {
        probe_nss_groups(principal, env)
    } else {
        vec![gid]
    };
    let prefix = if live { "nss-contract:ok" } else { "nss-contract:file-ok" };
    if expect_machine {
        if uid != MACHINE_UID || gid != MACHINE_GID {
            return (
                false,
                format!("nss-contract:machine-uid-gid uid={uid} gid={gid}"),
            );
        }
        if !gids.is_empty() && gids != [MACHINE_GID] && !gids.contains(&MACHINE_GID) {
            return (
                false,
                format!("nss-contract:machine-groups {:?}", gids),
            );
        }
        (true, prefix.into())
    } else if uid == FALLBACK_NOBODY_UID || gid == FALLBACK_NOBODY_GID {
        (
            false,
            format!("nss-contract:user-fallback uid={uid} gid={gid} gids={gids:?}"),
        )
    } else if !gids.is_empty() && gids.iter().all(|&g| g == FALLBACK_NOBODY_GID || g == 0) {
        (
            false,
            format!("nss-contract:user-fallback-gids {:?} uid={uid} gid={gid}", gids),
        )
    } else if gids.is_empty() && live {
        (false, format!("nss-contract:user-no-groups uid={uid} gid={gid}"))
    } else {
        (true, format!("{prefix}:{uid}:{gid}:{}gids", gids.len()))
    }
}

fn ld_preload_for_ganesha_nss() -> PathBuf {
    let nss = resolve_nss_wrapper_so().unwrap_or_else(PathBuf::new);
    crate::ganesha_getgrouplist::ld_preload_chain_for_ganesha(&nss)
}

fn resolve_nss_wrapper_so() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("NSS_WRAPPER_SO") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let arch = std::env::consts::ARCH;
    let candidates = [
        format!("/usr/lib/{arch}-linux-gnu/libnss_wrapper.so"),
        format!("/usr/lib/{arch}/libnss_wrapper.so"),
        "/usr/lib64/libnss_wrapper.so".into(),
        "/usr/lib/x86_64-linux-gnu/libnss_wrapper.so".into(),
        "/usr/lib/aarch64-linux-gnu/libnss_wrapper.so".into(),
        "/usr/lib/libnss_wrapper.so".into(),
    ];
    candidates
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_minimal_nss(base: &Path, login: &str, uid: u32, gid: u32) {
        fs::create_dir_all(base).unwrap();
        fs::write(
            base.join("nss_passwd"),
            format!("{login}:x:{uid}:{gid}:gecos:/nonexistent:/usr/sbin/nologin\n"),
        )
        .unwrap();
        fs::write(
            base.join("nss_group"),
            format!("root:x:0:\n{login}:x:{gid}:\n"),
        )
        .unwrap();
    }

    #[test]
    fn nss_lookup_names_covers_principal_short_and_host_segment() {
        let names = nss_lookup_names("host/blue-lt@TEST.COM");
        assert!(names.contains(&"host/blue-lt@TEST.COM".to_string()));
        assert!(names.contains(&"host/blue-lt".to_string()));
        assert!(names.contains(&"blue-lt".to_string()));
    }

    #[test]
    fn evaluate_nss_contract_machine_when_wrapper_and_files_present() {
        let td = tempfile::tempdir().unwrap();
        write_minimal_nss(td.path(), "blue-lt", 0, 0);
        let env = GaneshaNssEnv::from_paths(&td.path().join("nss_passwd"), &td.path().join("nss_group"));
        if !env.wrapper_available() {
            eprintln!("skip: libnss_wrapper.so not on host");
            return;
        }
        let (ok, msg) = evaluate_nss_contract("host/blue-lt@TEST.COM", &env, true);
        assert!(ok, "machine nss contract failed: {msg}");
        assert!(msg.starts_with("nss-contract:ok"));
    }

    #[test]
    fn evaluate_nss_contract_user_rejects_fallback_gid() {
        let td = tempfile::tempdir().unwrap();
        write_minimal_nss(td.path(), "testuser1@TEST.COM", 3788, 65534);
        let env = GaneshaNssEnv::from_paths(&td.path().join("nss_passwd"), &td.path().join("nss_group"));
        if !env.wrapper_available() {
            return;
        }
        let (ok, msg) = evaluate_nss_contract("testuser1@TEST.COM", &env, false);
        assert!(!ok, "fallback user must fail contract");
        assert!(msg.contains("fallback"), "msg={msg}");
    }

    #[test]
    fn probe_nss_groups_returns_supplemental_for_fqdn_login() {
        let td = tempfile::tempdir().unwrap();
        fs::write(
            td.path().join("nss_passwd"),
            "testuser1@EX.COM:x:3001:3005:user:/non:/nologin\n",
        )
        .unwrap();
        fs::write(
            td.path().join("nss_group"),
            "root:x:0:\ntestuser1@EX.COM:x:3005:\nstaff:x:3007:testuser1@EX.COM\n",
        )
        .unwrap();
        let env = GaneshaNssEnv::from_paths(
            &td.path().join("nss_passwd"),
            &td.path().join("nss_group"),
        );
        if !env.wrapper_available() {
            eprintln!("skip: libnss_wrapper.so not on host");
            return;
        }
        let gids = probe_nss_groups("testuser1@EX.COM", &env);
        assert!(gids.contains(&3005), "primary gid: {gids:?}");
        assert!(gids.contains(&3007), "supplemental gid from @ member field: {gids:?}");
    }

    #[test]
    fn fqdn_only_group_fixture_fails_short_name_exact_getgrouplist() {
        // Reproduces logs.txt split-brain: principal-expanded probes pass, Ganesha short pw_name fails.
        let td = tempfile::tempdir().unwrap();
        fs::write(
            td.path().join("nss_passwd"),
            "root:x:0:0:root:/root:/bin/sh\n\
             testuser1@EX.COM:x:3788:3002:user:/non:/nologin\n",
        )
        .unwrap();
        fs::write(
            td.path().join("nss_group"),
            "root:x:0:root\nstaff:x:3002:testuser1@EX.COM\naux:x:3007:testuser1@EX.COM\n",
        )
        .unwrap();
        let env = GaneshaNssEnv::from_paths(
            &td.path().join("nss_passwd"),
            &td.path().join("nss_group"),
        );
        let (fqdn_ok, _) = evaluate_nss_contract("testuser1@EX.COM", &env, false);
        if env.wrapper_available() {
            assert!(fqdn_ok, "FQDN-expanded contract should pass (masks gap at readiness)");
            let fqdn_gids = probe_nss_groups("testuser1@EX.COM", &env);
            let short_gids = probe_nss_groups_exact("testuser1", &env);
            eprintln!(
                "evidence logs.txt-gap: probe_nss_groups(FQDN)={fqdn_gids:?} probe_nss_groups_exact(short)={short_gids:?}"
            );
            let (short_ok, msg) =
                evaluate_short_name_getgrouplist_contract("testuser1@EX.COM", &env, 3);
            assert!(
                !short_ok,
                "FQDN-only member fields must fail exact short getgrouplist: {msg}"
            );
            assert_eq!(probe_nss_groups_exact("testuser1", &env), None);
        }
    }

    #[test]
    fn dual_login_fixture_passes_short_name_exact_getgrouplist() {
        // Materialize-shaped fixture: short passwd login + short group member fields (uid2grp path).
        let td = tempfile::tempdir().unwrap();
        fs::write(
            td.path().join("nss_passwd"),
            "root:x:0:0:root:/root:/bin/sh\n\
             testuser1:x:3788:3002:testuser1:/non:/nologin\n\
             testuser1@EX.COM:x:3788:3002:testuser1:/non:/nologin\n",
        )
        .unwrap();
        fs::write(
            td.path().join("nss_group"),
            "root:x:0:root,daemon,bin\n\
             staff:x:3002:testuser1,testuser1@EX.COM\n\
             writers:x:3005:testuser1,testuser1@EX.COM\n\
             aux:x:3007:testuser1,testuser1@EX.COM\n",
        )
        .unwrap();
        let env = GaneshaNssEnv::from_paths(
            &td.path().join("nss_passwd"),
            &td.path().join("nss_group"),
        );
        let (root_ok, root_msg) = evaluate_short_name_getgrouplist_contract("root@EX.COM", &env, 1);
        if env.wrapper_available() {
            assert!(root_ok, "root short getgrouplist: {root_msg}");
            assert_eq!(probe_nss_groups_exact("root", &env), Some(vec![0]));
            let gids = probe_nss_groups_exact("testuser1", &env).expect("short groups");
            eprintln!(
                "evidence uid2grp-chain: probe_nss_groups_exact(testuser1)={gids:?} (want primary 3002 + supplementals 3005,3007)"
            );
            let (user_ok, user_msg) =
                evaluate_short_name_getgrouplist_contract("testuser1@EX.COM", &env, 3);
            assert!(user_ok, "user short getgrouplist: {user_msg}");
            assert!(gids.contains(&3002), "primary gid: {gids:?}");
            assert!(gids.contains(&3007), "supplemental gid: {gids:?}");
            assert!(gids.contains(&3005), "supplemental gid 3005: {gids:?}");
        } else {
            let (file_ok, _) = evaluate_short_name_getgrouplist_contract("testuser1@EX.COM", &env, 1);
            assert!(file_ok, "file-level short passwd must exist");
        }
    }

    #[test]
    fn ganesha_ld_preload_prepends_shim_before_nss_wrapper() {
        let preload = ld_preload_for_ganesha_nss();
        let s = preload.to_string_lossy();
        if s.is_empty() {
            return;
        }
        let parts: Vec<&str> = s.split(':').filter(|p| !p.is_empty()).collect();
        if parts.len() >= 2 {
            assert!(
                parts[0].contains("getgrouplist_shim"),
                "shim must be first in LD_PRELOAD chain: {s}"
            );
            assert!(
                parts.iter().any(|p| p.contains("nss_wrapper")),
                "nss_wrapper must follow shim: {s}"
            );
        } else if parts.len() == 1 {
            assert!(
                parts[0].contains("nss_wrapper") || parts[0].contains("getgrouplist_shim"),
                "single preload entry must be shim or nss_wrapper: {s}"
            );
        }
    }
}