//! Request-time Ganesha identity uses getpwnam.

use std::path::Path;
use std::process::Command;

use crate::ganesha_nss_contract::{evaluate_nss_contract, GaneshaNssEnv};
use crate::ganesha_readiness::{probe_socket_grps, probe_socket_grouplist};
use crate::NfsKlldapConfig;
use nfs_klldap_identity::{parse_group_row, parse_passwd_row};

/// Principals exercised by preflight (user TGT + server host + client machine.
#[derive(Clone, Debug)]
pub struct IdentityPrincipals {
    pub user: Option<String>,
    pub server_host: String,
    pub client_host: Option<String>,
}

/// Principals that must be visible in nss_wrapper before Ganesha starts (FQDN.
pub fn warm_principals_for_startup(
    cfg: Option<&NfsKlldapConfig>,
    realm: &str,
    host_short: &str,
) -> Vec<String> {
    let nss_env = GaneshaNssEnv::from_runtime_defaults();
    let base = identity_principals_for_check(cfg, realm, host_short, &nss_env);
    let mut out = Vec::new();
    if let Some(u) = base.user {
        out.push(u);
    }
    out.push(base.server_host);
    if let Some(c) = base.client_host {
        out.push(c);
    }
    if let Some(cfg) = cfg {
        for p in &cfg.ganesha.warm_principals {
            let t = p.trim();
            if !t.is_empty() && !out.iter().any(|x| x == t) {
                out.push(t.to_string());
            }
        }
    }
    out
}

/// Returns (all_ok, failure tags) after socket warm + nss contract probes.
pub fn warm_principals_nss_ready(
    principals: &[String],
    env: &GaneshaNssEnv,
    socket_path: &str,
) -> (bool, Vec<String>) {
    let mut fails = Vec::new();
    for p in principals {
        let expect_machine = p.starts_with("host/");
        let (ok, detail) = evaluate_nss_contract(p, env, expect_machine);
        if !ok {
            fails.push(detail);
            continue;
        }
        if probe_socket_grps(p, socket_path).is_none() {
            fails.push(format!("socket-grps-miss:{p}"));
            continue;
        }
        if probe_socket_grouplist(p, socket_path).is_none() {
            fails.push(format!("socket-grouplist-miss:{p}"));
        }
    }
    (fails.is_empty(), fails)
}

/// First non-empty value among the given env keys.
fn env_first_nonempty(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| {
        std::env::var(k)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

/// Probe user principal: env override, then [probe] config, then auto-pick.
pub fn probe_user_principal(
    cfg: Option<&NfsKlldapConfig>,
    nss_env: &GaneshaNssEnv,
) -> Option<String> {
    env_first_nonempty(&[
        "NFS_KLLDAP_PROBE_USER_PRINCIPAL",
        "TEST_IDHELPER_CHECK_USER_PRINCIPAL",
    ])
    .or_else(|| {
        cfg.and_then(|c| c.probe.user_principal.clone())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })
    .or_else(|| auto_probe_user(nss_env))
}

/// Probe client host name: env override, then [probe] config, then auto-pick.
pub fn probe_client_host(
    cfg: Option<&NfsKlldapConfig>,
    nss_env: &GaneshaNssEnv,
    server_short: &str,
) -> Option<String> {
    env_first_nonempty(&[
        "NFS_KLLDAP_PROBE_CLIENT_HOST",
        "TEST_IDHELPER_CHECK_CLIENT_HOST",
        "NFS_KLLDAP_IDHELPER_CLIENT_HOST",
    ])
    .or_else(|| {
        cfg.and_then(|c| c.probe.client_host.clone())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })
    .or_else(|| auto_probe_client(nss_env, server_short))
}

/// Passwd rows (name, uid, gid) from the snapshot plus extrausers.
fn snapshot_passwd_rows(nss_env: &GaneshaNssEnv) -> Vec<(String, u32, u32)> {
    let mut rows: Vec<(String, u32, u32)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut paths = vec![nss_env.nss_passwd.clone()];
    if let Some(p) = nss_env.extrausers_passwd.clone() {
        paths.push(p);
    }
    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for row in text.lines().filter_map(parse_passwd_row) {
            if seen.insert(row.name.clone()) {
                rows.push((row.name, row.uid, row.gid));
            }
        }
    }
    rows
}

/// Distinct gid count for the names in the snapshot group files.
fn snapshot_gid_count(nss_env: &GaneshaNssEnv, names: &[&str], primary_gid: u32) -> usize {
    let mut gids = std::collections::HashSet::new();
    gids.insert(primary_gid);
    let mut paths = vec![nss_env.nss_group.clone()];
    if let Some(p) = nss_env.extrausers_group.clone() {
        paths.push(p);
    }
    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for row in text.lines().filter_map(parse_group_row) {
            if row.members.iter().any(|m| names.contains(&m.as_str())) {
                gids.insert(row.gid);
            }
        }
    }
    gids.len()
}

/// First principal-form user in the snapshot, preferring multi-group users.
fn auto_probe_user(nss_env: &GaneshaNssEnv) -> Option<String> {
    let mut candidates: Vec<(String, u32)> = snapshot_passwd_rows(nss_env)
        .into_iter()
        .filter(|(name, uid, _)| *uid > 0 && name.contains('@') && !name.starts_with("host/"))
        .map(|(name, _, gid)| (name, gid))
        .collect();
    candidates.sort();
    let rich = candidates.iter().find(|(name, gid)| {
        let short = nfs_klldap_identity::principal_local_part(name);
        snapshot_gid_count(nss_env, &[name.as_str(), short], *gid) >= 2
    });
    rich.or_else(|| candidates.first()).map(|(n, _)| n.clone())
}

/// First enrolled client machine in the snapshot besides the server itself.
fn auto_probe_client(nss_env: &GaneshaNssEnv, server_short: &str) -> Option<String> {
    let mut hosts: Vec<String> = snapshot_passwd_rows(nss_env)
        .into_iter()
        .filter_map(|(name, _, _)| {
            let rest = name.strip_prefix("host/")?;
            let host = rest.split('@').next()?.trim();
            if host.is_empty() {
                return None;
            }
            Some(host.to_string())
        })
        .filter(|h| {
            let first = h.split('.').next().unwrap_or(h);
            first != server_short && h != server_short
        })
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts.into_iter().next()
}

/// Resolved probe principals; user and client legs may be absent.
pub fn identity_principals_for_check(
    cfg: Option<&NfsKlldapConfig>,
    realm: &str,
    host_short: &str,
    nss_env: &GaneshaNssEnv,
) -> IdentityPrincipals {
    let user = probe_user_principal(cfg, nss_env).map(|u| {
        if u.contains('@') {
            u
        } else {
            format!("{u}@{realm}")
        }
    });
    let client_host = probe_client_host(cfg, nss_env, host_short).map(|c| {
        if c.contains('@') {
            c
        } else if c.contains('/') {
            format!("{c}@{realm}")
        } else {
            format!("host/{c}@{realm}")
        }
    });
    IdentityPrincipals {
        user,
        server_host: format!("host/{host_short}@{realm}"),
        client_host,
    }
}

fn run_idhelper_grps(idh: &str, principal: &str, nss_passwd: &Path, nss_group: &Path) {
    let mut cmd = Command::new(idh);
    cmd.args(["grps", principal])
        .env("NSS_PASSWD", nss_passwd)
        .env("NSS_GROUP", nss_group)
        .env("NSS_EXTRAUSERS_PASSWD", nss_passwd)
        .env("NSS_EXTRAUSERS_GROUP", nss_group);
    if std::path::Path::new("/usr/bin/timeout").exists() {
        cmd = Command::new("timeout");
        cmd.args(["8", idh, "grps", principal])
            .env("NSS_PASSWD", nss_passwd)
            .env("NSS_GROUP", nss_group)
            .env("NSS_EXTRAUSERS_PASSWD", nss_passwd)
            .env("NSS_EXTRAUSERS_GROUP", nss_group);
    }
    let _ = cmd.output();
}

/// Tempdir-isolated pipeline: idhelper grps → temp nss files → nss_wrapper co.
pub fn run_identity_pipeline(principals: &IdentityPrincipals, idh: &str) -> (bool, String) {
    let td = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => return (false, format!("identity-pipeline:fail:init:{e}")),
    };
    let nss_passwd = td.path().join("nss_passwd");
    let nss_group = td.path().join("nss_group");
    let mut targets: Vec<(&str, &str, bool)> = Vec::new();
    if let Some(u) = principals.user.as_deref() {
        targets.push(("user", u, false));
    }
    targets.push(("host-server", principals.server_host.as_str(), true));
    if let Some(c) = principals.client_host.as_deref() {
        targets.push(("host-client", c, true));
    }
    for (_, p, _) in &targets {
        run_idhelper_grps(idh, p, &nss_passwd, &nss_group);
    }
    let env = GaneshaNssEnv::from_paths(&nss_passwd, &nss_group);
    let mut ok = true;
    let mut tags = Vec::new();
    for (lab, principal, expect_machine) in &targets {
        let (cok, detail) = evaluate_nss_contract(principal, &env, *expect_machine);
        tags.push(format!("{detail}:{lab}"));
        if cok {
            tags.push(format!("identity-pipeline:ok:{lab}"));
        } else {
            ok = false;
            tags.push(format!("identity-pipeline:fail:{lab}"));
        }
    }
    (ok, tags.join(" "))
}

#[cfg(test)]
mod tests {
    use super::{identity_principals_for_check, warm_principals_for_startup};
    use crate::{GaneshaNssEnv, NfsKlldapConfig};
    use std::path::PathBuf;

    const SUPERVISOR_GANESHA_NSS_ENV_KEYS: &[(&str, &str)] = &[
        ("NSS_PASSWD", "/var/lib/nfs-klldap/nss_passwd"),
        ("NSS_GROUP", "/var/lib/nfs-klldap/nss_group"),
        ("NSS_EXTRAUSERS_PASSWD", "/var/lib/extrausers/passwd"),
        ("NSS_EXTRAUSERS_GROUP", "/var/lib/extrausers/group"),
    ];

    #[test]
    fn warm_principals_include_fqdn_user() {
        let mut cfg = NfsKlldapConfig::default();
        cfg.probe.user_principal = Some("testuser1".into());
        let principals = warm_principals_for_startup(Some(&cfg), "TESTLAB.LOCAL", "nfs-server");
        assert!(
            principals.iter().any(|p| p == "testuser1@TESTLAB.LOCAL"),
            "warm set must include FQDN user: {principals:?}"
        );
        assert!(principals.iter().any(|p| p.starts_with("host/")));
    }

    #[test]
    fn probe_legs_absent_without_config_or_snapshot() {
        let td = tempfile::tempdir().unwrap();
        let env = GaneshaNssEnv::from_paths(&td.path().join("pw"), &td.path().join("gr"));
        let p = identity_principals_for_check(None, "TESTLAB.LOCAL", "nfs-server", &env);
        assert!(p.user.is_none(), "no user leg expected: {p:?}");
        assert!(p.client_host.is_none(), "no client leg expected: {p:?}");
        assert_eq!(p.server_host, "host/nfs-server@TESTLAB.LOCAL");
    }

    #[test]
    fn auto_probe_prefers_multi_group_user_and_skips_server_host() {
        let td = tempfile::tempdir().unwrap();
        let pw = td.path().join("nss_passwd");
        let gr = td.path().join("nss_group");
        std::fs::write(
            &pw,
            "root:x:0:0:root:/root:/bin/sh\n\
             alice@TESTLAB.LOCAL:x:4001:4001:user:/nonexistent:/usr/sbin/nologin\n\
             bob@TESTLAB.LOCAL:x:4002:4002:user:/nonexistent:/usr/sbin/nologin\n\
             host/nfs-server@TESTLAB.LOCAL:x:0:0:host:/non:/nologin\n\
             host/client-a@TESTLAB.LOCAL:x:0:0:host:/non:/nologin\n",
        )
        .unwrap();
        std::fs::write(&gr, "alice:x:4001:\nbob:x:4002:\nextra:x:4100:bob\n").unwrap();
        let env = GaneshaNssEnv::from_paths(&pw, &gr);
        let p = identity_principals_for_check(None, "TESTLAB.LOCAL", "nfs-server", &env);
        assert_eq!(p.user.as_deref(), Some("bob@TESTLAB.LOCAL"));
        assert_eq!(p.client_host.as_deref(), Some("host/client-a@TESTLAB.LOCAL"));
    }

    #[test]
    fn supervisor_ganesha_nss_env_parity() {
        let g = GaneshaNssEnv::from_runtime_defaults();
        for (key, default) in SUPERVISOR_GANESHA_NSS_ENV_KEYS {
            std::env::remove_var(key);
            let g2 = GaneshaNssEnv::from_runtime_defaults();
            let expected = PathBuf::from(*default);
            let actual = match *key {
                "NSS_PASSWD" => g2.nss_passwd.clone(),
                "NSS_GROUP" => g2.nss_group.clone(),
                "NSS_EXTRAUSERS_PASSWD" => g2.extrausers_passwd.clone().unwrap(),
                "NSS_EXTRAUSERS_GROUP" => g2.extrausers_group.clone().unwrap(),
                _ => panic!("unknown key"),
            };
            assert_eq!(actual, expected, "default mismatch for {key}");
            std::env::set_var(key, "/tmp/parity-test");
            let g3 = GaneshaNssEnv::from_runtime_defaults();
            let overridden = match *key {
                "NSS_PASSWD" => g3.nss_passwd,
                "NSS_GROUP" => g3.nss_group,
                "NSS_EXTRAUSERS_PASSWD" => g3.extrausers_passwd.unwrap(),
                "NSS_EXTRAUSERS_GROUP" => g3.extrausers_group.unwrap(),
                _ => unreachable!(),
            };
            assert_eq!(overridden, PathBuf::from("/tmp/parity-test"));
            std::env::remove_var(key);
        }
        let _ = g;
    }
}
