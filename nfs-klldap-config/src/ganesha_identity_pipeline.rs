//! Request-time Ganesha identity == libnfsidmap getpwnam under NSS_WRAPPER (idmap_log_contract).

use std::path::Path;
use std::process::Command;

use crate::ganesha_nss_contract::{evaluate_nss_contract, GaneshaNssEnv};
use crate::ganesha_readiness::{probe_socket_grps, probe_socket_grouplist};
use crate::NfsKlldapConfig;

/// Principals exercised by preflight (user TGT + server host + client machine).
#[derive(Clone, Debug)]
pub struct IdentityPrincipals {
    pub user: String,
    pub server_host: String,
    pub client_host: String,
}

/// Principals that must be visible in nss_wrapper before Ganesha starts (FQDN user + host variants).
pub fn warm_principals_for_startup(
    cfg: Option<&NfsKlldapConfig>,
    realm: &str,
    host_short: &str,
) -> Vec<String> {
    let base = identity_principals_for_check(realm, host_short);
    let mut out = vec![base.user, base.server_host, base.client_host];
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

pub fn identity_principals_for_check(realm: &str, host_short: &str) -> IdentityPrincipals {
    let user_sample = std::env::var("TEST_IDHELPER_CHECK_USER_PRINCIPAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("testuser1@{realm}"));
    let client_short = std::env::var("TEST_IDHELPER_CHECK_CLIENT_HOST")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "blue-lt".to_string());
    let user = if user_sample.contains('@') {
        user_sample
    } else {
        format!("{user_sample}@{realm}")
    };
    IdentityPrincipals {
        user,
        server_host: format!("host/{host_short}@{realm}"),
        client_host: format!("host/{client_short}@{realm}"),
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

/// Tempdir-isolated pipeline: idhelper grps → temp nss files → nss_wrapper contract (Ganesha path).
pub fn run_identity_pipeline(realm: &str, host_short: &str, idh: &str) -> (bool, String) {
    let principals = identity_principals_for_check(realm, host_short);
    let td = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => return (false, format!("identity-pipeline:fail:init:{e}")),
    };
    let nss_passwd = td.path().join("nss_passwd");
    let nss_group = td.path().join("nss_group");
    for p in [
        &principals.user,
        &principals.server_host,
        &principals.client_host,
    ] {
        run_idhelper_grps(idh, p, &nss_passwd, &nss_group);
    }
    let env = GaneshaNssEnv::from_paths(&nss_passwd, &nss_group);
    let mut ok = true;
    let mut tags = Vec::new();
    for (lab, principal, expect_machine) in [
        ("user", principals.user.as_str(), false),
        ("host-server", principals.server_host.as_str(), true),
        ("host-client", principals.client_host.as_str(), true),
    ] {
        let (cok, detail) = evaluate_nss_contract(principal, &env, expect_machine);
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
    use super::warm_principals_for_startup;
    use crate::GaneshaNssEnv;
    use std::path::PathBuf;

    const SUPERVISOR_GANESHA_NSS_ENV_KEYS: &[(&str, &str)] = &[
        ("NSS_PASSWD", "/var/lib/nfs-klldap/nss_passwd"),
        ("NSS_GROUP", "/var/lib/nfs-klldap/nss_group"),
        ("NSS_EXTRAUSERS_PASSWD", "/var/lib/extrausers/passwd"),
        ("NSS_EXTRAUSERS_GROUP", "/var/lib/extrausers/group"),
    ];

    #[test]
    fn warm_principals_include_fqdn_user() {
        let principals = warm_principals_for_startup(None, "TESTLAB.LOCAL", "nfs-server");
        assert!(
            principals.iter().any(|p| p == "testuser1@TESTLAB.LOCAL"),
            "warm set must include FQDN user: {principals:?}"
        );
        assert!(principals.iter().any(|p| p.starts_with("host/")));
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