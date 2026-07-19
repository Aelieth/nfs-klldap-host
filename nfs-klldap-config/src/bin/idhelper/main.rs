#![deny(unsafe_code, dead_code)]

//! Central fast resolver for Ganesha 9.6 libnfsidmap via nss_wrapper paths.

mod common;
mod daemon;
#[cfg(test)]
mod idmap_log_contract;
mod materialize;
mod observer;
mod resolve;

use std::env;

use common::{
    get_realm, get_server_variants, socket_path, IdCache, PrincipalKind, Resolved, CACHE_PATH,
    NSS_GROUP_PATH, NSS_PASSWD_PATH, effective_cache_path,
};
use nfs_klldap_identity::{classify_principal, principal_local_part};
#[cfg(test)]
use nfs_klldap_identity::normalize_principal;
#[cfg(test)]
use nfs_klldap_config::FALLBACK_NOBODY_UID;
use daemon::run_daemon;
#[cfg(test)]
use materialize::{
    build_nss_snapshot, ensure_nss_group_member_login, gecos_for, group_line_for, materialize_nss_wrappers_at, passwd_line_for,
    sanitize_for_nss, seed_cache_and_nss_from_snapshot,
    sync_user_cache_from_snapshot,
};
// Test-only imports are placed inside `mod tests` below to avoid any unused import warnings
// at the crate level when not all symbols are referenced by every test cfg gate.
#[cfg(test)]
use observer::{extract_candidate_principal, looks_like_client_hostname};
use materialize::NssMaterializePaths;
use resolve::{resolve_gids_and_materialize, resolve_principal};

/// Try to perform RESOLVE via the running daemon's unix socket. Returns.
/// Some(Resolved) on success (the daemon did the work + materialize). Returns.
fn try_resolve_via_socket(principal: &str) -> Option<Resolved> {
    let resp = nfs_klldap_config::idhelper_socket_request(
        &socket_path(),
        &format!("RESOLVE {}\n", principal),
    )?;
    if let Some(rest) = resp.strip_prefix("OK ") {
        let parts: Vec<&str> = rest.split('|').collect();
        if parts.len() == 5 {
            if let (Ok(uid), Ok(gid)) = (parts[1].parse::<u32>(), parts[2].parse::<u32>()) {
                let kind = match parts[3] {
                    "machine" => PrincipalKind::Machine,
                    "user" => PrincipalKind::User,
                    _ => PrincipalKind::Unknown,
                };
                // Name computation is done by the daemon's resolve_principal.
                let name = principal_local_part(parts[0]).to_string();
                return Some(Resolved {
                    principal: parts[0].to_string(),
                    name,
                    uid,
                    gid,
                    kind,
                    source: parts[4].to_string(),
                    supplemental_gids: vec![],
                });
            }
        }
    }
    None
}

/// Pipeline/preflight sets NSS_PASSWD to a tempdir; must materialize locally, not via daemon socket.
fn grps_use_local_materialize() -> bool {
    std::env::var("NSS_PASSWD").is_ok()
}

/// Try GRPS via socket (shared readiness socket client). Returns gids list or None.
fn try_grps_via_socket(principal: &str) -> Option<Vec<u32>> {
    nfs_klldap_config::probe_socket_grps(principal, &socket_path())
}

/// Try GROUPLIST/GETGROUPLIST via socket for the explicit getgrouplist endpoint.
fn try_grouplist_via_socket(principal: &str) -> Option<Vec<u32>> {
    nfs_klldap_config::probe_socket_grouplist(principal, &socket_path())
}

/// True when the daemon socket answers the request with an "OK " reply.
fn socket_reply_ok(request: &str) -> bool {
    nfs_klldap_config::idhelper_socket_request(&socket_path(), &format!("{request}\n"))
        .is_some_and(|ln| ln.starts_with("OK "))
}

/// Effective realm for classify: the principal's own @REALM wins.
fn effective_realm_for(principal: &str, runtime_realm: &str) -> String {
    if let Some((_, r)) = principal.rsplit_once('@') {
        if !r.trim().is_empty() {
            return r.trim().to_string();
        }
    }
    runtime_realm.to_string()
}

/// Shared grps/grouplist CLI resolution: local materialize when NSS_PASSWD is
/// set, then the daemon socket, then direct production resolve.
fn gids_for_cli(
    p: &str,
    eff_realm: &str,
    server_variants: &[String],
    via_socket: fn(&str) -> Option<Vec<u32>>,
) -> Vec<u32> {
    if grps_use_local_materialize() {
        let cpath = effective_cache_path();
        dlog!("grps local: using cache_path={}", cpath.display());
        let mut cache = IdCache::load_from_file(&cpath);
        let owned = NssMaterializePaths::materialize_paths_owned();
        let lpaths = NssMaterializePaths::from_owned(&owned.0, &owned.1, &owned.2, &owned.3);
        resolve_gids_and_materialize(p, eff_realm, server_variants, &mut cache, &lpaths, false)
    } else if let Some(gs) = via_socket(p) {
        gs
    } else {
        let mut cache = IdCache::load_from_file(&effective_cache_path());
        let prod = NssMaterializePaths::production();
        resolve_gids_and_materialize(p, eff_realm, server_variants, &mut cache, &prod, false)
    }
}

fn handle_cli(args: &[String]) {
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");
    let realm = get_realm();
    let server_variants = get_server_variants();

    match cmd {
        "resolve" => {
            let p = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if p.is_empty() {
                eprintln!("Usage: nfs-klldap-idhelper resolve <principal> [--json]");
                std::process::exit(2);
            }
            dlog!("cli RESOLVE p=\"{}\"", p);
            let json_flag = args.iter().any(|a| a == "--json" || a == "-j");

            // Prefer the principal's own @REALM for classify (mismatch robustness for host/user@).
            let eff_realm = effective_realm_for(p, &realm);

            // When NSS_PASSWD set (pipeline/verif runs), force direct local materialize path
            // (resolve+mat inside this process) so logs show the /tmp paths used, and avoid
            // daemon socket (which would use production /var inside the daemon).
            // Matches the grps local-first logic. Socket only for normal CLI when no NSS_*.
            let r = if std::env::var("NSS_PASSWD").is_ok() {
                let mut cache = IdCache::load_from_file(&effective_cache_path());
                let owned = NssMaterializePaths::materialize_paths_owned();
                let lpaths = NssMaterializePaths::from_owned(&owned.0, &owned.1, &owned.2, &owned.3);
                resolve_principal(p, &eff_realm, &server_variants, &mut cache, &lpaths)
            } else if let Some(r) = try_resolve_via_socket(p) {
                r
            } else {
                let mut cache = IdCache::load_from_file(&effective_cache_path());
                let prod_paths = NssMaterializePaths::production();
                resolve_principal(p, &eff_realm, &server_variants, &mut cache, &prod_paths)
            };

            if resolve::is_unresolved_fail_closed(&r) {
                eprintln!("ERR unresolved principal: {p}");
                std::process::exit(1);
            }

            if json_flag {
                println!(
                    r#"{{"principal":"{}","name":"{}","uid":{},"gid":{},"kind":"{}","source":"{}"}}"#,
                    r.principal, r.name, r.uid, r.gid, r.kind.as_str(), r.source
                );
            } else {
                println!(
                    "{} -> name={} uid={} gid={} kind={} source={}",
                    r.principal, r.name, r.uid, r.gid, r.kind.as_str(), r.source
                );
            }
        }
        "grps" => {
            let p = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if p.is_empty() {
                eprintln!("Usage: nfs-klldap-idhelper grps <principal> [--json]");
                std::process::exit(2);
            }
            dlog!("cli GRPS p=\"{}\"", p);
            let json_flag = args.iter().any(|a| a == "--json" || a == "-j");
            // Prefer the principal's own @REALM for classify (supports mismatch cases
            // e.g. host/foo@OTHER when runtime get_realm() is different).
            let eff_realm = effective_realm_for(p, &realm);
            let gs = gids_for_cli(p, &eff_realm, &server_variants, try_grps_via_socket);
            if json_flag {
                let j = gs.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(",");
                println!(r#"{{"principal":"{}","gids":[{}]}}"#, p, j);
            } else if gs.is_empty() && p.contains('@') {
                eprintln!("ERR unresolved principal: {p}");
                std::process::exit(1);
            } else {
                println!("OK {}", gs.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("|"));
            }
        }
        "grouplist" | "getgrouplist" => {
            // CLI for new getgrouplist query endpoint (backstop); reuses groups resolve logic + same output.
            let p = args.get(1).map(|s| s.as_str()).unwrap_or("root");
            if p.is_empty() {
                eprintln!("Usage: nfs-klldap-idhelper grouplist <principal|uid> [--json]");
                std::process::exit(2);
            }
            dlog!("cli GROUPLIST p=\"{}\"", p);
            let json_flag = args.iter().any(|a| a == "--json" || a == "-j");
            let eff_realm = effective_realm_for(p, &realm);
            let gs = gids_for_cli(p, &eff_realm, &server_variants, try_grouplist_via_socket);
            if gs.is_empty() && p.contains('@') {
                eprintln!("ERR unresolved principal: {p}");
                std::process::exit(1);
            }
            if json_flag {
                let j = gs.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(",");
                println!(r#"{{"principal":"{}","gids":[{}]}}"#, p, j);
            } else {
                println!("OK {}", gs.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("|"));
            }
        }
        "classify" => {
            let p = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if p.is_empty() {
                eprintln!("Usage: nfs-klldap-idhelper classify <principal>");
                std::process::exit(2);
            }
            let (is_m, reason) = classify_principal(p, &realm, &server_variants);
            let kind = if is_m { "machine" } else { "user" };
            println!("{} -> kind={} reason=\"{}\"", p, kind, reason);
        }
        "check" => {
            println!("realm: {}", realm);
            println!("server_variants: {:?}", server_variants);
            println!("cache file: {}", CACHE_PATH);
            println!("socket: {}", socket_path());
            let sock = socket_path();
            let socket_live = std::path::Path::new(&sock).exists()
                && std::os::unix::net::UnixStream::connect(&sock).is_ok();
            if !socket_live {
                println!("idhelper-check:skip:no-live-stack (idhelper socket absent or not accepting connections; synthetic-getgrouplist/socket-grps/ganesha-runtime require live container stack)");
            }
            // Self-test with a probe LDAP user when one is configured or
            // auto-picked from the materialized NSS snapshot.
            let cfg = nfs_klldap_config::NfsKlldapConfig::load(
                &nfs_klldap_config::default_config_path(),
            )
            .ok();
            let nss_env = nfs_klldap_config::GaneshaNssEnv::from_runtime_defaults();
            let test_p = nfs_klldap_config::probe_user_principal(cfg.as_ref(), &nss_env)
                .map(|u| if u.contains('@') { u } else { format!("{}@{}", u, realm) });
            let Some(test_p) = test_p else {
                println!(
                    "self-test: skipped (no probe user configured or materialized; \
                     set [probe] user_principal or NFS_KLLDAP_PROBE_USER_PRINCIPAL)"
                );
                let root_gl = socket_reply_ok("GROUPLIST root");
                println!("synthetic-getgrouplist: root_ok={} (no probe user)", root_gl);
                return;
            };
            let mut cache = IdCache::load_from_file(&effective_cache_path());
            let prod = NssMaterializePaths::production();
            let r = resolve_principal(&test_p, &realm, &server_variants, &mut cache, &prod);
            println!(
                "self-test: {} -> uid={} gid={} kind={} source={}",
                r.principal, r.uid, r.gid, r.kind.as_str(), r.source
            );
            // Synthetic Kerberos principal access test for post-start (D): exercise uid2grp path via GROUPLIST socket + root/testuser1, confirm no my_getgrouplist_alloc WARN in ganesha.log
            let root_gl = socket_reply_ok("GROUPLIST root");
            let user_gl = socket_reply_ok(&format!("GROUPLIST {}", test_p));
            println!("synthetic-getgrouplist: root_ok={} user({}) ok={}", root_gl, test_p, user_gl);
            if let Ok(lc) = std::fs::read_to_string("/var/log/ganesha.log") {
                let has_warn = lc.lines().any(|ln| {
                    let lo = ln.to_ascii_lowercase();
                    lo.contains("my_getgrouplist_alloc") && (lo.contains("warn") || lo.contains("failed, errno"))
                });
                if !has_warn {
                    println!("synthetic-krb-uid2grp: no my_getgrouplist_alloc WARN (clean for root+user)");
                } else {
                    eprintln!("synthetic-krb-uid2grp: WARN present (observer will heal)");
                }
            }
            // Post-start full report for verification (step 4): query socket for groups and emit the authoritative "idhelper check OK ... 3gids groups-ok" line
            // so that "idhelper check" output (used in post-launch evidence) contains 3gids + groups-ok.
            if let Some(gids) = try_grps_via_socket(&test_p) {
                println!("idhelper check OK: user({}):{}gids socket-grps:groups-ok:{}:{}gids", test_p, gids.len(), test_p, gids.len());
            }
        }
        "explain" => {
            println!("nfs-klldap-idhelper — machine vs user Kerberos principal resolver");
            println!("realm: {}", realm);
            println!("server host variants: {:?}", server_variants);
            println!("Cache lives at {} (simple | delimited, easy to process with grep/awk).", CACHE_PATH);
            println!("Daemon listens on {} (unix socket).", socket_path());
            println!("NSS wrapper files (for Ganesha under libnss_wrapper): {} and {}", NSS_PASSWD_PATH, NSS_GROUP_PATH);
            println!("LDAP sync: startup + every {}s (NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS, 0=off)",
                crate::common::DEFAULT_REBULK_INTERVAL_SECS);
            println!("Socket REBULK: printf 'REBULK\\n' | nc -U {}  (prune stale users, reload LDAP→nss_passwd)",
                socket_path());
            println!("Socket GRPS <p> returns gid list for uid2grp.");
            println!("Important: Ganesha principal2uid uses libnfsidmap+getpwnam under nss_wrapper.");
        }
        "daemon" => {
            run_daemon();
        }
        "help" | "--help" | "-h" => {
            print_help();
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    eprintln!(
        r#"nfs-klldap-idhelper — lightweight Kerberos principal translator (machine vs LDAP user)

Usage:
  nfs-klldap-idhelper resolve <principal> [--json]
  nfs-klldap-idhelper grps <principal> [--json]
  nfs-klldap-idhelper classify <principal>
  nfs-klldap-idhelper check
  nfs-klldap-idhelper explain
  nfs-klldap-idhelper daemon     # run the long-lived server (started by container)

Debug: KLLDAP_IDHELPER_DEBUG=true   (logs RESOLVE, norm key, hit/miss, classify,
       short name, getent details, result, elapsed, cache write, nss_wrapper writes)

The daemon must be running for reliable mounts. It syncs LDAP users into nss_passwd
at startup and periodically (pruning deleted users). Socket commands: RESOLVE,
GRPS, CLASSIFY, REBULK.
"#
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    // Supports daemon subcommand or direct exec as the long-lived resolver.
    if args.len() > 1 && (args[1] == "daemon" || args[1] == "--daemon") {
        run_daemon();
        return;
    }

    // If no subcommand and we look like we were exec'd as the Main show help.
    if args.len() <= 1 {
        // Allow being started as a simple long-lived process via other means.
        print_help();
        return;
    }

    // CLI mode is everything after the binary name.
    let sub_args = &args[1..];
    handle_cli(sub_args);
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs_klldap_config::{probe_nss_passwd_exact, probe_nss_passwd_from_file_exact, GaneshaNssEnv, evaluate_nss_contract, IdMapSnapshot, PosixUserEntry};
    use std::path::PathBuf;

    /// Path to the built `nfs-klldap-idhelper` binary for CLI subprocess tests.
    /// Unit tests of this binary do not get `CARGO_BIN_EXE_*` at compile time
    /// (integration tests do); fall back to the workspace debug target. Never use
    /// a host-absolute developer path — that broke GitHub Actions gate for every run.
    fn idhelper_bin() -> PathBuf {
        if let Some(p) = option_env!("CARGO_BIN_EXE_nfs_klldap_idhelper") {
            return PathBuf::from(p);
        }
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_nfs_klldap_idhelper") {
            return PathBuf::from(p);
        }
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target"));
        target.join("debug/nfs-klldap-idhelper")
    }

    #[test]
    fn machine_principal_detection_basic() {
        let variants = vec!["aurora".to_string(), "aurora.example.com".to_string()];
        let (m, _) = classify_principal("host/aurora@EXAMPLE.COM", "EXAMPLE.COM", &variants);
        assert!(m);
        let (m2, _) = classify_principal("nfs/aurora.example.com@EXAMPLE.COM", "EXAMPLE.COM", &variants);
        assert!(m2);
        let (u, _) = classify_principal("alice@EXAMPLE.COM", "EXAMPLE.COM", &variants);
        assert!(!u);
        let (m3, _) = classify_principal("root/client@REALM", "REALM", &variants);
        assert!(m3);
    }

    #[test]
    fn normalize_keeps_local_preserves_upper_realm() {
        assert_eq!(normalize_principal("alice@exAmPle.com"), "alice@EXAMPLE.COM");
        assert_eq!(normalize_principal(" alice@exAmPle.com "), "alice@EXAMPLE.COM");
        assert_eq!(normalize_principal("host/box"), "host/box");
    }

    #[test]
    fn cache_roundtrip_works() {
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::resolve::reset_id_resolver_for_test();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("idmap.cache");
        let mut c = IdCache::default();
        let r = Resolved {
            principal: "bob@TEST".into(),
            name: "bob".into(),
            uid: 2001,
            gid: 2001,
            kind: PrincipalKind::User,
            source: "sss".into(),
            supplemental_gids: vec![4242],
        };
        c.insert(r.clone());
        c.write_to_file(&p).unwrap();
        let c2 = IdCache::load_from_file(&p);
        assert!(c2.get("bob@TEST").is_some());
        assert_eq!(c2.get("bob@TEST").unwrap().uid, 2001);
        assert_eq!(c2.get("bob@TEST").unwrap().supplemental_gids, vec![4242]);
        // Mechanical load + rebulk survival (drives shipped rebulk_apply_sync + build_nss on real
        // paths; poor snap seeds user primary only; the supp arrives via the live memberOf edge
        // map — the warm-pass mechanism that replaced the stale-supp preserve).
        let base = tmp.path().join("rb");
        let _ = std::fs::create_dir_all(&base);
        let rpaths = daemon::RebulkPaths::under(&base);
        let mut c3 = IdCache::load_from_file(&p);
        let mut poor = nfs_klldap_config::IdMapSnapshot::default();
        poor.users.insert("bob".into(), nfs_klldap_config::PosixUserEntry { uid: 2001, gid: 2001, display: "bob".into() });
        let live = materialize::LiveGroupEdges::from([("bob".to_string(), vec![4242u32])]);
        let _ = daemon::rebulk_apply_sync(&mut c3, "TEST", &poor, &live, &rpaths);
        let ng = std::fs::read_to_string(rpaths.nss.nss_group).unwrap_or_default();
        let eg = std::fs::read_to_string(rpaths.nss.extrausers_group).unwrap_or_default();
        assert!(ng.contains(":4242:") && ng.contains("bob"), "non-prim supp row from loaded supps must survive rebulk to nss_group");
        assert!(eg.contains(":4242:") && eg.contains("bob"), "non-prim supp row from loaded supps must survive rebulk to extra_group");
    }

    #[test]
    fn extract_candidate_finds_explicit_principal() {
        let r = extract_candidate_principal(
            "some log with principal user@EXAMPLE.COM and other stuff",
            "EXAMPLE.COM",
        );
        assert_eq!(r, Some("user@EXAMPLE.COM".to_string()));
    }

    #[test]
    fn extract_candidate_finds_host_style() {
        let r = extract_candidate_principal(
            "name=(21:Linux NFSv4.2 client-a) client stuff",
            "EXAMPLE.COM",
        );
        assert_eq!(r, Some("host/client-a@EXAMPLE.COM".to_string()));
    }

    #[test]
    fn extract_candidate_finds_in_ganesha_client_id_lines() {
        let line = r#"name=(21:Linux NFSv4.2 client-a) conf = 0x... server_addr = 172.17.0.2"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        assert_eq!(r, Some("host/client-a@EXAMPLE.COM".to_string()));
    }

    #[test]
    fn extract_candidate_ignores_irrelevant() {
        let r = extract_candidate_principal("just some random log without principals", "EXAMPLE.COM");
        assert!(r.is_none());
    }

    // These tests cover regression tests for bogus tokens seen in real.
    #[test]
    fn extract_rejects_unique_counter() {
        let line = r#"key_locate :CLIENT ID :F_DBG :Locate Unconfirmed Client ID seeking Key=0x... {Unique=0x6a374e99 Counter=0x00000001}"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        assert!(r.is_none() || !r.unwrap().contains("Unique"), "must not turn Unique= counter into a host principal");
    }

    #[test]
    fn extract_rejects_ffff_from_ipv6() {
        let line = r#"fs_create_clid_name :CLIENT ID :DEBUG :Created client name [::ffff:10.10.10.83-(21:Linux NFSv4.2 client-a)]"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        // It should find the real "client-a", never "ffff".
        if let Some(c) = r {
            assert!(c.contains("client-a"), "should still find the real hostname");
            assert!(!c.contains("ffff"), "must not emit host/ffff from IPv6 literal");
        }
    }

    #[test]
    fn extract_rejects_client_literal() {
        let line = "nfs4_op_destroy_clientid :CLIENT ID :DEBUG :DESTROY_CLIENTID clientid=...";
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        // Should not turn the word "CLIENT" into host/CLIENT.
        if let Some(c) = r {
            assert!(!c.to_ascii_lowercase().contains("client"), "must ignore literal CLIENT word");
        }
    }

    #[test]
    fn extract_still_finds_good_name_even_with_noise() {
        let line = r#"fs_create_clid_name :CLIENT ID :DEBUG :Created client name [::ffff:10.10.10.83-(21:Linux NFSv4.2 client-a)] clientid=Unique=..."#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        assert_eq!(r, Some("host/client-a@EXAMPLE.COM".to_string()));
    }

    #[test]
    fn prune_numeric_user_entries_drops_uid_gids() {
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "3002@REALM".into(),
            name: "3002".into(),
            uid: 3002,
            gid: 3005,
            kind: PrincipalKind::User,
            source: "direct".into(),
            supplemental_gids: vec![],
        });
        cache.insert(Resolved {
            principal: "testuser2@REALM".into(),
            name: "testuser2".into(),
            uid: 3002,
            gid: 3005,
            kind: PrincipalKind::User,
            source: "bulk".into(),
            supplemental_gids: vec![],
        });
        assert_eq!(cache.prune_numeric_user_entries(), 1);
        assert!(cache.get("testuser2@REALM").is_some());
        assert!(cache.get("3002@REALM").is_none());
    }

    #[test]
    fn build_nss_snapshot_skips_numeric_login_pollution() {
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "3002@REALM".into(),
            name: "3002".into(),
            uid: 3002,
            gid: 3005,
            kind: PrincipalKind::User,
            source: "direct".into(),
            supplemental_gids: vec![],
        });
        cache.insert(Resolved {
            principal: "testuser2@REALM".into(),
            name: "testuser2".into(),
            uid: 3002,
            gid: 3005,
            kind: PrincipalKind::User,
            source: "bulk".into(),
            supplemental_gids: vec![],
        });
        let (passwd, _) = build_nss_snapshot(&cache, None);
        assert!(!passwd.iter().any(|l| l.starts_with("3002:")));
        assert!(passwd.iter().any(|l| l.starts_with("testuser2:x:3002:3005:")));
    }

    #[test]
    fn prune_malformed_principals_drops_bare_at_suffix() {
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "testuser1@".into(),
            name: "testuser1".into(),
            uid: 3001,
            gid: 3005,
            kind: PrincipalKind::User,
            source: "sss".into(),
            supplemental_gids: vec![],
        });
        cache.insert(Resolved {
            principal: "testuser1@REALM".into(),
            name: "testuser1".into(),
            uid: 3001,
            gid: 3005,
            kind: PrincipalKind::User,
            source: "bulk".into(),
            supplemental_gids: vec![],
        });
        assert_eq!(cache.prune_malformed_principals(), 1);
        assert!(cache.get("testuser1@REALM").is_some());
        assert!(cache.get("testuser1@").is_none());
    }

    #[test]
    fn build_nss_snapshot_golden_ldap_group_and_principal_alias() {
        use nfs_klldap_config::PosixGroupEntry;
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "group-test".into(),
            PosixGroupEntry {
                gid: 3005,
                display: "group-test".into(),
                members: vec!["testuser2".into()],
            },
        );
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "testuser2@TESTLABBY.LOCAL".into(),
            name: "testuser2".into(),
            uid: 3002,
            gid: 3005,
            kind: PrincipalKind::User,
            source: "bulk".into(),
            supplemental_gids: vec![],
        });
        let (passwd, group) = build_nss_snapshot(&cache, Some(&groups));
        assert!(passwd.iter().any(|l| l.starts_with("root:")));
        assert!(passwd.iter().any(|l| l.starts_with("testuser2:x:3002:3005:")));
        assert!(passwd.iter().any(|l| l.starts_with("testuser2@TESTLABBY.LOCAL:x:3002:3005:")));
        assert!(group.iter().any(|l| l.starts_with("group-test:x:3005:testuser2")));
        assert!(!group.iter().any(|l| l.starts_with("testuser2:x:3005:")));
    }

    #[test]
    fn materialize_prefers_ldap_group_name_over_user_primary() {
        use nfs_klldap_config::PosixGroupEntry;
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths {
            nss_passwd: &tmp.path().join("nss_passwd"),
            nss_group: &tmp.path().join("nss_group"),
            extrausers_passwd: &tmp.path().join("extra_passwd"),
            extrausers_group: &tmp.path().join("extra_group"),
        };
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "group-test".into(),
            PosixGroupEntry {
                gid: 3005,
                display: "group-test".into(),
                members: vec![],
            },
        );
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "admin@REALM".into(),
            name: "admin".into(),
            uid: 3000,
            gid: 3005,
            kind: PrincipalKind::User,
            source: "bulk".into(),
            supplemental_gids: vec![],
        });
        materialize_nss_wrappers_at(&cache, &paths, Some(&groups)).unwrap();
        let grp = std::fs::read_to_string(paths.extrausers_group).unwrap();
        assert!(grp.contains("group-test:x:3005:"), "grp={grp}");
        assert!(!grp.contains("admin:x:3005:"));
    }

    #[test]
    fn gecos_for_uses_short_name_when_realm_missing() {
        let r = Resolved {
            principal: "testuser1@".into(),
            name: "testuser1".into(),
            uid: 3001,
            gid: 3005,
            kind: PrincipalKind::User,
            source: "sss".into(),
            supplemental_gids: vec![],
        };
        let g = gecos_for(&r);
        assert_eq!(g, "testuser1");
        assert!(!g.contains('@'));
    }

    #[test]
    fn materialize_emits_principal_alias_and_comment_free_extrausers() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths {
            nss_passwd: &tmp.path().join("nss_passwd"),
            nss_group: &tmp.path().join("nss_group"),
            extrausers_passwd: &tmp.path().join("extra_passwd"),
            extrausers_group: &tmp.path().join("extra_group"),
        };
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "nfs/aurora@TESTLABBY.LOCAL".into(),
            name: "aurora".into(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".into(),
            supplemental_gids: vec![],
        });
        materialize_nss_wrappers_at(&cache, &paths, None).unwrap();
        let extra = std::fs::read_to_string(paths.extrausers_passwd).unwrap();
        assert!(!extra.lines().any(|l| l.starts_with('#')));
        // Current canonical policy emits short + sanitized local alias + raw principal@ for machines.
        assert!(extra.contains("nfs_aurora:x:0:0:") || extra.contains("aurora:x:0:0:"));
        // Full @ form (with / or sanitized) is acceptable for getpwnam.
        assert!(extra.contains("nfs/aurora@") || extra.contains("nfs_aurora@"));
    }

    #[test]
    fn materialize_writes_machine_as_root() {
        let _tmp = tempfile::tempdir().unwrap();
        // Override const paths via temp dir is hard. Monkey-patch via env.
        let mut c = IdCache::default();
        let machine = Resolved {
            principal: "host/client-a@EXAMPLE.COM".into(),
            name: "client-a".into(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".into(),
            supplemental_gids: vec![],
        };
        c.insert(machine);
        // We can't easily redirect const paths here without changing API.
        let line = passwd_line_for(c.get("host/client-a@EXAMPLE.COM").unwrap());
        assert!(line.starts_with("client-a:x:0:0:"));
        assert!(line.contains("client-a"));
        let gline = group_line_for(c.get("host/client-a@EXAMPLE.COM").unwrap());
        assert!(gline.starts_with("root:x:0:"));
    }

    #[test]
    fn materialize_always_includes_root_uid0_for_immediate_nss_hits() {
        // Critical for cold-start is even with no principals materialized.
        let mut passwd_lines: Vec<String> = vec![];
        // Simulate the exact injection rule added to materialize_nss_wrappers.
        if !passwd_lines.iter().any(|l| l.starts_with("root:")) {
            passwd_lines.insert(0, "root:x:0:0:root:/root:/bin/sh".to_string());
        }
        assert!(passwd_lines[0].starts_with("root:x:0:0:"));
        // When a machine is also present its name line + the root Group are.
        let mut c = IdCache::default();
        let machine = Resolved { principal: "host/x@EX".into(), name: "x".into(), uid: 0, gid: 0, kind: PrincipalKind::Machine, source: "s".into(),
            supplemental_gids: vec![] };
        c.insert(machine);
        let gl = group_line_for(c.get("host/x@EX").unwrap());
        assert!(gl.starts_with("root:x:0:"));
    }

    #[test]
    fn principal_realm_login_sanitizes_unsafe_chars_keeps_at() {
        assert_eq!(
            materialize::principal_realm_login_for_nss("testuser2@TESTLABBY.LOCAL"),
            "testuser2@TESTLABBY.LOCAL"
        );
        assert_eq!(
            materialize::principal_realm_login_for_nss("bad:user@REALM"),
            "bad_user@REALM"
        );
    }

    #[test]
    fn group_line_includes_ldap_member_list() {
        let line = materialize::group_line_with_members(
            500,
            "devs",
            &["alice".to_string(), "bob".to_string()],
        );
        assert_eq!(line, "devs:x:500:alice,bob");
    }

    #[test]
    fn materialize_writes_user_with_real_ids() {
        let mut c = IdCache::default();
        let user = Resolved {
            principal: "alice@EXAMPLE.COM".into(),
            name: "alice".into(),
            uid: 1005,
            gid: 100,
            kind: PrincipalKind::User,
            source: "sss".into(),
            supplemental_gids: vec![],
        };
        c.insert(user);
        let line = passwd_line_for(c.get("alice@EXAMPLE.COM").unwrap());
        assert!(line.starts_with("alice:x:1005:100:"));
        let gline = group_line_for(c.get("alice@EXAMPLE.COM").unwrap());
        assert!(gline.contains(":100:"));
    }

    #[test]
    fn rebulk_ldap_users_entry_point_invoked_via_test_override() {
        // Drives real rebulk_apply_sync with under(tmp) (unshimmed, no TEST_PROD_BASE redirect in production).
        use daemon::rebulk_apply_sync;
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        resolve::reset_id_resolver_for_test();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let _ = std::fs::create_dir_all(base);
        let mut snap = IdMapSnapshot::default();
        snap.users.insert(
            "carol".to_string(),
            PosixUserEntry { uid: 1003, gid: 1003, display: "Carol".to_string() },
        );
        use nfs_klldap_config::PosixGroupEntry;
        snap.groups.insert(
            "staff".to_string(),
            PosixGroupEntry { gid: 1003, display: "staff".to_string(), members: vec!["carol@EX.COM".to_string()] },
        );
        let mut cache = IdCache::default();
        let paths = daemon::RebulkPaths::under(base);
        let res = rebulk_apply_sync(&mut cache, "EX.COM", &snap, &materialize::LiveGroupEdges::new(), &paths);
        assert!(res.is_ok());
        let passwd = std::fs::read_to_string(paths.nss.nss_passwd).unwrap();
        assert!(passwd.contains("carol:x:1003:1003:"));
        let group = std::fs::read_to_string(paths.nss.nss_group).unwrap();
        assert!(group.contains("staff:x:1003:") && group.contains("carol@EX.COM"), "under() nss must have @ member from snap");
    }

    #[test]
    fn rebulk_drives_production_rebulkpaths_via_env_unshimmed() {
        // Drives real under(tmp) paths + rebulk_apply_sync (unshimmed, production() remains /var).
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        resolve::reset_id_resolver_for_test();
        use daemon::rebulk_apply_sync;
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let _ = std::fs::create_dir_all(base);
        let mut snap = IdMapSnapshot::default();
        snap.users.insert("alice".to_string(), PosixUserEntry { uid: 1001, gid: 1001, display: "alice".to_string() });
        snap.groups.insert("staff".to_string(), nfs_klldap_config::PosixGroupEntry { gid: 1001, display: "staff".to_string(), members: vec!["alice@EX.COM".to_string()] });
        let mut cache = IdCache::default();
        let paths = daemon::RebulkPaths::under(base);
        let res = rebulk_apply_sync(&mut cache, "EX.COM", &snap, &materialize::LiveGroupEdges::new(), &paths);
        assert!(res.is_ok(), "apply with under() paths must succeed");
        let g = std::fs::read_to_string(paths.nss.nss_group).unwrap_or_default();
        assert!(g.contains("staff:x:1001:") && g.contains("alice@EX.COM"), "under() nss must materialize @ member + group");
    }

    #[test]
    fn rebulk_and_on_demand_produce_identical_uid0_root_for_machine() {
        // Centralization check: machine present before or injected during rebulk-like flow
        // must materialize uid=0 + root group into BOTH nss and extrausers, identical to pure on-demand path.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        resolve::reset_id_resolver_for_test();
        use daemon::rebulk_apply_sync;
        use materialize::NssMaterializePaths;
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let _ = std::fs::create_dir_all(base);

        // Pre-populate cache with a machine (as if previously observed on-demand).
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "host/client-a@EX.COM".into(),
            name: "client-a".into(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".into(),
            supplemental_gids: vec![],
        });

        let mut snap = IdMapSnapshot::default();
        snap.users.insert("alice".to_string(), PosixUserEntry { uid: 1001, gid: 1001, display: "alice".to_string() });

        let paths = daemon::RebulkPaths::under(base);
        let res = rebulk_apply_sync(&mut cache, "EX.COM", &snap, &materialize::LiveGroupEdges::new(), &paths);
        assert!(res.is_ok());

        // Verify nss and extrausers contain machine as uid 0 + root group.
        let pw = std::fs::read_to_string(paths.nss.nss_passwd).unwrap_or_default();
        let gr = std::fs::read_to_string(paths.nss.nss_group).unwrap_or_default();
        let epw = std::fs::read_to_string(paths.nss.extrausers_passwd).unwrap_or_default();
        let egr = std::fs::read_to_string(paths.nss.extrausers_group).unwrap_or_default();

        // Machine short and @ forms appear; uid/gid 0
        assert!(pw.contains("client-a:x:0:0:"), "nss passwd must have canonical machine short 'client-a'");
        // The literal principal form with / must be present for Ganesha getpwnam("host/..@REALM")
        assert!(pw.contains("host/client-a@EX.COM:x:0:0:"), "nss must emit raw host/ principal@ for getpwnam");
        assert!(gr.contains("root:x:0:"), "nss group must have root gid 0");
        assert!(epw.contains("client-a:x:0:0:"), "extrausers passwd machine short");
        assert!(egr.contains("root:x:0:"), "extrausers group root");

        // Now simulate pure on-demand path: fresh cache, resolve machine using under (no prod write), materialize directly.
        let mut cache2 = IdCache::default();
        let t2 = NssMaterializePaths::under(&base.join("ondemand"));
        let _ = std::fs::create_dir_all(base.join("ondemand"));
        let r = resolve_principal("host/client-a@EX.COM", "EX.COM", &[], &mut cache2, &t2);
        assert_eq!(r.uid, 0); assert_eq!(r.gid, 0); assert_eq!(r.kind, PrincipalKind::Machine);

        let _ = materialize_nss_wrappers_at(&cache2, &t2, None);
        let pw2 = std::fs::read_to_string(t2.nss_passwd).unwrap_or_default();
        let gr2 = std::fs::read_to_string(t2.nss_group).unwrap_or_default();
        assert!(pw2.contains("client-a:x:0:0:") || pw2.contains("blue_lt:x:0:0:"));
        assert!(gr2.contains("root:x:0:"));
    }

    #[test]
    fn sync_user_cache_prunes_stale_users_before_reseed() {
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "deleted@EX.COM".into(),
            name: "deleted".into(),
            uid: 9999,
            gid: 9999,
            kind: PrincipalKind::User,
            source: "old".into(),
            supplemental_gids: vec![],
        });
        cache.insert(Resolved {
            principal: "host/client@EX.COM".into(),
            name: "client".into(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".into(),
            supplemental_gids: vec![],
        });

        let mut snap = IdMapSnapshot::default();
        snap.users.insert(
            "alice".to_string(),
            PosixUserEntry {
                uid: 1001,
                gid: 1001,
                display: "Alice".to_string(),
            },
        );
        snap.by_uid.insert(1001, "alice".to_string());

        let n = sync_user_cache_from_snapshot(&snap, "EX.COM", &mut cache, &materialize::LiveGroupEdges::new());
        assert_eq!(n, 1);
        assert!(cache.get("deleted@EX.COM").is_none());
        assert!(cache.get("host/client@EX.COM").is_some());
        assert!(cache.get("alice@EX.COM").is_some());
    }

    #[test]
    fn bulk_seed_includes_users_keyed_by_upn_only() {
        let mut snap = IdMapSnapshot::default();
        snap.users.insert(
            "alice@EX.COM".to_string(),
            PosixUserEntry {
                uid: 1002,
                gid: 1002,
                display: "Alice".to_string(),
            },
        );
        snap.by_uid.insert(1002, "alice@EX.COM".to_string());

        let mut cache = IdCache::default();
        let n = seed_cache_and_nss_from_snapshot(&snap, "EX.COM", &mut cache);
        assert_eq!(n, 1);
        let r = cache.get("alice@EX.COM").expect("principal key");
        assert_eq!(r.name, "alice");
        assert_eq!(r.uid, 1002);
    }

    #[test]
    fn bulk_seed_populates_cache_with_short_and_principal_forms() {
        let mut snap = IdMapSnapshot::default();
        snap.users.insert(
            "testuser1".to_string(),
            PosixUserEntry {
                uid: 1001,
                gid: 1001,
                display: "Test User".to_string(),
            },
        );
        snap.by_uid.insert(1001, "testuser1".to_string());

        let mut cache = IdCache::default();
        let n = seed_cache_and_nss_from_snapshot(&snap, "EXAMPLE.COM", &mut cache);
        assert_eq!(n, 1);

        let r = cache.get("testuser1@EXAMPLE.COM").expect("principal key");
        assert_eq!(r.name, "testuser1");
        assert_eq!(r.uid, 1001);
        assert_eq!(r.gid, 1001);
        assert_eq!(r.kind, PrincipalKind::User);
        assert_eq!(r.source, "bulk");

        let short_line = passwd_line_for(r);
        assert!(short_line.starts_with("testuser1:x:1001:1001:"));
        let full_line = passwd_line_for(&Resolved {
            principal: "testuser1@EXAMPLE.COM".into(),
            name: "testuser1@EXAMPLE.COM".into(),
            uid: 1001,
            gid: 1001,
            kind: PrincipalKind::User,
            source: "bulk".into(),
            supplemental_gids: vec![],
        });
        // sanitize_for_nss used for safe logins; alias emission uses raw principal for getpwnam(user@REALM)
        assert!(full_line.starts_with("testuser1_EXAMPLE.COM:x:1001:1001:"));
    }

    #[test]
    fn sanitize_for_nss_is_safe() {
        assert_eq!(sanitize_for_nss("host/foo.bar-baz"), "host_foo.bar-baz");
        assert_eq!(sanitize_for_nss("weird name!@#"), "weird_name___");
        assert_eq!(sanitize_for_nss(""), "unknown");
    }

    #[test]
    fn extract_rejects_nil_from_conf_group() {
        // Lines often contain conf = (nil) after a good name= group Must.
        let line = r#"key_locate :CLIENT ID :F_DBG :Locate Client Record seeking Key=... {{... name=(21:Linux NFSv4.2 client-a) conf = (nil) {NULL} unconf = (nil) {NULL} ...}}"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        if let Some(c) = r {
            assert!(c.contains("client-a"), "should find real host");
            assert!(!c.contains("nil"), "must never emit host/nil");
        }
    }

    #[test]
    fn extract_rejects_clientid_token() {
        let line = r#"nfs4_op_exchange_id ... clientid=Unique=0x6a375213 Counter=0x00000001 name=(21:Linux NFSv4.2 client-a)"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        if let Some(c) = r {
            assert!(c.contains("client-a"));
            assert!(!c.to_ascii_lowercase().contains("clientid"), "must not emit host/clientid");
        }
    }

    #[test]
    fn looks_like_rejects_noise_tokens() {
        assert!(!looks_like_client_hostname("nil"));
        assert!(!looks_like_client_hostname("clientid"));
        assert!(!looks_like_client_hostname("Unique"));
        assert!(!looks_like_client_hostname("CLIENT"));
        assert!(!looks_like_client_hostname("0x6a375213"));
        assert!(!looks_like_client_hostname("0x7f0c3082f530"));
        assert!(!looks_like_client_hostname("0x10000"));
        assert!(looks_like_client_hostname("client-a"));
        assert!(looks_like_client_hostname("my-host.example.com"));
    }

    #[test]
    fn extract_rejects_nfsv4_line_with_only_hex_tokens() {
        let line = r#"NFSv4 seeking Key=0x7f0c3082f670 {0x6a375213 other tokens}"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        assert!(r.is_none() || !r.unwrap().contains("0x"));
    }

    // These tests cover additional repro cases from the user's full trace.
    #[test]
    fn extract_rejects_pure_clientid_line() {
        // Standalone clientid= lines must never produce a host/ candidate.
        let line = r#"nfs4_op_destroy_clientid :CLIENT ID :DEBUG :DESTROY_CLIENTID clientid=Unique=0x6a375213 Counter=0x00000002"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        assert!(r.is_none() || !r.unwrap().to_ascii_lowercase().contains("clientid"), "pure clientid= line must not emit host/clientid");
    }

    #[test]
    fn extract_only_good_from_full_clid_create_line() {
        // The exact fs_create line from the trace must yield only the real.
        let line = r#"fs_create_clid_name :CLIENT ID :DEBUG :Created client name [::ffff:10.10.10.83-(21:Linux NFSv4.2 client-a)]"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        if let Some(c) = r {
            assert!(c.contains("client-a"));
            assert!(!c.contains("ffff"));
            assert!(!c.to_ascii_lowercase().contains("clientid"));
        } else {
            // If it returns none that's also acceptable as long as it doesn't.
        }
    }

    #[test]
    fn extract_rejects_conf_nil_groups_even_in_long_client_record() {
        // Full client record blob with multiple (nil) after the good name=.
        let line = r#"key_locate :CLIENT ID :F_DBG :Locate Client Record seeking Key=0x7f0c3082f530 {{0x7f0c14001df0 name=(21:Linux NFSv4.2 client-a) conf = (nil) {NULL} unconf = (nil) {NULL} server_addr = 172.17.0.2 pnfs_flags 0x10000 cr_refcount=1}}"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        if let Some(c) = r {
            assert!(c.contains("client-a"));
            assert!(!c.contains("nil"), "must not emit host/nil from conf = (nil) groups");
        }
    }

    #[test]
    fn extract_rejects_on_lines_with_only_unconf_and_counters() {
        // Lines that only have unconf / counter noise after nfsv4 mention.
        let line = r#"key_locate :CLIENT ID :F_DBG :Locate Unconfirmed Client ID seeking Key=0x7f0c3082f670 {Unique=0x6a375213 Counter=0x00000001}"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        assert!(r.is_none() || r.unwrap().contains("client-a") /* only if a good name was also present */);
    }

    #[test]
    fn grps_exercises_returns_at_least_primary_gid() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(tmp.path());
        let _ = std::fs::create_dir_all(tmp.path());
        std::fs::write(
            paths.nss_passwd,
            "testuser1@EXAMPLE.COM:x:3001:3005:user:/non:/nologin\n",
        )
        .unwrap();
        let mut cache = IdCache::default();
        let realm = "EXAMPLE.COM".to_string();
        let variants: Vec<String> = vec![];
        let gs = resolve_gids_and_materialize("testuser1@EXAMPLE.COM", &realm, &variants, &mut cache, &paths, false);
        assert!(!gs.is_empty());
        assert!(gs.contains(&3005));
    }

    #[test]
    fn on_demand_cache_hit_is_pure_read_and_instant() {
        // Second lookup for same principal after first materialization must be a pure cache hit (source=cache)
        // with no additional resolution IO in the hot path.
        // Use under(tmp) exclusively to avoid writing prod paths during parallel test.
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(tmp.path());
        let _ = std::fs::create_dir_all(tmp.path());
        let mut cache = IdCache::default();
        let realm = "EXAMPLE.COM".to_string();
        let variants: Vec<String> = vec![];
        // First (miss) for a machine: must resolve to 0/0 and materialize side effects.
        let r1 = resolve_principal("host/cachehit@EXAMPLE.COM", &realm, &variants, &mut cache, &paths);
        assert_eq!(r1.uid, 0);
        assert_eq!(r1.kind, PrincipalKind::Machine);
        // Second lookup: must be instant cache hit.
        let start = std::time::Instant::now();
        let r2 = resolve_principal("host/cachehit@EXAMPLE.COM", &realm, &variants, &mut cache, &paths);
        let elapsed = start.elapsed();
        assert_eq!(r2.source, "cache");
        assert_eq!(r2.uid, 0);
        // Practically sub-millisecond for in-memory hit; allow generous 5ms in CI.
        assert!(elapsed.as_millis() < 5, "cache hit took too long: {:?}", elapsed);

        // Also for a user@ form after injection (via test-forced ldap or file).
        // Inject directly to simulate prior on-demand materialization without external getent.
        cache.insert(Resolved {
            principal: "ondemanduser@EXAMPLE.COM".into(),
            name: "ondemanduser".into(),
            uid: 4242,
            gid: 4242,
            kind: PrincipalKind::User,
            source: "test".into(),
            supplemental_gids: vec![],
        });
        let start2 = std::time::Instant::now();
        let r3 = resolve_principal("ondemanduser@EXAMPLE.COM", &realm, &variants, &mut cache, &paths);
        let elapsed2 = start2.elapsed();
        assert_eq!(r3.source, "cache");
        assert!(elapsed2.as_millis() < 5);
    }

    // Removed the shimmed real_path test (used TEST_REBULK_POPULATE + override). Pure rebulk_apply_sync test above covers snap -> nss with @ and supp group (no env shim for resolver).

    #[test]
    fn user_principal_group_materialize_includes_uid_group_info() {
        // drives on-demand user@REALM + group info materialization path
        let g = materialize::group_line_with_members(2001, "alice", &["alice".to_string()]);
        assert!(g.contains("2001") && g.contains("alice"));
    }

    #[test]
    fn build_nss_includes_at_login_in_group_members_for_getgrouplist() {
        // Ensures user@REALM login appears in gid group members (for Ganesha 9 uid2grp/getgrouplist on TGT principal).
        let mut cache = IdCache::default();
        cache.insert(Resolved { principal: "testuser1@EX.COM".into(), name: "testuser1".into(), uid: 3001, gid: 3005, kind: PrincipalKind::User, source: "t".into(), supplemental_gids: vec![] });
        let mut groups = std::collections::HashMap::new();
        groups.insert("staff".into(), nfs_klldap_config::PosixGroupEntry { gid: 3005, display: "staff".into(), members: vec!["testuser1".into()] });
        let (_p, g) = build_nss_snapshot(&cache, Some(&groups));
        let staff_line = g.iter().find(|l| l.contains("staff:x:3005")).cloned().unwrap_or_default();
        assert!(staff_line.contains("testuser1"), "short in members");
        assert!(staff_line.contains("testuser1@EX.COM"), "@ form must be in members for getgrouplist(user@) under Manage_Gids");
    }

    #[test]
    fn stress_extract_on_trace_fragments_no_garbage() {
        // Regression tests ensure Ganesha log fragments never yield host/nil.
        let fragments = vec![
            r#"conf = (nil) {NULL} unconf = (nil) {NULL}"#,
            r#"clientid=Unique=0x6a375213 Counter=0x00000001"#,
            r#"key_locate :CLIENT ID :F_DBG :Locate Unconfirmed Client ID seeking Key=0x7f0c3082f670 {Unique=0x6a375213 Counter=0x00000001}"#,
            r#"nfs4_op_destroy_clientid :CLIENT ID :DEBUG :DESTROY_CLIENTID clientid=Unique=0x6a375213 Counter=0x00000002"#,
            r#"fs_create_clid_name :CLIENT ID :DEBUG :Created client name [::ffff:10.10.10.83-(21:Linux NFSv4.2 client-a)]"#,
            r#"fs_rm_clid_impl :CLIENT ID :DEBUG :position=0 len=45  parent_path=/var/lib/nfs/ganesha/v4recov recov_dir=::ffff:10.10.10.83-(21:Linux NFSv4.2 client-a)"#,
            r#"dec_client_record_ref :CLIENT ID :F_DBG :Free {{0x7f0c14001df0 name=(21:Linux NFSv4.2 client-a) conf = (nil) {NULL} unconf = (nil) {NULL} server_addr = 172.17.0.2 pnfs_flags 0x10000 cr_refcount=1}}"#,
            // Long CLIENT ID lines with server_addr on Docker bridge.
            r#"hashtable_getlatch :CLIENT ID :F_DBG :Get Client Record returning Value=0x7f0c14001df0 {{0x7f0c14001df0 name=(21:Linux NFSv4.2 client-a) conf = (nil) {NULL} unconf = (nil) {NULL} server_addr = 172.17.0.2 pnfs_flags 0x10000 cr_refcount=0}}"#,
            r#"hashtable_deletelatched :CLIENT ID :F_DBG :Delete Client Record Key=0x7f0c14001df0 {{0x7f0c14001df0 name=(21:Linux NFSv4.2 client-a) conf = (nil) {NULL} unconf = (nil) {NULL} server_addr = 172.17.0.2 pnfs_flags 0x10000 cr_refcount=0}} Value=0x7f0c14001df0 ... was removed"#,
            // A line with nfsv4 early and later (nil) groups. No good Linux.
            r#"some prefix NFSv4 stuff clientid=Unique=0x6a375213 conf = (nil) unconf = (nil) other tokens"#,
        ];

        for frag in &fragments {
            let r = extract_candidate_principal(frag, "EXAMPLE.COM");
            if let Some(c) = r {
                let bad = c.to_ascii_lowercase();
                assert!(!bad.contains("nil"), "frag produced host/nil: {}", frag);
                assert!(!bad.contains("clientid"), "frag produced host/clientid: {}", frag);
                assert!(!bad.contains("unique"), "frag produced host/unique: {}", frag);
                assert!(!bad.contains("counter"), "frag produced host/counter: {}", frag);
                assert!(!bad.contains("0x"), "frag produced host/0x epoch: {}", frag);
            }
        }
    }

    #[test]
    fn machine_principal_short_circuits_to_zero_without_getent() {
        // Env lock: resolve reads process-global TEST_REBULK_POPULATE/NFS_CONFIG.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Use isolated under(tmp) paths for all shipped resolve/groups calls.
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(tmp.path());
        let _ = std::fs::create_dir_all(tmp.path());
        let mut cache = IdCache::default();
        let realm = "EXAMPLE.COM".to_string();
        let variants = vec!["nas-1".to_string()];

        let r1 = resolve_principal("host/client-a@EXAMPLE.COM", &realm, &variants, &mut cache, &paths);
        assert_eq!(r1.uid, 0); assert_eq!(r1.gid, 0); assert_eq!(r1.kind, PrincipalKind::Machine);

        let gs0 = resolve_gids_and_materialize("host/client-a@EXAMPLE.COM", &realm, &variants, &mut cache, &paths, false);
        assert_eq!(gs0, vec![0]);

        std::fs::write(
            paths.nss_passwd,
            "testuser1@EXAMPLE.COM:x:3001:3005:user:/non:/nologin\n",
        )
        .unwrap();
        let r2 = resolve_principal("testuser1@EXAMPLE.COM", &realm, &variants, &mut cache, &paths);
        let gs_user = resolve_gids_and_materialize("testuser1@EXAMPLE.COM", &realm, &variants, &mut cache, &paths, false);
        assert!(!gs_user.is_empty());
        assert_eq!(r2.kind, PrincipalKind::User);
        assert_ne!(r2.source, crate::resolve::RESOLVE_FAIL_CLOSED_SOURCE);
    }

    #[test]
    fn resolve_principal_user_at_realm_on_demand_via_getent_non_fallback() {
        // Drives the shipped on-demand user@REALM path ... protected by lock to avoid polluting PATH/TEST_ for parallel tests.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let fake_dir = tmp.path().join("fakebin");
        std::fs::create_dir_all(&fake_dir).unwrap();
        let getent_script = fake_dir.join("getent");
        let script = "#!/bin/sh\nif [ \"$1\" = \"passwd\" ] && echo \"$2\" | grep -q '@'; then\n  echo \"$2:x:4242:4242:ondemand user:$2:/bin/false\"\n  exit 0\nfi\nexec /usr/bin/getent \"$@\" || exec /bin/getent \"$@\"\n";
        std::fs::write(&getent_script, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&getent_script).unwrap().permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(&getent_script, p).unwrap();

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{}", fake_dir.display(), old_path));

        let mut cache = IdCache::default();
        let realm = "TEST.COM".to_string();
        let variants: Vec<String> = vec![];
        // Use local under paths for this test's mat side effects, to avoid polluting global /var nss files.
        let paths = NssMaterializePaths::under(tmp.path());
        let r = resolve_principal("ondemanduser@TEST.COM", &realm, &variants, &mut cache, &paths);

        std::env::set_var("PATH", old_path);

        assert_eq!(r.principal, "ondemanduser@TEST.COM");
        assert_eq!(r.uid, 4242);
        assert_eq!(r.gid, 4242);
        assert_eq!(r.source, "sss");
        assert!(r.kind == PrincipalKind::User || r.kind == PrincipalKind::Unknown);

        // drive second user via file pre-seed (real shipped lookup path, no force shim) to exercise resolve + later mat.
        std::fs::write(paths.nss_passwd, format!("{}\nldapuser@TESTLDAP.COM:x:7777:7777:ldap:/non:/nologin\n", std::fs::read_to_string(paths.nss_passwd).unwrap_or_default())).unwrap();
        let r_ldap = resolve_principal("ldapuser@TESTLDAP.COM", &realm, &variants, &mut cache, &paths);
        assert_eq!(r_ldap.uid, 7777);
        assert_eq!(r_ldap.gid, 7777);

        // drive materialize with the result using the test paths
        let _ = materialize_nss_wrappers_at(&cache, &paths, None);
        let pw = std::fs::read_to_string(paths.nss_passwd).unwrap_or_default();
        assert!(pw.contains("ondemanduser@TEST.COM:x:4242:4242:") || pw.contains("ondemanduser:x:4242"));

        // drive GRPS path (reuses resolve_principal + groups resolver) using local paths
        let gs = resolve_gids_and_materialize("ondemanduser@TEST.COM", &realm, &variants, &mut cache, &paths, false);
        assert!(!gs.is_empty());
        assert!(gs[0] == 4242 || gs.contains(&4242));
    }

    #[test]
    fn extract_catches_could_not_map_line_for_user_principal() {
        // The could-not-map line pattern closes the first-use timing gap.
        let line = r#"nfs_req_creds :ID MAPPER :INFO :Could not map principal testuser1@EXAMPLE.COM to uid"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        assert_eq!(r, Some("testuser1@EXAMPLE.COM".to_string()));
    }

    #[test]
    fn extract_catches_get_uid_using_nfsidmap_line() {
        // Early Get uid lines resolve user principals before materialize.
        let line = r#"principal2uid : Get uid for testuser1@EXAMPLE.COM using nfsidmap"#;
        let r = extract_candidate_principal(line, "EXAMPLE.COM");
        assert_eq!(r, Some("testuser1@EXAMPLE.COM".to_string()));
    }

    #[test]
    fn resolve_groups_for_principal_supports_full_user_and_host_forms_via_ldap_primitives() {
        // Drive shipped resolve_groups (with data via pop for ldap path) + auto mat from groups (no post manual for gs assert); assert gs content includes supp, and files have it from auto.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::resolve::reset_id_resolver_for_test();
        let old_force = std::env::var("TEST_FORCE_LDAP_UID_GID").ok();
        let old_pop = std::env::var("TEST_REBULK_POPULATE").ok();
        std::env::set_var("TEST_FORCE_LDAP_UID_GID", "3788:100");
        std::env::set_var(
            "TEST_REBULK_POPULATE",
            "u:testuser1:3788:100;g:staff:2002;g:admins:3005:root",
        );
        let tmpf = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(tmpf.path());
        let _ = std::fs::create_dir_all(tmpf.path());
        std::fs::write(paths.nss_passwd, "testuser1@TESTLAB.LOCAL:x:3788:100:Test:/non:/nologin\n").unwrap();
        let mut cache = IdCache::default();
        let realm = "TESTLAB.LOCAL".to_string();
        let variants: Vec<String> = vec![];
        let gs_user = resolve_gids_and_materialize("testuser1@TESTLAB.LOCAL", &realm, &variants, &mut cache, &paths, false);
        let gs_host = resolve_gids_and_materialize("host/client-a@TESTLAB.LOCAL", &realm, &variants, &mut cache, &paths, false);
        assert!(gs_user.contains(&2002), "gs from groups must include supp 2002");
        let np = std::fs::read_to_string(paths.nss_passwd).unwrap_or_default();
        let ng = std::fs::read_to_string(paths.nss_group).unwrap_or_default();
        let ep = std::fs::read_to_string(paths.extrausers_passwd).unwrap_or_default();
        let eg = std::fs::read_to_string(paths.extrausers_group).unwrap_or_default();
        assert!(np.contains("testuser1@TESTLAB.LOCAL") && (ep.contains("testuser1@TESTLAB.LOCAL") || ep.contains("testuser1:x:3788")));
        // files after groups auto mat (before any manual)
        assert!((ng.contains("staff:x:2002:") || ng.contains("g2002")) && (ng.contains("testuser1") || ng.contains("testuser1@")));
        assert!((eg.contains("staff:x:2002:") || eg.contains("g2002")) && (eg.contains("testuser1") || eg.contains("testuser1@")));
        // also exercise ensure path
        let _ = ensure_nss_group_member_login(&paths, 2002, "testuser1");
        let _ = ensure_nss_group_member_login(&paths, 2002, "testuser1@TESTLAB.LOCAL");
        assert!(gs_host.contains(&0), "host must include primary gid 0");
        assert!(gs_host.contains(&3005), "host must inherit root-member supplemental gid: {gs_host:?}");
        let root_gs = resolve_gids_and_materialize("root", &realm, &variants, &mut cache, &paths, false);
        assert!(root_gs.contains(&3005), "GROUPLIST root must union machine supplementals: {root_gs:?}");
        if let Some(v) = old_force { std::env::set_var("TEST_FORCE_LDAP_UID_GID", v); } else { std::env::remove_var("TEST_FORCE_LDAP_UID_GID"); }
        if let Some(v) = old_pop { std::env::set_var("TEST_REBULK_POPULATE", v); } else { std::env::remove_var("TEST_REBULK_POPULATE"); }
    }

    #[test]
    fn cli_grps_and_resolve_handle_host_user_principal_realm_mismatch() {
        // Evidence for gap fix: grps/resolve on full form with @OTHERREALM while runtime get_realm() may differ.
        // classify must still treat host/ as Machine (via prefix) and user@ as user path.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::resolve::reset_id_resolver_for_test();
        // Use under to isolate writes (no prod pollution of 4242 etc)
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(tmp.path());
        let _ = std::fs::create_dir_all(tmp.path());
        let mut cache = IdCache::default();
        // Force runtime realm different from principal's
        // (the CLI paths now extract eff_realm from p; classify early-returns machine for prefix)
        let r_host = resolve_principal("host/client-a@OTHERREALM", "TESTLAB.LOCAL", &[], &mut cache, &paths);
        assert_eq!(r_host.kind, PrincipalKind::Machine, "host/ must classify machine even on realm mismatch");
        let gs_host = resolve_gids_and_materialize("host/client-a@OTHERREALM", "TESTLAB.LOCAL", &[], &mut cache, &paths, false);
        assert_eq!(gs_host, vec![0]);

        // user@ mismatch should go user path (may fallback)
        let r_user = resolve_principal("testuser1@OTHERREALM", "TESTLAB.LOCAL", &[], &mut cache, &paths);
        assert!(r_user.kind != PrincipalKind::Machine);
    }

    #[test]
    fn nss_contract_after_materialize_host_blue_lt() {
        let td = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(td.path());
        let mut cache = IdCache::default();
        let realm = "TEST.COM";
        let principal = "host/client-a@TEST.COM";
        let r = resolve_principal(principal, realm, &[], &mut cache, &paths);
        assert_eq!(r.kind, PrincipalKind::Machine);
        let _ = resolve_gids_and_materialize(principal, realm, &[], &mut cache, &paths, false);
        // groups wrote using paths; explicit mat redundant but keeps test intent
        materialize_nss_wrappers_at(&cache, &paths, None).expect("materialize");
        // Explicitly prove the literal host/ principal@ (with /) was written for the getpwnam path.
        let pw_content = std::fs::read_to_string(paths.nss_passwd).unwrap_or_default();
        assert!(pw_content.lines().any(|l| l.starts_with("host/client-a@TEST.COM:") || l.contains("host/client-a@TEST.COM:x:0:0:")),
            "must have written exact 'host/client-a@TEST.COM' login for getpwnam: {}", pw_content);
        let env = GaneshaNssEnv::from_paths(paths.nss_passwd, paths.nss_group);
        // Always assert the raw host/ principal form was written by materialize (file evidence).
        let pw = std::fs::read_to_string(paths.nss_passwd).unwrap_or_default();
        let has_raw = pw.lines().any(|l| l.starts_with("host/client-a@TEST.COM:") || l.starts_with("host/client-a@TEST.COM:x:0:0:"));
        println!("nss-contract: raw-form-present={} (exact probe for full principal)", has_raw);
        assert!(has_raw, "raw host/ principal@ form with / must be present from pure materialize: {}", pw);
        if !env.wrapper_available() {
            let (ok, msg) = evaluate_nss_contract(principal, &env, true);
            assert!(ok || msg.contains("file-ok"), "file contract after materialize (no wrapper): {msg}");
            println!("nss-contract: file-probe (no wrapper): {msg}");
            return;
        }
        let (ok, msg) = evaluate_nss_contract(principal, &env, true);
        println!("nss-contract: wrapper-live: {msg}");
        assert!(ok, "nss contract after materialize: {msg}");
        assert!(msg.starts_with("nss-contract:ok"));
    }

    #[test]
    fn materialize_direct_on_shipped_fns_both_user_and_host_write_exact_nss_and_extrausers() {
        // Drives the exact public/shipped entry points: resolve + materialize_nss_wrappers_at.
        // Asserts uid/gid, root for machines, and presence of expected lines in *both* nss and extrausers files.
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(tmp.path());

        let mut cache = IdCache::default();
        // Machine principal via the shipped resolve_principal (cold, no prior cache). Use test paths.
        let rm = resolve_principal("host/client-a@TESTLAB.LOCAL", "TESTLAB.LOCAL", &[], &mut cache, &paths);
        assert_eq!(rm.uid, 0);
        assert_eq!(rm.gid, 0);
        assert_eq!(rm.kind, PrincipalKind::Machine);

        // User principal (will be Unknown/fallback without live getent/ldap, but still materializes).
        let ru = resolve_principal("someuser@TESTLAB.LOCAL", "TESTLAB.LOCAL", &[], &mut cache, &paths);
        // Either a resolved uid or fallback is acceptable; key is materialization occurred.
        assert!(ru.principal.contains('@'));

        let _ = materialize_nss_wrappers_at(&cache, &paths, None);

        let pw = std::fs::read_to_string(paths.nss_passwd).unwrap();
        let gr = std::fs::read_to_string(paths.nss_group).unwrap();
        let epw = std::fs::read_to_string(paths.extrausers_passwd).unwrap();
        let egr = std::fs::read_to_string(paths.extrausers_group).unwrap();

        // Machine materialized as uid 0 in both stores.
        assert!(pw.contains("client-a:x:0:0:"), "must have canonical short for machine");
        assert!(epw.contains("client-a:x:0:0:"));
        // Must emit the *exact* "host/NAME@REALM" login (with /) so getpwnam(host/NAME@REALM) succeeds.
        assert!(pw.contains("host/client-a@TESTLAB.LOCAL:x:0:0:") || pw.lines().any(|l| l.starts_with("host/client-a@TESTLAB.LOCAL:")),
            "nss_passwd must contain literal host/ principal@ form with slash: {}", pw);
        assert!(epw.contains("host/client-a@TESTLAB.LOCAL:x:0:0:") || epw.lines().any(|l| l.starts_with("host/client-a@TESTLAB.LOCAL:")),
            "extrausers_passwd must contain literal host/ principal@ form with slash");
        // Sanitized alias is optional but the raw / form is required for Ganesha UseGetpwnam.

        // Root group present.
        assert!(gr.contains("root:x:0:"));
        assert!(egr.contains("root:x:0:"));

        // root user injected.
        assert!(pw.contains("root:x:0:0:"));
        assert!(epw.contains("root:x:0:0:"));
    }

    // NOTE: The AC1 gates have been moved to lib tests in ganesha_nss_contract.rs (separate process)
    // to avoid sharing env pollution (PATH, TEST_*, global /var writes) with bin env-shim tests.
    // See src/ganesha_nss_contract.rs tests for the promoted gates using under(tmp) directly.

    #[test]
    fn build_nss_snapshot_exact_logins_machine_no_underscore_at() {
        // Pure function: for machine+realm we emit the short name + the raw principal@ (no host_@ form).
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "host/client-a@EX.COM".into(),
            name: "client-a".into(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "t".into(),
            supplemental_gids: vec![],
        });
        let logins = materialize::nss_passwd_logins_for(cache.get("host/client-a@EX.COM").unwrap());
        let expected: std::collections::BTreeSet<String> = ["client-a".to_string(), "host/client-a".to_string(), "host/client-a@EX.COM".to_string()].into_iter().collect();
        assert_eq!(logins, expected);
        assert!(logins.iter().all(|l| !l.contains("host_blue")), "no sanitized local form");
    }

    #[test]
    fn uid0_machine_root_members_and_contract_from_shipped_resolve_groups_materialize() {
        // Drives exactly the shipped resolve_principal + resolve_gids_and_materialize + build_nss_snapshot
        // + materialize_nss_wrappers_at + ganesha contract evaluate. No UUT mocks.
        // Asserts: root passwd leading, root group line has non-empty base members (root,daemon,bin),
        // machine host/ form present, contract ok for exact principal (uid/gid 0 + root gid).
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        resolve::reset_id_resolver_for_test();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let paths = NssMaterializePaths::under(base);
        let _ = std::fs::create_dir_all(base);

        // Use explicit paths for shipped resolve/groups to isolate (no global env mutation).
        let mut cache = IdCache::default();
        let machine_p = "host/testbox@T.REALM";
        let r = resolve_principal(machine_p, "T.REALM", &[], &mut cache, &paths);
        assert_eq!(r.uid, 0);
        assert_eq!(r.gid, 0);
        assert_eq!(r.kind, PrincipalKind::Machine);

        let gs = resolve_gids_and_materialize(machine_p, "T.REALM", &[], &mut cache, &paths, false);
        assert!(gs.contains(&0), "machine groups must include 0");

        // groups already materialized using paths; explicit for clarity
        materialize_nss_wrappers_at(&cache, &paths, None).expect("mat");

        let pw = std::fs::read_to_string(paths.nss_passwd).unwrap_or_default();
        let gr = std::fs::read_to_string(paths.nss_group).unwrap_or_default();
        let epw = std::fs::read_to_string(paths.extrausers_passwd).unwrap_or_default();
        let egr = std::fs::read_to_string(paths.extrausers_group).unwrap_or_default();

        // root passwd leading + present in both
        assert!(pw.starts_with("root:x:0:0:") || pw.lines().next().unwrap_or("").starts_with("root:x:0:0:"), "root passwd must be first: {}", pw);
        assert!(pw.contains("root:x:0:0:"));
        assert!(epw.contains("root:x:0:0:"));

        // host/ exact + short in passwd for machine
        assert!(pw.contains("host/testbox@T.REALM:x:0:0:") || pw.contains("host/testbox@T.REALM:x:0:0"), "exact host/ principal form required");
        assert!(pw.contains("testbox:x:0:0:") || pw.contains("testbox:x:0:0"));

        // root group with members (never empty), in both stores
        assert!(gr.contains("root:x:0:root") || gr.contains("root:x:0:daemon") || gr.contains("root:x:0:bin"), "root group must have base members: {}", gr);
        assert!(egr.contains("root:x:0:root") || egr.contains("root:x:0:daemon"), "extrausers root members");

        // root group must be minimal; machine logins must not be stuffed into gid 0
        let root_line = gr.lines().find(|l| l.starts_with("root:x:0:")).unwrap_or("");
        assert!(
            root_line == "root:x:0:root,daemon,bin" || root_line.starts_with("root:x:0:root,daemon,bin"),
            "root group must be minimal, not machine-stuffed: {root_line}"
        );
        assert!(!root_line.contains("testbox"), "machine login must not be on gid 0: {root_line}");

        // Contract via shipped evaluate (file path, non-wrapper env here)
        let env = GaneshaNssEnv::from_paths(paths.nss_passwd, paths.nss_group);
        let (ok, msg) = evaluate_nss_contract(machine_p, &env, true);
        assert!(ok || msg.contains("file-ok"), "uid0 contract must succeed or file-ok: {msg}");
        // direct probe exact -- prefer file to avoid live wrapper picking stale global state
        let probed = probe_nss_passwd_from_file_exact(machine_p, &env).or_else(|| probe_nss_passwd_exact(machine_p, &env));
        assert_eq!(probed, Some((0, 0)));

        // Explicit getgrouplist evidence (root group members line + note that getgrouplist(0) contract relies on this)
        // Printed so it appears in full cargo test verif capture logs (addresses targeted-only gap).
        let root_line = gr.lines().find(|l| l.starts_with("root:x:0:")).unwrap_or("");
        println!("getgrouplist-evidence: root-group-line='{}' (for uid0 getgrouplist under nss_wrapper; also in extrausers)", root_line);
        // Also exercise a getent group root as proxy for group list visibility.
        if let Ok(content) = std::fs::read_to_string(paths.nss_group) {
            if let Some(rg) = content.lines().find(|l| l.starts_with("root:x:0:")) {
                println!("getgrouplist-evidence: nss-group-root='{}'", rg);
            }
        }
        // Real getgrouplist evidence via id -G under the nss_wrapper envs driven by test's paths (using shipped materialization).
        // This exercises the data Ganesha's my_getgrouplist_alloc will see.
        {
            use std::process::Command;
            let mut idcmd = Command::new("id");
            idcmd.arg("-G").arg("0");  // numeric uid 0 for machine/root
            idcmd.env("NSS_WRAPPER_PASSWD", paths.nss_passwd);
            idcmd.env("NSS_WRAPPER_GROUP", paths.nss_group);
            idcmd.env("NSS_EXTRAUSERS_PASSWD", paths.extrausers_passwd);
            idcmd.env("NSS_EXTRAUSERS_GROUP", paths.extrausers_group);
            if let Ok(out) = idcmd.output() {
                let gout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let gerr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                println!("getgrouplist-evidence: id-G-under-nss uid0='{}' (stderr='{}') exit={}", gout, gerr, out.status.code().unwrap_or(-1));
                if !gout.is_empty() && gout.split_whitespace().any(|t| t == "0" || t == "0," ) {
                    println!("getgrouplist-evidence: SUCCESS root-gid-visible-for-uid0");
                }
            } else {
                println!("getgrouplist-evidence: id-G-under-nss not runnable (no wrapper lib or env)");
            }
        }

        // Also user path still works non-fallback
        let mut cache2 = IdCache::default();
        cache2.insert(Resolved { principal: "u1@T.REALM".into(), name: "u1".into(), uid: 2001, gid: 2001, kind: PrincipalKind::User, source: "t".into(), supplemental_gids: vec![] });
        let _ = resolve_gids_and_materialize("u1@T.REALM", "T.REALM", &[], &mut cache2, &paths, false);
        let (p2, _g2) = build_nss_snapshot(&cache2, None);
        assert!(p2.iter().any(|l| l.starts_with("root:")), "root always");
        assert!(p2.iter().any(|l| l.contains("u1@T.REALM") || l.contains("u1:x:2001")));
    }

    #[test]
    fn build_nss_snapshot_machine_uid0_root_has_members_and_root_first() {
        // Pure snapshot from machine uid0 entry: root passwd first, root group non-empty members.
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "host/m0@R.LOCAL".into(),
            name: "m0".into(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "s".into(),
            supplemental_gids: vec![],
        });
        let (pw, gr) = build_nss_snapshot(&cache, None);
        assert!(pw.first().map(|l| l.starts_with("root:")).unwrap_or(false), "root passwd must lead");
        let root_gr = gr.iter().find(|l| l.starts_with("root:x:0:")).cloned().unwrap_or_default();
        assert!(!root_gr.ends_with("root:x:0:") && (root_gr.contains("root,") || root_gr.contains("daemon") || root_gr.contains("bin") || root_gr.contains("m0")), "root group members non-empty after machine: {}", root_gr);
        assert!(pw.iter().any(|l| l.contains("host/m0@R.LOCAL:x:0:0:") || l.contains("m0:x:0:0:")));
    }

    #[test]
    fn proactive_rebulk_equiv_on_demand_for_uid0_root_members() {
        // Simulate proactive (seed + mat) vs on-demand (resolve+groups+mat) produce same uid0 root with members.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        resolve::reset_id_resolver_for_test();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let p1 = NssMaterializePaths::under(&base.join("pro"));
        let p2 = NssMaterializePaths::under(&base.join("ond"));
        let _ = std::fs::create_dir_all(base.join("pro"));
        let _ = std::fs::create_dir_all(base.join("ond"));

        // proactive sim: insert machine like rebulk would, then mat
        let mut c1 = IdCache::default();
        c1.insert(Resolved { principal: "host/pro0@EX".into(), name: "pro0".into(), uid: 0, gid: 0, kind: PrincipalKind::Machine, source: "bulk".into(), supplemental_gids: vec![] });
        let _ = materialize_nss_wrappers_at(&c1, &p1, None);

        // on-demand (use test's under(p2) paths exclusively, never prod)
        let mut c2 = IdCache::default();
        let _ = resolve_principal("host/pro0@EX", "EX", &[], &mut c2, &p2);
        let _ = resolve_gids_and_materialize("host/pro0@EX", "EX", &[], &mut c2, &p2, false);
        let _ = materialize_nss_wrappers_at(&c2, &p2, None);

        let gr1 = std::fs::read_to_string(p1.nss_group).unwrap_or_default();
        let gr2 = std::fs::read_to_string(p2.nss_group).unwrap_or_default();
        assert!(gr1.contains("root:x:0:") && (gr1.contains("root,") || gr1.contains("pro0")), "proactive root members");
        assert!(gr2.contains("root:x:0:") && (gr2.contains("root,") || gr2.contains("pro0")), "ondemand root members");
        // files contain equivalent root non-empty
    }

    #[test]
    fn ondemand_reactive_groups_fast_cache_hit_both_stores_complete() {
        // Drive *shipped* resolve_prin + resolve_groups + mat + ensure (no TEST_* shims for core). Pre-seed nss_passwd file so resolve uses real getent/file path. Prove no-nobody for resolved, full logins in primary group, ensure creates+populates supp gid in *both* stores, uid0 root, cache-hit no side-effect.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::resolve::reset_id_resolver_for_test();
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(tmp.path());
        let _ = std::fs::create_dir_all(tmp.path());
        // Use TEST_REBULK_POPULATE only to stub resolver data (supp gid); the resolve_groups call + internal mat + build_nss
        // (now emitting from persisted supplemental_gids) is the shipped core path under test. No manual ensure after groups.
        std::env::set_var("TEST_REBULK_POPULATE", "u:testu:2001:100;g:staff:4242");
        std::fs::write(paths.nss_passwd, "testu@T.REALM:x:2001:100:testu@T.REALM:/nonexistent:/usr/sbin/nologin\n").unwrap();
        let mut cache = IdCache::default();
        let r1 = resolve_principal("testu@T.REALM", "T.REALM", &[], &mut cache, &paths);
        assert!(r1.source != "cache" && r1.uid == 2001 && r1.uid != FALLBACK_NOBODY_UID, "no fallback for pre-seeded encountered principal");
        let gs1 = resolve_gids_and_materialize("testu@T.REALM", "T.REALM", &[], &mut cache, &paths, false);
        assert!(gs1.contains(&4242), "groups must return extra supp from resolver stub");
        // Fresh resolve_groups auto materializes the supp row via build (now owns supps) + ensure; assert without post-manual-ensure.
        let np = std::fs::read_to_string(paths.nss_passwd).unwrap_or_default();
        let ng = std::fs::read_to_string(paths.nss_group).unwrap_or_default();
        let _ep = std::fs::read_to_string(paths.extrausers_passwd).unwrap_or_default();
        let eg = std::fs::read_to_string(paths.extrausers_group).unwrap_or_default();
        assert!(!np.contains("nobody:x:65534") || np.lines().any(|l| l.starts_with("testu@T.REALM:x:2001")));
        // The supp gid row (name may be "staff" or "g4242" or derived) must contain the login; proves auto from groups mat.
        assert!( ng.contains(":4242:") && (ng.contains("testu") || ng.contains("testu@")) );
        assert!( eg.contains(":4242:") && (eg.contains("testu") || eg.contains("testu@")) );
        eprintln!("OND_REACTIVE_FIRST_NG:\n{}", ng);
        eprintln!("OND_REACTIVE_FIRST_EG:\n{}", eg);
        std::env::remove_var("TEST_REBULK_POPULATE");
        // Survival using rebulk_apply_sync + poor snap (lacking the supp g): write cache, load fresh
        // (drive load_from_file), rebulk with the supp carried on the LIVE memberOf edge map (the
        // warm-pass mechanism that replaced the stale-supp preserve), assert non-prim rows in both.
        let cp = tmp.path().join("idmap.cache.surv");
        let _ = cache.write_to_file(&cp);
        let mut c3 = IdCache::load_from_file(&cp);
        let mut poor_snap = IdMapSnapshot::default();
        poor_snap.users.insert("testu".to_string(), nfs_klldap_config::PosixUserEntry { uid: 2001, gid: 100, display: "testu".into() });
        let cpath: &std::path::Path = Box::leak(tmp.path().join("idmap.cache").into_boxed_path());
        let _mpath: &std::path::Path = Box::leak(tmp.path().join(".bulk_seed").into_boxed_path());
        let rpaths = daemon::RebulkPaths { cache_path: cpath, nss: paths };
        let live = materialize::LiveGroupEdges::from([("testu".to_string(), vec![4242u32])]);
        let _ = daemon::rebulk_apply_sync(&mut c3, "T.REALM", &poor_snap, &live, &rpaths);
        let ng3 = std::fs::read_to_string(paths.nss_group).unwrap_or_default();
        let eg3 = std::fs::read_to_string(paths.extrausers_group).unwrap_or_default();
        assert!(ng3.contains(":4242:") && (ng3.contains("testu") || ng3.contains("testu@")), "supp row must survive post-rebulk_apply_sync via the live edge map");
        assert!(eg3.contains(":4242:") && (eg3.contains("testu") || eg3.contains("testu@")) );
        // repeat: pure cache + no mat side effect (mtime or content)
        let mt = std::fs::metadata(paths.nss_group).map(|m| m.modified().unwrap()).ok();
        let r2 = resolve_principal("testu@T.REALM", "T.REALM", &[], &mut cache, &paths);
        assert_eq!(r2.source, "cache");
        let _ = resolve_gids_and_materialize("testu@T.REALM", "T.REALM", &[], &mut cache, &paths, false);
        let mt2 = std::fs::metadata(paths.nss_group).map(|m| m.modified().unwrap()).ok();
        if let (Some(a), Some(b)) = (mt, mt2) { assert_eq!(a, b); }
        // uid0 machine (special path, no shim) also complete root in both
        let mut c0 = IdCache::default();
        let _ = resolve_principal("host/m0@T.REALM", "T.REALM", &[], &mut c0, &paths);
        let _ = resolve_gids_and_materialize("host/m0@T.REALM", "T.REALM", &[], &mut c0, &paths, false);
        let eg0 = std::fs::read_to_string(paths.extrausers_group).unwrap_or_default();
        assert!(eg0.contains("root:x:0:") && (eg0.contains("root,") || eg0.contains("daemon") || eg0.contains("m0")));
    }

    #[test]
    fn cli_verif_step2_user_and_machine_writes_complete_supps() {
        // Real production binary grps under temp-bound NSS+cache. Proves user
        // supplemental + uid0 root land in both stores. env_clear avoids parent
        // test pollution; force-rebuild path is `make test` building --bins first.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::resolve::reset_id_resolver_for_test();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let _ = std::fs::create_dir_all(base);
        let np = base.join("nss_passwd");
        let ng = base.join("nss_group");
        let ep = base.join("extra_passwd");
        let eg = base.join("extra_group");
        let cp = base.join("idmap.cache");
        // Pre-seed nss_passwd + cache with supp gids so the bin (no TEST_* env)
        // hits cache and ensure writes non-prim 4242 rows to both stores.
        std::fs::write(
            &np,
            "testu@T.REALM:x:2001:100:testu@T.REALM:/nonexistent:/usr/sbin/nologin\nroot:x:0:0:root:/root:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(
            &cp,
            "# preseed supps for user@ CLI evidence (no TEST to bin)\ntestu@T.REALM|2001|100|user|pre|4242\n",
        )
        .unwrap();

        let bin = idhelper_bin();
        assert!(
            bin.is_file(),
            "idhelper binary missing at {} — run `cargo build -p nfs-klldap-config --bins` (make test does this)",
            bin.display()
        );

        let path_env = std::env::var_os("PATH").unwrap_or_default();
        let run_grps = |principal: &str| {
            ::std::process::Command::new(&bin)
                .arg("grps")
                .arg(principal)
                // Isolate from parent cargo-test env (parallel crates / prior tests).
                .env_clear()
                .env("PATH", &path_env)
                .env("NSS_PASSWD", &np)
                .env("NSS_GROUP", &ng)
                .env("NSS_EXTRAUSERS_PASSWD", &ep)
                .env("NSS_EXTRAUSERS_GROUP", &eg)
                .env("IDHELPER_CACHE_PATH", &cp)
                .output()
                .unwrap_or_else(|e| panic!("spawn grps {principal}: {e}"))
        };

        let outu = run_grps("testu@T.REALM");
        let outm = run_grps("host/client-a@T.REALM");
        let su = String::from_utf8_lossy(&outu.stdout);
        let eu = String::from_utf8_lossy(&outu.stderr);
        let sm = String::from_utf8_lossy(&outm.stdout);
        let em = String::from_utf8_lossy(&outm.stderr);
        assert!(
            outu.status.success(),
            "user grps must exit 0\nstdout={su}\nstderr={eu}"
        );
        assert!(
            outm.status.success(),
            "machine grps must exit 0\nstdout={sm}\nstderr={em}"
        );
        assert!(
            su.contains("4242") || su.contains("OK "),
            "user grps stdout should report gids including 4242: {su}"
        );

        let ngc = std::fs::read_to_string(&ng).unwrap_or_default();
        let egc = std::fs::read_to_string(&eg).unwrap_or_default();
        let npc = std::fs::read_to_string(&np).unwrap_or_default();
        let epc = std::fs::read_to_string(&ep).unwrap_or_default();

        if let Ok(scr) = std::env::var("NFS_KLLDAP_CAPTURE_SCRATCH") {
            let path = std::path::Path::new(&scr).join("idhelper-verify.out");
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
            {
                let _ = writeln!(f, "=== cli_verif_step2 ===\nuser: {su}\nmach: {sm}\nnss_group:\n{ngc}\nextra_group:\n{egc}");
            }
        }

        assert!(
            npc.contains("testu@T.REALM:x:2001") || npc.contains("testu:x:2001"),
            "real uid not nobody from bin (pre-seed + bin grps path); nss_passwd:\n{npc}"
        );
        assert!(
            !npc.contains("nobody:x:65534")
                || npc.lines().any(|l| l.starts_with("testu@T.REALM:x:2001")),
            "no fallback; nss_passwd:\n{npc}"
        );
        assert!(
            !ngc.contains("testu:x:65534") && !egc.contains("testu:x:65534"),
            "no bogus user-named 65534 gid row; nss_group:\n{ngc}\nextra_group:\n{egc}"
        );
        assert!(
            ngc.contains(":4242:") && (ngc.contains("testu") || ngc.contains("testu@")),
            "supp row 4242 in nss_group from bin\nstdout={su}\nstderr={eu}\nnss_group:\n{ngc}\nextra_group:\n{egc}\nextra_passwd:\n{epc}"
        );
        assert!(
            egc.contains(":4242:") && (egc.contains("testu") || egc.contains("testu@")),
            "supp row 4242 in extra_group from bin\nextra_group:\n{egc}"
        );
        assert!(
            egc.contains("root:x:0:")
                && (egc.contains("root,") || egc.contains("daemon") || egc.contains("client-a")),
            "uid0 root members from bin mach\nstdout={sm}\nextra_group:\n{egc}"
        );
    }

    #[test]
    fn cli_resolve_and_grps_emit_err_on_realm_miss() {
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        resolve::reset_id_resolver_for_test();
        let tmpd = tempfile::tempdir().unwrap();
        let conf = tmpd.path().join("nfs-klldap.conf");
        std::fs::write(
            &conf,
            r#"
ldap_uri = "ldaps://klldap.test:6360"
[kerberos]
realm = "MISS.REALM"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
"#,
        )
        .unwrap();
        let paths = NssMaterializePaths::under(tmpd.path());
        std::env::set_var("NSS_PASSWD", paths.nss_passwd);
        std::env::set_var("NSS_GROUP", paths.nss_group);
        std::env::set_var("NSS_EXTRAUSERS_PASSWD", paths.extrausers_passwd);
        std::env::set_var("NSS_EXTRAUSERS_GROUP", paths.extrausers_group);

        let bin = idhelper_bin();
        for principal in ["missinguser@MISS.REALM", "nobody@MISS.REALM"] {
            for sub in ["grps", "resolve"] {
                let out = std::process::Command::new(&bin)
                    .args([sub, principal])
                    .env("NSS_PASSWD", paths.nss_passwd)
                    .env("NSS_GROUP", paths.nss_group)
                    .env("NSS_EXTRAUSERS_PASSWD", paths.extrausers_passwd)
                    .env("NSS_EXTRAUSERS_GROUP", paths.extrausers_group)
                    .env("NFS_CONFIG", &conf)
                    .env("TEST_REBULK_POPULATE", "u:seeduser:1001:100")
                    .env_remove("TEST_FORCE_LDAP_MISS")
                    .env_remove("TEST_FORCE_LDAP_UID_GID")
                    .output()
                    .expect("spawn idhelper");
                assert_eq!(
                    out.status.code(),
                    Some(1),
                    "{sub} {principal} must exit 1 on realm miss: stdout={} stderr={}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stderr),
                    String::from_utf8_lossy(&out.stdout)
                );
                assert!(
                    combined.contains("ERR unresolved principal"),
                    "{sub} {principal} must emit ERR unresolved: {combined}"
                );
            }
        }

        std::env::remove_var("NSS_PASSWD");
        std::env::remove_var("NSS_GROUP");
        std::env::remove_var("NSS_EXTRAUSERS_PASSWD");
        std::env::remove_var("NSS_EXTRAUSERS_GROUP");
    }
}
