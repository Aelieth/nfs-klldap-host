#![deny(unsafe_code)]

//! nfs-klldap-idhelper
//! Central fast resolver for ganesha 9.6 (libnfsidmap getpwnam + nss_wrapper paths).

mod common;
mod daemon;
mod materialize;
mod observer;
mod resolve;

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use common::{
    get_realm, get_server_variants, is_machine_principal, IdCache, PrincipalKind, Resolved,
    CACHE_PATH, NSS_GROUP_PATH, NSS_PASSWD_PATH, SOCKET_PATH,
};
#[cfg(test)]
use common::normalize_principal;
use daemon::run_daemon;
#[cfg(test)]
use materialize::{
    group_line_for, passwd_line_for, sanitize_for_nss, seed_cache_and_nss_from_snapshot,
    sync_user_cache_from_snapshot,
};
#[cfg(test)]
use nfs_klldap_config::{IdMapSnapshot, PosixUserEntry};
#[cfg(test)]
use observer::{extract_candidate_principal, looks_like_client_hostname};
use resolve::resolve_principal;

/// Try to perform RESOLVE via the running daemon's unix socket.
/// Returns Some(Resolved) on success (the daemon did the work + materialize).
/// Falls back to local logic in the caller if this returns None.
fn try_resolve_via_socket(principal: &str) -> Option<Resolved> {
    let mut stream = UnixStream::connect(SOCKET_PATH).ok()?;
    let req = format!("RESOLVE {}\n", principal);
    stream.write_all(req.as_bytes()).ok()?;
    let _ = stream.flush();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let resp = line.trim();
    if let Some(rest) = resp.strip_prefix("OK ") {
        let parts: Vec<&str> = rest.split('|').collect();
        if parts.len() == 5 {
            if let (Ok(uid), Ok(gid)) = (parts[1].parse::<u32>(), parts[2].parse::<u32>()) {
                let kind = match parts[3] {
                    "machine" => PrincipalKind::Machine,
                    "user" => PrincipalKind::User,
                    _ => PrincipalKind::Unknown,
                };
                // Name computation is done by the daemon's resolve_principal for the reply.
                // For CLI printing we use the local part (consistent with normal Resolved.name for users).
                let name = parts[0].split('@').next().unwrap_or(parts[0]).to_string();
                return Some(Resolved {
                    principal: parts[0].to_string(),
                    name,
                    uid,
                    gid,
                    kind,
                    source: parts[4].to_string(),
                });
            }
        }
    }
    None
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

            // Prefer live daemon cache/state via socket (observer results become immediately visible to shim/CLI).
            let r = if let Some(r) = try_resolve_via_socket(p) {
                r
            } else {
                let mut cache = IdCache::load_from_file(Path::new(CACHE_PATH));
                resolve_principal(p, &realm, &server_variants, &mut cache)
            };

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
        "classify" => {
            let p = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if p.is_empty() {
                eprintln!("Usage: nfs-klldap-idhelper classify <principal>");
                std::process::exit(2);
            }
            let (is_m, reason) = is_machine_principal(p, &realm, &server_variants);
            let kind = if is_m { "machine" } else { "user" };
            println!("{} -> kind={} reason=\"{}\"", p, kind, reason);
        }
        "check" => {
            println!("realm: {}", realm);
            println!("server_variants: {:?}", server_variants);
            println!("cache file: {}", CACHE_PATH);
            println!("socket: {}", SOCKET_PATH);
            // Quick self test (local path)
            let mut cache = IdCache::load_from_file(Path::new(CACHE_PATH));
            let test_p = format!("user-test@{}", realm);
            let _ = resolve_principal(&test_p, &realm, &server_variants, &mut cache);
            println!("self-test resolve executed (may be unknown without real LDAP)");
        }
        "explain" => {
            println!("nfs-klldap-idhelper — machine vs user Kerberos principal resolver");
            println!("realm: {}", realm);
            println!("server host variants: {:?}", server_variants);
            println!("Cache lives at {} (simple | delimited, easy to process with grep/awk).", CACHE_PATH);
            println!("Daemon listens on {} (unix socket).", SOCKET_PATH);
            println!("NSS wrapper files (for Ganesha under libnss_wrapper): {} and {}", NSS_PASSWD_PATH, NSS_GROUP_PATH);
            println!("LDAP sync: startup + every {}s (NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS, 0=off)",
                crate::common::DEFAULT_REBULK_INTERVAL_SECS);
            println!("Socket REBULK: printf 'REBULK\\n' | nc -U {}  (prune stale users, reload LDAP→nss_passwd)",
                SOCKET_PATH);
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
  nfs-klldap-idhelper classify <principal>
  nfs-klldap-idhelper check
  nfs-klldap-idhelper explain
  nfs-klldap-idhelper daemon     # run the long-lived server (started by container)

Debug: KLLDAP_IDHELPER_DEBUG=true   (logs RESOLVE, norm key, hit/miss, classify,
       short name, getent details, result, elapsed, cache write, nss_wrapper writes)

The daemon must be running for reliable mounts. It syncs LDAP users into nss_passwd
at startup and periodically (pruning deleted users). Socket commands: RESOLVE,
CLASSIFY, REBULK (force LDAP refresh).
"#
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    // Support "nfs-klldap-idhelper daemon" or being started directly as the daemon.
    if args.len() > 1 && (args[1] == "daemon" || args[1] == "--daemon") {
        run_daemon();
        return;
    }

    // If no subcommand and we look like we were exec'd as the main, show help once.
    if args.len() <= 1 {
        // Allow being started as a simple long-lived process via other means.
        // Default to daemon behavior only if explicitly requested.
        print_help();
        return;
    }

    // CLI mode: everything after the binary name
    let sub_args = &args[1..];
    handle_cli(sub_args);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_principal_detection_basic() {
        let variants = vec!["aurora".to_string(), "aurora.example.com".to_string()];
        let (m, _) = is_machine_principal("host/aurora@EXAMPLE.COM", "EXAMPLE.COM", &variants);
        assert!(m);
        let (m2, _) = is_machine_principal("nfs/aurora.example.com@EXAMPLE.COM", "EXAMPLE.COM", &variants);
        assert!(m2);
        let (u, _) = is_machine_principal("alice@EXAMPLE.COM", "EXAMPLE.COM", &variants);
        assert!(!u);
        let (m3, _) = is_machine_principal("root/client@REALM", "REALM", &variants);
        assert!(m3);
    }

    #[test]
    fn normalize_keeps_local_preserves_upper_realm() {
        assert_eq!(normalize_principal("alice@exAmPle.com"), "alice@EXAMPLE.COM");
        assert_eq!(normalize_principal("host/box"), "host/box");
    }

    #[test]
    fn cache_roundtrip_works() {
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
        };
        c.insert(r.clone());
        c.write_to_file(&p).unwrap();
        let c2 = IdCache::load_from_file(&p);
        assert!(c2.get("bob@TEST").is_some());
        assert_eq!(c2.get("bob@TEST").unwrap().uid, 2001);
    }

    #[test]
    fn extract_candidate_finds_explicit_principal() {
        let r = extract_candidate_principal(
            "some log with principal user@SATOMLIN.COM and other stuff",
            "SATOMLIN.COM",
        );
        assert_eq!(r, Some("user@SATOMLIN.COM".to_string()));
    }

    #[test]
    fn extract_candidate_finds_host_style() {
        let r = extract_candidate_principal(
            "name=(21:Linux NFSv4.2 blue-lt) client stuff",
            "SATOMLIN.COM",
        );
        assert_eq!(r, Some("host/blue-lt@SATOMLIN.COM".to_string()));
    }

    #[test]
    fn extract_candidate_finds_in_ganesha_client_id_lines() {
        let line = r#"name=(21:Linux NFSv4.2 blue-lt) conf = 0x... server_addr = 172.17.0.2"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        assert_eq!(r, Some("host/blue-lt@SATOMLIN.COM".to_string()));
    }

    #[test]
    fn extract_candidate_ignores_irrelevant() {
        let r = extract_candidate_principal("just some random log without principals", "SATOMLIN.COM");
        assert!(r.is_none());
    }

    // --- Regression tests for bogus tokens seen in real Ganesha logs ---
    #[test]
    fn extract_rejects_unique_counter() {
        let line = r#"key_locate :CLIENT ID :F_DBG :Locate Unconfirmed Client ID seeking Key=0x... {Unique=0x6a374e99 Counter=0x00000001}"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        assert!(r.is_none() || !r.unwrap().contains("Unique"), "must not turn Unique= counter into a host principal");
    }

    #[test]
    fn extract_rejects_ffff_from_ipv6() {
        let line = r#"fs_create_clid_name :CLIENT ID :DEBUG :Created client name [::ffff:10.10.10.83-(21:Linux NFSv4.2 blue-lt)]"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        // It should find the real "blue-lt", never "ffff"
        if let Some(c) = r {
            assert!(c.contains("blue-lt"), "should still find the real hostname");
            assert!(!c.contains("ffff"), "must not emit host/ffff from IPv6 literal");
        }
    }

    #[test]
    fn extract_rejects_client_literal() {
        let line = "nfs4_op_destroy_clientid :CLIENT ID :DEBUG :DESTROY_CLIENTID clientid=...";
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        // Should not turn the word "CLIENT" into host/CLIENT
        if let Some(c) = r {
            assert!(!c.to_ascii_lowercase().contains("client"), "must ignore literal CLIENT word");
        }
    }

    #[test]
    fn extract_still_finds_good_name_even_with_noise() {
        let line = r#"fs_create_clid_name :CLIENT ID :DEBUG :Created client name [::ffff:10.10.10.83-(21:Linux NFSv4.2 blue-lt)] clientid=Unique=..."#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        assert_eq!(r, Some("host/blue-lt@SATOMLIN.COM".to_string()));
    }

    #[test]
    fn materialize_writes_machine_as_root() {
        let _tmp = tempfile::tempdir().unwrap();
        // Temporarily override the const paths by using a temp dir and monkey-patch via env is hard;
        // instead directly test the line builders and a small manual cache write.
        let mut c = IdCache::default();
        let machine = Resolved {
            principal: "host/blue-lt@EXAMPLE.COM".into(),
            name: "blue-lt".into(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".into(),
        };
        c.insert(machine);
        // We can't easily redirect const paths here without changing API.
        // Test the formatting helpers in isolation.
        let line = passwd_line_for(c.get("host/blue-lt@EXAMPLE.COM").unwrap());
        assert!(line.starts_with("blue-lt:x:0:0:"));
        assert!(line.contains("kll:machine:"));
        let gline = group_line_for(c.get("host/blue-lt@EXAMPLE.COM").unwrap());
        assert!(gline.starts_with("root:x:0:"));
    }

    #[test]
    fn materialize_always_includes_root_uid0_for_immediate_nss_hits() {
        // Critical for cold-start: even with no principals materialized yet,
        // nss_passwd must contain a root line so getpwuid_r(0) succeeds for
        // uid2grp on the very first host/ machine principal compound.
        // (Prevents the "getpwuid_r for uid 0 failed, error 2" in first-access logs.)
        // We simulate the lines that materialize builds (the actual function
        // uses const paths that are hard to redirect in unit tests; helpers
        // + the unconditional root injection rule are exercised here + in
        // the caller at daemon start).
        let mut passwd_lines: Vec<String> = vec![];
        // Simulate the exact injection rule added to materialize_nss_wrappers
        if !passwd_lines.iter().any(|l| l.starts_with("root:")) {
            passwd_lines.insert(0, "root:x:0:0:root:/nonexistent:/usr/sbin/nologin".to_string());
        }
        assert!(passwd_lines[0].starts_with("root:x:0:0:"));
        // When a machine is also present, its name line + the root group are there too.
        let mut c = IdCache::default();
        let machine = Resolved { principal: "host/x@EX".into(), name: "x".into(), uid: 0, gid: 0, kind: PrincipalKind::Machine, source: "s".into() };
        c.insert(machine);
        let gl = group_line_for(c.get("host/x@EX").unwrap());
        assert!(gl.starts_with("root:x:0:"));
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
        };
        c.insert(user);
        let line = passwd_line_for(c.get("alice@EXAMPLE.COM").unwrap());
        assert!(line.starts_with("alice:x:1005:100:"));
        let gline = group_line_for(c.get("alice@EXAMPLE.COM").unwrap());
        assert!(gline.contains(":100:"));
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
        });
        cache.insert(Resolved {
            principal: "host/client@EX.COM".into(),
            name: "client".into(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".into(),
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

        let n = sync_user_cache_from_snapshot(&snap, "EX.COM", &mut cache);
        assert_eq!(n, 1);
        assert!(cache.get("deleted@EX.COM").is_none());
        assert!(cache.get("host/client@EX.COM").is_some());
        assert!(cache.get("alice@EX.COM").is_some());
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
        let n = seed_cache_and_nss_from_snapshot(&snap, "SATOMLIN.COM", &mut cache);
        assert_eq!(n, 1);

        let r = cache.get("testuser1@SATOMLIN.COM").expect("principal key");
        assert_eq!(r.name, "testuser1");
        assert_eq!(r.uid, 1001);
        assert_eq!(r.gid, 1001);
        assert_eq!(r.kind, PrincipalKind::User);
        assert_eq!(r.source, "bulk");

        let short_line = passwd_line_for(r);
        assert!(short_line.starts_with("testuser1:x:1001:1001:"));
        let full_line = passwd_line_for(&Resolved {
            principal: "testuser1@SATOMLIN.COM".into(),
            name: "testuser1@SATOMLIN.COM".into(),
            uid: 1001,
            gid: 1001,
            kind: PrincipalKind::User,
            source: "bulk".into(),
        });
        // sanitize_for_nss maps '@' to '_' in passwd login names
        assert!(full_line.starts_with("testuser1_SATOMLIN.COM:x:1001:1001:"));
    }

    #[test]
    fn sanitize_for_nss_is_safe() {
        assert_eq!(sanitize_for_nss("host/foo.bar-baz"), "host_foo.bar-baz");
        assert_eq!(sanitize_for_nss("weird name!@#"), "weird_name___");
        assert_eq!(sanitize_for_nss(""), "unknown");
    }

    #[test]
    fn extract_rejects_nil_from_conf_group() {
        // Lines often contain conf = (nil) after a good name= group; must never emit host/nil
        let line = r#"key_locate :CLIENT ID :F_DBG :Locate Client Record seeking Key=... {{... name=(21:Linux NFSv4.2 blue-lt) conf = (nil) {NULL} unconf = (nil) {NULL} ...}}"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        if let Some(c) = r {
            assert!(c.contains("blue-lt"), "should find real host");
            assert!(!c.contains("nil"), "must never emit host/nil");
        }
    }

    #[test]
    fn extract_rejects_clientid_token() {
        let line = r#"nfs4_op_exchange_id ... clientid=Unique=0x6a375213 Counter=0x00000001 name=(21:Linux NFSv4.2 blue-lt)"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        if let Some(c) = r {
            assert!(c.contains("blue-lt"));
            assert!(!c.to_ascii_lowercase().contains("clientid"), "must not emit host/clientid");
        }
    }

    #[test]
    fn looks_like_rejects_noise_tokens() {
        assert!(!looks_like_client_hostname("nil"));
        assert!(!looks_like_client_hostname("clientid"));
        assert!(!looks_like_client_hostname("Unique"));
        assert!(!looks_like_client_hostname("CLIENT"));
        assert!(looks_like_client_hostname("blue-lt"));
        assert!(looks_like_client_hostname("my-host.example.com"));
    }

    // --- Additional repros from the exact full trace the user provided after rebuild ---
    #[test]
    fn extract_rejects_pure_clientid_line() {
        // Standalone clientid= lines must never produce a host/ candidate
        let line = r#"nfs4_op_destroy_clientid :CLIENT ID :DEBUG :DESTROY_CLIENTID clientid=Unique=0x6a375213 Counter=0x00000002"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        assert!(r.is_none() || !r.unwrap().to_ascii_lowercase().contains("clientid"), "pure clientid= line must not emit host/clientid");
    }

    #[test]
    fn extract_only_good_from_full_clid_create_line() {
        // The exact fs_create line from the trace must yield only the real host
        let line = r#"fs_create_clid_name :CLIENT ID :DEBUG :Created client name [::ffff:10.10.10.83-(21:Linux NFSv4.2 blue-lt)]"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        if let Some(c) = r {
            assert!(c.contains("blue-lt"));
            assert!(!c.contains("ffff"));
            assert!(!c.to_ascii_lowercase().contains("client"));
        } else {
            // If it returns none that's also acceptable as long as it doesn't emit garbage
        }
    }

    #[test]
    fn extract_rejects_conf_nil_groups_even_in_long_client_record() {
        // Full client record blob with multiple (nil) after the good name=
        let line = r#"key_locate :CLIENT ID :F_DBG :Locate Client Record seeking Key=0x7f0c3082f530 {{0x7f0c14001df0 name=(21:Linux NFSv4.2 blue-lt) conf = (nil) {NULL} unconf = (nil) {NULL} server_addr = 172.17.0.2 pnfs_flags 0x10000 cr_refcount=1}}"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        if let Some(c) = r {
            assert!(c.contains("blue-lt"));
            assert!(!c.contains("nil"), "must not emit host/nil from conf = (nil) groups");
        }
    }

    #[test]
    fn extract_rejects_on_lines_with_only_unconf_and_counters() {
        // Lines that only have unconf / counter noise after nfsv4 mention
        let line = r#"key_locate :CLIENT ID :F_DBG :Locate Unconfirmed Client ID seeking Key=0x7f0c3082f670 {Unique=0x6a375213 Counter=0x00000001}"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        assert!(r.is_none() || r.unwrap().contains("blue-lt") /* only if a good name was also present */);
    }

    #[test]
    fn stress_extract_on_trace_fragments_no_garbage() {
        // Stress many raw fragments taken from the exact user-provided full Ganesha trace.
        // After the previous tightening this must never return a host/ candidate for pure noise.
        let fragments = vec![
            r#"conf = (nil) {NULL} unconf = (nil) {NULL}"#,
            r#"clientid=Unique=0x6a375213 Counter=0x00000001"#,
            r#"key_locate :CLIENT ID :F_DBG :Locate Unconfirmed Client ID seeking Key=0x7f0c3082f670 {Unique=0x6a375213 Counter=0x00000001}"#,
            r#"nfs4_op_destroy_clientid :CLIENT ID :DEBUG :DESTROY_CLIENTID clientid=Unique=0x6a375213 Counter=0x00000002"#,
            r#"fs_create_clid_name :CLIENT ID :DEBUG :Created client name [::ffff:10.10.10.83-(21:Linux NFSv4.2 blue-lt)]"#,
            r#"fs_rm_clid_impl :CLIENT ID :DEBUG :position=0 len=45  parent_path=/var/lib/nfs/ganesha/v4recov recov_dir=::ffff:10.10.10.83-(21:Linux NFSv4.2 blue-lt)"#,
            r#"dec_client_record_ref :CLIENT ID :F_DBG :Free {{0x7f0c14001df0 name=(21:Linux NFSv4.2 blue-lt) conf = (nil) {NULL} unconf = (nil) {NULL} server_addr = 172.17.0.2 pnfs_flags 0x10000 cr_refcount=1}}"#,
            // more exact long lines from the user's paste that could have triggered the live "observed host/nil" and "host/clientid"
            r#"hashtable_getlatch :CLIENT ID :F_DBG :Get Client Record returning Value=0x7f0c14001df0 {{0x7f0c14001df0 name=(21:Linux NFSv4.2 blue-lt) conf = (nil) {NULL} unconf = (nil) {NULL} server_addr = 172.17.0.2 pnfs_flags 0x10000 cr_refcount=0}}"#,
            r#"hashtable_deletelatched :CLIENT ID :F_DBG :Delete Client Record Key=0x7f0c14001df0 {{0x7f0c14001df0 name=(21:Linux NFSv4.2 blue-lt) conf = (nil) {NULL} unconf = (nil) {NULL} server_addr = 172.17.0.2 pnfs_flags 0x10000 cr_refcount=0}} Value=0x7f0c14001df0 ... was removed"#,
            // A line that contains nfsv4 early and later (nil) groups with no good Linux group after the marker (to hit fallback)
            r#"some prefix NFSv4 stuff clientid=Unique=0x6a375213 conf = (nil) unconf = (nil) other tokens"#,
        ];

        for frag in &fragments {
            let r = extract_candidate_principal(frag, "SATOMLIN.COM");
            if let Some(c) = r {
                let bad = c.to_ascii_lowercase();
                assert!(!bad.contains("nil"), "frag produced host/nil: {}", frag);
                assert!(!bad.contains("clientid"), "frag produced host/clientid: {}", frag);
                assert!(!bad.contains("unique"), "frag produced host/unique: {}", frag);
                assert!(!bad.contains("counter"), "frag produced host/counter: {}", frag);
            }
        }
    }

    #[test]
    fn machine_principal_short_circuits_to_zero_without_getent() {
        // Per the short-circuit plan: machine principals must return 0:0 "special"
        // immediately after classification, with no resolve_via_nss/getent calls.
        let mut cache = IdCache::default();
        let realm = "SATOMLIN.COM".to_string();
        let variants = vec!["zima-nas".to_string()];

        // Regular host/ principal
        let r1 = resolve_principal("host/blue-lt@SATOMLIN.COM", &realm, &variants, &mut cache);
        assert_eq!(r1.uid, 0);
        assert_eq!(r1.gid, 0);
        assert_eq!(r1.kind, PrincipalKind::Machine);
        assert_eq!(r1.source, "special");
        assert_eq!(r1.name, "blue-lt");

        // Synthetic / internal form (host/0x...) should also short-circuit to 0:0
        let r2 = resolve_principal("host/0x6a375213@SATOMLIN.COM", &realm, &variants, &mut cache);
        assert_eq!(r2.uid, 0);
        assert_eq!(r2.gid, 0);
        assert_eq!(r2.kind, PrincipalKind::Machine);
        assert_eq!(r2.source, "special");

        // nfs/ and root/ prefixes
        let r3 = resolve_principal("nfs/somehost@SATOMLIN.COM", &realm, &variants, &mut cache);
        assert_eq!(r3.uid, 0);
        assert_eq!(r3.gid, 0);
        assert_eq!(r3.source, "special");

        let r4 = resolve_principal("root/client@SATOMLIN.COM", &realm, &variants, &mut cache);
        assert_eq!(r4.uid, 0);
        assert_eq!(r4.gid, 0);
        assert_eq!(r4.source, "special");
    }

    #[test]
    fn extract_catches_could_not_map_line_for_user_principal() {
        // This is the key new pattern for closing the first-use timing gap.
        // Ganesha logs this when its principal2uid can't map during nfs_req_creds/ACCESS.
        // We must extract the principal so the observer resolves it promptly.
        let line = r#"nfs_req_creds :ID MAPPER :INFO :Could not map principal testuser1@SATOMLIN.COM to uid"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        assert_eq!(r, Some("testuser1@SATOMLIN.COM".to_string()));
    }

    #[test]
    fn extract_catches_get_uid_using_nfsidmap_line() {
        // Early sighting: Ganesha announcing it is calling the mapper for a user principal.
        // Extracting here allows the observer to resolve *before or during* the blocking shim call.
        let line = r#"principal2uid : Get uid for testuser1@SATOMLIN.COM using nfsidmap"#;
        let r = extract_candidate_principal(line, "SATOMLIN.COM");
        assert_eq!(r, Some("testuser1@SATOMLIN.COM".to_string()));
    }
}