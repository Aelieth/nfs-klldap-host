//! Unix-socket daemon: long-lived resolver + Ganesha integration.

use crate::dlog;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::common::{
    get_realm, get_server_variants, is_machine_principal, IdCache, BULK_SEED_MARKER, CACHE_PATH,
    DEFAULT_REBULK_INTERVAL_SECS, SOCKET_PATH,
};
use crate::materialize::{
    apply_cache_to_nss_if_changed, materialize_nss_wrappers, sync_user_cache_from_snapshot,
};
use crate::observer::start_ganesha_observer;
use crate::resolve::{get_or_init_resolver, resolve_principal, ID_RESOLVER};

/// LDAP bulk load then nss materialize; must complete before supervisor starts ganesha.nfsd.
fn rebulk_ldap_users(cache: &mut IdCache, realm: &str) -> Option<usize> {
    let (r, dn, pw) = ID_RESOLVER.get().and_then(|o| o.as_ref())?;
    let loaded = r.load_full_identities(dn, pw);
    let snap = r.snapshot();
    let synced = sync_user_cache_from_snapshot(&snap, realm, cache);
    match apply_cache_to_nss_if_changed(cache) {
        Ok(true) => {}
        Ok(false) => dlog!("rebulk: nss materialize skipped (cache unchanged)"),
        Err(e) => {
            eprintln!("[idhelper] WARN: rebulk nss materialize failed: {}", e);
            return None;
        }
    }
    let _ = fs::write(BULK_SEED_MARKER, format!("{}\n", synced));
    eprintln!(
        "[idhelper] rebulk: ldap_loaded={} users_synced={} (nss_passwd refreshed)",
        loaded, synced
    );
    Some(synced)
}

fn rebulk_interval_secs() -> u64 {
    std::env::var("NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_REBULK_INTERVAL_SECS)
}

fn start_periodic_rebulk(cache: Arc<Mutex<IdCache>>, realm: String) {
    let secs = rebulk_interval_secs();
    if secs == 0 {
        eprintln!(
            "[idhelper] periodic LDAP rebulk disabled (NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS=0)"
        );
        return;
    }
    eprintln!(
        "[idhelper] periodic LDAP rebulk every {}s (NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS)",
        secs
    );
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(secs));
            let _ = get_or_init_resolver();
            if let Ok(mut guard) = cache.lock() {
                let _ = rebulk_ldap_users(&mut guard, &realm);
            }
        }
    });
}

pub(crate) fn run_daemon() {
    let realm = get_realm();
    let server_variants = get_server_variants();

    // Ensure runtime directories
    let _ = fs::create_dir_all("/var/run/nfs-klldap");
    let _ = fs::create_dir_all("/var/lib/nfs-klldap");
    let _ = fs::create_dir_all("/var/lib/extrausers");

    // Remove stale socket
    let _ = fs::remove_file(SOCKET_PATH);

    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("FATAL: cannot bind idhelper socket at {}: {}", SOCKET_PATH, e);
            std::process::exit(1);
        }
    };

    // Make socket world-accessible inside container (root only usage is also fine)
    let _ = fs::set_permissions(SOCKET_PATH, std::os::unix::fs::PermissionsExt::from_mode(0o666));

    // Load persisted cache (machines + any prior resolves). User rows are replaced
    // on first LDAP sync below — do not materialize stale users to nss_passwd yet.
    let cache = Arc::new(Mutex::new(IdCache::load_from_file(Path::new(CACHE_PATH))));

    println!("[idhelper] daemon listening on {}", SOCKET_PATH);
    println!("[idhelper] realm={} variants={:?}", realm, server_variants);

    // Eagerly initialize + bulk-load the full user+group map (10m authoritative cache).
    let _ = get_or_init_resolver();
    {
        let mut guard = cache.lock().unwrap();
        if let Some(seeded) = rebulk_ldap_users(&mut guard, &realm) {
            eprintln!(
                "[idhelper] initial sync: {} LDAP users in nss_wrapper (principal2uid/libnfsidmap path)",
                seeded
            );
        }
    }

    // Always auto pre-resolve the *server's own* host principals at cold start.
    for v in &server_variants {
        let p = format!("host/{}@{}", v, realm);
        let mut guard = cache.lock().unwrap();
        let _ = resolve_principal(&p, &realm, &server_variants, &mut guard);
        eprintln!("[idhelper] pre-resolved server host principal at startup: {}", p);
    }

    {
        let guard = cache.lock().unwrap();
        let _ = materialize_nss_wrappers(&guard);
    }

    if let Ok(list) = std::env::var("NFS_KLLDAP_IDHELPER_PRERESOLVE") {
        for p in list.split(',') {
            let p = p.trim();
            if !p.is_empty() {
                let mut guard = cache.lock().unwrap();
                let _ = resolve_principal(p, &realm, &server_variants, &mut guard);
                eprintln!("[idhelper] pre-resolved at startup: {}", p);
            }
        }
    }

    let cache_for_watcher = Arc::clone(&cache);
    start_ganesha_observer(realm.clone(), server_variants.clone(), cache_for_watcher);

    start_periodic_rebulk(Arc::clone(&cache), realm.clone());

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let realm = realm.clone();
                let variants = server_variants.clone();
                let cache = Arc::clone(&cache);
                thread::spawn(move || {
                    if let Err(e) = handle_client(s, &realm, &variants, &cache) {
                        eprintln!("[idhelper] client error: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("[idhelper] accept error: {}", e);
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Handle one idhelper socket request; shared by daemon accept loop and tests.
pub(crate) fn dispatch_idhelper_request(
    req: &str,
    realm: &str,
    server_variants: &[String],
    cache: &mut IdCache,
) -> String {
    let mut parts = req.splitn(2, ' ');
    let verb = parts.next().unwrap_or("").to_ascii_uppercase();
    let arg = parts.next().unwrap_or("").trim();

    match verb.as_str() {
        "PING" => "OK\n".to_string(),
        "CLASSIFY" => {
            if arg.is_empty() {
                "ERR missing principal\n".to_string()
            } else {
                let (is_m, reason) = is_machine_principal(arg, realm, server_variants);
                let k = if is_m { "machine" } else { "user" };
                format!("OK {}|{}\n", k, reason)
            }
        }
        "RESOLVE" => {
            if arg.is_empty() {
                "ERR missing principal\n".to_string()
            } else {
                dlog!("socket RESOLVE arg=\"{}\"", arg);
                let r = resolve_principal(arg, realm, server_variants, cache);
                format!(
                    "OK {}|{}|{}|{}|{}\n",
                    r.principal, r.uid, r.gid, r.kind.as_str(), r.source
                )
            }
        }
        "REBULK" => match rebulk_ldap_users(cache, realm) {
            Some(n) => format!("OK {}\n", n),
            None => "ERR rebulk failed\n".to_string(),
        },
        _ => "ERR unknown command\n".to_string(),
    }
}

fn handle_client(
    mut stream: UnixStream,
    realm: &str,
    server_variants: &[String],
    cache: &Arc<Mutex<IdCache>>,
) -> io::Result<()> {
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let req = line.trim();
    if req.is_empty() {
        return Ok(());
    }

    let out = {
        let mut guard = cache.lock().unwrap();
        dispatch_idhelper_request(req, realm, server_variants, &mut guard)
    };

    stream.write_all(out.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod socket_resolve_tests {
    use super::*;
    use crate::common::{
        last_materialized_fingerprint_for_tests, record_materialized_fingerprint,
        reset_materialize_fingerprint_for_tests, PrincipalKind, Resolved, CACHE_PATH,
        MATERIALIZE_FP_TEST_LOCK, NSS_PASSWD_PATH,
    };
    use crate::resolve::set_test_nss_resolve_for_tests;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn ensure_idhelper_runtime_dirs() {
        let _ = fs::create_dir_all("/var/lib/nfs-klldap");
        let _ = fs::create_dir_all("/var/lib/extrausers");
        let _ = fs::create_dir_all("/var/run/nfs-klldap");
    }

    #[test]
    fn socket_resolve_user_miss_materializes_nss_and_records_fp() {
        let _g = MATERIALIZE_FP_TEST_LOCK.lock().unwrap();
        reset_materialize_fingerprint_for_tests();
        ensure_idhelper_runtime_dirs();
        set_test_nss_resolve_for_tests(Some(HashMap::from([(
            "alice".to_string(),
            (1001, 1001, "sss".to_string()),
        )])));

        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("idhelper.sock");
        let listener = UnixListener::bind(&sock).expect("bind socket");
        let cache = Arc::new(Mutex::new(IdCache::default()));
        let realm = "EX.COM".to_string();
        let variants = vec!["srv".to_string()];
        let cache_t = Arc::clone(&cache);
        let realm_t = realm.clone();
        let variants_t = variants.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            handle_client(stream, &realm_t, &variants_t, &cache_t).expect("handle");
        });

        let mut client = UnixStream::connect(&sock).expect("connect");
        writeln!(client, "RESOLVE alice@EX.COM").expect("write");
        let mut resp = String::new();
        client.read_to_string(&mut resp).expect("read");
        server.join().expect("server join");

        assert_eq!(resp.trim(), "OK alice@EX.COM|1001|1001|user|sss");

        let guard = cache.lock().unwrap();
        assert_eq!(
            last_materialized_fingerprint_for_tests(),
            Some(guard.content_fingerprint())
        );
        let nss = fs::read_to_string(NSS_PASSWD_PATH).expect("nss_passwd");
        assert!(
            nss.contains("alice:x:1001:1001:"),
            "socket RESOLVE must materialize user into nss_passwd"
        );
        let cache_txt = fs::read_to_string(CACHE_PATH).expect("cache file");
        assert!(
            cache_txt.contains("alice@EX.COM|1001|1001|user|sss"),
            "socket RESOLVE must persist cache"
        );

        set_test_nss_resolve_for_tests(None);
    }

    #[test]
    fn dispatch_resolve_cache_hit_skips_materialize() {
        let _g = MATERIALIZE_FP_TEST_LOCK.lock().unwrap();
        reset_materialize_fingerprint_for_tests();
        ensure_idhelper_runtime_dirs();

        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "host/cached@EX.COM".into(),
            name: "cached".into(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".into(),
        });
        record_materialized_fingerprint(&cache);
        let nss_before = fs::read(NSS_PASSWD_PATH).unwrap_or_default();

        let resp = dispatch_idhelper_request(
            "RESOLVE host/cached@EX.COM",
            "EX.COM",
            &["srv".to_string()],
            &mut cache,
        );
        assert_eq!(resp.trim(), "OK host/cached@EX.COM|0|0|machine|cache");

        let nss_after = fs::read(NSS_PASSWD_PATH).unwrap_or_default();
        assert_eq!(nss_before, nss_after, "cache HIT must not rewrite nss_passwd");
        assert_eq!(
            last_materialized_fingerprint_for_tests(),
            Some(cache.content_fingerprint())
        );
    }
}