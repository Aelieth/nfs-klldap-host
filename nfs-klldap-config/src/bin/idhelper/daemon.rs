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
    get_realm, get_server_variants, IdCache, BULK_SEED_MARKER, CACHE_PATH,
    DEFAULT_REBULK_INTERVAL_SECS, SOCKET_PATH,
};
use nfs_klldap_config::{classify_principal, IdMapSnapshot};

use crate::materialize::{
    cache_changed_since, materialize_nss_wrappers, materialize_nss_wrappers_at,
    sync_user_cache_from_snapshot, NssMaterializePaths,
};
use crate::observer::start_ganesha_observer;
use crate::resolve::{get_or_init_resolver, resolve_principal, ID_RESOLVER};

/// Paths rebulk writes: idmap cache, bulk-seed marker, nss_wrapper outputs.
#[derive(Clone, Copy)]
pub(crate) struct RebulkPaths<'a> {
    pub cache_path: &'a Path,
    pub bulk_seed_marker: &'a Path,
    pub nss: NssMaterializePaths<'a>,
}

impl RebulkPaths<'_> {
    pub(crate) fn production() -> RebulkPaths<'static> {
        RebulkPaths {
            cache_path: Path::new(CACHE_PATH),
            bulk_seed_marker: Path::new(BULK_SEED_MARKER),
            nss: NssMaterializePaths::production(),
        }
    }
}

/// Outcome of rebulk_apply_sync for tests asserting materialize skip vs execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RebulkOutcome {
    pub synced: usize,
    pub materialized: bool,
}

/// Sync LDAP snapshot into cache; materialize nss when fingerprint changes.
pub(crate) fn rebulk_apply_sync(
    cache: &mut IdCache,
    realm: &str,
    snap: &IdMapSnapshot,
    paths: &RebulkPaths<'_>,
) -> Result<RebulkOutcome, io::Error> {
    let fp_before = cache.content_fingerprint();
    let synced = sync_user_cache_from_snapshot(snap, realm, cache);
    let materialized = if cache_changed_since(fp_before, cache) {
        materialize_nss_wrappers_at(cache, &paths.nss, Some(&snap.groups))?;
        cache.write_to_file(paths.cache_path)?;
        true
    } else {
        false
    };
    fs::write(paths.bulk_seed_marker, format!("{}\n", synced))?;
    Ok(RebulkOutcome {
        synced,
        materialized,
    })
}

#[cfg(test)]
pub(crate) mod test_rebulk {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use super::*;

    #[derive(Clone)]
    pub(crate) struct TestRebulkOverride {
        pub snap: IdMapSnapshot,
        pub paths: RebulkPaths<'static>,
    }

    thread_local! {
        static TEST_REBULK: RefCell<Option<TestRebulkOverride>> = const { RefCell::new(None) };
    }

    pub(crate) fn current_override() -> Option<TestRebulkOverride> {
        TEST_REBULK.with(|slot| slot.borrow().clone())
    }

    pub(crate) fn with_test_rebulk_override<F, R>(ov: TestRebulkOverride, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        TEST_REBULK.with(|slot| {
            *slot.borrow_mut() = Some(ov);
        });
        let out = f();
        TEST_REBULK.with(|slot| {
            *slot.borrow_mut() = None;
        });
        out
    }

    pub(crate) fn rebulk_paths_in(base: &Path) -> RebulkPaths<'static> {
        let leak = |p: PathBuf| -> &'static Path {
            Box::leak(p.into_boxed_path())
        };
        RebulkPaths {
            cache_path: leak(base.join("idmap.cache")),
            bulk_seed_marker: leak(base.join(".bulk_seed_done")),
            nss: NssMaterializePaths {
                nss_passwd: leak(base.join("nss_passwd")),
                nss_group: leak(base.join("nss_group")),
                extrausers_passwd: leak(base.join("extrausers/passwd")),
                extrausers_group: leak(base.join("extrausers/group")),
            },
        }
    }
}

/// LDAP bulk load and nss materialize; must finish before ganesha.nfsd starts.
pub(crate) fn rebulk_ldap_users(cache: &mut IdCache, realm: &str) -> Option<usize> {
    #[cfg(test)]
    if let Some(ov) = test_rebulk::current_override() {
        return match rebulk_apply_sync(cache, realm, &ov.snap, &ov.paths) {
            Ok(o) => Some(o.synced),
            Err(e) => {
                eprintln!("[idhelper] WARN: rebulk nss materialize failed: {}", e);
                None
            }
        };
    }

    let (r, dn, pw) = ID_RESOLVER.get().and_then(|o| o.as_ref())?;
    let loaded = r.load_full_identities(dn, pw);
    let snap = r.snapshot();
    let fp_before = cache.content_fingerprint();
    match rebulk_apply_sync(cache, realm, &snap, &RebulkPaths::production()) {
        Ok(o) => {
            if o.materialized {
                eprintln!(
                    "[idhelper] rebulk: ldap_loaded={} users_synced={} (nss_passwd refreshed, fp 0x{:x}->0x{:x})",
                    loaded, o.synced, fp_before, cache.content_fingerprint()
                );
            } else {
                eprintln!(
                    "[idhelper] rebulk: ldap_loaded={} users_synced={} (nss unchanged, fp=0x{:x})",
                    loaded, o.synced, fp_before
                );
            }
            Some(o.synced)
        }
        Err(e) => {
            eprintln!("[idhelper] WARN: rebulk nss materialize failed: {}", e);
            None
        }
    }
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

    // Load persisted cache; user rows refresh on first LDAP sync below.
    let cache = Arc::new(Mutex::new(IdCache::load_from_file(Path::new(CACHE_PATH))));

    println!("[idhelper] daemon listening on {}", SOCKET_PATH);
    println!("[idhelper] realm={} variants={:?}", realm, server_variants);

    // Eagerly bulk-load the full user+group map into the 10m resolver cache.
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

    // Always auto pre-resolve the *server's own* host nfs service
    // Principals at cold start.
    for v in &server_variants {
        for prefix in ["host", "nfs"] {
            let p = format!("{}/{}@{}", prefix, v, realm);
            let mut guard = cache.lock().unwrap();
            let _ = resolve_principal(&p, &realm, &server_variants, &mut guard);
            eprintln!(
                "[idhelper] pre-resolved server {} principal at startup: {}",
                prefix, p
            );
        }
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

    let mut parts = req.splitn(2, ' ');
    let verb = parts.next().unwrap_or("").to_ascii_uppercase();
    let arg = parts.next().unwrap_or("").trim();

    let mut out = String::new();

    match verb.as_str() {
        "PING" => {
            out.push_str("OK\n");
        }
        "CLASSIFY" => {
            if arg.is_empty() {
                out.push_str("ERR missing principal\n");
            } else {
                let (is_m, reason) = classify_principal(arg, realm, server_variants);
                let k = if is_m { "machine" } else { "user" };
                out.push_str(&format!("OK {}|{}\n", k, reason));
            }
        }
        "RESOLVE" => {
            if arg.is_empty() {
                out.push_str("ERR missing principal\n");
            } else {
                dlog!("socket RESOLVE arg=\"{}\"", arg);
                let mut guard = cache.lock().unwrap();
                let r = resolve_principal(arg, realm, server_variants, &mut guard);
                out.push_str(&format!(
                    "OK {}|{}|{}|{}|{}\n",
                    r.principal, r.uid, r.gid, r.kind.as_str(), r.source
                ));
            }
        }
        "REBULK" => {
            let mut guard = cache.lock().unwrap();
            match rebulk_ldap_users(&mut guard, realm) {
                Some(n) => out.push_str(&format!("OK {}\n", n)),
                None => out.push_str("ERR rebulk failed\n"),
            }
        }
        _ => {
            out.push_str("ERR unknown command\n");
        }
    }

    stream.write_all(out.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod rebulk_ldap_users_tests {
    use super::test_rebulk::{rebulk_paths_in, with_test_rebulk_override, TestRebulkOverride};
    use super::*;
    use nfs_klldap_config::{PosixGroupEntry, PosixUserEntry};
    use std::fs;
    use std::thread::sleep;
    use std::time::Duration;

    fn alice_snapshot() -> IdMapSnapshot {
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
        snap
    }

    #[test]
    fn rebulk_ldap_users_materializes_nss_on_first_sync() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = rebulk_paths_in(tmp.path());
        let ov = TestRebulkOverride {
            snap: alice_snapshot(),
            paths,
        };
        with_test_rebulk_override(ov, || {
            let mut cache = IdCache::default();
            let n = rebulk_ldap_users(&mut cache, "EX.COM").expect("rebulk succeeds");
            assert_eq!(n, 1);
            let passwd = fs::read_to_string(paths.nss.nss_passwd).expect("nss_passwd written");
            assert!(passwd.contains("alice:x:1001:1001:"));
            assert!(fs::metadata(paths.bulk_seed_marker).is_ok());
        });
    }

    #[test]
    fn rebulk_ldap_users_skips_nss_rewrite_when_snapshot_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = rebulk_paths_in(tmp.path());
        let ov = TestRebulkOverride {
            snap: alice_snapshot(),
            paths,
        };
        with_test_rebulk_override(ov, || {
            let mut cache = IdCache::default();
            assert!(rebulk_ldap_users(&mut cache, "EX.COM").is_some());
            let mtime1 = fs::metadata(paths.nss.nss_passwd)
                .expect("first rebulk writes nss_passwd")
                .modified()
                .unwrap();
            sleep(Duration::from_millis(50));
            assert!(rebulk_ldap_users(&mut cache, "EX.COM").is_some());
            let mtime2 = fs::metadata(paths.nss.nss_passwd)
                .unwrap()
                .modified()
                .unwrap();
            assert_eq!(
                mtime1, mtime2,
                "unchanged LDAP snapshot must not rewrite nss_passwd"
            );
        });
    }

    #[test]
    fn rebulk_ldap_users_rewrites_nss_when_snapshot_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = rebulk_paths_in(tmp.path());
        let mut snap1 = alice_snapshot();
        let ov1 = TestRebulkOverride {
            snap: snap1.clone(),
            paths,
        };
        with_test_rebulk_override(ov1, || {
            let mut cache = IdCache::default();
            assert!(rebulk_ldap_users(&mut cache, "EX.COM").is_some());
        });

        snap1.users.insert(
            "bob".to_string(),
            PosixUserEntry {
                uid: 1002,
                gid: 1002,
                display: "Bob".to_string(),
            },
        );
        snap1.by_uid.insert(1002, "bob".to_string());
        let ov2 = TestRebulkOverride { snap: snap1, paths };
        with_test_rebulk_override(ov2, || {
            let mut cache = IdCache::default();
            sync_user_cache_from_snapshot(&alice_snapshot(), "EX.COM", &mut cache);
            let mtime_before = fs::metadata(paths.nss.nss_passwd).unwrap().modified().unwrap();
            sleep(Duration::from_millis(50));
            assert!(rebulk_ldap_users(&mut cache, "EX.COM").is_some());
            let mtime_after = fs::metadata(paths.nss.nss_passwd).unwrap().modified().unwrap();
            assert_ne!(mtime_before, mtime_after);
            let passwd = fs::read_to_string(paths.nss.nss_passwd).unwrap();
            assert!(passwd.contains("bob:x:1002:1002:"));
        });
    }

    #[test]
    fn rebulk_materializes_ldap_group_member_lists() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = rebulk_paths_in(tmp.path());
        let mut snap = alice_snapshot();
        snap.groups.insert(
            "devs".to_string(),
            PosixGroupEntry {
                gid: 500,
                display: "devs".to_string(),
                members: vec!["alice".to_string(), "bob".to_string()],
            },
        );
        snap.by_gid.insert(500, "devs".to_string());
        let ov = TestRebulkOverride { snap, paths };
        with_test_rebulk_override(ov, || {
            let mut cache = IdCache::default();
            assert!(rebulk_ldap_users(&mut cache, "EX.COM").is_some());
            let group = fs::read_to_string(paths.nss.nss_group).expect("nss_group written");
            assert!(
                group.contains("devs:x:500:alice,bob"),
                "LDAP member preload must appear in nss group line; got:\n{group}"
            );
        });
    }

    #[test]
    fn rebulk_apply_sync_reports_materialized_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = rebulk_paths_in(tmp.path());
        let snap = alice_snapshot();
        let mut cache = IdCache::default();
        let first = rebulk_apply_sync(&mut cache, "EX.COM", &snap, &paths).unwrap();
        assert!(first.materialized);
        let second = rebulk_apply_sync(&mut cache, "EX.COM", &snap, &paths).unwrap();
        assert!(!second.materialized);
    }
}
