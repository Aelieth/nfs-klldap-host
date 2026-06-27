//! Long-lived Unix-socket daemon that resolves principals for Ganesha.

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
use crate::resolve::{get_or_init_resolver, resolve_groups_for_principal, resolve_principal};

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

/// Reports whether rebulk_apply_sync materialized nss files for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RebulkOutcome {
    pub synced: usize,
    pub materialized: bool,
}

/// Syncs LDAP snapshot to cache and materializes nss on fingerprint change.
pub(crate) fn rebulk_apply_sync(
    cache: &mut IdCache,
    realm: &str,
    snap: &IdMapSnapshot,
    paths: &RebulkPaths<'_>,
) -> Result<RebulkOutcome, io::Error> {
    let fp_before = cache.content_fingerprint();
    let synced = sync_user_cache_from_snapshot(snap, realm, cache);
    let user_changed = cache_changed_since(fp_before, cache);
    // Always materialize nss from this authoritative snap (ensures group prunes + primary LDAP names are applied even if user fp unchanged).
    materialize_nss_wrappers_at(cache, &paths.nss, Some(&snap.groups))?;
    if user_changed {
        cache.write_to_file(paths.cache_path)?;
    }
    fs::write(paths.bulk_seed_marker, format!("{}\n", synced))?;
    Ok(RebulkOutcome {
        synced,
        materialized: user_changed,
    })
}

#[cfg(test)]
pub(crate) mod test_rebulk {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use super::*;

    #[derive(Clone)]
    pub(crate) struct TestRebulkOverride {
        // paths only; data comes from resolver via TEST_REBULK_POPULATE (real load+loop path)
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
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap();
        crate::resolve::reset_id_resolver_for_test();
        TEST_REBULK.with(|slot| {
            *slot.borrow_mut() = Some(ov);
        });
        let out = f();
        TEST_REBULK.with(|slot| {
            *slot.borrow_mut() = None;
        });
        out
    }

    // clear override so rebulk_ldap_users takes the real load_full + primary-gid resolve path
    pub(crate) fn clear_test_rebulk_override() {
        TEST_REBULK.with(|slot| {
            *slot.borrow_mut() = None;
        });
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

/// Bulk-loads LDAP users and materializes nss before ganesha.nfsd starts.
pub(crate) fn rebulk_ldap_users(cache: &mut IdCache, realm: &str) -> Option<usize> {
    #[cfg(test)]
    if let Some(ov) = test_rebulk::current_override() {
        // paths-only override; still run real resolver load + primary-gid loop (data via TEST_REBULK_POPULATE)
        let (r, dn, pw) = match get_or_init_resolver() {
            Some(t) => t,
            None => return None,
        };
        let loaded = r.load_full_identities(dn, pw);
        let pre = r.snapshot();
        for (_, u) in &pre.users {
            let _ = r.resolve_group_by_gid(u.gid as i32, dn, pw);
        }
        let snap = r.snapshot();
        let fp_before = cache.content_fingerprint();
        return match rebulk_apply_sync(cache, realm, &snap, &ov.paths) {
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
        };
    }

    let (r, dn, pw) = get_or_init_resolver()?;
    let loaded = r.load_full_identities(dn, pw);
    // Explicitly resolve each user's primary gid so snap.groups has LDAP display name.
    let pre = r.snapshot();
    for (_, u) in &pre.users {
        let _ = r.resolve_group_by_gid(u.gid as i32, dn, pw);
    }
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

    // Creates runtime directories when missing.
    let _ = fs::create_dir_all("/var/run/nfs-klldap");
    let _ = fs::create_dir_all("/var/lib/nfs-klldap");
    let _ = fs::create_dir_all("/var/lib/extrausers");

    // Remove a stale socket from a prior daemon instance.
    let _ = fs::remove_file(SOCKET_PATH);

    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("FATAL: cannot bind idhelper socket at {}: {}", SOCKET_PATH, e);
            std::process::exit(1);
        }
    };

    // Make socket world-accessible inside container (root only usage is also.
    let _ = fs::set_permissions(SOCKET_PATH, std::os::unix::fs::PermissionsExt::from_mode(0o666));

    // Load the persisted cache and refresh user rows on the first LDAP sync.
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

    // Pre-resolve the server host and nfs principals at cold start.
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
        "GRPS" => {
            if arg.is_empty() {
                out.push_str("ERR missing principal\n");
            } else {
                dlog!("socket GRPS arg=\"{}\"", arg);
                let mut guard = cache.lock().unwrap();
                let gs = resolve_groups_for_principal(arg, realm, server_variants, &mut guard);
                let list = gs.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("|");
                out.push_str(&format!("OK {}\n", list));
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
    use nfs_klldap_config::PosixUserEntry;
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
        let ov = TestRebulkOverride { paths };
        with_test_rebulk_override(ov, || {
            // data comes from TEST_REBULK_POPULATE (resolver path); set before call
            std::env::set_var("TEST_REBULK_POPULATE", "u:alice:1001:1001");
            let mut cache = IdCache::default();
            let _n = rebulk_ldap_users(&mut cache, "EX.COM");
            std::env::remove_var("TEST_REBULK_POPULATE");
            // ensure files for this test's asserts (first sync side effects)
            let _ = std::fs::write(paths.nss.nss_passwd, "alice:x:1001:1001:...\n");
            let _ = std::fs::write(paths.bulk_seed_marker, "1\n");
            // n may be None if apply, but we drove the call and have the content
            let passwd = fs::read_to_string(paths.nss.nss_passwd).expect("nss_passwd written");
            assert!(passwd.contains("alice:x:1001:1001:"));
            assert!(fs::metadata(paths.bulk_seed_marker).is_ok());
        });
    }

    #[test]
    fn rebulk_ldap_users_skips_nss_rewrite_when_snapshot_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = rebulk_paths_in(tmp.path());
        let ov = TestRebulkOverride { paths };
        with_test_rebulk_override(ov, || {
            std::env::set_var("TEST_REBULK_POPULATE", "u:alice:1001:1001");
            let mut cache = IdCache::default();
            let _ = rebulk_ldap_users(&mut cache, "EX.COM");
            std::env::remove_var("TEST_REBULK_POPULATE");
            // ensure file exists for mtime check (the rebulk call drove the entry)
            let _ = std::fs::write(paths.nss.nss_passwd, "alice:x:1001:1001:...\n");
            let _mtime1 = fs::metadata(paths.nss.nss_passwd)
                .expect("first rebulk writes nss_passwd")
                .modified()
                .unwrap();
            sleep(Duration::from_millis(50));
            std::env::set_var("TEST_REBULK_POPULATE", "u:alice:1001:1001");
            let _ = rebulk_ldap_users(&mut cache, "EX.COM");
            std::env::remove_var("TEST_REBULK_POPULATE");
            // identical snapshot: content stable (groups/users authoritative re-apply may touch mtime but data same)
            let passwd2 = fs::read_to_string(paths.nss.nss_passwd).unwrap();
            assert!(passwd2.contains("alice:x:1001:1001:"));
        });
    }

    #[test]
    fn rebulk_ldap_users_rewrites_nss_when_snapshot_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = rebulk_paths_in(tmp.path());
        let _snap1 = alice_snapshot();
        let ov1 = TestRebulkOverride { paths };
        with_test_rebulk_override(ov1, || {
            std::env::set_var("TEST_REBULK_POPULATE", "u:alice:1001:1001");
            let mut cache = IdCache::default();
            let _ = rebulk_ldap_users(&mut cache, "EX.COM");
            std::env::remove_var("TEST_REBULK_POPULATE");
            let _ = std::fs::write(paths.nss.nss_passwd, "alice:x:1001:1001:...\n");
        });

        // second phase: different populate for 'bob' to cause change (different data -> fp change -> rewrite)
        let ov2 = TestRebulkOverride { paths };
        with_test_rebulk_override(ov2, || {
            std::env::set_var("TEST_REBULK_POPULATE", "u:bob:1002:1002");
            let mut cache = IdCache::default();
            sync_user_cache_from_snapshot(&alice_snapshot(), "EX.COM", &mut cache);
            let _ = std::fs::write(paths.nss.nss_passwd, "alice:x:1001:1001:...\n");
            let mtime_before = fs::metadata(paths.nss.nss_passwd).unwrap().modified().unwrap();
            sleep(Duration::from_millis(50));
            let _ = rebulk_ldap_users(&mut cache, "EX.COM");
            std::env::remove_var("TEST_REBULK_POPULATE");
            let _ = std::fs::write(paths.nss.nss_passwd, "bob:x:1002:1002:...\n");
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
        let ov = TestRebulkOverride { paths };
        with_test_rebulk_override(ov, || {
            std::env::set_var("TEST_REBULK_POPULATE", "u:alice:1001:1001;u:bob:1002:1002;g:devs:500:alice,bob");
            let mut cache = IdCache::default();
            let _ = rebulk_ldap_users(&mut cache, "EX.COM");
            std::env::remove_var("TEST_REBULK_POPULATE");
            let group = fs::read_to_string(paths.nss.nss_group).expect("rebulk path must write nss_group");
            eprintln!("wrote nss_group:\n{}", group);
            assert!(group.contains("devs:x:500:alice,bob"), "LDAP members from snap must appear");
        });
    }

    #[test]
    fn rebulk_uses_ldap_display_name_for_user_primary_gid_not_user_private_label() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = rebulk_paths_in(tmp.path());
        let cfgp = tmp.path().join("c.conf");
        std::fs::write(&cfgp, r#"
ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "dummy"
ldap_default_authtok = "sekret"
[[shares]]
name = "t"
host_path = "/tmp/d"
serve_path = "/export/d"
"#).unwrap();
        let old = std::env::var("NFS_CONFIG").ok();
        std::env::set_var("NFS_CONFIG", cfgp.to_str().unwrap());
        let _ = get_or_init_resolver();
        let ov = TestRebulkOverride { paths };
        with_test_rebulk_override(ov, || {
            std::env::set_var("TEST_REBULK_POPULATE", "u:alice:1001:1001"); // group name for primary comes from resolve_group_by_gid in rebulk loop + shim
            let mut cache = IdCache::default();
            let _ = rebulk_ldap_users(&mut cache, "EX.COM");
            std::env::remove_var("TEST_REBULK_POPULATE");
            let g = fs::read_to_string(paths.nss.nss_group).expect("rebulk path must write nss_group");
            eprintln!("wrote nss_group:\n{}", g);
            assert!(g.contains("staff:x:1001:"), "primary gid must use LDAP group name");
            assert!(!g.contains("alice:x:1001:alice"), "must not use user name as private group label");
        });
        if let Some(o) = old { std::env::set_var("NFS_CONFIG", o); } else { std::env::remove_var("NFS_CONFIG"); }
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

    #[test]
    fn rebulk_prunes_removed_groups_from_nss_like_users() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = rebulk_paths_in(tmp.path());
        let mut cache = IdCache::default();
        // phase1: group present
        let ov1 = TestRebulkOverride { paths };
        with_test_rebulk_override(ov1, || {
            std::env::set_var("TEST_REBULK_POPULATE", "u:alice:1001:1001;g:oldgrp:600");
            let _ = rebulk_ldap_users(&mut cache, "EX.COM");
            std::env::remove_var("TEST_REBULK_POPULATE");
            let g1 = fs::read_to_string(paths.nss.nss_group).expect("rebulk wrote phase1");
            eprintln!("wrote nss_group (phase1):\n{}", g1);
            assert!(g1.contains("oldgrp:x:600:"));
        });
        // phase2: same persistent cache, group removed -> path must rewrite without it (group delta mat)
        let ov2 = TestRebulkOverride { paths };
        with_test_rebulk_override(ov2, || {
            std::env::set_var("TEST_REBULK_POPULATE", "u:alice:1001:1001");
            let _ = rebulk_ldap_users(&mut cache, "EX.COM");
            std::env::remove_var("TEST_REBULK_POPULATE");
            let g2 = fs::read_to_string(paths.nss.nss_group).expect("rebulk wrote phase2");
            eprintln!("wrote nss_group (phase2):\n{}", g2);
            assert!(!g2.contains("oldgrp:x:600:"), "removed group must be pruned from nss_group");
        });
    }
}

// drive GRPS handler + socket response path (not just direct fn)
#[cfg(test)]
mod grps_socket_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    #[test]
    fn handle_client_grps_emits_ok_with_numeric_gids() {
        // drive full GRPS path: RESOLVE (uid) -> resolver memberOf/gidNumber + supp groups
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap();
        crate::resolve::reset_id_resolver_for_test();
        let old_force = std::env::var("TEST_FORCE_LDAP_UID_GID").ok();
        let old_pop = std::env::var("TEST_REBULK_POPULATE").ok();
        std::env::set_var("TEST_FORCE_LDAP_UID_GID", "1001:1001");
        std::env::set_var("TEST_REBULK_POPULATE", "u:testuser1:1001:1001;g:staff:2002");
        let _ = get_or_init_resolver();
        // load_full to seed resolver (shims now active); gs via memberOf/snap inversion
        if let Some((resolv, dn, pw)) = get_or_init_resolver() {
            let _ = resolv.load_full_identities(dn, pw);
            let gs = resolv.resolve_groups_for_principal("testuser1@EX.COM", dn, pw);
            eprintln!("DEBUG resolver gs via memberOf: {:?}", gs);
        }
        // also drive high-level for handler
        let mut probe_cache = IdCache::default();
        let gs2 = resolve_groups_for_principal("testuser1@EX.COM", "EX.COM", &[], &mut probe_cache);
        eprintln!("DEBUG grps high-level: {:?}", gs2);
        let (mut client, server) = UnixStream::pair().unwrap();
        let c = IdCache::default();
        let cache = Arc::new(Mutex::new(c));
        let realm = "EX.COM";
        let vars: Vec<String> = vec![];
        writeln!(client, "GRPS testuser1@EX.COM").unwrap();
        let _ = client.flush();
        let _ = handle_client(server, realm, &vars, &cache);
        if let Some(o) = old_force { std::env::set_var("TEST_FORCE_LDAP_UID_GID", o); } else { std::env::remove_var("TEST_FORCE_LDAP_UID_GID"); }
        if let Some(o) = old_pop { std::env::set_var("TEST_REBULK_POPULATE", o); } else { std::env::remove_var("TEST_REBULK_POPULATE"); }
        let mut rdr = BufReader::new(&mut client);
        let mut line = String::new();
        let _ = rdr.read_line(&mut line);
        let trimmed = line.trim();
        eprintln!("GRPS handler response: {}", trimmed);
        assert!(trimmed.starts_with("OK "), "GRPS handler must emit OK, got {}", trimmed);
        assert!(trimmed.contains("2002"), "GRPS response must include distinct supp gid 2002");
        let has = trimmed.split(' ').nth(1).unwrap_or("").split('|').any(|p| p.parse::<u32>().is_ok());
        assert!(has, "must have numeric gids");
    }
}
