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
    get_realm, get_server_variants, is_machine_principal, IdCache, CACHE_PATH, SOCKET_PATH,
};
use crate::common::BULK_SEED_MARKER;
use crate::materialize::{materialize_nss_wrappers, seed_cache_and_nss_from_snapshot};
use crate::observer::start_ganesha_observer;
use crate::resolve::{get_or_init_resolver, resolve_principal, ID_RESOLVER};

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

    let cache = Arc::new(Mutex::new(IdCache::load_from_file(Path::new(CACHE_PATH))));

    // Immediately materialize any cached principals into the nss_wrapper files.
    // Ganesha may already be (or will soon be) running under LD_PRELOAD against these files.
    {
        let guard = cache.lock().unwrap();
        let _ = materialize_nss_wrappers(&guard);
    }

    println!("[idhelper] daemon listening on {}", SOCKET_PATH);
    println!("[idhelper] realm={} variants={:?}", realm, server_variants);

    // Eagerly initialize + bulk-load the full user+group map (10m authoritative cache).
    // This is the central "bring in all users and groups with aligned gid/uid" step.
    // All subsequent nfsidmap / resolve / materialize paths prefer this in-memory data.
    let _ = get_or_init_resolver();
    if let Some((r, dn, pw)) = ID_RESOLVER.get().and_then(|o| o.as_ref()) {
        let n = r.load_full_identities(dn, pw);
        eprintln!("[idhelper] bulk-loaded {} users+groups into 10m identity cache", n);

        // Seed nss_wrapper/extrausers with every LDAP user so Ganesha's in-process
        // libnfsidmap principal2uid path (getpwnam under LD_PRELOAD) succeeds on the
        // first krb5 compound — the nfsidmap binary shim is not on that code path.
        let snap = r.snapshot();
        let mut guard = cache.lock().unwrap();
        let seeded = seed_cache_and_nss_from_snapshot(&snap, &realm, &mut guard);
        if let Err(e) = materialize_nss_wrappers(&guard) {
            eprintln!("[idhelper] WARN: bulk nss materialize failed: {}", e);
        } else {
            eprintln!(
                "[idhelper] bulk-seeded {} users into nss_wrapper (principal2uid/libnfsidmap path)",
                seeded
            );
            let _ = fs::write(BULK_SEED_MARKER, format!("{}\n", seeded));
        }
        drop(guard);
    }

    // Always auto pre-resolve the *server's own* host principals at cold start.
    // This ensures machine->uid0 (including the synthetic root entry) is materialized
    // in nss_wrapper/extrausers *before* Ganesha serves any compounds. Fixes the
    // repeated "getpwuid_r for uid 0 failed, error 2" + "Unsupported code path" for
    // host/ principals seen on first access in logs. Uses the same config-driven
    // variants + realm that the rest of the stack uses.
    for v in &server_variants {
        let p = format!("host/{}@{}", v, realm);
        let mut guard = cache.lock().unwrap();
        let _ = resolve_principal(&p, &realm, &server_variants, &mut guard);
        eprintln!("[idhelper] pre-resolved server host principal at startup: {}", p);
    }

    // Re-materialize after any auto pre-resolves (root + server hosts).
    {
        let guard = cache.lock().unwrap();
        let _ = materialize_nss_wrappers(&guard);
    }

    // Optional pre-resolution at startup (for testing or known environments).
    // Set e.g. NFS_KLLDAP_IDHELPER_PRERESOLVE="testuser1@REALM,alice@REALM"
    // Optional extra pre-resolve for known users (bulk seed already covers LDAP users).
    // Operators can use this (via entrypoint compose env) to preload specific LDAP
    // users for zero-delay first access.
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

    // Start background log observer so we automatically see mount/auth activity
    // from Ganesha (client IDs, names like "Linux NFSv4.x <host>", any @REALM principals
    // that appear in logs). Candidates are fed to resolve_principal for classification
    // and caching. Detailed debug output (when KLLDAP_IDHELPER_DEBUG=true) will be
    // emitted for the observed principals.
    let cache_for_watcher = Arc::clone(&cache);
    start_ganesha_observer(realm.clone(), server_variants.clone(), cache_for_watcher);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let realm = realm.clone();
                let variants = server_variants.clone();
                let cache = Arc::clone(&cache);
                thread::spawn(move || {
                    if let Err(e) = handle_client(s, &realm, &variants, &cache) {
                        // best effort logging
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
                let (is_m, reason) = is_machine_principal(arg, realm, server_variants);
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
        _ => {
            out.push_str("ERR unknown command\n");
        }
    }

    stream.write_all(out.as_bytes())?;
    stream.flush()?;
    Ok(())
}
