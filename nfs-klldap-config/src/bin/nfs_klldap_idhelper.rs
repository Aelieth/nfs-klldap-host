//! nfs-klldap-idhelper
//!
//! Lightweight, memory-efficient, always-running helper for ID and Kerberos
//! principal translation between machine ("root") credentials and LDAP-backed
//! user principals inside the nfs-klldap-host container.
//!
//! Goals (per requirements):
//! - Runs as a long-lived daemon (started by entrypoint) so it is available for
//!   every single mount attempt. Mounts currently collapse without it.
//! - Extremely lightweight for the hot path. 4K video file serving workloads
//!   demand low CPU/memory and fast resolution.
//! - Primary fast lookup path is a simple, regular on-disk cache file that is
//!   cheap to process (line-oriented, predictable format, easy to mmap/grep).
//! - Unix domain socket for fast local queries from scripts, UI, ganesha-ctl,
//!   and future small clients. One small allocation per request at most.
//! - Clear distinction between machine principals (host/, nfs/, root/, and
//!   server/client host variants) and regular LDAP user principals.
//! - Safe: does NOT inject arbitrary data into ganesha.conf. Ganesha config
//!   generation stays conservative and parser-safe. Translation lives here.
//! - Can operate standalone (direct NSS resolution) when the daemon is not
//!   reachable (early boot, diagnostics).
//!
//! Cache file format (simple, robust, file-processing friendly):
//!   # nfs-klldap-idhelper cache v1
//!   # principal|uid|gid|kind|source
//!   alice@EXAMPLE.COM|1001|1001|user|sss
//!   host/fedora-immutable.example.com@EXAMPLE.COM|0|0|machine|special
//!
//! kind: "user" | "machine" | "unknown"
//! source: "sss" | "special" | "direct" | "cache"
//!
//! The daemon keeps an in-memory map + atomically rewrites the cache file on
//! changes. Consumers can read the file directly for lowest-overhead cases
//! (small file, linear scan is fine; number of active principals is tiny).
//!
//! Protocol over /var/run/nfs-klldap/idhelper.sock (line based):
//!   RESOLVE <principal>\n   ->  OK <principal>|<uid>|<gid>|<kind>|<source>\n
//!                           or  ERR <message>\n
//!   CLASSIFY <principal>\n  ->  OK <kind>|<reason>\n
//!   PING\n                  ->  OK\n
//!
//! CLI usage:
//!   nfs-klldap-idhelper resolve 'alice@EXAMPLE.COM' [--json]
//!   nfs-klldap-idhelper classify 'host/foo@REALM'
//!   nfs-klldap-idhelper check
//!   nfs-klldap-idhelper daemon   # run the server (normally via entrypoint)

use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const SOCKET_PATH: &str = "/var/run/nfs-klldap/idhelper.sock";
const CACHE_PATH: &str = "/var/lib/nfs-klldap/idmap.cache";
const CACHE_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    Machine,
    Unknown,
}

impl PrincipalKind {
    fn as_str(&self) -> &'static str {
        match self {
            PrincipalKind::User => "user",
            PrincipalKind::Machine => "machine",
            PrincipalKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub principal: String,
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub kind: PrincipalKind,
    pub source: String,
}

#[derive(Default)]
struct IdCache {
    // normalized principal -> entry
    entries: HashMap<String, Resolved>,
}

impl IdCache {
    fn get(&self, norm: &str) -> Option<&Resolved> {
        self.entries.get(norm)
    }

    fn insert(&mut self, r: Resolved) {
        let key = normalize_principal(&r.principal);
        self.entries.insert(key, r);
    }

    fn load_from_file(path: &Path) -> Self {
        let mut c = IdCache::default();
        if let Ok(f) = File::open(path) {
            let r = BufReader::new(f);
            for line in r.lines().map_while(Result::ok) {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                // principal|uid|gid|kind|source
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() != 5 {
                    continue;
                }
                if let (Ok(uid), Ok(gid)) = (parts[1].parse::<u32>(), parts[2].parse::<u32>()) {
                    let kind = match parts[3] {
                        "machine" => PrincipalKind::Machine,
                        "user" => PrincipalKind::User,
                        _ => PrincipalKind::Unknown,
                    };
                    let res = Resolved {
                        principal: parts[0].to_string(),
                        name: parts[0].split('@').next().unwrap_or(parts[0]).to_string(),
                        uid,
                        gid,
                        kind,
                        source: parts[4].to_string(),
                    };
                    c.insert(res);
                }
            }
        }
        c
    }

    fn write_to_file(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("tmp");
        {
            let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
            let mut w = BufWriter::new(f);
            writeln!(w, "# nfs-klldap-idhelper cache v{}", CACHE_VERSION)?;
            writeln!(w, "# principal|uid|gid|kind|source")?;
            // Stable order for easier file processing / diffing
            let mut items: Vec<_> = self.entries.values().collect();
            items.sort_by(|a, b| a.principal.cmp(&b.principal));
            for e in items {
                writeln!(
                    w,
                    "{}|{}|{}|{}|{}",
                    e.principal, e.uid, e.gid, e.kind.as_str(), e.source
                )?;
            }
        }
        fs::rename(tmp, path)?;
        Ok(())
    }
}

/// Return true if this looks like a machine / host / root Kerberos principal.
/// Matches common patterns used by clients with host keytabs (Fedora Immutable etc.)
/// as well as the server's own NFS service principals.
pub fn is_machine_principal(principal: &str, realm: &str, server_variants: &[String]) -> (bool, String) {
    let p = principal.trim();
    let lower = p.to_ascii_lowercase();
    let realm_lower = realm.to_ascii_lowercase();

    // Strip realm for matching if present
    let local = if let Some(at) = lower.rfind('@') {
        &lower[..at]
    } else {
        &lower
    };

    if local.starts_with("host/") || local.starts_with("nfs/") || local.starts_with("root/") {
        return (true, format!("matches well-known machine prefix in {}", local));
    }

    // Match server host principals (e.g. nfs/aurora or host/aurora)
    for v in server_variants {
        let v_l = v.to_ascii_lowercase();
        if local == format!("host/{}", v_l) || local == format!("nfs/{}", v_l) {
            return (true, format!("matches server host principal for {}", v));
        }
    }

    // If the bare local part (without service/) equals a server variant and there is a service prefix
    // already handled above, but also catch things like "host-foo" style if ever presented.
    // Also treat anything that looks like a host credential from a client keytab.
    // A simple heuristic: if it contains a / and the right side looks like a hostname, treat as machine.
    if local.contains('/') {
        let after_slash = local.split('/').nth(1).unwrap_or("");
        if !after_slash.is_empty() && (after_slash.chars().any(|c| c.is_ascii_alphanumeric()) || after_slash.contains('.')) {
            // Additional signal: if it ends with our known realm or is presented as host-like
            if lower.ends_with(&format!("@{}", realm_lower)) || lower.contains("host") || lower.contains("nfs") {
                return (true, "contains host/service prefix and hostname-like component".to_string());
            }
        }
    }

    // Explicit machine-like names sometimes used for the NFS client host credential.
    if local == "host" || local == "nfs" || local == "root" {
        return (true, "bare machine service name".to_string());
    }

    (false, "treated as regular user principal".to_string())
}

/// Normalize a principal for cache key and lookup.
/// Lowercases the realm part, keeps the local part as presented (SSSD is often case-sensitive for uid).
fn normalize_principal(p: &str) -> String {
    let p = p.trim();
    if let Some(at) = p.rfind('@') {
        let (local, realm) = p.split_at(at);
        format!("{}{}", local, realm.to_ascii_uppercase())
    } else {
        p.to_string()
    }
}

/// Try to resolve a name (possibly "user@REALM") to uid/gid via getent (NSS).
/// This is the direct path used by both CLI and daemon on miss.
fn resolve_via_nss(name_or_principal: &str) -> Option<(u32, u32, String)> {
    // Try as-is first (handles user@REALM in some setups)
    if let Some(res) = resolve_getent(name_or_principal) {
        return Some(res);
    }
    // Try without realm
    if let Some(at) = name_or_principal.rfind('@') {
        let short = &name_or_principal[..at];
        if let Some(res) = resolve_getent(short) {
            return Some(res);
        }
    }
    // Try common variants
    let short = name_or_principal.split('@').next().unwrap_or(name_or_principal);
    resolve_getent(short)
}

fn resolve_getent(name: &str) -> Option<(u32, u32, String)> {
    // getent passwd <name> -> name:pass:uid:gid:...
    let out = Command::new("getent")
        .args(["passwd", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next()?;
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() > 3 {
        if let (Ok(uid), Ok(gid)) = (parts[2].parse::<u32>(), parts[3].parse::<u32>()) {
            return Some((uid, gid, "sss".to_string()));
        }
    }
    None
}

/// Perform full classification + resolution.
/// This is the heart of the helper.
fn resolve_principal(
    principal: &str,
    realm: &str,
    server_variants: &[String],
    cache: &mut IdCache,
) -> Resolved {
    let norm = normalize_principal(principal);
    if let Some(existing) = cache.get(&norm).cloned() {
        let mut e = existing;
        e.source = "cache".to_string();
        return e;
    }

    let (is_machine, _reason) = is_machine_principal(principal, realm, server_variants);

    let kind = if is_machine {
        PrincipalKind::Machine
    } else {
        PrincipalKind::User
    };

    // Attempt resolution
    let resolved = if is_machine {
        // Machine principals often map to root (0) on the server side for certain ops,
        // or to a special "machine" identity if one exists in LDAP.
        // We prefer explicit root (0:0) for machine credentials unless a real user is found.
        // First see if NSS has an entry for the short machine name.
        let short = principal
            .split('@')
            .next()
            .unwrap_or(principal)
            .split('/')
            .next_back()
            .unwrap_or(principal);
        if let Some((uid, gid, src)) = resolve_via_nss(short) {
            Resolved {
                principal: principal.to_string(),
                name: short.to_string(),
                uid,
                gid,
                kind: PrincipalKind::Machine,
                source: src,
            }
        } else {
            // Default machine credential treatment: root
            Resolved {
                principal: principal.to_string(),
                name: short.to_string(),
                uid: 0,
                gid: 0,
                kind: PrincipalKind::Machine,
                source: "special".to_string(),
            }
        }
    } else {
        // Regular user
        let looked = resolve_via_nss(principal).or_else(|| resolve_via_nss(principal.split('@').next().unwrap_or(principal)));
        if let Some((uid, gid, src)) = looked {
            let name = principal.split('@').next().unwrap_or(principal).to_string();
            Resolved {
                principal: principal.to_string(),
                name,
                uid,
                gid,
                kind,
                source: src,
            }
        } else {
            // Unknown / unmapped -> nobody-ish but keep the info
            let name = principal.split('@').next().unwrap_or(principal).to_string();
            Resolved {
                principal: principal.to_string(),
                name,
                uid: 65534,
                gid: 65534,
                kind: PrincipalKind::Unknown,
                source: "direct".to_string(),
            }
        }
    };

    // Store
    cache.insert(resolved.clone());

    // Persist to the cache file (best effort, non-fatal)
    let _ = cache.write_to_file(Path::new(CACHE_PATH));

    // Optional: try to warm SSSD cache for the resolved name (non-blocking)
    if resolved.uid != 0 && resolved.uid != 65534 {
        let _ = Command::new("sss_cache")
            .args(["-u", &resolved.name])
            .output();
    }

    resolved
}

fn get_server_variants() -> Vec<String> {
    // Best effort: use hostname variants. In container this should be the real host.
    // We also accept any that the caller may pass via env or args later.
    if let Ok(h) = std::env::var("NFS_KLLDAP_SERVER_HOSTNAME") {
        if !h.trim().is_empty() {
            let mut v = vec![h.trim().to_string()];
            if let Some(short) = h.split('.').next() {
                if short != h.trim() {
                    v.push(short.to_string());
                }
            }
            return v;
        }
    }
    // Fallback to common container hostname discovery
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            let mut v = vec![h.clone()];
            if let Some(short) = h.split('.').next() {
                if short != h {
                    v.push(short.to_string());
                }
            }
            return v;
        }
    }
    vec!["localhost".to_string()]
}

fn get_realm() -> String {
    // Prefer the same derivation the rest of the stack uses.
    if let Ok(r) = std::env::var("NFS_KLLDAP_KERBEROS_REALM") {
        if !r.trim().is_empty() {
            return r.trim().to_uppercase();
        }
    }
    // Try to read from generated krb5.conf as a hint
    if let Ok(content) = std::fs::read_to_string("/etc/krb5.conf") {
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with("default_realm") {
                if let Some(eq) = t.find('=') {
                    let r = t[eq + 1..].trim().to_string();
                    if !r.is_empty() {
                        return r.to_uppercase();
                    }
                }
            }
        }
    }
    "EXAMPLE.COM".to_string()
}

fn handle_cli(args: &[String]) {
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");
    let realm = get_realm();
    let server_variants = get_server_variants();

    let mut cache = IdCache::load_from_file(Path::new(CACHE_PATH));

    match cmd {
        "resolve" => {
            let p = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if p.is_empty() {
                eprintln!("Usage: nfs-klldap-idhelper resolve <principal> [--json]");
                std::process::exit(2);
            }
            let json = args.iter().any(|a| a == "--json" || a == "-j");
            let r = resolve_principal(p, &realm, &server_variants, &mut cache);
            if json {
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
            // Quick self test
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
            println!("Important: Ganesha config is kept conservative. This helper does the translation.");
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

The daemon must be running for reliable mounts. It keeps an efficient in-memory
+ file-backed cache so that every mount can quickly obtain the correct uid/gid
and know whether the credential is a machine (host/nfs/root) or regular user.
"#
    );
}

fn run_daemon() {
    let realm = get_realm();
    let server_variants = get_server_variants();

    // Ensure runtime directories
    let _ = fs::create_dir_all("/var/run/nfs-klldap");
    let _ = fs::create_dir_all("/var/lib/nfs-klldap");

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

    println!("[idhelper] daemon listening on {}", SOCKET_PATH);
    println!("[idhelper] realm={} variants={:?}", realm, server_variants);

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
}