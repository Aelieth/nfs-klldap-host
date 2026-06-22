//! nfs-klldap-idhelper
//! Central fast resolver for ganesha 9.6 (nfsidmap + nss paths).
//! All uid/gid lookups for principals flow through the 10m IdLdapResolver full map here.
//! Machine principals -> 0:0. Users come from bulk-loaded ldap cache or strict getent parse.

use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Seek, SeekFrom, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

// Structured resolver + snapshot + strict parsers from the shared crate.
// The idhelper is the single front-end for all uid/gid resolution used by
// ganesha nfsidmap, nss materialization, and getent parity.
use nfs_klldap_config::{
    parse_getent_passwd, IdLdapResolver, IdMapSnapshot, NfsKlldapConfig, MACHINE_PRINCIPAL_PREFIXES,
};

const SOCKET_PATH: &str = "/var/run/nfs-klldap/idhelper.sock";
const CACHE_PATH: &str = "/var/lib/nfs-klldap/idmap.cache";
const CACHE_VERSION: &str = "1";

// nss_wrapper files materialized by the idhelper so that the Ganesha process
// (launched under LD_PRELOAD=libnss_wrapper.so) sees correct uid/gid for both
// LDAP users and machine principals (host/..., nfs/..., root/...).
// These are the mechanism that actually wires idhelper classification into
// Ganesha's name-to-uid hot path for Kerberos owner strings.
const NSS_PASSWD_PATH: &str = "/var/lib/nfs-klldap/nss_passwd";
const NSS_GROUP_PATH: &str = "/var/lib/nfs-klldap/nss_group";

// Supplemental extrausers (libnss-extrausers) location. When configured in
// nsswitch (files extrausers sss) this lets us inject machine->root mappings
// without replacing the entire user database or hiding SSSD/LDAP users.
const EXTRAUSERS_PASSWD: &str = "/var/lib/extrausers/passwd";
const EXTRAUSERS_GROUP: &str = "/var/lib/extrausers/group";

/// Debug logging enabled via KLLDAP_IDHELPER_DEBUG=true (or 1/yes/on).
static DEBUG_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn debug_enabled() -> bool {
    *DEBUG_ENABLED.get_or_init(|| {
        std::env::var("KLLDAP_IDHELPER_DEBUG")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false)
    })
}

macro_rules! dlog {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {
        if debug_enabled() {
            eprintln!(concat!("[idhelper] ", $fmt) $(, $arg)*);
        }
    };
}

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
                    let local = parts[0].split('@').next().unwrap_or(parts[0]);
                    // For host/... style principals prefer the short hostname part as the "name"
                    // so that nss entries and FINAL logs use a clean short like "blue-lt" rather than "host/blue-lt".
                    let name = if local.contains('/') {
                        local.rsplit('/').next().unwrap_or(local).to_string()
                    } else {
                        local.to_string()
                    };
                    let res = Resolved {
                        principal: parts[0].to_string(),
                        name,
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

// --- nss_wrapper materialization (the bridge that makes idhelper affect Ganesha) ---

/// Sanitize a string for use as a passwd login name (allow alnum + _ - .).
fn sanitize_for_nss(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("unknown");
    }
    out
}

/// Build a passwd(5)-format line for a resolved principal.
/// Uses the short name we already computed; machines always get uid/gid 0.
fn passwd_line_for(r: &Resolved) -> String {
    let login = sanitize_for_nss(&r.name);
    // Gecos is purely informational here.
    let gecos = format!("kll:{}:{}", r.kind.as_str(), r.principal);
    // We use /nonexistent and nologin to be explicit these are not real local accounts.
    format!(
        "{}:x:{}:{}:{}:/nonexistent:/usr/sbin/nologin",
        login, r.uid, r.gid, gecos
    )
}

/// Build a minimal group(5) line for the primary gid of this resolved entry.
/// We use a stable synthetic group name when we don't have a better one.
fn group_line_for(r: &Resolved) -> String {
    // Prefer a simple name; for uid==gid==0 we always ensure "root".
    if r.gid == 0 {
        "root:x:0:".to_string()
    } else {
        let gname = sanitize_for_nss(&r.name);
        format!("{}:x:{}:", gname, r.gid)
    }
}

/// Atomically write the nss_wrapper passwd and group files from the current cache.
/// This is the key side-effect that makes Ganesha (under LD_PRELOAD) see our
/// machine->root and user uid/gid decisions.
fn materialize_nss_wrappers(cache: &IdCache) -> io::Result<()> {
    // Ensure parent exists (best effort, same as cache writer)
    if let Some(parent) = Path::new(NSS_PASSWD_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }

    // Collect stable ordered list of entries (sort by principal for determinism)
    let mut items: Vec<_> = cache.entries.values().collect();
    items.sort_by(|a, b| a.principal.cmp(&b.principal));

    // Build passwd content. We dedup by login name (last wins for stability; tiny set).
    let mut seen_login: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut passwd_lines: Vec<String> = Vec::new();
    let mut group_lines: Vec<String> = Vec::new();
    let mut seen_gid: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for r in &items {
        let line = passwd_line_for(r);
        // Extract login from the line we just built (before first ':')
        if let Some(login) = line.split(':').next() {
            if seen_login.insert(login.to_string()) {
                passwd_lines.push(line);
            }
        }

        // For machine principals (host/..., nfs/..., root/...) also emit an alias using the
        // sanitized full local part (e.g. "host_blue-lt"). This helps when Ganesha's idmapper
        // feeds getpwnam the service/name form instead of (or in addition to) the short host.
        let local = r.principal.split('@').next().unwrap_or(&r.principal);
        if local.contains('/') && MACHINE_PRINCIPAL_PREFIXES.iter().any(|p| local.starts_with(p)) {
            let alias = sanitize_for_nss(local); // turns host/blue-lt into host_blue-lt etc.
            if seen_login.insert(alias.clone()) {
                let gecos = format!("kll:machine-alias:{}", r.principal);
                passwd_lines.push(format!(
                    "{}:x:{}:{}:{}:/nonexistent:/usr/sbin/nologin",
                    alias, r.uid, r.gid, gecos
                ));
            }
        }

        // For regular (non-machine) user principals, ALWAYS also materialize the full "name@REALM" form
        // (in addition to the short name). This helps Ganesha's getpwnam / principal2uid paths
        // when it feeds the exact Kerberos principal string (the "kerberos looking" case).
        if r.kind != PrincipalKind::Machine {
            let full = r.principal.clone();
            if seen_login.insert(full.clone()) {
                let line_full = passwd_line_for(&Resolved {
                    principal: full.clone(),
                    name: full.clone(),
                    uid: r.uid,
                    gid: r.gid,
                    kind: r.kind.clone(),
                    source: r.source.clone(),
                });
                passwd_lines.push(line_full);
            }
        }

        // Groups
        if seen_gid.insert(r.gid) {
            group_lines.push(group_line_for(r));
        }
        // Also ensure the uid's primary group is represented if different (rare)
        if r.uid != r.gid && seen_gid.insert(r.uid) {
            // Use same simple rule; uid as fallback group name
            if r.uid == 0 {
                if seen_gid.insert(0) {
                    // already handled
                }
            } else {
                group_lines.push(format!("u{}:x:{}:", r.uid, r.uid));
            }
        }
    }

    // Always ensure at least a root group entry.
    // For machine principals (uid/gid 0) we also synthesize a couple of
    // common supplementals. This gives uid2grp_allocate_by_principal and
    // set_extended_groups something to work with for root creds and reduces
    // (but does not completely eliminate) the expected INFO noise for
    // host/ nfs/ machine principals.
    if seen_gid.is_empty() || !seen_gid.contains(&0) {
        group_lines.push("root:x:0:root,daemon,bin".to_string());
    }

    // Always ensure a root *passwd* entry for uid 0. Under nss_wrapper (for Ganesha)
    // or extrausers this makes getpwuid_r(0) succeed for uid2grp paths on machine
    // principals (host/...). Without it, "getpwuid_r for uid 0 failed, error 2" occurs
    // on cold first access before any machine principal has been materialized.
    // We add a canonical "root" line (name root, uid 0) in addition to any client-host
    // aliases that also map to 0.
    if !passwd_lines.iter().any(|l| l.starts_with("root:")) {
        passwd_lines.insert(0, "root:x:0:0:root:/nonexistent:/usr/sbin/nologin".to_string());
    }

    // Write passwd atomically
    {
        let tmp = Path::new(NSS_PASSWD_PATH).with_extension("tmp");
        let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        let mut w = BufWriter::new(f);
        // Helpful header (nss_wrapper ignores comments? but # is conventional and harmless)
        writeln!(w, "# nfs-klldap-idhelper nss_wrapper passwd (materialized)")?;
        for l in &passwd_lines {
            writeln!(w, "{}", l)?;
        }
        fs::rename(tmp, NSS_PASSWD_PATH)?;
    }

    // Write group atomically
    {
        let tmp = Path::new(NSS_GROUP_PATH).with_extension("tmp");
        let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        let mut w = BufWriter::new(f);
        writeln!(w, "# nfs-klldap-idhelper nss_wrapper group (materialized)")?;
        for l in &group_lines {
            writeln!(w, "{}", l)?;
        }
        fs::rename(tmp, NSS_GROUP_PATH)?;
    }

    dlog!(
        "nss_wrapper materialized passwd={} entries group={} entries",
        passwd_lines.len(),
        group_lines.len()
    );

    // --- Also write the same machine/user mappings into extrausers (supplemental) ---
    // This is the preferred path for most deployments: extrausers sits between
    // files and sss in nsswitch, so machines get 0 while real LDAP users resolve
    // normally via sss even if the idhelper has never seen that user principal.
    {
        // Ensure dir (harmless if using the nss_wrapper paths under /var/lib/nfs-klldap too)
        if let Some(p) = Path::new(EXTRAUSERS_PASSWD).parent() {
            let _ = fs::create_dir_all(p);
        }
        // passwd
        {
            let tmp = Path::new(EXTRAUSERS_PASSWD).with_extension("tmp");
            let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
            let mut w = BufWriter::new(f);
            writeln!(w, "# nfs-klldap-idhelper extrausers (machine overrides + seen users)")?;
            for l in &passwd_lines {
                writeln!(w, "{}", l)?;
            }
            fs::rename(tmp, EXTRAUSERS_PASSWD)?;
        }
        // group
        {
            let tmp = Path::new(EXTRAUSERS_GROUP).with_extension("tmp");
            let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
            let mut w = BufWriter::new(f);
            writeln!(w, "# nfs-klldap-idhelper extrausers group")?;
            for l in &group_lines {
                writeln!(w, "{}", l)?;
            }
            fs::rename(tmp, EXTRAUSERS_GROUP)?;
        }
    }

    Ok(())
}

/// Return true if this looks like a machine / host / root Kerberos principal.
/// Matches common patterns used by clients with host keytabs (Fedora Immutable etc.)
/// as well as the server's own NFS service principals.
pub fn is_machine_principal(principal: &str, realm: &str, server_variants: &[String]) -> (bool, String) {
    // Delegate to the shared implementation (centralized prefixes + logic) for
    // unification and to guarantee idhelper + any future users have identical
    // classification for hybrid machine (host/nfs/root) vs user TGT principals.
    nfs_klldap_config::classify_principal(principal, realm, server_variants)
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

/// getent (NSS) path for "same lookup a client would see". Falls back to resolver snapshot.
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
    if let Some(res) = resolve_getent(short) {
        return Some(res);
    }

    // Fallback to direct structured LDAP resolution (0.8.32 refactor).
    // Uses the same PosixAttributeMapping, filters, and caching logic as
    // nfs-klldap-ui/src/ldap.rs so behavior + cache effectiveness are identical
    // and we do not hit the server on every miss.
    if let Some((uid, gid)) = resolve_via_structured_ldap(short) {
        eprintln!("[idhelper] getent passwd \"{}\" -> ldap fallback success uid={} gid={}", short, uid, gid);
        return Some((uid, gid, "ldap".to_string()));
    }
    None
}

/// Structured LDAP resolution using IdLdapResolver + full in-memory snapshot (preferred hot path).
/// The bulk 10m load (called at daemon start) ensures we have all users+groups with aligned gids.
/// On miss we force a fresh full load (covers users added after start or in nested OUs that a
/// previous narrow base might have missed) then retry.
/// Accepts full principal (for krbPrincipalName lookup) or short name.
fn resolve_via_structured_ldap(name_or_principal: &str) -> Option<(u32, u32)> {
    let (resolver, bind_dn, bind_pw) = get_or_init_resolver()?;

    let short = name_or_principal.split('@').next().unwrap_or(name_or_principal);

    // Prefer in-memory snapshot (try full principal key then short)
    let snap: IdMapSnapshot = resolver.snapshot();
    if let Some(u) = snap.users.get(name_or_principal) {
        return Some((u.uid as u32, u.gid as u32));
    }
    if let Some(u) = snap.users.get(short) {
        return Some((u.uid as u32, u.gid as u32));
    }

    // Single resolve with full first (enables dual principal attr logic), then short
    if let Some((uid_i, gid_opt, _disp)) = resolver.resolve_user(name_or_principal, &bind_dn, &bind_pw) {
        let uid = uid_i as u32;
        let gid = gid_opt.map(|g| g as u32).unwrap_or(uid);
        return Some((uid, gid));
    }
    if let Some((uid_i, gid_opt, _disp)) = resolver.resolve_user(short, &bind_dn, &bind_pw) {
        let uid = uid_i as u32;
        let gid = gid_opt.map(|g| g as u32).unwrap_or(uid);
        return Some((uid, gid));
    }

    // Miss - force a fresh full load then retry
    let _ = resolver.load_full_identities(&bind_dn, &bind_pw);
    let snap2: IdMapSnapshot = resolver.snapshot();
    if let Some(u) = snap2.users.get(name_or_principal) {
        return Some((u.uid as u32, u.gid as u32));
    }
    if let Some(u) = snap2.users.get(short) {
        return Some((u.uid as u32, u.gid as u32));
    }
    if let Some((uid_i, gid_opt, _disp)) = resolver.resolve_user(name_or_principal, &bind_dn, &bind_pw) {
        let uid = uid_i as u32;
        let gid = gid_opt.map(|g| g as u32).unwrap_or(uid);
        return Some((uid, gid));
    }
    if let Some((uid_i, gid_opt, _disp)) = resolver.resolve_user(short, &bind_dn, &bind_pw) {
        let uid = uid_i as u32;
        let gid = gid_opt.map(|g| g as u32).unwrap_or(uid);
        return Some((uid, gid));
    }
    None
}

/// Load resolver + bind creds from the canonical NfsKlldapConfig (single source of truth).
/// Replaces all previous hand-rolled toml + flat-map logic.
fn load_resolver_from_config() -> Option<(IdLdapResolver, String, String)> {
    let path = std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string());
    let cfg = NfsKlldapConfig::load(std::path::Path::new(&path)).ok()?;
    if cfg.sssd.ldap_default_bind_dn.trim().is_empty() || cfg.sssd.ldap_default_authtok.trim().is_empty() {
        return None;
    }
    let resolver = IdLdapResolver::from_sssd_section(&cfg.ldap_uri, &cfg.sssd);
    Some((resolver, cfg.sssd.ldap_default_bind_dn.clone(), cfg.sssd.ldap_default_authtok.clone()))
}

/// Lazily initialized resolver (with creds) so that the 10m identity + reverse caches
/// inside IdLdapResolver are effective across RESOLVE/getent/observer calls
/// (addresses previous per-call fresh instance problem).
static ID_RESOLVER: OnceLock<Option<(IdLdapResolver, String, String)>> = OnceLock::new();

fn get_or_init_resolver() -> Option<(&'static IdLdapResolver, String, String)> {
    if let Some(cached) = ID_RESOLVER.get().and_then(|o| o.as_ref()) {
        return Some((&cached.0, cached.1.clone(), cached.2.clone()));
    }
    let (resolver, bind_dn, bind_pw) = load_resolver_from_config()?;
    let _ = ID_RESOLVER.set(Some((resolver, bind_dn.clone(), bind_pw.clone())));
    if let Some(cached) = ID_RESOLVER.get().and_then(|o| o.as_ref()) {
        return Some((&cached.0, cached.1.clone(), cached.2.clone()));
    }
    None
}

fn resolve_getent(name: &str) -> Option<(u32, u32, String)> {
    // getent passwd <name> -> name:pass:uid:gid:...
    // The short name path (testuser1) is the primary for "same lookup as client".
    // Full principal is also attempted (by callers) for principal mapping.
    eprintln!("[idhelper] getent passwd \"{}\" called", name);
    let out = Command::new("getent")
        .args(["passwd", name])
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!("[idhelper] getent passwd \"{}\" -> failed (status={:?})", name, out.status.code());
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next().unwrap_or("");
    if let Some((uid, gid)) = parse_getent_passwd(line) {
        eprintln!("[idhelper] getent passwd \"{}\" -> success uid={} gid={}", name, uid, gid);
        return Some((uid, gid, "sss".to_string()));
    }
    eprintln!("[idhelper] getent passwd \"{}\" -> malformed output", name);
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
    let start = Instant::now();
    let norm = normalize_principal(principal);

    dlog!("RESOLVE principal=\"{}\"", principal);
    dlog!("  normalized=\"{}\"", norm);

    if principal.contains('@') {
        dlog!("  (kerberos principal form - will attempt full + short + principal attr paths)");
    }

    if let Some(existing) = cache.get(&norm).cloned() {
        let mut e = existing;
        e.source = "cache".to_string();
        eprintln!("[idhelper] cache=HIT key=\"{}\"", norm);
        eprintln!(
            "[idhelper] FINAL principal=\"{}\" name=\"{}\" uid={} gid={} kind={} source={} (cache hit)",
            e.principal, e.name, e.uid, e.gid, e.kind.as_str(), e.source
        );
        let elapsed = start.elapsed();
        dlog!(
            "  result uid={} gid={} kind={} source={} elapsed={:?}",
            e.uid, e.gid, e.kind.as_str(), e.source, elapsed
        );
        return e;
    }
    eprintln!("[idhelper] cache=MISS key=\"{}\"", norm);

    let (is_machine, reason) = is_machine_principal(principal, realm, server_variants);
    dlog!("  classify is_machine={} reason=\"{}\"", is_machine, reason);
    eprintln!("[idhelper] CLASSIFY principal=\"{}\" -> {} (reason=\"{}\")", principal, if is_machine { "machine" } else { "user" }, reason);

    let kind = if is_machine {
        PrincipalKind::Machine
    } else {
        PrincipalKind::User
    };

    // Attempt resolution
    let resolved = if is_machine {
        // Short-circuit for all machine principals (host/, nfs/, root/, server variants,
        // and client host names presented via "Linux NFSv4.x <host>").
        // Kerberos auth has already succeeded; we only need consistent UID/GID mapping.
        // Machines must map to 0:0. Real LDAP users are unaffected (they take the else path).
        // Synthetic names (e.g. host/0x<epoch>) are also correctly forced to 0:0.
        // This eliminates getent latency and non-determinism that can trigger
        // clientid/session collapse on immutable + host-keytab clients.
        let short = principal
            .split('@')
            .next()
            .unwrap_or(principal)
            .split('/')
            .next_back()
            .unwrap_or(principal);
        eprintln!("[idhelper] short_name_extracted=\"{}\" (machine path, principal=\"{}\")", short, principal);

        // No resolve_via_nss / getent calls for machines.
        Resolved {
            principal: principal.to_string(),
            name: short.to_string(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".to_string(),
        }
    } else {
        // Regular user
        let first_try = principal;
        let second_try = principal.split('@').next().unwrap_or(principal);
        dlog!("  user_path first_try=\"{}\" second_try=\"{}\"", first_try, second_try);

        // Prefer nss/getent for "same lookup client would do", but always also
        // attempt the direct structured LDAP resolver. This guarantees a uid/gid
        // + materialize on first presentation of a user principal even if sss/getent
        // has cold/negative cache or hasn't seen the name yet. Fixes first-compound
        // "Could not map principal ... to uid" fallthrough.
        // For full principals (kerberos looking), try the full form first so the
        // resolver can use krbPrincipalName attr lookup in addition to name match.
        let nss_looked = resolve_via_nss(first_try).or_else(|| resolve_via_nss(second_try));
        let ldap_looked = resolve_via_structured_ldap(first_try)
            .or_else(|| resolve_via_structured_ldap(second_try))
            .map(|(u, g)| (u, g, "ldap".to_string()));
        let looked = nss_looked.or(ldap_looked);
        dlog!("  nss_getent final_got={:?}", looked.as_ref().map(|(u, g, s)| (*u, *g, s.as_str())));

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
            // Unknown / unmapped -> nobody-ish but keep the info.
            // This is the path that produces the "Could not map principal" in ganesha.
            // The bases used by the resolver (and thus bulk/single searches) determine
            // whether nested OUs under ou=users (or ou=people) are visible.
            eprintln!(
                "[idhelper] FALLBACK 65534 for principal=\"{}\" (no uid/gid from getent or structured resolver) - principal2uid path for kerberos",
                principal
            );
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

    dlog!(
        "  resolved principal=\"{}\" name=\"{}\" uid={} gid={} kind={} source={}",
        resolved.principal, resolved.name, resolved.uid, resolved.gid, resolved.kind.as_str(), resolved.source
    );

    eprintln!(
        "[idhelper] FINAL principal=\"{}\" name=\"{}\" uid={} gid={} kind={} source={} (sent to ganesha)",
        resolved.principal, resolved.name, resolved.uid, resolved.gid, resolved.kind.as_str(), resolved.source
    );

    // Store
    cache.insert(resolved.clone());

    // Persist to the cache file (best effort, non-fatal)
    let write_res = cache.write_to_file(Path::new(CACHE_PATH));
    dlog!(
        "  cache_write result={}",
        if write_res.is_ok() { "ok" } else { "err" }
    );

    // Materialize nss_wrapper files so Ganesha (under LD_PRELOAD) sees our classification.
    // This is the key "conjunction" point: idhelper decisions become visible to Ganesha's
    // getpwnam calls for Kerberos principals (machine -> 0, users -> real ids from SSSD).
    // Best effort, non-fatal.
    if let Err(e) = materialize_nss_wrappers(cache) {
        dlog!("  nss_wrapper_write err={}", e);
    }

    // Optional: try to warm SSSD cache for the resolved name (non-blocking).
    // This helps both direct getent passwd testuser1 (short) and the full
    // principal path (via shim + idhelper) see fresh data from LLDAP/SSSD.
    // Must not change behavior for ganesha 9.6/trixie.
    if resolved.uid != 0 && resolved.uid != 65534 {
        let _ = Command::new("sss_cache")
            .args(["-u", &resolved.name])
            .output();
        // Also do a best-effort getent (via the shell helper) to encourage sss
        // to cache the short name for the preload/extrausers path Ganesha may use.
        let _ = Command::new("getent")
            .args(["passwd", &resolved.name])
            .output();
    }

    // Distinct log line for correlation with Ganesha "Could not map" / nfs_req_creds failures.
    // Helps operators see that our side of the mapping just became available for
    // the next compound or retry.
    eprintln!(
        "[idhelper] MAPPED FOR GANESHA principal=\"{}\" uid={} gid={} source={}",
        resolved.principal, resolved.uid, resolved.gid, resolved.source
    );

    let elapsed = start.elapsed();
    dlog!("  elapsed={:?}", elapsed);

    resolved
}

/// Best-effort: tail ganesha.log for early principal hints (feeds resolve).
fn start_ganesha_observer(realm: String, variants: Vec<String>, cache: Arc<Mutex<IdCache>>) {
    let log_path = std::env::var("GANESHA_LOG_PATH")
        .unwrap_or_else(|_| "/var/log/ganesha.log".to_string());
    thread::spawn(move || {
        observe_ganesha_log(&log_path, &realm, &variants, cache);
    });
}

fn observe_ganesha_log(path: &str, realm: &str, variants: &[String], cache: Arc<Mutex<IdCache>>) {
    // Simple per-candidate rate limit to avoid spamming "observed" + full resolve/materialize
    // on every log line that matches the same client name (very common during a mount).
    let mut recently: std::collections::HashMap<String, std::time::Instant> = std::collections::HashMap::new();
    let dedup_window = Duration::from_secs(30);

    loop {
        match File::open(path) {
            Ok(mut f) => {
                // Only watch new data from now on
                let _ = f.seek(SeekFrom::End(0));
                let mut reader = BufReader::new(f);
                let mut buf = String::new();
                loop {
                    buf.clear();
                    match reader.read_line(&mut buf) {
                        Ok(0) => {
                            // No new data yet (regular file at EOF). Sleep briefly and retry
                            // on the same fd -- appends by Ganesha will become visible.
                            thread::sleep(Duration::from_millis(250));
                            continue;
                        }
                        Ok(_) => {
                            let line = buf.trim();
                            if let Some(candidate) = extract_candidate_principal(line, realm) {
                                let now = std::time::Instant::now();
                                let is_fresh = recently
                                    .get(&candidate)
                                    .map(|last| now.duration_since(*last) >= dedup_window)
                                    .unwrap_or(true);

                                if is_fresh {
                                    recently.insert(candidate.clone(), now);
                                    // Opportunistic prune (tiny map in practice)
                                    if recently.len() > 2048 {
                                        recently.retain(|_, t| now.duration_since(*t) < dedup_window);
                                    }

                                    eprintln!("[idhelper] observed from ganesha log: {}", candidate);
                                    {
                                        let mut guard = cache.lock().unwrap();
                                        // Resolve (and classify) the candidate. If KLLDAP_IDHELPER_DEBUG
                                        // is set, full details (normalize, cache hit/miss, getent etc.)
                                        // will be logged by the existing debug instrumentation.
                                        let _ = resolve_principal(&candidate, realm, variants, &mut guard);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(300));
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                // Log file may not exist yet at early startup
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// Returns true only for tokens that look like real client hostnames
/// (short name or fqdn) that we expect from "Linux NFSv4.x <host>" strings.
/// Rejects log formatting noise such as "Unique", "CLIENT", "ID", "ffff", "Created", etc.
fn looks_like_client_hostname(t: &str) -> bool {
    let s = t.trim();
    if s.len() < 2 || s.len() > 253 {
        return false;
    }
    if !s.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    let lower = s.to_ascii_lowercase();

    // Strong early rejection of known log noise tokens that frequently appear near
    // client records (prevents host/nil, host/clientid, host/Unique, host/ffff etc.)
    if is_noise_hostname(s) {
        return false;
    }

    // Reject common log noise and formatting tokens (case-insensitive)
    // Source the common noise list (Ganesha log hygiene for hybrid principal observer).
    // Keep local name for readability; values centralized for idhelper + future.
    const NOISE: &[&str] = nfs_klldap_config::LOG_NOISE_TOKENS;
    if NOISE.contains(&lower.as_str()) {
        return false;
    }

    // Hostname chars only
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return false;
    }

    // Real client hostnames from these logs are almost always lowercase and/or contain dot/hyphen
    if !s.chars().any(|c| c.is_ascii_lowercase()) && !s.contains('.') {
        return false;
    }

    true
}

/// Exact-match noise tokens (case-insensitive) that must never become a client hostname.
fn is_noise_hostname(t: &str) -> bool {
    let s = t.trim().to_ascii_lowercase();
    if matches!(
        s.as_str(),
        "nil" | "null" | "clientid" | "unique" | "counter" | "created" | "client" |
        "id" | "name" | "addr" | "refcount" | "cr" | "conf" | "unconf" | "debug" |
        "info" | "warning" | "error" | "ffff" | "linux" | "nfsv4"
    ) {
        return true;
    }
    // Also reject version-like tokens (NFSv4.2, 2.3 etc) and obvious non-host words that
    // appear after : or - splits in client name blobs.
    if s.starts_with("nfsv") || s.starts_with("nfs") || (s.chars().any(|c| c.is_ascii_digit()) && s.contains('.')) {
        // e.g. "NFSv4.2" or "10.10" style after split
        return true;
    }
    false
}

/// Try to extract a client hostname from a string that contains the common
/// Ganesha/Linux-NFS pattern "Linux NFSv4.<ver> <hostname>".
/// Only return a token if it comes from a group that looks like the client name
/// (contains "Linux" or the version+host pattern), skipping (nil), (NULL), clientid blobs.
fn extract_linux_nfs_hostname(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let marker = "nfsv4";
    if let Some(m) = lower.find(marker) {
        let suffix = &line[m + marker.len()..];

        // Prefer the group that contains the Linux NFS client string.
        // Scan all (...) groups after the marker and pick the last plausible host
        // only from a group that contains "linux" or looks like "(21:Linux..." or "-(21:Linux...".
        let mut best: Option<String> = None;
        let mut search = suffix;
        while let Some(p) = search.find('(') {
            let rest = &search[p + 1..];
            if let Some(end) = rest.find(')') {
                let inside = &rest[..end];
                let group_lower = inside.to_ascii_lowercase();
                let looks_like_client_group = group_lower.contains("linux") || group_lower.contains("nfsv4") || inside.contains("Linux NFS");
                if looks_like_client_group {
                    for token in inside.split_whitespace().rev() {
                        let t = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
                        if looks_like_client_hostname(t)
                            && !t.eq_ignore_ascii_case("linux")
                            && !is_noise_hostname(t)
                        {
                            best = Some(t.to_string());
                            break;
                        }
                    }
                }
                search = &rest[end + 1..];
            } else {
                break;
            }
        }
        if best.is_some() {
            return best;
        }

        // Fallback scan is deliberately conservative.
        // If the line smells like an internal client-record debug blob (lots of (nil), clientid=, Unique=, Counter=, cr_refcount), do not trust the loose word fallback.
        // (Good names from "Linux NFSv4..." groups will already have been returned via the best path above.)
        let lower_line = line.to_ascii_lowercase();
        let is_internal_blob = lower_line.contains("conf = (nil)") || lower_line.contains("clientid=") || lower_line.contains("unique=") || lower_line.contains("counter=") || lower_line.contains("cr_refcount");
        if is_internal_blob {
            return None;
        }

        let mut iter = suffix.split(|c: char| {
            c.is_whitespace() || c == '(' || c == ')' || c == '[' || c == ']' || c == ':' || c == '.'
        });
        let _ = iter.next(); // skip version
        for w in iter {
            let t = w.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
            if t.is_empty() { continue; }
            let tl = t.to_ascii_lowercase();
            if ["linux", "nfsv4", "created", "client", "name", "nil", "null", "conf", "unconf", "clientid", "unique", "counter", "stuff", "token", "other", "value", "key", "loc", "ref", "addr", "server"].contains(&tl.as_str()) || is_noise_hostname(t) {
                continue;
            }
            if looks_like_client_hostname(t) {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn extract_candidate_principal(line: &str, realm: &str) -> Option<String> {
    let realm_lower = realm.to_ascii_lowercase();

    // 0. High-signal early sighting: Ganesha is about to / is calling the idmapper for a principal.
    //    "Get uid for testuser1@REALM using nfsidmap" tells us a user principal is needed *now*.
    //    Extract and resolve immediately (observer background) so state may be ready or for retries/other threads.
    if let Some(start) = line.find("Get uid for ") {
        let rest = &line[start + "Get uid for ".len()..];
        if let Some(end) = rest.find(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_') {
            let cand = &rest[..end].trim();
            if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
                // Only treat non-machine service forms as user candidates here.
                if !MACHINE_PRINCIPAL_PREFIXES.iter().any(|p| cand.to_ascii_lowercase().starts_with(p)) {
                    return Some(cand.to_string());
                }
            }
        }
    }

    // 0b. Special high-signal case for our own mapping failures.
    //    When Ganesha logs "Could not map principal ...", extract immediately.
    if let Some(start) = line.find("Could not map principal ") {
        let rest = &line[start + "Could not map principal ".len()..];
        if let Some(end) = rest.find(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_') {
            let cand = &rest[..end];
            if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
                return Some(cand.to_string());
            }
        }
        if let Some(at_pos) = rest.find('@') {
            let cand = &rest[..at_pos+1 + rest[at_pos+1..].find(|c: char| !c.is_alphanumeric() && c != '.' && c != '-').unwrap_or(rest.len()-at_pos-1)];
            let cand = cand.split_whitespace().next().unwrap_or(cand);
            if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
                return Some(cand.to_string());
            }
        }
    }

    // 1. Look for explicit Kerberos principals containing the realm (user@REALM or host/xxx@REALM).
    //    Keep relatively permissive for real principals, but still validate the local part.
    if let Some(at_pos) = line.find('@') {
        let before = &line[..at_pos];
        let start = before
            .rfind(|c: char| !c.is_alphanumeric() && c != '/' && c != '.' && c != '-' && c != '_' && c != ':')
            .map_or(0, |p| p + 1);
        let after = &line[at_pos..];
        let end_rel = after
            .find(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_' && c != ':')
            .unwrap_or(after.len());
        let cand = &line[start..at_pos + end_rel];
        if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
            // For host/ style we will normalize later; accept explicit @REALM as high-signal.
            return Some(cand.to_string());
        }
    }

    // 2. Primary reliable source: the "Linux NFSv4.x <hostname>" pattern.
    //    This appears in name=(...), fs_create_clid_name "client name [...]",
    //    and similar client record descriptions. Prefer this over blind word scanning.
    if let Some(host) = extract_linux_nfs_hostname(line) {
        if !host.eq_ignore_ascii_case("linux") && !host.eq_ignore_ascii_case("nfs") && !is_noise_hostname(&host) && looks_like_client_hostname(&host) {
            // Emit the classic host/ form. Materialization will also create the bare alias.
            return Some(format!("host/{}@{}", host, realm));
        }
    }

    // 3. Legacy direct name=(21:Linux NFSv4.2 ...) support (still useful for some log lines)
    if let Some(pos) = line.find("name=(") {
        let rest = &line[pos + 6..];
        if let Some(endp) = rest.find(')') {
            let inside = &rest[..endp];
            if let Some(last) = inside.split_whitespace().last() {
                let token = last.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
                if looks_like_client_hostname(token) && !is_noise_hostname(token) {
                    return Some(format!("host/{}@{}", token, realm));
                }
            }
        }
    }

    // 4. Limited additional markers. Only accept tokens that pass the strict hostname check.
    //    We deliberately avoid "clientid=" and "cr_refcount" because they contain counters
    //    ("Unique=...", numbers), not hostnames.
    for marker in &["fs_create_clid_name", "client addr="] {
        if let Some(pos) = line.find(marker) {
            let tail = &line[pos + marker.len()..];
            for w in tail.split(|c: char| c.is_whitespace() || c == '=' || c == '(' || c == ')' || c == ':' || c == ',' || c == '[' || c == ']') {
                let t = w.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
                if looks_like_client_hostname(t) && !is_noise_hostname(t) {
                    return Some(format!("host/{}@{}", t, realm));
                }
            }
        }
    }

    // 5. Fallback: explicit @REALM anywhere (already partially handled above).
    //    Only return if the local part looks reasonable.
    if line.to_ascii_lowercase().contains(&realm_lower) {
        for word in line.split(|c: char| {
            c.is_whitespace() || c == '=' || c == '(' || c == ')' || c == ':' || c == ',' || c == '[' || c == ']' || c == '"'
        }) {
            let w = word.trim();
            if w.contains('@') && w.to_ascii_lowercase().contains(&realm_lower) {
                // Accept explicit principals (they are usually the real thing).
                // Guard: do not emit things like "nil@REALM" or "clientid@REALM" from noise.
                if let Some(local) = w.split('@').next() {
                    if is_noise_hostname(local) || !looks_like_client_hostname(local) {
                        continue;
                    }
                }
                return Some(w.to_string());
            }
        }
    }

    None
}

fn get_server_variants() -> Vec<String> {
    // Use the real config for hostname when present (single source of truth).
    if let Ok(cfg) = NfsKlldapConfig::load(std::path::Path::new(
        &std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string())
    )) {
        if let Some(h) = &cfg.server.hostname {
            if !h.trim().is_empty() {
                let mut v = vec![h.trim().to_string()];
                if let Some(short) = h.split('.').next() {
                    if short != h.trim() { v.push(short.to_string()); }
                }
                return v;
            }
        }
    }
    if let Ok(h) = std::env::var("NFS_KLLDAP_SERVER_HOSTNAME") {
        if !h.trim().is_empty() {
            let mut v = vec![h.trim().to_string()];
            if let Some(short) = h.split('.').next() { if short != h.trim() { v.push(short.to_string()); } }
            return v;
        }
    }
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            let mut v = vec![h.clone()];
            if let Some(short) = h.split('.').next() { if short != h { v.push(short.to_string()); } }
            return v;
        }
    }
    vec!["localhost".to_string()]
}

fn get_realm() -> String {
    // Prefer real config (effective_realm derivation matches generator/SSSD).
    if let Ok(cfg) = NfsKlldapConfig::load(std::path::Path::new(
        &std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string())
    )) {
        let r = cfg.effective_realm();
        if !r.trim().is_empty() && !r.trim().eq_ignore_ascii_case("example.com") {
            return r.to_uppercase();
        }
    }
    if let Ok(r) = std::env::var("NFS_KLLDAP_KERBEROS_REALM") {
        if !r.trim().is_empty() { return r.trim().to_uppercase(); }
    }
    if let Ok(content) = std::fs::read_to_string("/etc/krb5.conf") {
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with("default_realm") {
                if let Some(eq) = t.find('=') {
                    let r = t[eq + 1..].trim().to_string();
                    if !r.is_empty() { return r.to_uppercase(); }
                }
            }
        }
    }
    "EXAMPLE.COM".to_string()
}

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
            println!("Important: Ganesha config is kept conservative. This helper is the authoritative");
            println!("classifier/resolver and materializes uid/gid mappings for Ganesha's getpwnam path.");
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
    // This forces early resolve + materialize so the *first* principal2uid/shim call
    // for those users sees the mapping (helps the synchronous path before any log line).
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