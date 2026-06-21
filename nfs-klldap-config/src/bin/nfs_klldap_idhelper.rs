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
//!   generation stays conservative and parser-safe. Translation lives here
//!   and is surfaced to Ganesha via nss_wrapper files (see below).
//! - Can operate standalone (direct NSS resolution) when the daemon is not
//!   reachable (early boot, diagnostics).
//!
//! Ganesha integration (the reason the idhelper exists):
//! The idhelper materializes small nss_wrapper and extrausers passwd/group files.
//! Ganesha is launched (when enabled) under LD_PRELOAD pointing at the wrapper,
//! or benefits from extrausers in nsswitch. This supplies the classification
//! (machine principals to uid 0, users to real LDAP ids) so that Ganesha's
//! getpwnam path during Kerberos owner mapping sees correct stable values.
//! The goal is preventing immutable clients from tearing down sessions from
//! mixing root and user credentials.
//!
//! Principal mapping parity requirement (ganesha 9.6 + trixie specific):
//! The container (server) must be able to perform the *same* information lookup
//! that a client does: `getent passwd testuser1` (and the full principal form
//! via idhelper). Ganesha's internal mapper sometimes calls "nfsidmap" for
//! "testuser1@REALM" (and host/... principals). The companion nfsidmap-idhelper
//! shim (in PATH only for ganesha) + this binary ensure consistent uid/gid for
//! both short names and full Kerberos principals. This was identified from
//! ganesha.log lines containing "using nfsidmap", "Could not map principal",
//! and uid2grp "Unsupported code path". Changes here must remain compatible
//! with ganesha 9.6 parser/startup on Debian 13-slim trixie-backports.
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
//!
//! Debug logging:
//!   KLLDAP_IDHELPER_DEBUG=true   (enables detailed RESOLVE logs: normalized key,
//!                                 cache hit/miss, classification, short name, getent
//!                                 attempts, final result, elapsed, cache write)

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

// Structured resolver (0.8.32): re-uses PosixAttributeMapping + filters + caching
// from the same logic that powers nfs-klldap-ui/src/ldap.rs.
use nfs_klldap_config::{IdLdapResolver, SssdSection};

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
        if local.contains('/') && (local.starts_with("host/") || local.starts_with("nfs/") || local.starts_with("root/")) {
            let alias = sanitize_for_nss(local); // turns host/blue-lt into host_blue-lt etc.
            if seen_login.insert(alias.clone()) {
                let gecos = format!("kll:machine-alias:{}", r.principal);
                passwd_lines.push(format!(
                    "{}:x:{}:{}:{}:/nonexistent:/usr/sbin/nologin",
                    alias, r.uid, r.gid, gecos
                ));
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

    // Always ensure at least a root group entry
    if seen_gid.is_empty() || !seen_gid.contains(&0) {
        group_lines.push("root:x:0:".to_string());
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
/// Ensures the server can do `getent passwd testuser1` (and full principal via
/// the idhelper) the same way clients do. See top-of-file comment on the
/// ganesha 9.6 / trixie principal mapping stabilization requirement.
/// SSSD lookup is used (via getent nss), and config-driven LDAP fallback ensures
/// resolution to ldap exists using info from nfs-klldap.conf.
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

/// Structured LDAP resolution using IdLdapResolver (preferred).
/// Falls back to legacy shell ldapsearch only if we cannot load creds/mapping.
/// Returns (uid, gid) or None. gid often equals uid for the primary group.
/// Now correctly populates search bases from nfs-klldap.conf (sssd.* or top-level)
/// so the same effective bases used by generator/SSSD/UI are honored.
fn resolve_via_structured_ldap(short_name: &str) -> Option<(u32, u32)> {
    let (resolver, bind_dn, bind_pw) = get_or_init_resolver()?;

    // Use the structured path (caches + identical filters). Resolver lives for daemon lifetime.
    if let Some((uid_i, gid_opt, _disp)) = resolver.resolve_user(short_name, &bind_dn, &bind_pw) {
        let uid = uid_i as u32;
        // Prefer gidNumber from the same posixAccount user entry (matches legacy ldapsearch behavior and
        // what the generator/SSSD expect). Fall back to uid or a group name lookup.
        let gid = gid_opt.map(|g| g as u32)
            .or_else(|| resolver.resolve_group(short_name, &bind_dn, &bind_pw).map(|(g, _)| g as u32))
            .unwrap_or(uid);
        return Some((uid, gid));
    }

    // Legacy shell fallback (use a sensible base; resolver already used correct one for main path).
    let base = "ou=people,dc=example,dc=com"; // conservative (structured path already honored conf)
    // uri only for the ldapsearch -H; use a placeholder that the shell path tolerates or fetch if needed
    resolve_via_ldap_shell_with_base(short_name, "ldaps://localhost", &bind_dn, &bind_pw, base)
}

/// Legacy shell ldapsearch path (kept as last-resort compatibility shim).
/// Do not extend; new work goes through IdLdapResolver.
/// base is now passed from the loaded config when available.
fn resolve_via_ldap_shell_with_base(short_name: &str, uri: &str, bind: &str, pw: &str, base: &str) -> Option<(u32, u32)> {
    let out = std::process::Command::new("ldapsearch")
        .args([
            "-o", "ldif-wrap=no",
            "-o", "tls_reqcert=never",
            "-x",
            "-H", uri,
            "-D", bind,
            "-w", pw,
            "-b", base,
            "-LLL",
            &format!("(uid={})", short_name),
            "uidNumber", "gidNumber",
        ])
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut uid = None;
    let mut gid = None;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("uidNumber:") {
            uid = l.split(':').nth(1).and_then(|s| s.trim().parse::<u32>().ok());
        } else if l.starts_with("gidNumber:") {
            gid = l.split(':').nth(1).and_then(|s| s.trim().parse::<u32>().ok());
        }
    }
    match (uid, gid) {
        (Some(u), Some(g)) => Some((u, g)),
        (Some(u), None) => Some((u, u)),
        _ => None,
    }
}

/// Load (uri, bind_dn, bind_pw) using the same sources the rest of the stack prefers.
/// Prefers explicit sssd. keys then top-level, then common env fallbacks.
fn load_ldap_creds_from_conf() -> Option<(String, String, String)> {
    let conf = load_conf();
    let uri = conf.get("sssd.ldap_uri")
        .or_else(|| conf.get("ldap_uri"))
        .cloned()
        .or_else(|| std::env::var("NFS_KLLDAP_LDAP_URI").ok())
        .or_else(|| std::env::var("LDAP_URI").ok())?;

    let bind = conf.get("sssd.ldap_default_bind_dn")
        .or_else(|| conf.get("ldap_default_bind_dn"))
        .cloned()
        .or_else(|| std::env::var("NFS_KLLDAP_SSSD_LDAP_DEFAULT_BIND_DN").ok())
        .or_else(|| std::env::var("NFS_KLLDAP_LLDAP_USER").ok())?;

    let pw = conf.get("sssd.ldap_default_authtok")
        .or_else(|| conf.get("ldap_default_authtok"))
        .cloned()
        .or_else(|| std::env::var("NFS_KLLDAP_SSSD_LDAP_DEFAULT_AUTHTOK").ok())
        .or_else(|| std::env::var("NFS_KLLDAP_LLDAP_PW").ok())?;

    if bind.trim().is_empty() || pw.trim().is_empty() {
        return None;
    }
    Some((uri, bind, pw))
}

/// Build a populated SssdSection from the flat conf map (or env) so that
/// effective_ldap_search_bases + resolve_posix... are driven by the actual
/// nfs-klldap.conf (including ldap_*_search_base). This ensures "resolution
/// information from the config is properly utilized".
fn build_sssd_for_resolver(conf: &std::collections::HashMap<String, String>) -> SssdSection {
    let mut s = SssdSection::default();

    // binds (required)
    if let Some(v) = conf.get("sssd.ldap_default_bind_dn").or_else(|| conf.get("ldap_default_bind_dn")) {
        s.ldap_default_bind_dn = v.clone();
    }
    if let Some(v) = conf.get("sssd.ldap_default_authtok").or_else(|| conf.get("ldap_default_authtok")) {
        s.ldap_default_authtok = v.clone();
    }

    // search bases (the key part for correct subtree queries)
    s.ldap_search_base = conf.get("sssd.ldap_search_base")
        .or_else(|| conf.get("ldap_search_base"))
        .cloned();
    s.ldap_user_search_base = conf.get("sssd.ldap_user_search_base")
        .or_else(|| conf.get("ldap_user_search_base"))
        .cloned();
    s.ldap_group_search_base = conf.get("sssd.ldap_group_search_base")
        .or_else(|| conf.get("ldap_group_search_base"))
        .cloned();

    // tls / other common that affect no_tls_verify etc.
    s.ldap_tls_reqcert = conf.get("sssd.ldap_tls_reqcert").or_else(|| conf.get("ldap_tls_reqcert")).cloned();
    s.ldap_id_use_start_tls = conf.get("sssd.ldap_id_use_start_tls")
        .or_else(|| conf.get("ldap_id_use_start_tls"))
        .and_then(|v| v.parse::<bool>().ok());

    // also copy any kllldap flag if present for ignored attrs / member (not strictly needed for id resolve)
    s.kllldap_ignored_attributes = conf.get("sssd.kllldap_ignored_attributes")
        .or_else(|| conf.get("kllldap_ignored_attributes"))
        .and_then(|v| v.parse::<bool>().ok());

    s
}

/// Lazily initialized resolver (with creds) so that the 10m identity + reverse caches
/// inside IdLdapResolver are effective across RESOLVE/getent/observer calls
/// (addresses previous per-call fresh instance problem).
static ID_RESOLVER: OnceLock<Option<(IdLdapResolver, String, String)>> = OnceLock::new();

fn get_or_init_resolver() -> Option<(&'static IdLdapResolver, String, String)> {
    if let Some(cached) = ID_RESOLVER.get().and_then(|o| o.as_ref()) {
        return Some((&cached.0, cached.1.clone(), cached.2.clone()));
    }
    let (uri, bind_dn, bind_pw) = load_ldap_creds_from_conf()?;
    let conf = load_conf();
    let mut sssd = build_sssd_for_resolver(&conf);
    sssd.ldap_default_bind_dn = bind_dn.clone();
    sssd.ldap_default_authtok = bind_pw.clone();
    let resolver = IdLdapResolver::from_sssd_section(&uri, &sssd);
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
    let line = s.lines().next()?;
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() > 3 {
        if let (Ok(uid), Ok(gid)) = (parts[2].parse::<u32>(), parts[3].parse::<u32>()) {
            eprintln!("[idhelper] getent passwd \"{}\" -> success uid={} gid={}", name, uid, gid);
            return Some((uid, gid, "sss".to_string()));
        }
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

        let looked = resolve_via_nss(first_try).or_else(|| resolve_via_nss(second_try));
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
            // Unknown / unmapped -> nobody-ish but keep the info
            eprintln!("[idhelper] getent for user principal=\"{}\" returned nothing -> falling back to 65534:65534", principal);
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
    }

    let elapsed = start.elapsed();
    dlog!("  elapsed={:?}", elapsed);

    resolved
}

/// Start a background observer that tails Ganesha's log to "catch" mount/auth attempts.
/// When lines containing client identities or possible principals appear, we extract
/// candidates (e.g. host/<client>@REALM from client names, or explicit user@REALM) and
/// feed them through resolve_principal. This makes the idhelper see activity even if
/// nothing is explicitly calling the RESOLVE socket/CLI.
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
    const NOISE: &[&str] = &[
        "unique", "client", "id", "debug", "info", "warning", "error",
        "ffff", "counter", "created", "name", "addr", "cr", "refcount",
        "nil", "null", "clientid", "conf", "unconf", "linux", "nfsv4"
    ];
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

/// Simple parser to load resolution info directly from nfs-klldap.conf (the source of truth).
/// This ensures "resolution information from the config/nfs-klldap.conf is properly utilized"
/// for realm, hostname (for principals), and ldap settings (for direct resolution fallback).
/// Keys are normalized from toml sections (e.g. "kerberos.realm", "sssd.ldap_uri", "server.hostname").
/// Falls back gracefully if conf not present or unreadable (e.g. during unit tests).
fn load_conf() -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;
    let path = std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string());
    let mut m: HashMap<String, String> = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(&path) {
        let mut current_section = String::new();
        for raw in content.lines() {
            let line = raw.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len()-1].trim().to_string();
                continue;
            }
            if let Some(eq) = line.find('=') {
                let key = line[..eq].trim().to_string();
                let val = line[eq+1..].trim().trim_matches('"').trim_matches('\'').to_string();
                if !current_section.is_empty() {
                    let full = format!("{}.{}", current_section, key);
                    m.insert(full.to_lowercase(), val.clone());
                }
                m.insert(key.to_lowercase(), val);
            }
        }
        if std::env::var("KLLDAP_IDHELPER_DEBUG").is_ok() {
            eprintln!("[idhelper-debug] load_conf from {} inserted keys: {:?}", path, m.keys().collect::<Vec<_>>());
        }
    }
    m
}

fn get_server_variants() -> Vec<String> {
    // Best effort: use hostname variants. In container this should be the real host.
    // Prefer resolution info from nfs-klldap.conf (properly utilizing the source config).
    let conf = load_conf();
    if let Some(h) = conf.get("server.hostname").or_else(|| conf.get("hostname")) {
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
    // Use conf first so resolution information from nfs-klldap.conf (kerberos.realm) is properly utilized.
    let conf = load_conf();
    if let Some(r) = conf.get("kerberos.realm").or_else(|| conf.get("realm")) {
        if !r.trim().is_empty() {
            return r.trim().to_uppercase();
        }
    }
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
            dlog!("cli RESOLVE p=\"{}\"", p);
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
}