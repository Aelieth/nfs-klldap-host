//! Shared types, constants, and config helpers for nfs-klldap-idhelper.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use nfs_klldap_config::{classify_principal, NfsKlldapConfig};

pub(crate) const SOCKET_PATH: &str = "/var/run/nfs-klldap/idhelper.sock";
pub(crate) const CACHE_PATH: &str = "/var/lib/nfs-klldap/idmap.cache";
const CACHE_VERSION: &str = "1";

// nss_wrapper files materialized by the idhelper so that the Ganesha process
// (launched under LD_PRELOAD=libnss_wrapper.so) sees correct uid/gid for both
// LDAP users and machine principals (host/..., nfs/..., root/...).
// These are the mechanism that actually wires idhelper classification into
// Ganesha's name-to-uid hot path for Kerberos owner strings.
pub(crate) const NSS_PASSWD_PATH: &str = "/var/lib/nfs-klldap/nss_passwd";
pub(crate) const NSS_GROUP_PATH: &str = "/var/lib/nfs-klldap/nss_group";

// Supplemental extrausers (libnss-extrausers) location. When configured in
// nsswitch (files extrausers sss) this lets us inject machine->root mappings
// without replacing the entire user database or hiding SSSD/LDAP users.
pub(crate) const EXTRAUSERS_PASSWD: &str = "/var/lib/extrausers/passwd";
pub(crate) const EXTRAUSERS_GROUP: &str = "/var/lib/extrausers/group";

/// Written after LDAP bulk-seed into nss_wrapper; entrypoint waits on this before Ganesha.
pub(crate) const BULK_SEED_MARKER: &str = "/var/lib/nfs-klldap/.bulk_seed_done";

/// Debug logging enabled via KLLDAP_IDHELPER_DEBUG=true (or 1/yes/on).
static DEBUG_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub(crate) fn debug_enabled() -> bool {
    *DEBUG_ENABLED.get_or_init(|| {
        std::env::var("KLLDAP_IDHELPER_DEBUG")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false)
    })
}

#[macro_export]
macro_rules! dlog {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {
        if $crate::common::debug_enabled() {
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
    pub(crate) fn as_str(&self) -> &'static str {
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
pub struct IdCache {
    // normalized principal -> entry
    pub(crate) entries: HashMap<String, Resolved>,
}

impl IdCache {
    pub(crate) fn get(&self, norm: &str) -> Option<&Resolved> {
        self.entries.get(norm)
    }

    pub(crate) fn insert(&mut self, r: Resolved) {
        let key = normalize_principal(&r.principal);
        self.entries.insert(key, r);
    }

    pub fn load_from_file(path: &Path) -> Self {
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

    pub(crate) fn write_to_file(&self, path: &Path) -> io::Result<()> {
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
pub fn is_machine_principal(
    principal: &str,
    realm: &str,
    server_variants: &[String],
) -> (bool, String) {
    // Delegate to the shared implementation (centralized prefixes + logic) for
    // unification and to guarantee idhelper + any future users have identical
    // classification for hybrid machine (host/nfs/root) vs user TGT principals.
    classify_principal(principal, realm, server_variants)
}

/// Normalize a principal for cache key and lookup.
/// Lowercases the realm part, keeps the local part as presented (SSSD is often case-sensitive for uid).
pub fn normalize_principal(p: &str) -> String {
    let p = p.trim();
    if let Some(at) = p.rfind('@') {
        let (local, realm) = p.split_at(at);
        format!("{}{}", local, realm.to_ascii_uppercase())
    } else {
        p.to_string()
    }
}

pub(crate) fn get_server_variants() -> Vec<String> {
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

pub(crate) fn get_realm() -> String {
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
