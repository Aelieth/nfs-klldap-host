//! Shared types, constants, and config helpers for nfs-klldap-idhelper.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use nfs_klldap_config::{any_share_manage_gids_enabled, classify_principal, NfsKlldapConfig};
use nfs_klldap_identity::nfs_keytab_host_variants;

pub(crate) const SOCKET_PATH: &str = "/var/run/nfs-klldap/idhelper.sock";
pub(crate) const CACHE_PATH: &str = "/var/lib/nfs-klldap/idmap.cache";
const CACHE_VERSION: &str = "1";

// nss_wrapper passwd/group files Ganesha reads under LD_PRELOAD for Kerberos principal→uid.
pub(crate) const NSS_PASSWD_PATH: &str = "/var/lib/nfs-klldap/nss_passwd";
pub(crate) const NSS_GROUP_PATH: &str = "/var/lib/nfs-klldap/nss_group";

// Supplemental extrausers entries for machine→root mappings alongside SSSD users.
pub(crate) const EXTRAUSERS_PASSWD: &str = "/var/lib/extrausers/passwd";
pub(crate) const EXTRAUSERS_GROUP: &str = "/var/lib/extrausers/group";

/// Written after LDAP bulk-seed into nss_wrapper; entrypoint waits on this before Ganesha.
pub(crate) const BULK_SEED_MARKER: &str = "/var/lib/nfs-klldap/.bulk_seed_done";

/// Default periodic LDAP→nss_wrapper sync interval (matches IdLdapResolver 10m TTL).
pub(crate) const DEFAULT_REBULK_INTERVAL_SECS: u64 = 10 * 60;

/// Debug logging enabled via KLLDAP_IDHELPER_DEBUG=true (or 1/yes/on).
static DEBUG_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// True when any share has effective Manage_Gids (controls supplementary-group log noise).
pub(crate) fn manage_gids_expected() -> bool {
    let path =
        std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string());
    #[cfg(test)]
    {
        return NfsKlldapConfig::load(std::path::Path::new(&path))
            .map(|cfg| any_share_manage_gids_enabled(&cfg))
            .unwrap_or(true);
    }
    #[cfg(not(test))]
    {
        static EXPECT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *EXPECT.get_or_init(|| {
            NfsKlldapConfig::load(std::path::Path::new(&path))
                .map(|cfg| any_share_manage_gids_enabled(&cfg))
                .unwrap_or(true)
        })
    }
}

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

    /// Stable hash of cache contents; used to skip redundant nss materialize writes.
    pub(crate) fn content_fingerprint(&self) -> u64 {
        let mut keys: Vec<_> = self.entries.keys().collect();
        keys.sort();
        let mut h: u64 = 0xcbf29ce484222325;
        for k in keys {
            if let Some(r) = self.entries.get(k) {
                for b in k
                    .bytes()
                    .chain(r.name.bytes())
                    .chain(r.uid.to_le_bytes())
                    .chain(r.gid.to_le_bytes())
                    .chain(r.kind.as_str().bytes())
                {
                    h = h.wrapping_mul(0x100000001b3) ^ u64::from(b);
                }
            }
        }
        h
    }

    /// Remove user and unknown entries; keep machine principals (host/, nfs/, etc.).
    /// Returns the number of entries removed.
    pub(crate) fn prune_non_machine_users(&mut self) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, r| r.kind == PrincipalKind::Machine);
        before.saturating_sub(self.entries.len())
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
                    let local = principal_local_part(parts[0]);
                    // Machine principals use the trailing host segment as the nss login name.
                    let name = if local.contains('/') {
                        machine_short_name(parts[0]).to_string()
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

/// True when principal is a machine service name (host/nfs/root) vs a user TGT.
pub fn is_machine_principal(
    principal: &str,
    realm: &str,
    server_variants: &[String],
) -> (bool, String) {
    classify_principal(principal, realm, server_variants)
}

pub(crate) use nfs_klldap_config::{machine_short_name, principal_local_part};

/// Normalize a principal for cache key and lookup.
/// Uppercases realm; local part matches principal_local_part (trim + first @ segment).
pub fn normalize_principal(p: &str) -> String {
    let p = p.trim();
    if let Some(at) = p.find('@') {
        let local = principal_local_part(p);
        let realm = p[at + 1..].trim();
        format!("{}@{}", local, realm.to_ascii_uppercase())
    } else {
        p.to_string()
    }
}

fn config_path() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string()),
    )
}

fn load_runtime_config() -> Option<NfsKlldapConfig> {
    NfsKlldapConfig::load(&config_path()).ok()
}

fn resolve_hostname_for_idhelper() -> String {
    if let Some(h) = load_runtime_config()
        .and_then(|cfg| cfg.server.hostname)
        .filter(|h| !h.trim().is_empty())
    {
        return h.trim().to_string();
    }
    if let Ok(h) = std::env::var("NFS_KLLDAP_SERVER_HOSTNAME") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    "localhost".to_string()
}

pub(crate) fn get_server_variants() -> Vec<String> {
    let variants = nfs_keytab_host_variants(&resolve_hostname_for_idhelper());
    if variants.is_empty() {
        vec!["localhost".to_string()]
    } else {
        variants
    }
}

pub(crate) fn get_realm() -> String {
    if let Some(cfg) = load_runtime_config() {
        let r = cfg.effective_realm();
        if !r.trim().is_empty() && !r.trim().eq_ignore_ascii_case("example.com") {
            return r.to_uppercase();
        }
    }
    if let Ok(r) = std::env::var("NFS_KLLDAP_KERBEROS_REALM") {
        if !r.trim().is_empty() {
            return r.trim().to_uppercase();
        }
    }
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

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    #[test]
    fn identical_reinsert_keeps_fingerprint() {
        let mut c = IdCache::default();
        let r = Resolved {
            principal: "alice@TEST".into(),
            name: "alice".into(),
            uid: 1001,
            gid: 1001,
            kind: PrincipalKind::User,
            source: "sss".into(),
        };
        c.insert(r.clone());
        let fp = c.content_fingerprint();
        c.insert(r);
        assert_eq!(fp, c.content_fingerprint());
    }

    #[test]
    fn changed_uid_updates_fingerprint() {
        let mut c = IdCache::default();
        c.insert(Resolved {
            principal: "bob@TEST".into(),
            name: "bob".into(),
            uid: 1001,
            gid: 1001,
            kind: PrincipalKind::User,
            source: "sss".into(),
        });
        let fp = c.content_fingerprint();
        c.insert(Resolved {
            principal: "bob@TEST".into(),
            name: "bob".into(),
            uid: 1002,
            gid: 1001,
            kind: PrincipalKind::User,
            source: "ldap".into(),
        });
        assert_ne!(fp, c.content_fingerprint());
    }
}
