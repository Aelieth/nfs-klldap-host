//! Shared types, constants, and config helpers for nfs-klldap-idhelper.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use nfs_klldap_config::{
    any_share_manage_gids_enabled, runtime_realm_from_disk,
    runtime_server_variants_from_disk, NfsKlldapConfig,
};
use nfs_klldap_identity::{machine_short_name, normalize_principal, principal_local_part};
pub(crate) const SOCKET_PATH: &str = "/var/run/nfs-klldap/idhelper.sock";
pub(crate) const CACHE_PATH: &str = "/var/lib/nfs-klldap/idmap.cache";
const CACHE_VERSION: &str = "1";

// Nss_wrapper passwd/group for LD_PRELOAD principal→uid mapping in Ganesha.
pub(crate) const NSS_PASSWD_PATH: &str = "/var/lib/nfs-klldap/nss_passwd";
pub(crate) const NSS_GROUP_PATH: &str = "/var/lib/nfs-klldap/nss_group";

// Supplemental extrausers entries for machine→root mappings. Written.
pub(crate) const EXTRAUSERS_PASSWD: &str = "/var/lib/extrausers/passwd";
pub(crate) const EXTRAUSERS_GROUP: &str = "/var/lib/extrausers/group";

/// The entrypoint waits on this marker after LDAP bulk-seed finishes.
pub(crate) const BULK_SEED_MARKER: &str = "/var/lib/nfs-klldap/.bulk_seed_done";

/// The default LDAP sync interval matches the IdLdapResolver ten-minute TTL.
pub(crate) const DEFAULT_REBULK_INTERVAL_SECS: u64 = 10 * 60;

/// Debug logging enabled via KLLDAP_IDHELPER_DEBUG=true (or 1/yes/on).
static DEBUG_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Serializes env-mutating idhelper tests under parallel cargo test.
#[cfg(test)]
pub(crate) static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Returns true when any share enables Manage_Gids logging.
pub(crate) fn manage_gids_expected() -> bool {
    let path =
        std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string());
    #[cfg(test)]
    {
        NfsKlldapConfig::load(std::path::Path::new(&path))
            .map(|cfg| any_share_manage_gids_enabled(&cfg))
            .unwrap_or(true)
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
    // Normalized principal  maps to  entry.
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

    /// Returns a stable hash so nss materialize skips unchanged cache writes.
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

    /// Removes users but keeps machine principals like host/ and nfs/.
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
                // Principal|uid|gid|kind|source.
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
                    // Machines use the trailing host segment as short name.
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
            // Stable order for easier file processing / diffing.
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

pub(crate) fn get_server_variants() -> Vec<String> {
    runtime_server_variants_from_disk()
}

pub(crate) fn get_realm() -> String {
    runtime_realm_from_disk()
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
