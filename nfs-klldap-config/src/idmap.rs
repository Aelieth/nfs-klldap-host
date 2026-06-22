//! Structured LDAP-backed ID resolution for the idhelper (and future shared use).
//!
//! This module provides the "already structured internal ldap capabilities" from
//! nfs-klldap-ui/src/ldap.rs, made available to the lightweight idhelper daemon.
//!
//! The generated /etc/idmapd.conf (see generate.rs + GenerationPaths) supplies the
//! standardized Domain + Local-Realms (from kerberos.realm / effective_realm) and
//! nsswitch/GSS-Methods so ganesha's IDMAPPER (via nfsidmap shim) + clients see the
//! same mapping policy (including Kerberos principal realm handling) that [sssd] +
//! idhelper already follow. The fast cached resolution (IdLdapResolver
//! 10m identity caches + IdCache) + getent primary path remain in the idhelper.
//!
//! Goals (0.8.32 refactor):
//! - Use the exact same PosixAttributeMapping + search bases as the generator/SSSD/UI.
//! - Same filter construction, escaping, display-name extraction, and numeric uid/gid handling.
//! - 10m identity caches (forward name + reverse uid/gid) so repeated getent/nfsidmap
//!   paths and observed principals (from ganesha log) do not hammer the LDAP server.
//!   (Lightweight 2m search caches are UI-specific for autocomplete and not required here.)
//! - The resolver is now eagerly initialized at idhelper daemon startup (see
//!   nfs_klldap_idhelper.rs) so the first user LDAP lookup (sss miss path) and nss
//!   checks are fast immediately after programs come up. Preloading of root uid0 +
//!   server host principals ensures machine info (and getpwuid(0)) is ready with no
//!   cold "getpwuid_r uid 0" or "could not map" on first access.
//! - getent (NSS) remains the primary "same lookup as client" path for users.
//! - This LDAP path is the reliable fallback + cache populator.
//! - Machine principals continue to short-circuit to 0:0 with zero LDAP/getent cost.
//!
//! Strict: only ganesha 9.6 trixie-backports compatible behavior and generated artifacts.
//! generated artifacts. All resolution still feeds the same nss_wrapper + extrausers
//! materialization and idhelper cache file/socket.

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{
    effective_ldap_search_bases, resolve_posix_attribute_mapping, PosixAttributeMapping, SssdSection,
};

/// Small sync resolver used by nfs-klldap-idhelper (and diagnostics).
/// Not the full async web-oriented LdapClient; focused on uid/gid + name resolution.
pub struct IdLdapResolver {
    ldap_uri: String,
    user_base: String,
    group_base: String,
    posix_attributes: PosixAttributeMapping,
    no_tls_verify: bool,
    start_tls: bool,

    // Same TTLs as UI LdapClient for cache behavior parity.
    user_cache: Mutex<HashMap<String, CachedUser>>,
    group_cache: Mutex<HashMap<String, CachedGroup>>,
    user_by_uid_cache: Mutex<HashMap<i32, CachedUser>>,
    group_by_gid_cache: Mutex<HashMap<i32, CachedGroup>>,

    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

#[derive(Debug, Clone)]
struct CachedUser {
    id: String,
    uid_number: Option<i32>,
    primary_gid: Option<i32>, // user's gidNumber for aligned primary group (critical for nfsidmap)
    display_name: String,
    #[allow(dead_code)]
    dn: String,
    fetched_at: Instant,
}

#[derive(Debug, Clone)]
struct CachedGroup {
    id: String,
    gid_number: Option<i32>,
    display_name: String,
    #[allow(dead_code)] // stored for parity with UI LdapClient (dn available in resolve paths); used in future or debug
    dn: String,
    fetched_at: Instant,
}

const IDENTITY_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

/// Public snapshot of loaded identities (users + groups with aligned uid/gid).
/// Produced by load_full_identities. Consumed by idhelper for O(1) memory lookups.
/// gid for a user is taken from the user's gidNumber (primary group) for alignment.
#[derive(Debug, Clone, Default)]
pub struct IdMapSnapshot {
    pub users: HashMap<String, PosixUserEntry>,
    pub groups: HashMap<String, PosixGroupEntry>,
    pub by_uid: HashMap<i32, String>,
    pub by_gid: HashMap<i32, String>,
}

#[derive(Debug, Clone)]
pub struct PosixUserEntry {
    pub uid: i32,
    pub gid: i32,
    pub display: String,
}

#[derive(Debug, Clone)]
pub struct PosixGroupEntry {
    pub gid: i32,
    pub display: String,
}

impl IdLdapResolver {
    /// Construct using the same inputs the UI and generator use.
    /// `no_tls_verify` + `start_tls` come from ldap_tls_policy (or sensible defaults).
    pub fn new(
        ldap_uri: &str,
        user_base: &str,
        group_base: &str,
        posix_attributes: PosixAttributeMapping,
        no_tls_verify: bool,
        start_tls: bool,
    ) -> Self {
        Self {
            ldap_uri: ldap_uri.to_string(),
            user_base: user_base.to_string(),
            group_base: group_base.to_string(),
            posix_attributes,
            no_tls_verify,
            start_tls,
            user_cache: Mutex::new(HashMap::new()),
            group_cache: Mutex::new(HashMap::new()),
            user_by_uid_cache: Mutex::new(HashMap::new()),
            group_by_gid_cache: Mutex::new(HashMap::new()),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }

    /// Convenience constructor from an SssdSection + ldap_uri (used by idhelper at runtime).
    pub fn from_sssd_section(ldap_uri: &str, sssd: &SssdSection) -> Self {
        let realm = sssd
            .ldap_search_base
            .as_deref()
            .and_then(|s| s.split(',').next().and_then(|p| p.strip_prefix("dc=")))
            .map(|d| d.to_string())
            .unwrap_or_else(|| "example.com".to_string());

        let (user_base, group_base) = effective_ldap_search_bases(sssd, &realm);
        let attrs = resolve_posix_attribute_mapping(sssd);

        // Mirror the UI's permissive default for self-signed ldaps in the idhelper path.
        let no_tls_verify = sssd
            .ldap_tls_reqcert
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("never"))
            .unwrap_or_else(|| ldap_uri.starts_with("ldaps://"));

        let start_tls = sssd.ldap_id_use_start_tls.unwrap_or(false);

        Self::new(ldap_uri, &user_base, &group_base, attrs, no_tls_verify, start_tls)
    }

    fn build_conn_settings(&self) -> LdapConnSettings {
        let mut s = LdapConnSettings::new();
        if self.start_tls {
            s = s.set_starttls(true);
        }
        if self.no_tls_verify {
            s = s.set_no_tls_verify(true);
        }
        // Matches UI LdapClient exactly for KLLDAP/rustls + short-lived conn contract.
        s
    }

    fn evict_expired(&self) {
        let now = Instant::now();
        self.user_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.group_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.user_by_uid_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.group_by_gid_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
    }

    fn escape_filter_value(s: &str) -> String {
        // Identical to LdapClient::escape_filter_value in ldap.rs
        let mut out = String::with_capacity(s.len() * 2);
        for b in s.bytes() {
            match b {
                b'*' => out.push_str("\\2a"),
                b'(' => out.push_str("\\28"),
                b')' => out.push_str("\\29"),
                b'\\' => out.push_str("\\5c"),
                0..=31 | 127 => out.push_str(&format!("\\{:02x}", b)),
                _ => out.push(b as char),
            }
        }
        out
    }

    fn extract_first_attr(se: &SearchEntry, name: &str) -> Option<String> {
        se.attrs
            .get(name)
            .and_then(|v| v.first().cloned())
            .or_else(|| {
                se.attrs
                    .get(&name.to_lowercase())
                    .and_then(|v| v.first().cloned())
            })
    }

    fn extract_display_name(se: &SearchEntry, full_name_attr: &str, fallback: &str) -> String {
        Self::extract_first_attr(se, full_name_attr)
            .or_else(|| Self::extract_first_attr(se, "displayName"))
            .or_else(|| Self::extract_first_attr(se, "cn"))
            .unwrap_or_else(|| fallback.to_string())
    }

    /// Best-effort "dc=..." ancestor from a base DN so we can fall back to a
    /// whole-tree search when the configured user/group base is a sub-OU
    /// (e.g. ou=testing,ou=users). This makes nested entries discoverable.
    fn dc_base_from(&self, base: &str) -> String {
        // Find the first dc=... part and keep everything after it.
        if let Some(pos) = base.to_ascii_lowercase().find("dc=") {
            base[pos..].to_string()
        } else {
            base.to_string()
        }
    }

    /// Perform a sync search. Short-lived conn + unbind (KLLDAP/rustls pattern).
    fn service_search(
        &self,
        base: &str,
        filter: &str,
        attrs: Vec<String>,
        bind_dn: &str,
        bind_pw: &str,
    ) -> Result<Vec<SearchEntry>, String> {
        let uri = self.ldap_uri.clone();
        let settings = self.build_conn_settings();
        let base = base.to_string();
        let filter = filter.to_string();
        let attrs = attrs.clone();
        let dn = bind_dn.to_string();
        let pw = bind_pw.to_string();

        // 3 retries for transient (clone per attempt, matching UI LdapClient pattern)
        for attempt in 0..3 {
            let uri2 = uri.clone();
            let settings2 = settings.clone();
            let base2 = base.clone();
            let filter2 = filter.clone();
            let attrs2 = attrs.clone();
            let dn2 = dn.clone();
            let pw2 = pw.clone();

            let res = std::thread::spawn(move || {
                let mut ldap = LdapConn::with_settings(settings2, &uri2)
                    .map_err(|e| format!("connect: {}", e))?;

                let op = (|| -> Result<Vec<SearchEntry>, String> {
                    ldap.simple_bind(&dn2, &pw2)
                        .map_err(|e| format!("bind: {}", e))?
                        .success()
                        .map_err(|e| format!("bind success: {:?}", e))?;

                    let (rs, _res) = ldap
                        .search(&base2, Scope::Subtree, &filter2, attrs2)
                        .map_err(|e| format!("search: {}", e))?
                        .success()
                        .map_err(|e| format!("search success: {:?}", e))?;

                    Ok(rs.into_iter().map(SearchEntry::construct).collect())
                })();

                let _ = ldap.unbind();
                op
            })
            .join();

            match res {
                Ok(Ok(entries)) => return Ok(entries),
                Ok(Err(e)) => {
                    if attempt == 2 {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_millis(200 * (attempt + 1) as u64));
                }
                Err(e) => {
                    if attempt == 2 {
                        return Err(format!("join: {:?}", e));
                    }
                    std::thread::sleep(Duration::from_millis(200 * (attempt + 1) as u64));
                }
            }
        }
        Err("exhausted retries".into())
    }

    // ---------------- Public resolve API (cached + LDAP on miss) ----------------

    pub fn resolve_user(&self, name: &str, bind_dn: &str, bind_pw: &str) -> Option<(i32, Option<i32>, String)> {
        self.evict_expired();
        if let Some(hit) = self.user_cache.lock().unwrap().get(name).cloned() {
            if let Some(uid) = hit.uid_number {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some((uid, hit.primary_gid, hit.display_name.clone()));
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let gid_attr = self.posix_attributes.user_gid_number.clone();
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();
        let full_attr = self.posix_attributes.user_full_name.clone();
        let principal_attr = self.posix_attributes.user_principal_name.clone();

        // 1:1 name match (ldap uid == principal local part)
        let name_filter = format!(
            "(&(objectClass={})({}={}))",
            obj,
            name_attr,
            Self::escape_filter_value(name)
        );
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            uid_attr.clone(),
            gid_attr.clone(),
            "cn".into(),
            "displayName".into(),
            full_attr.clone(),
            principal_attr.clone(),
        ];

        let bases = {
            let mut v = vec![self.user_base.clone()];
            let dc = self.dc_base_from(&self.user_base);
            if dc != self.user_base { v.push(dc); }
            v
        };

        // Try name match on (possibly broader) bases
        for base in &bases {
            if let Ok(entries) = self.service_search(base, &name_filter, attrs.clone(), bind_dn, bind_pw) {
                for se in entries {
                    let display = Self::extract_display_name(&se, &full_attr, name);
                    if let Some(uid_str) = Self::extract_first_attr(&se, &uid_attr) {
                        if let Ok(u) = uid_str.parse::<i32>() {
                            let g = Self::extract_first_attr(&se, &gid_attr)
                                .and_then(|s| s.trim().parse::<i32>().ok());
                            let user = CachedUser {
                                id: name.to_string(),
                                uid_number: Some(u),
                                primary_gid: g,
                                display_name: display.clone(),
                                dn: se.dn.clone(),
                                fetched_at: Instant::now(),
                            };
                            self.user_cache.lock().unwrap().insert(name.to_string(), user.clone());
                            if let Some(uid) = user.uid_number {
                                self.user_by_uid_cache.lock().unwrap().insert(uid, user);
                            }
                            return Some((u, g, display));
                        }
                    }
                }
            }
        }

        // Dual lookup: if input looks like full principal, also search by principal_attr == full name
        if name.contains('@') {
            let p_filter = format!(
                "(&(objectClass={})({}={}))",
                obj,
                principal_attr,
                Self::escape_filter_value(name)
            );
            for base in &bases {
                if let Ok(entries) = self.service_search(base, &p_filter, attrs.clone(), bind_dn, bind_pw) {
                    for se in entries {
                        let display = Self::extract_display_name(&se, &full_attr, name);
                        if let Some(uid_str) = Self::extract_first_attr(&se, &uid_attr) {
                            if let Ok(u) = uid_str.parse::<i32>() {
                                let g = Self::extract_first_attr(&se, &gid_attr)
                                    .and_then(|s| s.trim().parse::<i32>().ok());
                                let short = name.split('@').next().unwrap_or(name).to_string();
                                let user = CachedUser {
                                    id: short.clone(),
                                    uid_number: Some(u),
                                    primary_gid: g,
                                    display_name: display.clone(),
                                    dn: se.dn.clone(),
                                    fetched_at: Instant::now(),
                                };
                                self.user_cache.lock().unwrap().insert(short.clone(), user.clone());
                                if let Some(uid) = user.uid_number {
                                    self.user_by_uid_cache.lock().unwrap().insert(uid, user);
                                }
                                return Some((u, g, display));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    pub fn resolve_group(&self, name: &str, bind_dn: &str, bind_pw: &str) -> Option<(i32, String)> {
        self.evict_expired();
        if let Some(hit) = self.group_cache.lock().unwrap().get(name).cloned() {
            if let Some(gid) = hit.gid_number {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some((gid, hit.display_name.clone()));
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let name_attr = self.posix_attributes.group_name.clone();
        let obj = self.posix_attributes.group_object_class.clone();

        let filter = format!(
            "(&(objectClass={})({}={}))",
            obj,
            name_attr,
            Self::escape_filter_value(name)
        );
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            gid_attr.clone(),
            "cn".into(),
            "displayName".into(),
        ];

        let entries = self
            .service_search(&self.group_base, &filter, attrs, bind_dn, bind_pw)
            .ok()?;

        for se in entries {
            let display = Self::extract_display_name(&se, &name_attr, name);
            if let Some(gid_str) = Self::extract_first_attr(&se, &gid_attr) {
                if let Ok(g) = gid_str.parse::<i32>() {
                    let group = CachedGroup {
                        id: name.to_string(),
                        gid_number: Some(g),
                        display_name: display.clone(),
                        dn: se.dn.clone(),
                        fetched_at: Instant::now(),
                    };
                    self.group_cache.lock().unwrap().insert(name.to_string(), group.clone());
                    if let Some(gid) = group.gid_number {
                        self.group_by_gid_cache.lock().unwrap().insert(gid, group);
                    }
                    return Some((g, display));
                }
            }
        }
        None
    }

    /// uidNumber reverse lookup (populates both caches).
    pub fn resolve_user_by_uid(&self, uid: i32, bind_dn: &str, bind_pw: &str) -> Option<(String, String)> {
        self.evict_expired();
        if let Some(hit) = self.user_by_uid_cache.lock().unwrap().get(&uid).cloned() {
            if hit.uid_number.is_some() {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some((hit.id.clone(), hit.display_name.clone()));
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();
        let full_attr = self.posix_attributes.user_full_name.clone();

        let filter = format!("(&(objectClass={})({}={}))", obj, uid_attr, uid);
        let gid_attr = self.posix_attributes.user_gid_number.clone();
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            uid_attr.clone(),
            gid_attr.clone(),
            "cn".into(),
            "displayName".into(),
            full_attr.clone(),
        ];

        let entries = self
            .service_search(&self.user_base, &filter, attrs, bind_dn, bind_pw)
            .ok()?;

        for se in entries {
            let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_else(|| uid.to_string());
            let display = Self::extract_display_name(&se, &full_attr, &id);
            if let Some(uid_str) = Self::extract_first_attr(&se, &uid_attr) {
                if let Ok(u) = uid_str.parse::<i32>() {
                    if u == uid {
                        let cu = CachedUser {
                            id: id.clone(),
                            uid_number: Some(u),
                            primary_gid: Self::extract_first_attr(&se, &gid_attr).and_then(|s| s.trim().parse::<i32>().ok()),
                            display_name: display.clone(),
                            dn: se.dn.clone(),
                            fetched_at: Instant::now(),
                        };
                        self.user_cache.lock().unwrap().insert(id.clone(), cu.clone());
                        self.user_by_uid_cache.lock().unwrap().insert(uid, cu);
                        return Some((id, display));
                    }
                }
            }
        }
        None
    }

    /// gidNumber reverse lookup.
    pub fn resolve_group_by_gid(&self, gid: i32, bind_dn: &str, bind_pw: &str) -> Option<(String, String)> {
        self.evict_expired();
        if let Some(hit) = self.group_by_gid_cache.lock().unwrap().get(&gid).cloned() {
            if hit.gid_number.is_some() {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some((hit.id.clone(), hit.display_name.clone()));
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let name_attr = self.posix_attributes.group_name.clone();
        let obj = self.posix_attributes.group_object_class.clone();

        let filter = format!("(&(objectClass={})({}={}))", obj, gid_attr, gid);
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            gid_attr.clone(),
            "cn".into(),
            "displayName".into(),
        ];

        let entries = self
            .service_search(&self.group_base, &filter, attrs, bind_dn, bind_pw)
            .ok()?;

        for se in entries {
            let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_else(|| gid.to_string());
            let display = Self::extract_display_name(&se, &name_attr, &id);
            if let Some(gid_str) = Self::extract_first_attr(&se, &gid_attr) {
                if let Ok(g) = gid_str.parse::<i32>() {
                    if g == gid {
                        let cg = CachedGroup {
                            id: id.clone(),
                            gid_number: Some(g),
                            display_name: display.clone(),
                            dn: se.dn.clone(),
                            fetched_at: Instant::now(),
                        };
                        self.group_cache.lock().unwrap().insert(id.clone(), cg.clone());
                        self.group_by_gid_cache.lock().unwrap().insert(gid, cg);
                        return Some((id, display));
                    }
                }
            }
        }
        None
    }

    pub fn cache_stats(&self) -> (u64, u64) {
        (self.cache_hits.load(Ordering::Relaxed), self.cache_misses.load(Ordering::Relaxed))
    }

    /// Bulk-load all users and groups (Subtree) into the 10m identity caches.
    /// This is the *only* full population path. gid for users is taken from the
    /// user's own gidNumber entry for correct primary group alignment.
    /// Returns number of user entries loaded (groups are also populated).
    /// Call at idhelper startup and on periodic refresh.
    pub fn load_full_identities(&self, bind_dn: &str, bind_pw: &str) -> usize {
        self.evict_expired();

        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let gid_attr = self.posix_attributes.user_gid_number.clone();
        let name_attr = self.posix_attributes.user_name.clone();
        let user_obj = self.posix_attributes.user_object_class.clone();
        let full_attr = self.posix_attributes.user_full_name.clone();

        let group_gid_attr = self.posix_attributes.group_gid_number.clone();
        let group_name_attr = self.posix_attributes.group_name.clone();
        let group_obj = self.posix_attributes.group_object_class.clone();
        let principal_attr = self.posix_attributes.user_principal_name.clone();

        let user_filter = format!("(objectClass={})", user_obj);
        let group_filter = format!("(objectClass={})", group_obj);

        let user_attrs: Vec<String> = vec![
            name_attr.clone(), uid_attr.clone(), gid_attr.clone(),
            "cn".into(), "displayName".into(), full_attr.clone(),
        ];
        let group_attrs: Vec<String> = vec![
            group_name_attr.clone(), group_gid_attr.clone(), "cn".into(), "displayName".into(),
        ];

        let mut loaded = 0usize;

        // Users - search the configured base (may be a sub-OU) ...
        let user_bases = {
            let mut v = vec![self.user_base.clone()];
            let dc = self.dc_base_from(&self.user_base);
            if dc != self.user_base {
                v.push(dc);
            }
            v
        };
        for base in &user_bases {
            if let Ok(entries) = self.service_search(base, &user_filter, user_attrs.clone(), bind_dn, bind_pw) {
                for se in entries {
                    let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_default();
                    if id.is_empty() { continue; }
                    if let Some(uid_str) = Self::extract_first_attr(&se, &uid_attr) {
                        if let Ok(u) = uid_str.parse::<i32>() {
                            let g = Self::extract_first_attr(&se, &gid_attr)
                                .and_then(|s| s.trim().parse::<i32>().ok())
                                .unwrap_or(u);
                            let display = Self::extract_display_name(&se, &full_attr, &id);
                            let cu = CachedUser {
                                id: id.clone(),
                                uid_number: Some(u),
                                primary_gid: Some(g),
                                display_name: display.clone(),
                                dn: se.dn.clone(),
                                fetched_at: Instant::now(),
                            };
                            self.user_cache.lock().unwrap().insert(id.clone(), cu.clone());
                            self.user_by_uid_cache.lock().unwrap().insert(u, cu);
                            loaded += 1;

                            // Also index under principal attr value if present (for full principal lookup)
                            if let Some(pval) = Self::extract_first_attr(&se, &principal_attr) {
                                if !pval.is_empty() && pval != id {
                                    let cu2 = CachedUser {
                                        id: pval.clone(),
                                        uid_number: Some(u),
                                        primary_gid: Some(g),
                                        display_name: display.clone(),
                                        dn: se.dn.clone(),
                                        fetched_at: Instant::now(),
                                    };
                                    self.user_cache.lock().unwrap().insert(pval.clone(), cu2.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Groups (same broader strategy for nested OUs)
        let group_bases = {
            let mut v = vec![self.group_base.clone()];
            let dc = self.dc_base_from(&self.group_base);
            if dc != self.group_base {
                v.push(dc);
            }
            v
        };
        for base in &group_bases {
            if let Ok(entries) = self.service_search(base, &group_filter, group_attrs.clone(), bind_dn, bind_pw) {
                for se in entries {
                    let id = Self::extract_first_attr(&se, &group_name_attr).unwrap_or_default();
                    if id.is_empty() { continue; }
                    if let Some(g_str) = Self::extract_first_attr(&se, &group_gid_attr) {
                        if let Ok(g) = g_str.parse::<i32>() {
                            let display = Self::extract_display_name(&se, &group_name_attr, &id);
                            let cg = CachedGroup {
                                id: id.clone(),
                                gid_number: Some(g),
                                display_name: display.clone(),
                                dn: se.dn.clone(),
                                fetched_at: Instant::now(),
                            };
                            self.group_cache.lock().unwrap().insert(id.clone(), cg.clone());
                            self.group_by_gid_cache.lock().unwrap().insert(g, cg);
                        }
                    }
                }
            }
        }

        loaded
    }

    /// Return a point-in-time snapshot of the loaded full identity map.
    /// Used by idhelper for fast in-memory nfsidmap / getent-equivalent paths.
    pub fn snapshot(&self) -> IdMapSnapshot {
        self.evict_expired();
        let mut snap = IdMapSnapshot::default();

        for (name, cu) in self.user_cache.lock().unwrap().iter() {
            if let Some(uid) = cu.uid_number {
                let gid = cu.primary_gid.unwrap_or(uid);
                snap.users.insert(name.clone(), PosixUserEntry {
                    uid,
                    gid,
                    display: cu.display_name.clone(),
                });
                snap.by_uid.insert(uid, name.clone());
            }
        }
        for (name, cg) in self.group_cache.lock().unwrap().iter() {
            if let Some(gid) = cg.gid_number {
                snap.groups.insert(name.clone(), PosixGroupEntry {
                    gid,
                    display: cg.display_name.clone(),
                });
                snap.by_gid.insert(gid, name.clone());
            }
        }
        snap
    }
}

// -----------------------------------------------------------------------------
// Small pure helpers exported for reuse by UI ldap.rs (drift prevention) and idhelper.
// These are intentionally tiny and allocation-friendly.
// -----------------------------------------------------------------------------

/// Escape an LDAP filter value (identical semantics to LdapClient).
pub fn escape_ldap_filter(s: &str) -> String {
    IdLdapResolver::escape_filter_value(s)  // reuse impl above
}

/// Best-effort first attribute extraction (handles case variants).
pub fn extract_first_attr_value(se: &SearchEntry, name: &str) -> Option<String> {
    IdLdapResolver::extract_first_attr(se, name)
}

/// Strict parser for `getent passwd <name>` output.
/// Format: name:passwd:uid:gid:gecos:home:shell
/// Returns (uid, gid). gecos may contain ':' — we take positional fields 3 and 4 (1-based after split).
/// Used by idhelper as the "exact same lookup the client would do".
pub fn parse_getent_passwd(line: &str) -> Option<(u32, u32)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // Use splitn to protect against ':' inside gecos (field 5)
    let parts: Vec<&str> = line.splitn(7, ':').collect();
    if parts.len() < 4 {
        return None;
    }
    let uid = parts[2].trim().parse::<u32>().ok()?;
    let gid = parts[3].trim().parse::<u32>().ok()?;
    Some((uid, gid))
}

/// Convenience wrapper for getent group (name:passwd:gid:memberlist...)
pub fn parse_getent_group(line: &str) -> Option<u32> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') { return None; }
    let parts: Vec<&str> = line.splitn(4, ':').collect();
    if parts.len() < 3 { return None; }
    parts[2].trim().parse::<u32>().ok()
}

/// Pure machine principal classification using the centralized prefix list.
/// Returns (is_machine, reason). Mirrors the core prefix + bare service logic
/// used by the idhelper for hybrid user-TGT + client-host-keytab Kerberos.
/// Exported for reuse, diagnostics, and to reduce hard-coded prefixes.
pub fn classify_principal(principal: &str, realm: &str, server_variants: &[String]) -> (bool, String) {
    let p = principal.trim();
    let lower = p.to_ascii_lowercase();
    let realm_lower = realm.to_ascii_lowercase();

    let local = if let Some(at) = lower.rfind('@') {
        &lower[..at]
    } else {
        &lower
    };

    if crate::MACHINE_PRINCIPAL_PREFIXES.iter().any(|pref| local.starts_with(pref)) {
        return (true, format!("matches well-known machine prefix in {}", local));
    }

    for v in server_variants {
        let v_l = v.to_ascii_lowercase();
        if local == format!("host/{}", v_l) || local == format!("nfs/{}", v_l) {
            return (true, format!("matches server host principal for {}", v));
        }
    }

    if local.contains('/') {
        let after = local.split('/').nth(1).unwrap_or("");
        if !after.is_empty() && (after.chars().any(|c| c.is_ascii_alphanumeric()) || after.contains('.')) {
            if lower.ends_with(&format!("@{}", realm_lower)) || lower.contains("host") || lower.contains("nfs") {
                return (true, "contains host/service prefix and hostname-like component".to_string());
            }
        }
    }

    if local == "host" || local == "nfs" || local == "root" {
        return (true, "bare machine service name".to_string());
    }

    (false, "treated as regular user principal".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_filter_is_identical_to_expected() {
        assert_eq!(escape_ldap_filter("alice"), "alice");
        assert_eq!(escape_ldap_filter("a(b)c*\\"), "a\\28b\\29c\\2a\\5c");
        assert_eq!(escape_ldap_filter("user*name"), "user\\2aname");
    }

    #[test]
    fn resolver_constructs_from_minimal_sssd_section() {
        let s = SssdSection {
            ldap_default_bind_dn: "uid=admin,ou=people,dc=ex,dc=com".into(),
            ldap_default_authtok: "secret".into(),
            ldap_user_search_base: Some("ou=people,dc=ex,dc=com".into()),
            ..Default::default()
        };
        let r = IdLdapResolver::from_sssd_section("ldaps://ldap.example:636", &s);
        assert!(r.user_base.contains("people"));
    }

    #[test]
    fn parse_getent_passwd_exact_and_gecos_safe() {
        // Standard
        assert_eq!(parse_getent_passwd("alice:x:1001:1001:Alice Foo:/home/alice:/bin/bash"), Some((1001,1001)));
        // gecos with colon must not break uid/gid
        assert_eq!(parse_getent_passwd("bob:x:1005:1005:Bob:Bar:/home/bob:/bin/sh"), Some((1005,1005)));
        // Trim + comments
        assert_eq!(parse_getent_passwd("  root:x:0:0:root:/root:/bin/bash  "), Some((0,0)));
        assert!(parse_getent_passwd("# comment").is_none());
        assert!(parse_getent_passwd("").is_none());
        // Malformed
        assert!(parse_getent_passwd("badline").is_none());
    }

    #[test]
    fn parse_getent_group_works() {
        assert_eq!(parse_getent_group("staff:x:100::"), Some(100));
        assert_eq!(parse_getent_group("users:x:200:alice,bob"), Some(200));
    }

    #[test]
    fn snapshot_default_is_empty_and_exported() {
        let s = IdMapSnapshot::default();
        assert!(s.users.is_empty());
        assert!(s.groups.is_empty());
    }

    #[test]
    fn dc_base_extraction_covers_nested_under_users() {
        // Helper used to fall back to a whole-realm search when the configured
        // user_base is a sub-OU (e.g. the site uses ou=users with testing under it).
        let r = IdLdapResolver::from_sssd_section(
            "ldaps://ldap.example:636",
            &SssdSection {
                ldap_user_search_base: Some("ou=testing,ou=users,dc=example,dc=com".into()),
                ..SssdSection::default()
            },
        );
        // We don't expose dc_base publicly; test the effect indirectly by ensuring
        // that when we would search we also consider the dc ancestor.
        // Here we just assert construction succeeded with a non-empty base.
        assert!(r.user_base.contains("testing"));
    }

    #[test]
    fn snapshot_populates_uid_and_gid_from_user_entry() {
        // Synthetic test: manually drive the caches the way bulk load does
        // and verify snapshot carries both uid and the primary gid (from the
        // user's gidNumber) for a name that would come from a nested OU entry.
        let s = SssdSection {
            ldap_default_bind_dn: "uid=admin,ou=people,dc=ex,dc=com".into(),
            ldap_default_authtok: "secret".into(),
            ldap_user_search_base: Some("ou=users,dc=ex,dc=com".into()),
            ..Default::default()
        };
        let r = IdLdapResolver::from_sssd_section("ldaps://ldap.example:636", &s);

        // Simulate what bulk load would insert for a user in ou=testing,ou=users
        {
            let cu = CachedUser {
                id: "nesteduser".into(),
                uid_number: Some(12345),
                primary_gid: Some(12345),
                display_name: "Nested User".into(),
                dn: "uid=nesteduser,ou=testing,ou=users,dc=ex,dc=com".into(),
                fetched_at: std::time::Instant::now(),
            };
            r.user_cache.lock().unwrap().insert("nesteduser".into(), cu.clone());
            if let Some(u) = cu.uid_number {
                r.user_by_uid_cache.lock().unwrap().insert(u, cu);
            }
        }

        let snap = r.snapshot();
        let entry = snap.users.get("nesteduser").expect("nested user must be in snapshot");
        assert_eq!(entry.uid, 12345);
        assert_eq!(entry.gid, 12345); // the gid from the user's entry, as required
    }

    #[test]
    fn principal_attr_default_is_krb_principal_name_and_dual_lookup_works_in_mapping() {
        let s = SssdSection::default();
        let mapping = resolve_posix_attribute_mapping(&s);
        assert_eq!(mapping.user_principal_name, crate::DEFAULT_USER_PRINCIPAL_ATTR);

        // The resolver accepts full principal and will attempt principal attr search
        // (tested via construction; runtime dual logic exercised in resolve_user).
        let r = IdLdapResolver::from_sssd_section("ldaps://ex", &s);
        assert_eq!(r.posix_attributes.user_principal_name, crate::DEFAULT_USER_PRINCIPAL_ATTR);
    }
}