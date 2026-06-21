//! Structured LDAP-backed ID resolution for the idhelper (and future shared use).
//!
//! This module provides the "already structured internal ldap capabilities" from
//! nfs-klldap-ui/src/ldap.rs, made available to the lightweight idhelper daemon.
//!
//! Goals (0.8.32 refactor):
//! - Use the exact same PosixAttributeMapping + search bases as the generator/SSSD/UI.
//! - Same filter construction, escaping, display-name extraction, and numeric uid/gid handling.
//! - 10m identity caches (forward name + reverse uid/gid) so repeated getent/nfsidmap
//!   paths and observed principals (from ganesha log) do not hammer the LDAP server.
//!   (Lightweight 2m search caches are UI-specific for autocomplete and not required here.)
//! - getent (NSS) remains the primary "same lookup as client" path for users.
//! - This LDAP path is the reliable fallback + cache populator.
//! - Machine principals continue to short-circuit to 0:0 with zero LDAP/getent cost.
//!
//! Strict adherence: no changes to ganesha 9.6 / Debian trixie-backports behavior or
//! generated artifacts. All resolution still feeds the same nss_wrapper + extrausers
//! materialization and idhelper cache file/socket.

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{effective_ldap_search_bases, resolve_posix_attribute_mapping, PosixAttributeMapping, SssdSection};

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
    display_name: String,
    #[allow(dead_code)] // stored for parity with UI LdapClient (dn available in resolve paths); used in future or debug
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
                return Some((uid, None, hit.display_name.clone())); // gid not cached in this path yet
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let gid_attr = self.posix_attributes.user_gid_number.clone();
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();
        let full_attr = self.posix_attributes.user_full_name.clone();

        let filter = format!(
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
        ];

        let entries = self
            .service_search(&self.user_base, &filter, attrs, bind_dn, bind_pw)
            .ok()?;

        for se in entries {
            let display = Self::extract_display_name(&se, &full_attr, name);
            if let Some(uid_str) = Self::extract_first_attr(&se, &uid_attr) {
                if let Ok(u) = uid_str.parse::<i32>() {
                    let g = Self::extract_first_attr(&se, &gid_attr)
                        .and_then(|s| s.trim().parse::<i32>().ok());
                    let user = CachedUser {
                        id: name.to_string(),
                        uid_number: Some(u),
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
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            uid_attr.clone(),
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
        // Just ensure it doesn't panic and has bases
        // (real LDAP not exercised in unit test)
        assert!(r.user_base.contains("people"));
    }
}