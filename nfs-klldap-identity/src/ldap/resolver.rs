//! Sync LDAP-backed ID resolution (idhelper + shared UI fallback path).

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::constants::IDENTITY_CACHE_TTL_SECS;
use crate::constants::IDENTITY_NEGATIVE_TTL_SECS;
use crate::constants::MACHINE_GID;
use crate::krb5::{
    classify_principal, machine_short_name, principal_local_part,
};
use crate::ldap::filter::escape_ldap_filter;
use crate::ldap::posix::{
    effective_ldap_search_bases, resolve_posix_attribute_mapping, LdapSearchBasesInput,
    PosixAttributeMapping, PosixMappingInput,
};

const IDENTITY_CACHE_TTL: Duration = Duration::from_secs(IDENTITY_CACHE_TTL_SECS);
/// Misses are remembered briefly so unknown names cannot generate an LDAP
/// query (with its full connect+bind) on every single lookup.
const NEGATIVE_TTL: Duration = Duration::from_secs(IDENTITY_NEGATIVE_TTL_SECS);

/// Inputs for constructing an IdLdapResolver without TOML/serde dependencies.
#[derive(Debug, Clone, Default)]
pub struct LdapResolverInputs {
    pub ldap_uri: String,
    pub realm: String,
    pub search_bases: LdapSearchBasesInput,
    pub posix_mapping: PosixMappingInput,
    pub ldap_tls_reqcert: Option<String>,
    pub ldap_tls_cacert: Option<String>,
    pub ldap_id_use_start_tls: Option<bool>,
}

/// Small sync resolver used by nfs-klldap-idhelper (and diagnostics).
pub struct IdLdapResolver {
    ldap_uri: String,
    user_base: String,
    group_base: String,
    posix_attributes: PosixAttributeMapping,
    no_tls_verify: bool,
    start_tls: bool,
    tls_cacert: Option<String>,

    user_cache: Mutex<HashMap<String, CachedUser>>,
    group_cache: Mutex<HashMap<String, CachedGroup>>,
    user_by_uid_cache: Mutex<HashMap<i32, CachedUser>>,
    group_by_gid_cache: Mutex<HashMap<i32, CachedGroup>>,
    /// memberOf group DN -> gid (misses cached too, at NEGATIVE_TTL).
    group_gid_by_dn_cache: Mutex<HashMap<String, CachedDnGid>>,
    /// username -> (dn, memberOf list) for the groups-for-principal path.
    memberof_cache: Mutex<HashMap<String, CachedMemberOf>>,
    /// Keys of recent authoritative misses (u:/g:/uid:/gid: prefixed).
    negative_cache: Mutex<HashMap<String, Instant>>,
    /// One bound connection reused across searches; rebound only when the
    /// bind DN changes or an operation on it fails.
    conn_pool: Mutex<Option<PooledConn>>,

    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    bind_count: AtomicU64,
}

/// A live bound LdapConn plus the DN it authenticated as.
struct PooledConn {
    ldap: LdapConn,
    bound_as: String,
}

#[derive(Debug, Clone)]
struct CachedDnGid {
    gid: Option<i32>,
    fetched_at: Instant,
}

#[derive(Debug, Clone)]
struct CachedMemberOf {
    dn: String,
    memberofs: Vec<String>,
    fetched_at: Instant,
}

impl std::fmt::Debug for IdLdapResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdLdapResolver")
            .field("ldap_uri", &self.ldap_uri)
            .field("user_base", &self.user_base)
            .field("group_base", &self.group_base)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct CachedUser {
    id: String,
    uid_number: Option<i32>,
    primary_gid: Option<i32>,
    display_name: String,
    fetched_at: Instant,
}

#[derive(Debug, Clone)]
struct CachedGroup {
    id: String,
    gid_number: Option<i32>,
    display_name: String,
    members: Vec<String>,
    fetched_at: Instant,
}

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
    /// Member login names (from LDAP member / uniqueMember preload).
    pub members: Vec<String>,
}

/// Raw autocomplete list row from LDAP: (id, numeric uid/gid, display, dn).
pub type PosixListRow = (String, Option<i32>, String, String);

/// Parameters for list search (avoids clippy::too_many_arguments on the helper).
struct PosixListParams<'a> {
    base: &'a str,
    filter: &'a str,
    name_attr: &'a str,
    num_attr: &'a str,
    display_attr: &'a str,
    bind_dn: &'a str,
    bind_pw: &'a str,
}

impl IdLdapResolver {
    pub fn new(
        ldap_uri: &str,
        user_base: &str,
        group_base: &str,
        posix_attributes: PosixAttributeMapping,
        no_tls_verify: bool,
        start_tls: bool,
        tls_cacert: Option<String>,
    ) -> Self {
        Self {
            ldap_uri: ldap_uri.to_string(),
            user_base: user_base.to_string(),
            group_base: group_base.to_string(),
            posix_attributes,
            no_tls_verify,
            start_tls,
            tls_cacert,
            user_cache: Mutex::new(HashMap::new()),
            group_cache: Mutex::new(HashMap::new()),
            user_by_uid_cache: Mutex::new(HashMap::new()),
            group_by_gid_cache: Mutex::new(HashMap::new()),
            group_gid_by_dn_cache: Mutex::new(HashMap::new()),
            memberof_cache: Mutex::new(HashMap::new()),
            negative_cache: Mutex::new(HashMap::new()),
            conn_pool: Mutex::new(None),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            bind_count: AtomicU64::new(0),
        }
    }

    /// True when `key` was marked as an authoritative miss within NEGATIVE_TTL.
    fn negative_hit(&self, key: &str) -> bool {
        self.negative_cache
            .lock()
            .unwrap()
            .get(key)
            .is_some_and(|t| t.elapsed() < NEGATIVE_TTL)
    }

    /// Remember an authoritative miss (also shields the KDC-side LDAP during
    /// outages: repeated failures back off to one query per NEGATIVE_TTL).
    fn mark_negative(&self, key: String) {
        self.negative_cache.lock().unwrap().insert(key, Instant::now());
    }

    /// TLS decisions delegate to the shared ldap_tls_policy (cacert-aware).
    pub fn from_inputs(inputs: &LdapResolverInputs) -> Self {
        let (user_base, group_base) =
            effective_ldap_search_bases(&inputs.search_bases, &inputs.realm);
        let attrs = resolve_posix_attribute_mapping(&inputs.posix_mapping);

        let (no_tls_verify, start_tls) = crate::ldap::tls::ldap_tls_policy(
            &inputs.ldap_uri,
            inputs.ldap_tls_reqcert.as_deref(),
            inputs.ldap_tls_cacert.as_deref(),
            inputs.ldap_id_use_start_tls,
        );

        Self::new(
            &inputs.ldap_uri,
            &user_base,
            &group_base,
            attrs,
            no_tls_verify,
            start_tls,
            inputs.ldap_tls_cacert.clone(),
        )
    }

    pub fn user_base(&self) -> &str {
        &self.user_base
    }

    pub fn group_base(&self) -> &str {
        &self.group_base
    }

    pub fn posix_attributes(&self) -> &PosixAttributeMapping {
        &self.posix_attributes
    }

    /// Clear all caches (UI + idhelper reuse). 1-2 sentences.
    pub fn clear_caches(&self) {
        self.user_cache.lock().unwrap().clear();
        self.group_cache.lock().unwrap().clear();
        self.user_by_uid_cache.lock().unwrap().clear();
        self.group_by_gid_cache.lock().unwrap().clear();
        self.group_gid_by_dn_cache.lock().unwrap().clear();
        self.memberof_cache.lock().unwrap().clear();
        self.negative_cache.lock().unwrap().clear();
    }

    /// Evict expired (exposed for shared use by UI wrapper). 1 sentence.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.user_cache
            .lock()
            .unwrap()
            .retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.group_cache
            .lock()
            .unwrap()
            .retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.user_by_uid_cache
            .lock()
            .unwrap()
            .retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.group_by_gid_cache
            .lock()
            .unwrap()
            .retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        // DN->gid entries: positive results live the full TTL, misses briefly.
        self.group_gid_by_dn_cache.lock().unwrap().retain(|_, v| {
            let age = now.duration_since(v.fetched_at);
            if v.gid.is_some() { age < IDENTITY_CACHE_TTL } else { age < NEGATIVE_TTL }
        });
        self.memberof_cache
            .lock()
            .unwrap()
            .retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.negative_cache
            .lock()
            .unwrap()
            .retain(|_, t| now.duration_since(*t) < NEGATIVE_TTL);
    }

    fn build_conn_settings(&self) -> LdapConnSettings {
        crate::ldap::tls::ldap_conn_settings(
            self.no_tls_verify,
            self.start_tls,
            self.tls_cacert.as_deref(),
        )
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

    /// Returns member login names from member, uniqueMember, and memberUid.
    fn extract_group_members(se: &SearchEntry, member_attr: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for attr in [member_attr, "uniqueMember", "memberUid", "memberuid"] {
            let values = se
                .attrs
                .get(attr)
                .or_else(|| se.attrs.get(&attr.to_lowercase()))
                .cloned()
                .unwrap_or_default();
            for raw in values {
                let name = if raw.contains('=') {
                    raw.split(',')
                        .next()
                        .and_then(|r| r.split('=').nth(1))
                        .unwrap_or(raw.as_str())
                        .trim()
                        .to_string()
                } else {
                    raw.trim().to_string()
                };
                if name.is_empty() {
                    continue;
                }
                if seen.insert(name.clone()) {
                    out.push(name);
                }
            }
        }
        out
    }

    /// Builds a fallback search base from the first dc= suffix in the DN.
    /// Supports principal-style lookups when the primary base does not match.
    fn dc_base_from(&self, base: &str) -> String {
        if let Some(pos) = base.to_ascii_lowercase().find("dc=") {
            base[pos..].to_string()
        } else {
            base.to_string()
        }
    }

    /// Takes the pooled connection when it is bound as `bind_dn`; a conn
    /// bound as someone else is discarded so the pool never mixes identities.
    fn take_pooled_conn(&self, bind_dn: &str) -> Option<LdapConn> {
        let mut slot = self.conn_pool.lock().unwrap();
        match slot.take() {
            Some(p) if p.bound_as == bind_dn => Some(p.ldap),
            Some(mut stale) => {
                let _ = stale.ldap.unbind();
                None
            }
            None => None,
        }
    }

    fn store_pooled_conn(&self, ldap: LdapConn, bind_dn: &str) {
        let mut slot = self.conn_pool.lock().unwrap();
        if let Some(mut old) = slot.take() {
            let _ = old.ldap.unbind();
        }
        *slot = Some(PooledConn { ldap, bound_as: bind_dn.to_string() });
    }

    /// Performs sync LDAP in a worker thread (callers may sit on an async
    /// runtime). The bound connection is pooled and reused across searches —
    /// a bind happens only on first use, DN change, or after an op failure —
    /// so identity resolution no longer produces one KLLDAP login per query.
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

        for attempt in 0..3 {
            let pooled = self.take_pooled_conn(&dn);
            let reused = pooled.is_some();
            let uri2 = uri.clone();
            let settings2 = settings.clone();
            let base2 = base.clone();
            let filter2 = filter.clone();
            let attrs2 = attrs.clone();
            let dn2 = dn.clone();
            let pw2 = pw.clone();
            let did_bind = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let did_bind2 = std::sync::Arc::clone(&did_bind);

            let res = std::thread::spawn(move || {
                let mut ldap = match pooled {
                    Some(c) => c,
                    None => {
                        let mut fresh = LdapConn::with_settings(settings2, &uri2)
                            .map_err(|e| format!("connect: {}", e))?;
                        did_bind2.store(true, Ordering::Relaxed);
                        fresh
                            .simple_bind(&dn2, &pw2)
                            .map_err(|e| format!("bind: {}", e))?
                            .success()
                            .map_err(|e| format!("bind success: {:?}", e))?;
                        fresh
                    }
                };

                match ldap
                    .search(&base2, Scope::Subtree, &filter2, attrs2)
                    .map_err(|e| format!("search: {}", e))
                    .and_then(|r| r.success().map_err(|e| format!("search success: {:?}", e)))
                {
                    Ok((rs, _res)) => Ok((
                        rs.into_iter().map(SearchEntry::construct).collect::<Vec<_>>(),
                        ldap,
                    )),
                    Err(e) => {
                        // A failed conn is never pooled again.
                        let _ = ldap.unbind();
                        Err(e)
                    }
                }
            })
            .join();

            if did_bind.load(Ordering::Relaxed) {
                self.bind_count.fetch_add(1, Ordering::Relaxed);
            }
            match res {
                Ok(Ok((entries, ldap))) => {
                    self.store_pooled_conn(ldap, &dn);
                    return Ok(entries);
                }
                Ok(Err(e)) => {
                    // A reused conn may simply be stale (server restart):
                    // retry immediately on a fresh bind before backing off.
                    if reused {
                        continue;
                    }
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

    pub fn resolve_user(
        &self,
        name: &str,
        bind_dn: &str,
        bind_pw: &str,
    ) -> Option<(i32, Option<i32>, String)> {
        self.evict_expired();
        if let Some(hit) = self.user_cache.lock().unwrap().get(name).cloned() {
            if let Some(uid) = hit.uid_number {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some((uid, hit.primary_gid, hit.display_name.clone()));
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        // test-support: seeded snapshot is authoritative; cache miss = LDAP miss.
        #[cfg(feature = "test-support")]
        if std::env::var("TEST_REBULK_POPULATE").is_ok() {
            return None;
        }

        if self.negative_hit(&format!("u:{name}")) {
            return None;
        }

        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let gid_attr = self.posix_attributes.user_gid_number.clone();
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();
        let full_attr = self.posix_attributes.user_full_name.clone();
        let principal_attr = self.posix_attributes.user_principal_name.clone();

        let name_filter = format!(
            "(&(objectClass={})({}={}))",
            obj,
            name_attr,
            escape_ldap_filter(name)
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
            if dc != self.user_base {
                v.push(dc);
            }
            v
        };

        for base in &bases {
            if let Ok(entries) = self.service_search(base, &name_filter, attrs.clone(), bind_dn, bind_pw)
            {
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
                                fetched_at: Instant::now(),
                            };
                            self.user_cache
                                .lock()
                                .unwrap()
                                .insert(name.to_string(), user.clone());
                            if let Some(uid) = user.uid_number {
                                self.user_by_uid_cache.lock().unwrap().insert(uid, user);
                            }
                            return Some((u, g, display));
                        }
                    }
                }
            }
        }

        // If username looks like UPN, retry search on krbPrincipalName.
        if name.contains('@') {
            let p_filter = format!(
                "(&(objectClass={})({}={}))",
                obj,
                principal_attr,
                escape_ldap_filter(name)
            );
            for base in &bases {
                if let Ok(entries) =
                    self.service_search(base, &p_filter, attrs.clone(), bind_dn, bind_pw)
                {
                    for se in entries {
                        let display = Self::extract_display_name(&se, &full_attr, name);
                        if let Some(uid_str) = Self::extract_first_attr(&se, &uid_attr) {
                            if let Ok(u) = uid_str.parse::<i32>() {
                                let g = Self::extract_first_attr(&se, &gid_attr)
                                    .and_then(|s| s.trim().parse::<i32>().ok());
                                let short = principal_local_part(name).to_string();
                                let user = CachedUser {
                                    id: short.clone(),
                                    uid_number: Some(u),
                                    primary_gid: g,
                                    display_name: display.clone(),
                                    fetched_at: Instant::now(),
                                };
                                self.user_cache
                                    .lock()
                                    .unwrap()
                                    .insert(short.clone(), user.clone());
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
        self.mark_negative(format!("u:{name}"));
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
        if self.negative_hit(&format!("g:{name}")) {
            return None;
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let name_attr = self.posix_attributes.group_name.clone();
        let obj = self.posix_attributes.group_object_class.clone();

        let filter = format!(
            "(&(objectClass={})({}={}))",
            obj,
            name_attr,
            escape_ldap_filter(name)
        );
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            gid_attr.clone(),
            "cn".into(),
            "displayName".into(),
        ];

        // Errors mark the key too: during an LDAP outage lookups back off to
        // one attempt per NEGATIVE_TTL instead of hammering the server.
        let entries = match self.service_search(&self.group_base, &filter, attrs, bind_dn, bind_pw)
        {
            Ok(e) => e,
            Err(_) => {
                self.mark_negative(format!("g:{name}"));
                return None;
            }
        };

        for se in entries {
            let display = Self::extract_display_name(&se, &name_attr, name);
            if let Some(gid_str) = Self::extract_first_attr(&se, &gid_attr) {
                if let Ok(g) = gid_str.parse::<i32>() {
                    let members = Self::extract_group_members(
                        &se,
                        &self.posix_attributes.group_member,
                    );
                    let group = CachedGroup {
                        id: name.to_string(),
                        gid_number: Some(g),
                        display_name: display.clone(),
                        members,
                        fetched_at: Instant::now(),
                    };
                    self.group_cache
                        .lock()
                        .unwrap()
                        .insert(name.to_string(), group.clone());
                    if let Some(gid) = group.gid_number {
                        self.group_by_gid_cache.lock().unwrap().insert(gid, group);
                    }
                    return Some((g, display));
                }
            }
        }
        self.mark_negative(format!("g:{name}"));
        None
    }

    pub fn resolve_user_by_uid(
        &self,
        uid: i32,
        bind_dn: &str,
        bind_pw: &str,
    ) -> Option<(String, String)> {
        self.evict_expired();
        if let Some(hit) = self.user_by_uid_cache.lock().unwrap().get(&uid).cloned() {
            if hit.uid_number.is_some() {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some((hit.id.clone(), hit.display_name.clone()));
            }
        }
        if self.negative_hit(&format!("uid:{uid}")) {
            return None;
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();
        let full_attr = self.posix_attributes.user_full_name.clone();
        let gid_attr = self.posix_attributes.user_gid_number.clone();

        let filter = format!("(&(objectClass={})({}={}))", obj, uid_attr, uid);
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            uid_attr.clone(),
            gid_attr.clone(),
            "cn".into(),
            "displayName".into(),
            full_attr.clone(),
        ];

        let entries = match self.service_search(&self.user_base, &filter, attrs, bind_dn, bind_pw)
        {
            Ok(e) => e,
            Err(_) => {
                self.mark_negative(format!("uid:{uid}"));
                return None;
            }
        };

        for se in entries {
            let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_else(|| uid.to_string());
            let display = Self::extract_display_name(&se, &full_attr, &id);
            if let Some(uid_str) = Self::extract_first_attr(&se, &uid_attr) {
                if let Ok(u) = uid_str.parse::<i32>() {
                    if u == uid {
                        let cu = CachedUser {
                            id: id.clone(),
                            uid_number: Some(u),
                            primary_gid: Self::extract_first_attr(&se, &gid_attr)
                                .and_then(|s| s.trim().parse::<i32>().ok()),
                            display_name: display.clone(),
                            fetched_at: Instant::now(),
                        };
                        self.user_cache.lock().unwrap().insert(id.clone(), cu.clone());
                        self.user_by_uid_cache.lock().unwrap().insert(uid, cu);
                        return Some((id, display));
                    }
                }
            }
        }
        self.mark_negative(format!("uid:{uid}"));
        None
    }

    pub fn resolve_group_by_gid(
        &self,
        gid: i32,
        bind_dn: &str,
        bind_pw: &str,
    ) -> Option<(String, String)> {
        self.evict_expired();
        if let Some(hit) = self.group_by_gid_cache.lock().unwrap().get(&gid).cloned() {
            if hit.gid_number.is_some() {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some((hit.id.clone(), hit.display_name.clone()));
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        // test-support: seed primary-gid groups for the rebulk loop without live LDAP.
        #[cfg(feature = "test-support")]
        if std::env::var("TEST_REBULK_POPULATE").is_ok() {
            let (name, disp) = if gid == 1001 { ("staff", "staff") } else if gid == 600 { ("oldgrp", "oldgrp") } else if gid == 500 { ("devs", "devs") } else { ("g", "g") };
            if name != "g" {
                let cg = CachedGroup { id: name.to_string(), gid_number: Some(gid), display_name: disp.to_string(), members: vec![], fetched_at: Instant::now() };
                self.group_cache.lock().unwrap().insert(name.to_string(), cg.clone());
                self.group_by_gid_cache.lock().unwrap().insert(gid, cg);
                return Some((name.to_string(), disp.to_string()));
            }
        }

        if self.negative_hit(&format!("gid:{gid}")) {
            return None;
        }

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

        let entries = match self.service_search(&self.group_base, &filter, attrs, bind_dn, bind_pw)
        {
            Ok(e) => e,
            Err(_) => {
                self.mark_negative(format!("gid:{gid}"));
                return None;
            }
        };

        for se in entries {
            let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_else(|| gid.to_string());
            let display = Self::extract_display_name(&se, &name_attr, &id);
            if let Some(gid_str) = Self::extract_first_attr(&se, &gid_attr) {
                if let Ok(g) = gid_str.parse::<i32>() {
                    if g == gid {
                        let members = Self::extract_group_members(
                            &se,
                            &self.posix_attributes.group_member,
                        );
                        let cg = CachedGroup {
                            id: id.clone(),
                            gid_number: Some(g),
                            display_name: display.clone(),
                            members,
                            fetched_at: Instant::now(),
                        };
                        self.group_cache.lock().unwrap().insert(id.clone(), cg.clone());
                        self.group_by_gid_cache.lock().unwrap().insert(gid, cg);
                        return Some((id, display));
                    }
                }
            }
        }
        self.mark_negative(format!("gid:{gid}"));
        None
    }

    fn group_gid_from_dn(&self, group_dn: &str, bind_dn: &str, bind_pw: &str) -> Option<i32> {
        // test-support: gid from the TEST spec for the GRPS memberOf path.
        #[cfg(feature = "test-support")]
        if let Ok(spec) = std::env::var("TEST_REBULK_POPULATE") {
            for tok in spec.split(';') {
                let f: Vec<&str> = tok.split(':').collect();
                if f.len() >= 3 && f[0] == "g" && (group_dn.contains(f[1]) || f[1] == "staff") {
                    if let Ok(g) = f[2].parse::<i32>() { return Some(g); }
                }
            }
            return Some(1001);
        }
        // The group is usually already cached (bulk load / prior resolve):
        // answer from the DN's RDN value without touching LDAP.
        if let Some(rdn) = group_dn
            .split(',')
            .next()
            .and_then(|r| r.split('=').nth(1))
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let groups = self.group_cache.lock().unwrap();
            if let Some(g) = groups.get(rdn).and_then(|c| c.gid_number) {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some(g);
            }
            if let Some(g) = groups
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(rdn))
                .and_then(|(_, c)| c.gid_number)
            {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some(g);
            }
        }
        // Whole-DN cache (positive full TTL, misses at NEGATIVE_TTL).
        if let Some(hit) = self.group_gid_by_dn_cache.lock().unwrap().get(group_dn) {
            let ttl = if hit.gid.is_some() { IDENTITY_CACHE_TTL } else { NEGATIVE_TTL };
            if hit.fetched_at.elapsed() < ttl {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return hit.gid;
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        let gid_attr = self.posix_attributes.group_gid_number.clone();
        // Errors cache as a short-TTL miss too (outage back-off, see above).
        let mut found = None;
        if let Ok(entries) =
            self.service_search(group_dn, "(objectClass=*)", vec![gid_attr.clone()], bind_dn, bind_pw)
        {
            for se in entries {
                if let Some(gs) = Self::extract_first_attr(&se, &gid_attr) {
                    if let Ok(g) = gs.trim().parse::<i32>() {
                        found = Some(g);
                        break;
                    }
                }
            }
        }
        self.group_gid_by_dn_cache.lock().unwrap().insert(
            group_dn.to_string(),
            CachedDnGid { gid: found, fetched_at: Instant::now() },
        );
        found
    }

    /// Resolve gids for principal (primary + supp) via memberOf + member/gidNumber after RESOLVE uid.
    pub fn resolve_groups_for_principal(&self, name_or_principal: &str, bind_dn: &str, bind_pw: &str) -> Vec<i32> {
        let (is_machine, _) = classify_principal(name_or_principal, "", &[]);
        if is_machine {
            let snap = self.snapshot();
            return machine_group_gids_for_principal(name_or_principal, &snap);
        }
        let mut gids: Vec<i32> = vec![];
        if let Some((_, Some(g), _)) = self.resolve_user(name_or_principal, bind_dn, bind_pw) {
            if !gids.contains(&g) {
                gids.push(g);
            }
        }
        let try_memberof = |n: &str| -> Option<Vec<String>> {
            self.lookup_user_dn_and_memberof(n, bind_dn, bind_pw).map(|(_, m)| m)
        };
        let mut memberofs = try_memberof(name_or_principal);
        if memberofs.is_none() {
            let short = principal_local_part(name_or_principal);
            if short != name_or_principal {
                memberofs = try_memberof(short);
            }
        }
        if let Some(mofs) = memberofs {
            for gdn in mofs {
                if let Some(g) = self.group_gid_from_dn(&gdn, bind_dn, bind_pw) {
                    if !gids.contains(&g) {
                        gids.push(g);
                    }
                }
            }
        }
        let short = principal_local_part(name_or_principal);
        let snap = self.snapshot();
        for ge in snap.groups.values() {
            if ge.members.iter().any(|m| m.eq_ignore_ascii_case(short) || m.eq_ignore_ascii_case(name_or_principal))
                && !gids.contains(&ge.gid)
            {
                gids.push(ge.gid);
            }
        }
        gids
    }

    /// Filter for exact user name lookup (permission editor resolve paths).
    pub fn user_filter_by_name(&self, name: &str) -> String {
        format!(
            "(&(objectClass={})({}={}))",
            self.posix_attributes.user_object_class,
            self.posix_attributes.user_name,
            escape_ldap_filter(name)
        )
    }

    /// Filter for exact group name lookup.
    pub fn group_filter_by_name(&self, name: &str) -> String {
        format!(
            "(&(objectClass={})({}={}))",
            self.posix_attributes.group_object_class,
            self.posix_attributes.group_name,
            escape_ldap_filter(name)
        )
    }

    /// Presence filter for the full POSIX user/group list. The permission-editor
    /// autocomplete fetches the whole list and matches queries client-side, so no
    /// query is ever interpolated here (the old query pathway produced exact-only
    /// numeric clauses and substring assertions on integer attributes that LLDAP
    /// rejects — both wrong for autocomplete).
    pub(crate) fn build_posix_list_filter(obj_class: &str, num_attr: &str) -> String {
        format!("(&(objectClass={})({}=*))", obj_class, num_attr)
    }

    fn search_list_posix(
        &self,
        p: &PosixListParams,
        limit: usize,
    ) -> Result<Vec<PosixListRow>, String> {
        let attrs = vec![
            p.name_attr.into(),
            p.num_attr.into(),
            "cn".into(),
            "displayName".into(),
            p.display_attr.into(),
        ];
        let entries = self.service_search(p.base, p.filter, attrs, p.bind_dn, p.bind_pw)?;
        let mut out = Vec::new();
        for se in entries {
            let id = Self::extract_first_attr(&se, p.name_attr).unwrap_or_default();
            if id.is_empty() {
                continue;
            }
            let display = Self::extract_display_name(&se, p.display_attr, &id);
            let num = Self::extract_first_attr(&se, p.num_attr).and_then(|s| s.parse::<i32>().ok());
            out.push((id, num, display, se.dn));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Full user list (up to `limit`) for permission-editor autocomplete; the
    /// caller filters client-side. Err = LDAP unreachable/rejected, distinct
    /// from an empty directory.
    pub fn search_list_users(
        &self,
        bind_dn: &str,
        bind_pw: &str,
        limit: usize,
    ) -> Result<Vec<PosixListRow>, String> {
        let pa = &self.posix_attributes;
        let filter = Self::build_posix_list_filter(&pa.user_object_class, &pa.user_uid_number);
        let params = PosixListParams {
            base: &self.user_base,
            filter: &filter,
            name_attr: &pa.user_name,
            num_attr: &pa.user_uid_number,
            display_attr: &pa.user_full_name,
            bind_dn,
            bind_pw,
        };
        self.search_list_posix(&params, limit)
    }

    /// Returns the DN of the first LDAP entry matching filter under base.
    pub fn lookup_first_dn(
        &self,
        base: &str,
        filter: &str,
        bind_dn: &str,
        bind_pw: &str,
    ) -> Option<String> {
        let entries = self
            .service_search(base, filter, vec!["1.1".into()], bind_dn, bind_pw)
            .ok()?;
        entries.into_iter().next().map(|se| se.dn)
    }

    /// Lookup user DN and memberOf values for WebUI credential verify.
    pub fn lookup_user_dn_and_memberof(
        &self,
        username: &str,
        bind_dn: &str,
        bind_pw: &str,
    ) -> Option<(String, Vec<String>)> {
        // test-support: fixed memberOf answer for GRPS tests.
        #[cfg(feature = "test-support")]
        if std::env::var("TEST_REBULK_POPULATE").is_ok() {
            return Some(("uid=test,ou=people".into(), vec!["cn=staff,ou=groups".into()]));
        }
        if let Some(hit) = self.memberof_cache.lock().unwrap().get(username) {
            if hit.fetched_at.elapsed() < IDENTITY_CACHE_TTL {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some((hit.dn.clone(), hit.memberofs.clone()));
            }
        }
        if self.negative_hit(&format!("mo:{username}")) {
            return None;
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        let filter = self.user_filter_by_name(username);
        let name_attr = self.posix_attributes.user_name.clone();
        let entries = match self.service_search(
            &self.user_base,
            &filter,
            vec![name_attr, "memberOf".into()],
            bind_dn,
            bind_pw,
        ) {
            Ok(e) => e,
            Err(_) => {
                self.mark_negative(format!("mo:{username}"));
                return None;
            }
        };
        let Some(se) = entries.into_iter().next() else {
            self.mark_negative(format!("mo:{username}"));
            return None;
        };
        let memberofs = se
            .attrs
            .get("memberOf")
            .or_else(|| se.attrs.get("memberof"))
            .cloned()
            .unwrap_or_default();
        self.memberof_cache.lock().unwrap().insert(
            username.to_string(),
            CachedMemberOf {
                dn: se.dn.clone(),
                memberofs: memberofs.clone(),
                fetched_at: Instant::now(),
            },
        );
        Some((se.dn, memberofs))
    }

    /// Lookup group DN by name for membership checks.
    pub fn lookup_group_dn(&self, group_name: &str, bind_dn: &str, bind_pw: &str) -> Option<String> {
        let filter = self.group_filter_by_name(group_name);
        self.lookup_first_dn(&self.group_base, &filter, bind_dn, bind_pw)
    }

    /// True when a user DN is returned by memberOf filter under user_base.
    pub fn user_dn_has_memberof(
        &self,
        user_dn: &str,
        group_dn: &str,
        bind_dn: &str,
        bind_pw: &str,
    ) -> bool {
        let filter = format!(
            "(&(objectClass={})(memberOf={}))",
            self.posix_attributes.user_object_class,
            escape_ldap_filter(group_dn)
        );
        let entries = self
            .service_search(&self.user_base, &filter, vec!["1.1".into()], bind_dn, bind_pw)
            .unwrap_or_default();
        entries
            .iter()
            .any(|e| e.dn.eq_ignore_ascii_case(user_dn))
    }

    /// Full group list (up to `limit`) for permission-editor autocomplete; the
    /// caller filters client-side. Err = LDAP unreachable/rejected, distinct
    /// from an empty directory.
    pub fn search_list_groups(
        &self,
        bind_dn: &str,
        bind_pw: &str,
        limit: usize,
    ) -> Result<Vec<PosixListRow>, String> {
        let pa = &self.posix_attributes;
        let filter = Self::build_posix_list_filter(&pa.group_object_class, &pa.group_gid_number);
        let params = PosixListParams {
            base: &self.group_base,
            filter: &filter,
            name_attr: &pa.group_name,
            num_attr: &pa.group_gid_number,
            display_attr: &pa.group_name,
            bind_dn,
            bind_pw,
        };
        self.search_list_posix(&params, limit)
    }

    pub fn cache_stats(&self) -> (u64, u64) {
        (
            self.cache_hits.load(Ordering::Relaxed),
            self.cache_misses.load(Ordering::Relaxed),
        )
    }

    /// Total LDAP binds performed since start (each is a KLLDAP "login").
    pub fn bind_stats(&self) -> u64 {
        self.bind_count.load(Ordering::Relaxed)
    }

    /// (user, group) cache entry counts for UI stats display.
    pub fn cache_entry_counts(&self) -> (usize, usize) {
        (
            self.user_cache.lock().unwrap().len(),
            self.group_cache.lock().unwrap().len(),
        )
    }

    /// Preloads posix users and groups and indexes UPN aliases in caches.
    pub fn load_full_identities(&self, bind_dn: &str, bind_pw: &str) -> usize {
        // Clear ALL caches (incl. memberOf / DN->gid / negative) so a rebulk is
        // fully fresh — a group-membership change must not be masked by a stale
        // memberof_cache entry (10-min TTL). This is the load-bearing prune for
        // propagation: partial clears here let a rebulk serve old membership.
        self.clear_caches();

        // test-support: drive rebulk + primary loop without live LDAP.
        #[cfg(feature = "test-support")]
        if let Ok(spec) = std::env::var("TEST_REBULK_POPULATE") {
            let mut cnt = 0usize;
            for tok in spec.split(';') {
                let f: Vec<&str> = tok.split(':').collect();
                if f.len() == 4 && f[0] == "u" {
                    if let (Ok(u), Ok(g)) = (f[2].parse::<i32>(), f[3].parse::<i32>()) {
                        let cu = CachedUser { id: f[1].to_string(), uid_number: Some(u), primary_gid: Some(g), display_name: f[1].to_string(), fetched_at: Instant::now() };
                        self.user_cache.lock().unwrap().insert(f[1].to_string(), cu.clone());
                        self.user_by_uid_cache.lock().unwrap().insert(u, cu);
                        cnt += 1;
                    }
                } else if f.len() >= 3 && f[0] == "g" {
                    if let Ok(g) = f[2].parse::<i32>() {
                        let members: Vec<String> = if f.len() > 3 {
                            f[3].split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect()
                        } else if f[1] == "staff" {
                            vec!["testuser1".to_string()]
                        } else {
                            vec![]
                        };
                        let cg = CachedGroup { id: f[1].to_string(), gid_number: Some(g), display_name: f[1].to_string(), members, fetched_at: Instant::now() };
                        self.group_cache.lock().unwrap().insert(f[1].to_string(), cg.clone());
                        self.group_by_gid_cache.lock().unwrap().insert(g, cg);
                    }
                }
            }
            return cnt;
        }

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
            name_attr.clone(),
            uid_attr.clone(),
            gid_attr.clone(),
            "cn".into(),
            "displayName".into(),
            full_attr.clone(),
        ];
        let group_member_attr = self.posix_attributes.group_member.clone();
        let group_attrs: Vec<String> = vec![
            group_name_attr.clone(),
            group_gid_attr.clone(),
            group_member_attr.clone(),
            "uniqueMember".into(),
            "memberUid".into(),
            "cn".into(),
            "displayName".into(),
        ];

        let mut loaded = 0usize;

        let user_bases = {
            let mut v = vec![self.user_base.clone()];
            let dc = self.dc_base_from(&self.user_base);
            if dc != self.user_base {
                v.push(dc);
            }
            v
        };
        for base in &user_bases {
            if let Ok(entries) =
                self.service_search(base, &user_filter, user_attrs.clone(), bind_dn, bind_pw)
            {
                for se in entries {
                    let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_default();
                    if id.is_empty() {
                        continue;
                    }
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
                                fetched_at: Instant::now(),
                            };
                            self.user_cache.lock().unwrap().insert(id.clone(), cu.clone());
                            self.user_by_uid_cache.lock().unwrap().insert(u, cu);
                            loaded += 1;

                            if let Some(pval) = Self::extract_first_attr(&se, &principal_attr) {
                                if !pval.is_empty() && pval != id {
                                    let cu2 = CachedUser {
                                        id: pval.clone(),
                                        uid_number: Some(u),
                                        primary_gid: Some(g),
                                        display_name: display.clone(),
                                        fetched_at: Instant::now(),
                                    };
                                    self.user_cache
                                        .lock()
                                        .unwrap()
                                        .insert(pval.clone(), cu2);
                                }
                            }
                        }
                    }
                }
            }
        }

        let group_bases = {
            let mut v = vec![self.group_base.clone()];
            let dc = self.dc_base_from(&self.group_base);
            if dc != self.group_base {
                v.push(dc);
            }
            v
        };
        for base in &group_bases {
            if let Ok(entries) =
                self.service_search(base, &group_filter, group_attrs.clone(), bind_dn, bind_pw)
            {
                for se in entries {
                    let id = Self::extract_first_attr(&se, &group_name_attr).unwrap_or_default();
                    if id.is_empty() {
                        continue;
                    }
                    if let Some(g_str) = Self::extract_first_attr(&se, &group_gid_attr) {
                        if let Ok(g) = g_str.parse::<i32>() {
                            let display = Self::extract_display_name(&se, &group_name_attr, &id);
                            let members =
                                Self::extract_group_members(&se, &group_member_attr);
                            let cg = CachedGroup {
                                id: id.clone(),
                                gid_number: Some(g),
                                display_name: display.clone(),
                                members,
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

    pub fn snapshot(&self) -> IdMapSnapshot {
        self.evict_expired();
        let mut snap = IdMapSnapshot::default();

        for (name, cu) in self.user_cache.lock().unwrap().iter() {
            if let Some(uid) = cu.uid_number {
                let gid = cu.primary_gid.unwrap_or(uid);
                snap.users.insert(
                    name.clone(),
                    PosixUserEntry {
                        uid,
                        gid,
                        display: cu.display_name.clone(),
                    },
                );
                snap.by_uid.insert(uid, name.clone());
            }
        }
        for (name, cg) in self.group_cache.lock().unwrap().iter() {
            if let Some(gid) = cg.gid_number {
                snap.groups.insert(
                    name.clone(),
                    PosixGroupEntry {
                        gid,
                        display: cg.display_name.clone(),
                        members: cg.members.clone(),
                    },
                );
                snap.by_gid.insert(gid, name.clone());
            }
        }
        snap
    }

}

/// Supplemental gids from LDAP snapshot group membership for a machine principal.
/// Includes groups listing the host short/local/principal forms or login `root` (uid0 getgrouplist path).
pub fn machine_supplemental_gids_from_snapshot(
    principal: &str,
    snap: &IdMapSnapshot,
) -> Vec<i32> {
    let short = machine_short_name(principal);
    let local = principal_local_part(principal);
    let mut supps = Vec::new();
    for entry in snap.groups.values() {
        let g = entry.gid;
        if g == 0 {
            continue;
        }
        let member_hit = entry.members.iter().any(|m| {
            let m = m.trim();
            m.eq_ignore_ascii_case(short)
                || m.eq_ignore_ascii_case(local)
                || m.eq_ignore_ascii_case(principal)
                || m.eq_ignore_ascii_case("root")
        });
        if member_hit && !supps.contains(&g) {
            supps.push(g);
        }
    }
    supps.sort_unstable();
    supps
}

/// Primary (0) + supplemental gids for a machine Kerberos principal.
pub fn machine_group_gids_for_principal(principal: &str, snap: &IdMapSnapshot) -> Vec<i32> {
    let mut gids = vec![MACHINE_GID as i32];
    for g in machine_supplemental_gids_from_snapshot(principal, snap) {
        if g != MACHINE_GID as i32 && !gids.contains(&g) {
            gids.push(g);
        }
    }
    gids
}

/// Best-effort first attribute extraction (handles case variants).
pub fn extract_first_attr_value(se: &SearchEntry, name: &str) -> Option<String> {
    IdLdapResolver::extract_first_attr(se, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{FALLBACK_NOBODY_GID, MACHINE_GID};

    #[test]
    fn group_gid_from_dn_answers_from_group_cache_without_ldap() {
        // Unreachable URI: any accidental LDAP path would return None fast.
        let r = IdLdapResolver::new(
            "ldaps://127.0.0.1:1",
            "ou=people,dc=t",
            "ou=groups,dc=t",
            resolve_posix_attribute_mapping(&PosixMappingInput::default()),
            true,
            false,
            None,
        );
        r.group_cache.lock().unwrap().insert(
            "media".into(),
            CachedGroup {
                id: "media".into(),
                gid_number: Some(3005),
                display_name: "media".into(),
                members: vec![],
                fetched_at: Instant::now(),
            },
        );
        assert_eq!(
            r.group_gid_from_dn("cn=media,ou=groups,dc=t", "dn", "pw"),
            Some(3005),
            "RDN short-circuit must resolve from the loaded group cache"
        );
        assert_eq!(
            r.group_gid_from_dn("cn=MEDIA,ou=groups,dc=t", "dn", "pw"),
            Some(3005),
            "case-insensitive RDN match must also short-circuit"
        );
    }

    #[test]
    fn negative_cache_blocks_repeat_ldap_misses_briefly() {
        let r = IdLdapResolver::new(
            "ldaps://127.0.0.1:1",
            "ou=people,dc=t",
            "ou=groups,dc=t",
            resolve_posix_attribute_mapping(&PosixMappingInput::default()),
            true,
            false,
            None,
        );
        // First miss walks the (refused) LDAP path and marks the key.
        assert!(r.resolve_group("nosuch", "dn", "pw").is_none());
        assert!(r.negative_hit("g:nosuch"), "miss must be remembered");
        let (_, misses_after_first) = r.cache_stats();
        // Second call must be answered by the negative cache, not LDAP.
        assert!(r.resolve_group("nosuch", "dn", "pw").is_none());
        let (_, misses_after_second) = r.cache_stats();
        assert_eq!(
            misses_after_first, misses_after_second,
            "negative hit must not re-enter the LDAP miss path"
        );
    }

    #[test]
    fn rebulk_clears_membership_and_related_caches() {
        // Regression: load_full_identities must clear the memberOf / DN->gid /
        // negative caches (not just user/group), or a group-membership change
        // stays masked for the 10-min TTL even after a rebulk — the 2026-07-11
        // propagation failure. clear() runs before the (refused) LDAP attempt.
        let r = IdLdapResolver::new(
            "ldaps://127.0.0.1:1",
            "ou=people,dc=t",
            "ou=groups,dc=t",
            resolve_posix_attribute_mapping(&PosixMappingInput::default()),
            true,
            false,
            None,
        );
        r.memberof_cache.lock().unwrap().insert(
            "testuser1".into(),
            CachedMemberOf {
                dn: "uid=testuser1,ou=people,dc=t".into(),
                memberofs: vec!["cn=oldgroup,ou=groups,dc=t".into()],
                fetched_at: Instant::now(),
            },
        );
        r.group_gid_by_dn_cache.lock().unwrap().insert(
            "cn=oldgroup,ou=groups,dc=t".into(),
            CachedDnGid { gid: Some(500), fetched_at: Instant::now() },
        );
        r.mark_negative("g:ghost".into());
        assert!(!r.memberof_cache.lock().unwrap().is_empty());

        let _ = r.load_full_identities("dn", "pw");

        assert!(r.memberof_cache.lock().unwrap().is_empty(), "rebulk must drop stale memberOf");
        assert!(
            r.group_gid_by_dn_cache.lock().unwrap().is_empty(),
            "rebulk must drop stale DN->gid entries"
        );
        assert!(!r.negative_hit("g:ghost"), "rebulk must drop negative-cache entries");
    }

    #[test]
    fn resolver_constructs_from_minimal_inputs() {
        let r = IdLdapResolver::from_inputs(&LdapResolverInputs {
            ldap_uri: "ldaps://ldap.example:636".into(),
            realm: "ex.com".into(),
            search_bases: LdapSearchBasesInput {
                ldap_user_search_base: Some("ou=people,dc=ex,dc=com".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        assert!(r.user_base().contains("people"));
    }

    #[test]
    fn snapshot_default_is_empty() {
        let s = IdMapSnapshot::default();
        assert!(s.users.is_empty());
        assert!(s.groups.is_empty());
    }

    #[test]
    fn posix_list_filter_is_presence_only() {
        let users = IdLdapResolver::build_posix_list_filter("posixAccount", "uidNumber");
        assert_eq!(users, "(&(objectClass=posixAccount)(uidNumber=*))");
        let groups = IdLdapResolver::build_posix_list_filter("posixGroup", "gidNumber");
        assert_eq!(groups, "(&(objectClass=posixGroup)(gidNumber=*))");
    }

    #[test]
    fn resolve_groups_for_principal_host_blue_lt_returns_root_gid() {
        let r = IdLdapResolver::from_inputs(&LdapResolverInputs::default());
        let gs = r.resolve_groups_for_principal("host/blue-lt@SATOMLIN.COM", "dn", "pw");
        assert_eq!(gs, vec![MACHINE_GID as i32]);
        assert!(!gs.contains(&(FALLBACK_NOBODY_GID as i32)));
    }

    #[test]
    fn machine_supplemental_gids_from_snapshot_includes_root_and_host_members() {
        let mut snap = IdMapSnapshot::default();
        snap.groups.insert(
            "admins".into(),
            PosixGroupEntry {
                gid: 3005,
                display: "admins".into(),
                members: vec!["root".into()],
            },
        );
        snap.groups.insert(
            "hosts".into(),
            PosixGroupEntry {
                gid: 3007,
                display: "hosts".into(),
                members: vec!["blue-lt".into()],
            },
        );
        let supps =
            machine_supplemental_gids_from_snapshot("host/blue-lt@SATOMLIN.COM", &snap);
        assert_eq!(supps, vec![3005, 3007]);
        let gids = machine_group_gids_for_principal("host/blue-lt@SATOMLIN.COM", &snap);
        assert_eq!(gids, vec![0, 3005, 3007]);
    }

    // Runs when the workspace enables test-support (config dev-deps); skipped standalone.
    #[cfg(feature = "test-support")]
    #[test]
    fn user_principal_groups_unchanged_via_ldap_shim() {
        std::env::set_var("TEST_REBULK_POPULATE", "u:testuser1:3001:100;g:staff:2002");
        let r = IdLdapResolver::from_inputs(&LdapResolverInputs::default());
        let _ = r.load_full_identities("dn", "pw");
        let gs = r.resolve_groups_for_principal("testuser1@REALM", "dn", "pw");
        std::env::remove_var("TEST_REBULK_POPULATE");
        assert!(!gs.is_empty());
        assert!(gs.contains(&2002));
    }
}
