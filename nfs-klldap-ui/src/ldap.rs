//! LdapClient (ldap3 + rustls). Shares uri/creds/PosixAttributeMapping with SSSD.
//! Fresh conn per op (short-lived + explicit unbind for KLLDAP/rustls TLS compatibility).
//! Identity cache (10m) + search cache (30s) + memberOf fast-path on verify.
//! See clear_cache / cache_stats_summary.

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use nfs_klldap_config::PosixAttributeMapping;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum LdapError {
    Network(String),
    Auth(String),
    Ldap(String),
}

impl std::fmt::Display for LdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdapError::Network(e) => write!(f, "Network error: {}", e),
            LdapError::Auth(e) => write!(f, "Authentication error: {}", e),
            LdapError::Ldap(e) => write!(f, "LDAP error: {}", e),
        }
    }
}

impl std::error::Error for LdapError {}

#[derive(Debug)]
pub struct LdapClient {
    /// ldap:// or ldaps:// URI from the central config (same one SSSD uses).
    ldap_uri: String,
    /// Effective search base for users (supports child OUs via Subtree scope).
    user_base: String,
    /// Effective search base for groups (supports child OUs via Subtree scope).
    group_base: String,

    service_conn: Option<LdapConn>,
    username: Option<String>,
    password: Option<String>,
    last_auth_time: Option<Instant>,
    posix_attributes: PosixAttributeMapping,
    no_tls_verify: bool,
    start_tls: bool,

    // Caches use std::sync::Mutex so LdapClient remains Sync (required for Axum handlers
    // that hold &LdapClient across await points via the outer tokio::sync::MutexGuard).
    user_cache: Mutex<HashMap<String, CachedUser>>,
    group_cache: Mutex<HashMap<String, CachedGroup>>,
    recent_user_searches: Mutex<HashMap<String, CachedSearch>>,
    recent_group_searches: Mutex<HashMap<String, CachedSearch>>,
    last_verified_memberofs: Mutex<Option<(String, Vec<String>, Instant)>>,
    admin_group_dn: Mutex<Option<String>>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    cache_clears: AtomicU64,
    last_cache_clear: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub dn: String,
    pub display_name: Option<String>,
    pub uid_number: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id: String,
    pub dn: String,
    pub display_name: Option<String>,
    pub gid_number: Option<i32>,
}

// ---------------------------------------------------------------------
// Simple in-memory TTL caches (zero-dep) to eliminate repeated binds/searches.
// Identity (name → uid/gid/DN) : 10 min
// Recent filter searches (autocomplete) : 30 s
// All access is behind the caller's Arc<Mutex<LdapClient>> so no extra locking.
// ---------------------------------------------------------------------

const IDENTITY_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const SEARCH_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_RECENT_SEARCHES: usize = 8;

#[derive(Debug, Clone)]
struct CachedUser {
    uid_number: Option<i32>,
    display_name: String,
    dn: String,
    fetched_at: Instant,
}

#[derive(Debug, Clone)]
struct CachedGroup {
    gid_number: Option<i32>,
    display_name: String,
    dn: String,
    fetched_at: Instant,
}

/// Lightweight stats for the settings UI (visible cache effectiveness).
#[derive(Debug, Clone, Default)]
pub struct LdapCacheStats {
    pub user_entries: usize,
    pub group_entries: usize,
    pub recent_search_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub clears: u64,
    pub last_cleared_ago_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct CachedSearch {
    results: Vec<(String, Option<i32>, String)>, // (id, numeric, display) — small and serializable enough
    fetched_at: Instant,
}

impl LdapClient {
    /// `user_base`/`group_base` from effective_ldap_search_bases (Subtree for child OUs).
    /// Bind identity must be full DN (or verbatim) for LDAPS reliability.
    pub fn new_with_attributes(
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
            service_conn: None,
            username: None,
            password: None,
            last_auth_time: None,
            posix_attributes,
            no_tls_verify,
            start_tls,
            // caches start empty
            user_cache: Mutex::new(HashMap::new()),
            group_cache: Mutex::new(HashMap::new()),
            recent_user_searches: Mutex::new(HashMap::new()),
            recent_group_searches: Mutex::new(HashMap::new()),
            last_verified_memberofs: Mutex::new(None),
            admin_group_dn: Mutex::new(None),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_clears: AtomicU64::new(0),
            last_cache_clear: Mutex::new(None),
        }
    }

    // connection settings (sync ldap3)

    fn build_conn_settings(&self) -> LdapConnSettings {
        let mut s = LdapConnSettings::new();
        if self.start_tls {
            s = s.set_starttls(true);
        }
        if self.no_tls_verify {
            s = s.set_no_tls_verify(true);
        }
        // TLS provider is installed early at application startup (see main.rs).
        // ldap3 handles the rest (roots, config, close_notify on unbind, etc.).
        // Short-lived connections + explicit unbind() are intentional for
        // compatibility with strict rustls LDAPS servers like KLLDAP.
        s
    }

    // -----------------------------------------------------------------
    // Cache helpers (private). All callers must have already done evict.
    // -----------------------------------------------------------------

    fn evict_expired(&self) {
        let now = Instant::now();

        self.user_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.group_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);

        self.recent_user_searches.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < SEARCH_CACHE_TTL);
        self.recent_group_searches.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < SEARCH_CACHE_TTL);

        let mut mem = self.last_verified_memberofs.lock().unwrap();
        if let Some((_, _, t)) = mem.as_ref() {
            if now.duration_since(*t) >= Duration::from_secs(120) {
                *mem = None;
            }
        }
    }

    fn cache_get_user(&self, name: &str) -> Option<CachedUser> {
        self.evict_expired();
        if let Some(hit) = self.user_cache.lock().unwrap().get(name).cloned() {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some(hit);
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn cache_put_user(&self, name: &str, u: &User) {
        self.user_cache.lock().unwrap().insert(
            name.to_string(),
            CachedUser {
                uid_number: u.uid_number,
                display_name: u.display_name.clone().unwrap_or_else(|| u.id.clone()),
                dn: u.dn.clone(),
                fetched_at: Instant::now(),
            },
        );
    }

    fn cache_get_group(&self, name: &str) -> Option<CachedGroup> {
        self.evict_expired();
        if let Some(hit) = self.group_cache.lock().unwrap().get(name).cloned() {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some(hit);
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn cache_put_group(&self, name: &str, g: &Group) {
        self.group_cache.lock().unwrap().insert(
            name.to_string(),
            CachedGroup {
                gid_number: g.gid_number,
                display_name: g.display_name.clone().unwrap_or_else(|| g.id.clone()),
                dn: g.dn.clone(),
                fetched_at: Instant::now(),
            },
        );
    }

    fn cache_put_search(&self, key: &str, is_user: bool, items: &[(String, Option<i32>, String)]) {
        let entry = CachedSearch {
            results: items.to_vec(),
            fetched_at: Instant::now(),
        };
        if is_user {
            let mut map = self.recent_user_searches.lock().unwrap();
            map.insert(key.to_string(), entry);
            if map.len() > MAX_RECENT_SEARCHES {
                if let Some(oldest) = map.keys().next().cloned() {
                    map.remove(&oldest);
                }
            }
        } else {
            let mut map = self.recent_group_searches.lock().unwrap();
            map.insert(key.to_string(), entry);
            if map.len() > MAX_RECENT_SEARCHES {
                if let Some(oldest) = map.keys().next().cloned() {
                    map.remove(&oldest);
                }
            }
        }
    }

    fn cache_get_search(&self, key: &str, is_user: bool) -> Option<Vec<(String, Option<i32>, String)>> {
        self.evict_expired();
        let map = if is_user { self.recent_user_searches.lock().unwrap() } else { self.recent_group_searches.lock().unwrap() };
        if let Some(hit) = map.get(key) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some(hit.results.clone());
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn clear_cache(&self) {
        self.user_cache.lock().unwrap().clear();
        self.group_cache.lock().unwrap().clear();
        self.recent_user_searches.lock().unwrap().clear();
        self.recent_group_searches.lock().unwrap().clear();
        *self.last_verified_memberofs.lock().unwrap() = None;
        *self.admin_group_dn.lock().unwrap() = None;
        self.cache_clears.fetch_add(1, Ordering::Relaxed);
        *self.last_cache_clear.lock().unwrap() = Some(Instant::now());
    }

    pub fn cache_stats_summary(&self) -> LdapCacheStats {
        let last_ago = self.last_cache_clear.lock().unwrap().map(|t| Instant::now().duration_since(t).as_secs());
        LdapCacheStats {
            user_entries: self.user_cache.lock().unwrap().len(),
            group_entries: self.group_cache.lock().unwrap().len(),
            recent_search_entries: self.recent_user_searches.lock().unwrap().len() + self.recent_group_searches.lock().unwrap().len(),
            hits: self.cache_hits.load(Ordering::Relaxed),
            misses: self.cache_misses.load(Ordering::Relaxed),
            clears: self.cache_clears.load(Ordering::Relaxed),
            last_cleared_ago_secs: last_ago,
        }
    }

    fn record_verified_memberofs(&self, username: &str, memberofs: Vec<String>) {
        *self.last_verified_memberofs.lock().unwrap() = Some((username.to_string(), memberofs, Instant::now()));
    }

    fn has_recent_memberof(&self, username: &str, group_dn: &str) -> bool {
        if let Some((u, list, _)) = &*self.last_verified_memberofs.lock().unwrap() {
            if u.eq_ignore_ascii_case(username) {
                return list.iter().any(|m| m.eq_ignore_ascii_case(group_dn));
            }
        }
        false
    }

    async fn resolve_admin_group_dn(&self, admin_group_name: &str) -> Option<String> {
        if let Some(dn) = &*self.admin_group_dn.lock().unwrap() {
            return Some(dn.clone());
        }
        if let Some((_, _)) = self.resolve_group(admin_group_name).await {
            if let Some(cached) = self.group_cache.lock().unwrap().get(admin_group_name) {
                *self.admin_group_dn.lock().unwrap() = Some(cached.dn.clone());
                return Some(cached.dn.clone());
            }
        }
        None
    }

    async fn get_or_bind_service(&mut self) -> Result<(), LdapError> {
        // No-op for now (we use fresh connect+bind+op+unbind per call inside
        // spawn_blocking because of the "sync" ldap3 API choice for KLLDAP compat).
        // This keeps things simple and safe. Long-lived conn optimization possible later.
        if self.username.is_none() || self.password.is_none() {
            return Err(LdapError::Auth("no service credentials".into()));
        }
        self.last_auth_time = Some(Instant::now());
        Ok(())
    }

    async fn service_search(
        &self,
        base: &str,
        filter: &str,
        attrs: Vec<String>,
    ) -> Result<Vec<SearchEntry>, LdapError> {
        let uri = self.ldap_uri.clone();
        let settings = self.build_conn_settings();
        let (u, p) = match (&self.username, &self.password) {
            (Some(u), Some(p)) => (u.clone(), p.clone()),
            _ => return Err(LdapError::Auth("no service credentials".into())),
        };
        let base = base.to_string();
        let filter = filter.to_string();

        // retry on transient connect errors
        for attempt in 0..3 {
            let result = tokio::task::spawn_blocking({
                let uri = uri.clone();
                let settings = settings.clone();
                let u = u.clone();
                let p = p.clone();
                let base = base.clone();
                let filter = filter.clone();
                let attrs = attrs.clone();

                move || {
                    let mut ldap = LdapConn::with_settings(settings, &uri)
                        .map_err(|e| format!("connect: {}", e))?;

                    // Best-effort clean TLS shutdown via UnbindRequest + unbind.
                    let op_result = (|| -> Result<Vec<SearchEntry>, String> {
                        ldap.simple_bind(&u, &p)
                            .map_err(|e| format!("bind: {}", e))?
                            .success()
                            .map_err(|e| format!("bind success: {:?}", e))?;

                        let (rs, _res) = ldap
                            .search(&base, Scope::Subtree, &filter, attrs)
                            .map_err(|e| format!("search: {}", e))?
                            .success()
                            .map_err(|e| format!("search success: {:?}", e))?;

                        let entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();
                        Ok(entries)
                    })();

                    let _ = ldap.unbind();
                    op_result
                }
            })
            .await;

            match result {
                Ok(Ok(entries)) => return Ok(entries),
                Ok(Err(e)) => {
                    if attempt == 2 {
                        return Err(LdapError::Ldap(e));
                    }
                    // Transient error, retry
                    tokio::time::sleep(std::time::Duration::from_millis(200 * (attempt + 1) as u64)).await;
                }
                Err(e) => {
                    if attempt == 2 {
                        return Err(LdapError::Network(format!("spawn_blocking join error: {}", e)));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200 * (attempt + 1) as u64)).await;
                }
            }
        }

        Err(LdapError::Ldap("exhausted retries".into()))
    }

    async fn ldap_search_entries(
        &self,
        base: &str,
        filter: &str,
        attrs: Vec<String>,
    ) -> Vec<SearchEntry> {
        self.service_search(base, filter, attrs)
            .await
            .unwrap_or_default()
    }

    fn escape_filter_value(s: &str) -> String {
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

    async fn try_simple_bind(&self, dn: &str, pw: &str) -> bool {
        let uri = self.ldap_uri.clone();
        let settings = self.build_conn_settings();
        let dn = dn.to_string();
        let pw = pw.to_string();

        tokio::task::spawn_blocking(move || {
            let mut ldap = LdapConn::with_settings(settings, &uri).ok()?;

            // Best-effort clean TLS shutdown via unbind even on bind rejection.
            let bind_ok = ldap.simple_bind(&dn, &pw).ok().and_then(|r| r.success().ok()).is_some();
            let _ = ldap.unbind();
            if bind_ok { Some(()) } else { None }
        })
        .await
        .is_ok()
    }

    pub async fn authenticate(&mut self, username: &str, password: &str) -> Result<(), LdapError> {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self.service_conn = None;
        self.clear_cache();
        self.get_or_bind_service().await?;
        Ok(())
    }

    pub async fn resolve_user(&self, name: &str) -> Option<(i32, String)> {
        if let Some(hit) = self.cache_get_user(name) {
            if let Some(uid) = hit.uid_number {
                return Some((uid, hit.display_name.clone()));
            }
        }

        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();

        let filter = format!(
            "(&(objectClass={})({}={}))",
            obj,
            name_attr,
            Self::escape_filter_value(name)
        );
        let full_attr = self.posix_attributes.user_full_name.clone();
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            uid_attr.clone(),
            "cn".into(),
            "displayName".into(),
            full_attr.clone(),
        ];

        let entries = match self.service_search(&self.user_base, &filter, attrs).await {
            Ok(e) => e,
            Err(_) => return None,
        };

        for se in entries {
            let display = Self::extract_display_name(&se, &full_attr, name);

            if let Some(uid_str) = Self::extract_first_attr(&se, &uid_attr) {
                if let Ok(u) = uid_str.parse::<i32>() {
                    let user = User {
                        id: name.to_string(),
                        dn: se.dn.clone(),
                        display_name: Some(display.clone()),
                        uid_number: Some(u),
                    };
                    self.cache_put_user(name, &user);
                    return Some((u, display));
                }
            }
        }
        None
    }

    pub async fn resolve_user_dn(&self, name: &str) -> Option<String> {
        if let Some(hit) = self.cache_get_user(name) {
            return Some(hit.dn);
        }

        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();

        let filter = format!(
            "(&(objectClass={})({}={}))",
            obj,
            name_attr,
            Self::escape_filter_value(name)
        );

        let entries = match self.service_search(&self.user_base, &filter, vec![name_attr]).await {
            Ok(e) => e,
            Err(_) => return None,
        };

        entries.into_iter().next().map(|se| se.dn)
    }

    // list/resolve (Subtree + shared PosixAttributeMapping)

    pub async fn resolve_group(&self, name: &str) -> Option<(i32, String)> {
        if let Some(hit) = self.cache_get_group(name) {
            if let Some(gid) = hit.gid_number {
                return Some((gid, hit.display_name.clone()));
            }
        }

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
            .ldap_search_entries(&self.group_base, &filter, attrs)
            .await;

        for se in entries {
            let display = Self::extract_display_name(&se, &name_attr, name);

            if let Some(gid_str) = Self::extract_first_attr(&se, &gid_attr) {
                if let Ok(g) = gid_str.parse::<i32>() {
                    let group = Group {
                        id: name.to_string(),
                        dn: se.dn.clone(),
                        display_name: Some(display.clone()),
                        gid_number: Some(g),
                    };
                    self.cache_put_group(name, &group);
                    return Some((g, display));
                }
            }
        }
        None
    }

    pub async fn list_users(&self, filter: Option<&str>) -> Vec<User> {
        let q = filter.unwrap_or("").trim();
        let cache_key = if q.is_empty() { "__all__".to_string() } else { q.to_string() };

        if let Some(cached) = self.cache_get_search(&cache_key, true) {
            return cached.into_iter().map(|(id, uid, display)| User {
                id,
                dn: String::new(), // DN not needed for list UI
                display_name: Some(display),
                uid_number: uid,
            }).collect();
        }

        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();

        let ldap_filter = if !q.is_empty() {
            let esc = Self::escape_filter_value(q);
            let full = self.posix_attributes.user_full_name.clone();
            format!(
                "(&(objectClass={})(|({}=*{}*)(cn=*{}*)(displayName=*{}*)({}=*{}*)))",
                obj, name_attr, esc, esc, esc, full, esc
            )
        } else {
            format!("(objectClass={})", obj)
        };

        let full = self.posix_attributes.user_full_name.clone();
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            uid_attr.clone(),
            "cn".into(),
            "displayName".into(),
            full,
        ];

        let entries = self
            .ldap_search_entries(&self.user_base, &ldap_filter, attrs)
            .await;

        let full_attr = self.posix_attributes.user_full_name.clone();
        let users: Vec<User> = entries
            .into_iter()
            .map(|se| {
                let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_default();
                let display = Self::extract_display_name(&se, &full_attr, &id);
                let uid = Self::extract_first_attr(&se, &uid_attr).and_then(|s| s.parse::<i32>().ok());
                User { id, dn: se.dn, display_name: Some(display.clone()), uid_number: uid }
            })
            .take(20)
            .collect();

        let _ = users.first().map(|u| u.dn.len());

        // populate short-lived search cache (store minimal tuples)
        let cache_items: Vec<(String, Option<i32>, String)> = users.iter().map(|u| (u.id.clone(), u.uid_number, u.display_name.clone().unwrap_or_default())).collect();
        self.cache_put_search(&cache_key, true, &cache_items);

        // also populate individual identity cache entries for future resolve_ hits
        for u in &users {
            self.cache_put_user(&u.id, u);
        }

        users
    }

    pub async fn list_groups(&self, filter: Option<&str>) -> Vec<Group> {
        let q = filter.unwrap_or("").trim();
        let cache_key = if q.is_empty() { "__all__".to_string() } else { q.to_string() };

        if let Some(cached) = self.cache_get_search(&cache_key, false) {
            return cached.into_iter().map(|(id, gid, display)| Group {
                id,
                dn: String::new(),
                display_name: Some(display),
                gid_number: gid,
            }).collect();
        }

        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let name_attr = self.posix_attributes.group_name.clone();
        let obj = self.posix_attributes.group_object_class.clone();

        let ldap_filter = if !q.is_empty() {
            let esc = Self::escape_filter_value(q);
            format!(
                "(&(objectClass={})(|({}=*{}*)(cn=*{}*)(displayName=*{}*)))",
                obj, name_attr, esc, esc, esc
            )
        } else {
            format!("(objectClass={})", obj)
        };

        let attrs: Vec<String> = vec![
            name_attr.clone(),
            gid_attr.clone(),
            "cn".into(),
            "displayName".into(),
        ];

        let entries = self
            .ldap_search_entries(&self.group_base, &ldap_filter, attrs)
            .await;

        let groups: Vec<Group> = entries
            .into_iter()
            .map(|se| {
                let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_default();
                let display = Self::extract_display_name(&se, &name_attr, &id);
                let gid = Self::extract_first_attr(&se, &gid_attr).and_then(|s| s.parse::<i32>().ok());
                Group { id, dn: se.dn, display_name: Some(display.clone()), gid_number: gid }
            })
            .take(20)
            .collect();

        let _ = groups.first().map(|g| g.dn.len());

        let cache_items: Vec<(String, Option<i32>, String)> = groups.iter().map(|g| (g.id.clone(), g.gid_number, g.display_name.clone().unwrap_or_default())).collect();
        self.cache_put_search(&cache_key, false, &cache_items);

        for g in &groups {
            self.cache_put_group(&g.id, g);
        }

        groups
    }

    pub async fn verify_user_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), LdapError> {
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();

        let user_filter = format!(
            "(&(objectClass={})({}={}))",
            obj,
            name_attr,
            Self::escape_filter_value(username)
        );
        let lookup_attrs: Vec<String> = vec![name_attr.clone(), "memberOf".into()];

        let entries = self
            .ldap_search_entries(&self.user_base, &user_filter, lookup_attrs)
            .await;

        let (user_dn, memberofs) = match entries.into_iter().next() {
            Some(se) => {
                let dn = se.dn;
                let m = se.attrs.get("memberOf").cloned().or_else(|| se.attrs.get("memberof").cloned()).unwrap_or_default();
                (dn, m)
            }
            None => {
                return Err(LdapError::Auth(
                    "user not found or service account lacks permission to search".into(),
                ));
            }
        };

        if self.try_simple_bind(&user_dn, password).await {
            self.record_verified_memberofs(username, memberofs);
            Ok(())
        } else {
            Err(LdapError::Auth(
                "Invalid username or password (KLLDAP/LDAP bind failed)".into(),
            ))
        }
    }

    pub fn authenticated_as(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn last_auth_time(&self) -> Option<Instant> {
        self.last_auth_time
    }

    pub async fn user_is_member_of_group(&self, username: &str, group_name: &str) -> bool {
        self.user_is_member_of(username, group_name).await
    }

    async fn user_is_member_of(&self, username: &str, group_name: &str) -> bool {
        // Fast path: if we just verified this exact user, use the memberOf list we already fetched.
        if let Some(admin_dn) = self.resolve_admin_group_dn(group_name).await {
            if self.has_recent_memberof(username, &admin_dn) {
                return true;
            }
        }

        let g_name = self.posix_attributes.group_name.clone();
        let g_obj = self.posix_attributes.group_object_class.clone();

        let g_filter = format!(
            "(&(objectClass={})({}={}))",
            g_obj,
            g_name,
            Self::escape_filter_value(group_name)
        );

        let g_entries = self
            .ldap_search_entries(&self.group_base, &g_filter, vec!["1.1".into()])
            .await;

        let group_dn = match g_entries.into_iter().next() {
            Some(e) if !e.dn.is_empty() => e.dn,
            _ => return false,
        };

        // After we have the group DN, the recent verify data may still help for this group.
        if self.has_recent_memberof(username, &group_dn) {
            return true;
        }

        let user_dn = match self.resolve_user_dn(username).await {
            Some(dn) => dn,
            None => return false,
        };

        let test_filter = format!(
            "(&(objectClass={})(memberOf={}))",
            self.posix_attributes.user_object_class,
            Self::escape_filter_value(&group_dn)
        );

        let test_entries = self
            .ldap_search_entries(&self.user_base, &test_filter, vec!["1.1".into()])
            .await;

        test_entries.iter().any(|e| e.dn.eq_ignore_ascii_case(&user_dn))
    }
}
