//! LdapClient wraps IdLdapResolver with UI search caches and admin verify.

use ldap3::{LdapConn, LdapConnSettings};
use nfs_klldap_config::{IdLdapResolver, PosixAttributeMapping};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum LdapError {
    Auth(String),
}

impl std::fmt::Display for LdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdapError::Auth(e) => write!(f, "Authentication error: {}", e),
        }
    }
}

impl std::error::Error for LdapError {}

#[derive(Debug)]
pub struct LdapClient {
    /// LDAP URI from central config (ldap:// or ldaps://, same as SSSD).
    ldap_uri: String,
    /// Effective search base for users (supports child OUs via Subtree scope).
    user_base: String,
    /// Holds the group search base and supports child OUs via Subtree scope.
    group_base: String,

    service_conn: Option<LdapConn>,
    username: Option<String>,
    password: Option<String>,
    last_auth_time: Option<Instant>,
    posix_attributes: PosixAttributeMapping,
    no_tls_verify: bool,
    start_tls: bool,

    // Std Mutex for Sync (Axum & across await via outer tokio Mutex).
    user_cache: Mutex<HashMap<String, CachedUser>>,
    group_cache: Mutex<HashMap<String, CachedGroup>>,
    // Reverse uid/gid→name caches for tree meta (10m TTL).
    user_by_uid_cache: Mutex<HashMap<i32, CachedUser>>,
    group_by_gid_cache: Mutex<HashMap<i32, CachedGroup>>,
    recent_user_searches: Mutex<HashMap<String, CachedSearch>>,
    recent_group_searches: Mutex<HashMap<String, CachedSearch>>,
    last_verified_memberofs: Mutex<Option<(String, Vec<String>, Instant)>>,
    admin_group_dn: Mutex<Option<String>>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    cache_clears: AtomicU64,
    last_cache_clear: Mutex<Option<Instant>>,

    /// Wraps a shared sync resolver whose caches clear_cache() rebuilds.
    identity_resolver: Arc<Mutex<IdLdapResolver>>,
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

// In-memory TTL caches (identity 10m, search 2m). Zero-dep.

const IDENTITY_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const SEARCH_CACHE_TTL: Duration = Duration::from_secs(2 * 60);
const MAX_RECENT_SEARCHES: usize = 8;
/// Max autocomplete rows for the permission editor.
/// The dropdown is scrollable.
const LIST_RESULT_LIMIT: usize = 25;

#[derive(Debug, Clone)]
struct CachedUser {
    id: String,
    uid_number: Option<i32>,
    display_name: String,
    dn: String,
    fetched_at: Instant,
}

#[derive(Debug, Clone)]
struct CachedGroup {
    id: String,
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
    // Cached search rows store id, numeric value, and display label.
    results: Vec<(String, Option<i32>, String)>,
    fetched_at: Instant,
}

impl LdapClient {
    /// Build a client using effective LDAP search bases and subtree scope.
    pub fn new_with_attributes(
        ldap_uri: &str,
        user_base: &str,
        group_base: &str,
        posix_attributes: PosixAttributeMapping,
        no_tls_verify: bool,
        start_tls: bool,
    ) -> Self {
        let identity_resolver = Arc::new(Mutex::new(IdLdapResolver::new(
            ldap_uri,
            user_base,
            group_base,
            posix_attributes.clone(),
            no_tls_verify,
            start_tls,
        )));
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
            user_cache: Mutex::new(HashMap::new()),
            group_cache: Mutex::new(HashMap::new()),
            user_by_uid_cache: Mutex::new(HashMap::new()),
            group_by_gid_cache: Mutex::new(HashMap::new()),
            recent_user_searches: Mutex::new(HashMap::new()),
            recent_group_searches: Mutex::new(HashMap::new()),
            last_verified_memberofs: Mutex::new(None),
            admin_group_dn: Mutex::new(None),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_clears: AtomicU64::new(0),
            last_cache_clear: Mutex::new(None),
            identity_resolver,
        }
    }

    fn build_identity_resolver(&self) -> IdLdapResolver {
        IdLdapResolver::new(
            &self.ldap_uri,
            &self.user_base,
            &self.group_base,
            self.posix_attributes.clone(),
            self.no_tls_verify,
            self.start_tls,
        )
    }

    fn service_bind_creds(&self) -> Option<(String, String)> {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => Some((u.clone(), p.clone())),
            _ => None,
        }
    }

    async fn with_identity<T, F>(&self, f: F) -> Option<T>
    where
        T: Send + 'static,
        F: FnOnce(&IdLdapResolver, &str, &str) -> Option<T> + Send + 'static,
    {
        let (bind_dn, bind_pw) = self.service_bind_creds()?;
        let inner = Arc::clone(&self.identity_resolver);
        tokio::task::spawn_blocking(move || {
            let resolver = inner.lock().unwrap();
            f(&resolver, &bind_dn, &bind_pw)
        })
        .await
        .ok()
        .flatten()
    }

    async fn fetch_entry_dn(&self, base: &str, filter: &str) -> Option<String> {
        let base = base.to_string();
        let filter = filter.to_string();
        self.with_identity(move |resolver, bind_dn, bind_pw| {
            resolver.lookup_first_dn(&base, &filter, bind_dn, bind_pw)
        })
        .await
    }

    // Connection settings (sync ldap3).

    fn build_conn_settings(&self) -> LdapConnSettings {
        let mut s = LdapConnSettings::new();
        if self.start_tls {
            s = s.set_starttls(true);
        }
        if self.no_tls_verify {
            s = s.set_no_tls_verify(true);
        }
        // TLS provider is installed early at application startup (see.
        s
    }

    // These tests cover cache helpers (private). all callers must have.

    fn evict_expired(&self) {
        let now = Instant::now();

        self.user_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.group_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);

        // Reverse uid/gid caches (same TTL).
        self.user_by_uid_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);
        self.group_by_gid_cache.lock().unwrap().retain(|_, v| now.duration_since(v.fetched_at) < IDENTITY_CACHE_TTL);

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
                id: u.id.clone(),
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
                id: g.id.clone(),
                gid_number: g.gid_number,
                display_name: g.display_name.clone().unwrap_or_else(|| g.id.clone()),
                dn: g.dn.clone(),
                fetched_at: Instant::now(),
            },
        );
    }

    // These tests cover reverse (uid/gid -> display) cache helpers --- used.
    fn cache_get_user_by_uid(&self, uid: i32) -> Option<CachedUser> {
        self.evict_expired();
        if let Some(hit) = self.user_by_uid_cache.lock().unwrap().get(&uid).cloned() {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some(hit);
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn cache_put_user_by_uid(&self, uid: i32, u: &User) {
        self.user_by_uid_cache.lock().unwrap().insert(
            uid,
            CachedUser {
                id: u.id.clone(),
                uid_number: u.uid_number,
                display_name: u.display_name.clone().unwrap_or_else(|| u.id.clone()),
                dn: u.dn.clone(),
                fetched_at: Instant::now(),
            },
        );
    }

    fn cache_get_group_by_gid(&self, gid: i32) -> Option<CachedGroup> {
        self.evict_expired();
        if let Some(hit) = self.group_by_gid_cache.lock().unwrap().get(&gid).cloned() {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some(hit);
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn cache_put_group_by_gid(&self, gid: i32, g: &Group) {
        self.group_by_gid_cache.lock().unwrap().insert(
            gid,
            CachedGroup {
                id: g.id.clone(),
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
        self.user_by_uid_cache.lock().unwrap().clear();
        self.group_by_gid_cache.lock().unwrap().clear();
        self.recent_user_searches.lock().unwrap().clear();
        self.recent_group_searches.lock().unwrap().clear();
        *self.last_verified_memberofs.lock().unwrap() = None;
        *self.admin_group_dn.lock().unwrap() = None;
        *self.identity_resolver.lock().unwrap() = self.build_identity_resolver();
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
        // No-op for now (we use fresh connect+bind+op+unbind per call inside.
        if self.username.is_none() || self.password.is_none() {
            return Err(LdapError::Auth("no service credentials".into()));
        }
        self.last_auth_time = Some(Instant::now());
        Ok(())
    }

    fn user_filter_by_name(&self, name: &str) -> String {
        self.identity_resolver.lock().unwrap().user_filter_by_name(name)
    }

    fn group_filter_by_name(&self, name: &str) -> String {
        self.identity_resolver.lock().unwrap().group_filter_by_name(name)
    }

    /// Strip permission-editor values like `Alice (1000)`.
    /// Keeps `1000` or `Alice` as needed.
    pub(crate) fn normalize_editor_search_query(q: Option<&str>) -> Option<String> {
        let s = q.map(str::trim).filter(|s| !s.is_empty())?;
        if let Some(open) = s.rfind('(') {
            if s.ends_with(')') {
                let inner = s[open + 1..s.len() - 1].trim();
                let digits = inner
                    .strip_prefix("UID")
                    .or_else(|| inner.strip_prefix("uid"))
                    .or_else(|| inner.strip_prefix("GID"))
                    .or_else(|| inner.strip_prefix("gid"))
                    .map(str::trim)
                    .unwrap_or(inner);
                if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
                    return Some(digits.to_string());
                }
                let name = s[..open].trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        Some(s.to_string())
    }

    /// Normalized query for permission-editor autocomplete.
    /// Matches name or numeric substring.
    fn normalize_list_query(filter: Option<&str>) -> (String, String, String) {
        let q_orig = Self::normalize_editor_search_query(filter).unwrap_or_default();
        let q_lower = q_orig.to_lowercase();
        let cache_key = if q_orig.is_empty() {
            "__all__".to_string()
        } else {
            q_orig.clone()
        };
        (q_orig, q_lower, cache_key)
    }

    fn matches_list_query(q_lower: &str, id: &str, display: &str, num: Option<i32>) -> bool {
        if q_lower.is_empty() {
            return true;
        }
        id.to_lowercase().contains(q_lower)
            || display.to_lowercase().contains(q_lower)
            || num
                .map(|n| n.to_string())
                .unwrap_or_default()
                .contains(q_lower)
    }

    fn sort_users_for_list(users: &mut [User]) {
        users.sort_by(|a, b| {
            let da = a.display_name.as_deref().unwrap_or(&a.id).to_lowercase();
            let db = b.display_name.as_deref().unwrap_or(&b.id).to_lowercase();
            da.cmp(&db).then_with(|| a.id.to_lowercase().cmp(&b.id.to_lowercase()))
        });
    }

    fn sort_groups_for_list(groups: &mut [Group]) {
        groups.sort_by(|a, b| {
            let da = a.display_name.as_deref().unwrap_or(&a.id).to_lowercase();
            let db = b.display_name.as_deref().unwrap_or(&b.id).to_lowercase();
            da.cmp(&db).then_with(|| a.id.to_lowercase().cmp(&b.id.to_lowercase()))
        });
    }

    fn try_push_user(
        results: &mut Vec<User>,
        seen: &mut HashSet<String>,
        q_lower: &str,
        u: User,
    ) {
        let Some(uid) = u.uid_number else {
            return;
        };
        let display = u.display_name.as_deref().unwrap_or(&u.id);
        if !Self::matches_list_query(q_lower, &u.id, display, Some(uid)) {
            return;
        }
        if seen.insert(u.id.clone()) {
            results.push(u);
        }
    }

    fn try_push_group(
        results: &mut Vec<Group>,
        seen: &mut HashSet<String>,
        q_lower: &str,
        g: Group,
    ) {
        let Some(gid) = g.gid_number else {
            return;
        };
        let display = g.display_name.as_deref().unwrap_or(&g.id);
        if !Self::matches_list_query(q_lower, &g.id, display, Some(gid)) {
            return;
        }
        if seen.insert(g.id.clone()) {
            results.push(g);
        }
    }

    async fn try_simple_bind(&self, dn: &str, pw: &str) -> bool {
        let uri = self.ldap_uri.clone();
        let settings = self.build_conn_settings();
        let dn = dn.to_string();
        let pw = pw.to_string();

        tokio::task::spawn_blocking(move || {
            let mut ldap = LdapConn::with_settings(settings, &uri).ok()?;

            // Best-effort clean TLS shutdown via unbind even on bind.
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

        let name_owned = name.to_string();
        let filter = self.user_filter_by_name(name);
        let user_base = self.user_base.clone();
        let resolved = self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                resolver.resolve_user(&name_owned, bind_dn, bind_pw)
            })
            .await?;

        let (uid, _, display) = resolved;
        let dn = self
            .fetch_entry_dn(&user_base, &filter)
            .await
            .unwrap_or_default();

        let user = User {
            id: name.to_string(),
            dn,
            display_name: Some(display.clone()),
            uid_number: Some(uid),
        };
        self.cache_put_user(name, &user);
        Some((uid, display))
    }

    pub async fn resolve_user_dn(&self, name: &str) -> Option<String> {
        if let Some(hit) = self.cache_get_user(name) {
            if !hit.dn.is_empty() {
                return Some(hit.dn);
            }
        }

        let filter = self.user_filter_by_name(name);
        self.fetch_entry_dn(&self.user_base, &filter).await
    }

    // List/resolve (Subtree + shared PosixAttributeMapping).

    pub async fn resolve_group(&self, name: &str) -> Option<(i32, String)> {
        if let Some(hit) = self.cache_get_group(name) {
            if let Some(gid) = hit.gid_number {
                return Some((gid, hit.display_name.clone()));
            }
        }

        let name_owned = name.to_string();
        let filter = self.group_filter_by_name(name);
        let group_base = self.group_base.clone();
        let resolved = self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                resolver.resolve_group(&name_owned, bind_dn, bind_pw)
            })
            .await?;

        let (gid, display) = resolved;
        let dn = self
            .fetch_entry_dn(&group_base, &filter)
            .await
            .unwrap_or_default();

        let group = Group {
            id: name.to_string(),
            dn,
            display_name: Some(display.clone()),
            gid_number: Some(gid),
        };
        self.cache_put_group(name, &group);
        Some((gid, display))
    }

    /// Resolves uidNumber to a user name and fills caches via subtree search.
    pub async fn resolve_user_by_uid(&self, uid: i32) -> Option<(String, String)> {
        if let Some(hit) = self.cache_get_user_by_uid(uid) {
            if hit.uid_number.is_some() {
                return Some((hit.id.clone(), hit.display_name.clone()));
            }
        }

        let filter = format!(
            "(&(objectClass={})({}={}))",
            self.posix_attributes.user_object_class, self.posix_attributes.user_uid_number, uid
        );
        let user_base = self.user_base.clone();
        let resolved = self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                resolver.resolve_user_by_uid(uid, bind_dn, bind_pw)
            })
            .await?;

        let (id, display) = resolved;
        let dn = self
            .fetch_entry_dn(&user_base, &filter)
            .await
            .unwrap_or_default();

        let user = User {
            id: id.clone(),
            dn,
            display_name: Some(display.clone()),
            uid_number: Some(uid),
        };
        self.cache_put_user(&id, &user);
        self.cache_put_user_by_uid(uid, &user);
        Some((id, display))
    }

    /// Resolves gidNumber to group name and display_name via subtree search.
    /// Uses dedicated 10m cache.
    pub async fn resolve_group_by_gid(&self, gid: i32) -> Option<(String, String)> {
        if let Some(hit) = self.cache_get_group_by_gid(gid) {
            if hit.gid_number.is_some() {
                return Some((hit.id.clone(), hit.display_name.clone()));
            }
        }

        let filter = format!(
            "(&(objectClass={})({}={}))",
            self.posix_attributes.group_object_class, self.posix_attributes.group_gid_number, gid
        );
        let group_base = self.group_base.clone();
        let resolved = self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                resolver.resolve_group_by_gid(gid, bind_dn, bind_pw)
            })
            .await?;

        let (id, display) = resolved;
        let dn = self
            .fetch_entry_dn(&group_base, &filter)
            .await
            .unwrap_or_default();

        let group = Group {
            id: id.clone(),
            dn,
            display_name: Some(display.clone()),
            gid_number: Some(gid),
        };
        self.cache_put_group(&id, &group);
        self.cache_put_group_by_gid(gid, &group);
        Some((id, display))
    }

    pub async fn list_users(&self, filter: Option<&str>) -> Vec<User> {
        let (q_orig, q_lower, cache_key) = Self::normalize_list_query(filter);

        let mut results: Vec<User> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();

        // Serves typed queries from cache while empty queries always hit LDAP.
        if !q_orig.is_empty() {
            for (id, cu) in self.user_cache.lock().unwrap().iter() {
                Self::try_push_user(
                    &mut results,
                    &mut seen_ids,
                    &q_lower,
                    User {
                        id: id.clone(),
                        dn: cu.dn.clone(),
                        display_name: Some(cu.display_name.clone()),
                        uid_number: cu.uid_number,
                    },
                );
            }
        }

        // Recent search cache (2m): re-apply query filter stale keys Must not.
        let search_cached = self.cache_get_search(&cache_key, true);
        if let Some(cached) = search_cached.clone() {
            for (id, uid, display) in cached {
                Self::try_push_user(
                    &mut results,
                    &mut seen_ids,
                    &q_lower,
                    User {
                        id,
                        dn: String::new(),
                        display_name: Some(display),
                        uid_number: uid,
                    },
                );
            }
        }

        // LDAP when caches miss, typed query misses or a stale empty __all__.
        let needs_ldap = if q_orig.is_empty() {
            search_cached.as_ref().is_none_or(|c| c.is_empty())
        } else {
            results.is_empty()
                && (search_cached.is_none()
                    || !q_lower.is_empty()
                    || search_cached.as_ref().is_some_and(|c| c.is_empty()))
        };
        if needs_ldap {
            let q = q_orig.clone();
            let limit = LIST_RESULT_LIMIT;
            if let Some(rows) = self
                .with_identity(move |resolver, bind_dn, bind_pw| {
                    Some(resolver.search_list_users(&q, bind_dn, bind_pw, limit))
                })
                .await
            {
                for (id, uid, display, dn) in rows {
                    Self::try_push_user(
                        &mut results,
                        &mut seen_ids,
                        &q_lower,
                        User {
                            id,
                            dn,
                            display_name: Some(display),
                            uid_number: uid,
                        },
                    );
                    if results.len() >= LIST_RESULT_LIMIT {
                        break;
                    }
                }
            }
        }

        Self::sort_users_for_list(&mut results);
        results.truncate(LIST_RESULT_LIMIT);

        let cache_items: Vec<(String, Option<i32>, String)> = results
            .iter()
            .filter(|u| u.uid_number.is_some())
            .map(|u| (u.id.clone(), u.uid_number, u.display_name.clone().unwrap_or_default()))
            .collect();
        self.cache_put_search(&cache_key, true, &cache_items);

        for u in &results {
            self.cache_put_user(&u.id, u);
            if let Some(uid) = u.uid_number {
                self.cache_put_user_by_uid(uid, u);
            }
        }

        results
    }

    pub async fn list_groups(&self, filter: Option<&str>) -> Vec<Group> {
        let (q_orig, q_lower, cache_key) = Self::normalize_list_query(filter);

        let mut results: Vec<Group> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();

        if !q_orig.is_empty() {
            for (id, cg) in self.group_cache.lock().unwrap().iter() {
                Self::try_push_group(
                    &mut results,
                    &mut seen_ids,
                    &q_lower,
                    Group {
                        id: id.clone(),
                        dn: cg.dn.clone(),
                        display_name: Some(cg.display_name.clone()),
                        gid_number: cg.gid_number,
                    },
                );
            }
        }

        let search_cached = self.cache_get_search(&cache_key, false);
        if let Some(cached) = search_cached.clone() {
            for (id, gid, display) in cached {
                Self::try_push_group(
                    &mut results,
                    &mut seen_ids,
                    &q_lower,
                    Group {
                        id,
                        dn: String::new(),
                        display_name: Some(display),
                        gid_number: gid,
                    },
                );
            }
        }

        let needs_ldap = if q_orig.is_empty() {
            search_cached.as_ref().is_none_or(|c| c.is_empty())
        } else {
            results.is_empty()
                && (search_cached.is_none()
                    || !q_lower.is_empty()
                    || search_cached.as_ref().is_some_and(|c| c.is_empty()))
        };
        if needs_ldap {
            let q = q_orig.clone();
            let limit = LIST_RESULT_LIMIT;
            if let Some(rows) = self
                .with_identity(move |resolver, bind_dn, bind_pw| {
                    Some(resolver.search_list_groups(&q, bind_dn, bind_pw, limit))
                })
                .await
            {
                for (id, gid, display, dn) in rows {
                    Self::try_push_group(
                        &mut results,
                        &mut seen_ids,
                        &q_lower,
                        Group {
                            id,
                            dn,
                            display_name: Some(display),
                            gid_number: gid,
                        },
                    );
                    if results.len() >= LIST_RESULT_LIMIT {
                        break;
                    }
                }
            }
        }

        Self::sort_groups_for_list(&mut results);
        results.truncate(LIST_RESULT_LIMIT);

        let cache_items: Vec<(String, Option<i32>, String)> = results
            .iter()
            .filter(|g| g.gid_number.is_some())
            .map(|g| (g.id.clone(), g.gid_number, g.display_name.clone().unwrap_or_default()))
            .collect();
        self.cache_put_search(&cache_key, false, &cache_items);

        for g in &results {
            self.cache_put_group(&g.id, g);
            if let Some(gid) = g.gid_number {
                self.cache_put_group_by_gid(gid, g);
            }
        }

        results
    }

    pub async fn verify_user_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), LdapError> {
        let name = username.to_string();
        let lookup_name = name.clone();
        let (user_dn, memberofs) = match self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                resolver.lookup_user_dn_and_memberof(&lookup_name, bind_dn, bind_pw)
            })
            .await
        {
            Some(v) => v,
            None => {
                return Err(LdapError::Auth(
                    "user not found or service account lacks permission to search".into(),
                ));
            }
        };

        if self.try_simple_bind(&user_dn, password).await {
            self.record_verified_memberofs(&name, memberofs);
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

    /// Verify password and admin-group membership for WebUI login.
    pub async fn verify_user_is_admin(
        &self,
        username: &str,
        password: &str,
        admin_group: &str,
    ) -> Result<(), LdapError> {
        self.verify_user_credentials(username, password).await?;

        if self.user_is_member_of_group(username, admin_group).await {
            Ok(())
        } else {
            Err(LdapError::Auth(format!(
                "Access denied: '{}' is not a member of the '{}' group.",
                username, admin_group
            )))
        }
    }

    async fn user_is_member_of(&self, username: &str, group_name: &str) -> bool {
        // Fast path: if we just verified this exact user use the memberOf.
        if let Some(admin_dn) = self.resolve_admin_group_dn(group_name).await {
            if self.has_recent_memberof(username, &admin_dn) {
                return true;
            }
        }

        let group_name = group_name.to_string();
        let group_dn = match self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                resolver.lookup_group_dn(&group_name, bind_dn, bind_pw)
            })
            .await
        {
            Some(dn) if !dn.is_empty() => dn,
            _ => return false,
        };

        if self.has_recent_memberof(username, &group_dn) {
            return true;
        }

        let user_dn = match self.resolve_user_dn(username).await {
            Some(dn) => dn,
            None => return false,
        };

        let user_dn = user_dn.clone();
        let group_dn = group_dn.clone();
        self.with_identity(move |resolver, bind_dn, bind_pw| {
            Some(resolver.user_dn_has_memberof(&user_dn, &group_dn, bind_dn, bind_pw))
        })
        .await
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod list_search_tests {
    use super::*;
    use nfs_klldap_config::{IdLdapResolver, PosixAttributeMapping};

    fn test_resolver() -> IdLdapResolver {
        IdLdapResolver::new(
            "ldap://127.0.0.1",
            "ou=people,dc=example,dc=com",
            "ou=groups,dc=example,dc=com",
            PosixAttributeMapping {
                user_object_class: "posixAccount".into(),
                group_object_class: "posixGroup".into(),
                user_name: "uid".into(),
                user_uid_number: "uidNumber".into(),
                user_gid_number: "gidNumber".into(),
                user_home_directory: "homeDirectory".into(),
                user_shell: "loginShell".into(),
                user_full_name: "cn".into(),
                group_name: "cn".into(),
                group_gid_number: "gidNumber".into(),
                group_member: "member".into(),
                user_principal_name: "krbPrincipalName".into(),
            },
            true,
            false,
        )
    }

    #[test]
    fn normalize_editor_search_query_strips_friendly_labels() {
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("Alice (1000)")),
            Some("1000".into())
        );
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("Bob (UID 2001)")),
            Some("2001".into())
        );
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("admins (GID 3000)")),
            Some("3000".into())
        );
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("carol")),
            Some("carol".into())
        );
        assert_eq!(LdapClient::normalize_editor_search_query(Some("")), None);
        assert_eq!(LdapClient::normalize_editor_search_query(None), None);
    }

    #[test]
    fn matches_list_query_name_and_uid_substring() {
        assert!(LdapClient::matches_list_query("ali", "alice", "Alice Smith", Some(1001)));
        assert!(LdapClient::matches_list_query("100", "bob", "Bob", Some(1001)));
        assert!(!LdapClient::matches_list_query("zzz", "alice", "Alice", Some(1001)));
        assert!(LdapClient::matches_list_query("", "any", "Any", Some(42)));
    }

    #[test]
    fn user_list_filter_requires_uid_number_and_supports_numeric_exact() {
        let r = test_resolver();
        let all = r.build_user_list_filter("");
        assert!(all.contains("posixAccount"));
        assert!(all.contains("(uidNumber=*)"));

        let num = r.build_user_list_filter("1001");
        assert!(num.contains("(uidNumber=1001)"));

        let name = r.build_user_list_filter("alice");
        assert!(name.contains("(uid=*alice*)"));
        assert!(name.contains("(uidNumber=*)"));
    }

    #[test]
    fn group_list_filter_requires_gid_number() {
        let r = test_resolver();
        let all = r.build_group_list_filter("");
        assert!(all.contains("posixGroup"));
        assert!(all.contains("(gidNumber=*)"));

        let num = r.build_group_list_filter("2000");
        assert!(num.contains("(gidNumber=2000)"));
    }

    #[test]
    fn try_push_user_skips_entries_without_uid() {
        let mut results = Vec::new();
        let mut seen = HashSet::new();
        LdapClient::try_push_user(
            &mut results,
            &mut seen,
            "",
            User {
                id: "noid".into(),
                dn: String::new(),
                display_name: None,
                uid_number: None,
            },
        );
        assert!(results.is_empty());

        LdapClient::try_push_user(
            &mut results,
            &mut seen,
            "bob",
            User {
                id: "bob".into(),
                dn: String::new(),
                display_name: Some("Bob".into()),
                uid_number: Some(1000),
            },
        );
        assert_eq!(results.len(), 1);
    }
}
