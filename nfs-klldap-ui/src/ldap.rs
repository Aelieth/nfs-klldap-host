//! LdapClient wraps IdLdapResolver with UI search caches and admin verify.

use ldap3::{LdapConn, LdapConnSettings};
use nfs_klldap_config::{IdLdapResolver, PosixAttributeMapping};
use std::collections::HashSet;
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

    service_conn: Option<LdapConn>,
    username: Option<String>,
    password: Option<String>,
    last_auth_time: Option<Instant>,
    no_tls_verify: bool,
    start_tls: bool,
    tls_cacert: Option<String>,

    // UI-only full-list caches (short TTL) for the permission-editor autocomplete;
    // queries are matched locally against these. Main POSIX caches live in identity_resolver.
    full_user_list: Mutex<Option<CachedSearch>>,
    full_group_list: Mutex<Option<CachedSearch>>,
    last_verified_memberofs: Mutex<Option<(String, Vec<String>, Instant)>>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    cache_clears: AtomicU64,
    last_cache_clear: Mutex<Option<Instant>>,
    /// When the periodic refresher last did a full bulk reload; skips a tick
    /// that would duplicate a very recent login-warm or manual refresh.
    last_full_refresh: Mutex<Option<Instant>>,

    /// Shared IdLdapResolver (caches + resolve). Deduped from prior UI mirrors.
    identity_resolver: Arc<Mutex<IdLdapResolver>>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub display_name: Option<String>,
    pub uid_number: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id: String,
    pub display_name: Option<String>,
    pub gid_number: Option<i32>,
}

// UI-only full-list cache TTL. Main identity caches live in IdLdapResolver.
// Kept short (independent of the periodic-refresh cadence): binds are the
// scarce resource, and a TTL-expiry fetch between refresh ticks rides the
// pooled connection (one search, zero binds), so there is no reason to stretch
// it to match the refresh interval.
const SEARCH_CACHE_TTL: Duration = Duration::from_secs(2 * 60);
/// Max rows fetched from LDAP for the full autocomplete list. Client-side memory
/// bound only — the resolver sends no server-side size limit.
const FULL_LIST_FETCH_LIMIT: usize = 1000;
/// Max autocomplete rows for the permission editor.
/// The dropdown is scrollable.
const LIST_RESULT_LIMIT: usize = 25;

/// One autocomplete row: (id, numeric uid/gid, display label).
type ListRow = (String, Option<i32>, String);

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
    /// LDAP binds since start — the KLLDAP-login pressure gauge. Low is good:
    /// the pooled connection means steady state is near zero.
    pub binds: u64,
    /// True when a bound connection is currently pooled.
    pub pool_warm: bool,
}

#[derive(Debug, Clone)]
struct CachedSearch {
    results: Vec<ListRow>,
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
        tls_cacert: Option<String>,
    ) -> Self {
        let identity_resolver = Arc::new(Mutex::new(IdLdapResolver::new(
            ldap_uri,
            user_base,
            group_base,
            posix_attributes,
            no_tls_verify,
            start_tls,
            tls_cacert.clone(),
        )));
        Self {
            ldap_uri: ldap_uri.to_string(),
            user_base: user_base.to_string(),
            service_conn: None,
            username: None,
            password: None,
            last_auth_time: None,
            no_tls_verify,
            start_tls,
            tls_cacert,
            full_user_list: Mutex::new(None),
            full_group_list: Mutex::new(None),
            last_verified_memberofs: Mutex::new(None),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_clears: AtomicU64::new(0),
            last_cache_clear: Mutex::new(None),
            last_full_refresh: Mutex::new(None),
            identity_resolver,
        }
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
        // TLS provider is installed early at application startup (main.rs).
        nfs_klldap_config::ldap_conn_settings(
            self.no_tls_verify,
            self.start_tls,
            self.tls_cacert.as_deref(),
        )
    }

    // These tests cover cache helpers (private). all callers must have.

    fn evict_expired(&self) {
        // Delegate POSIX user/group caches to shared IdLdapResolver (dedup). Keep UI-only full lists + memberof here.
        if let Ok(r) = self.identity_resolver.lock() { r.evict_expired(); }
        let now = Instant::now();
        for slot in [&self.full_user_list, &self.full_group_list] {
            let mut guard = slot.lock().unwrap();
            if guard.as_ref().is_some_and(|c| now.duration_since(c.fetched_at) >= SEARCH_CACHE_TTL) {
                *guard = None;
            }
        }
        let mut mem = self.last_verified_memberofs.lock().unwrap();
        if let Some((_, _, t)) = mem.as_ref() {
            if now.duration_since(*t) >= Duration::from_secs(120) {
                *mem = None;
            }
        }
    }

    fn store_full_list(&self, is_user: bool, rows: &[ListRow]) {
        let slot = if is_user { &self.full_user_list } else { &self.full_group_list };
        *slot.lock().unwrap() = Some(CachedSearch {
            results: rows.to_vec(),
            fetched_at: Instant::now(),
        });
    }

    fn cached_full_list(&self, is_user: bool) -> Option<Vec<ListRow>> {
        self.evict_expired();
        let slot = if is_user { &self.full_user_list } else { &self.full_group_list };
        let hit = slot.lock().unwrap().as_ref().map(|c| c.results.clone());
        if hit.is_some() {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
        hit
    }

    pub fn clear_cache(&self) {
        // Flush cached identities but KEEP the resolver instance: its pooled,
        // bound connection is the single long-lived LDAP session, and the
        // resolver's own clear_caches() empties the entry caches without
        // dropping it. Rebuilding here would throw away the pool (and the
        // bind/hit counters) on every manual clear. LDAP settings changes build
        // a whole new LdapClient (reload_nfs_client), so nothing needs the
        // connection inputs re-read here.
        if let Ok(r) = self.identity_resolver.lock() { r.clear_caches(); }
        *self.full_user_list.lock().unwrap() = None;
        *self.full_group_list.lock().unwrap() = None;
        *self.last_verified_memberofs.lock().unwrap() = None;
        self.cache_clears.fetch_add(1, Ordering::Relaxed);
        *self.last_cache_clear.lock().unwrap() = Some(Instant::now());
    }

    pub fn cache_stats_summary(&self) -> LdapCacheStats {
        // Report resolver-backed counts + UI search recents only (after dedup). 1 sentence.
        let last_ago = self.last_cache_clear.lock().unwrap().map(|t| Instant::now().duration_since(t).as_secs());
        let (user_entries, group_entries, binds, pool_warm) = self
            .identity_resolver
            .lock()
            .map(|r| (r.cache_entry_counts().0, r.cache_entry_counts().1, r.bind_stats(), r.pool_is_warm()))
            .unwrap_or((0, 0, 0, false));
        LdapCacheStats {
            user_entries,
            group_entries,
            recent_search_entries: [&self.full_user_list, &self.full_group_list]
                .iter()
                .filter(|s| s.lock().unwrap().is_some())
                .count(),
            hits: self.cache_hits.load(Ordering::Relaxed),
            misses: self.cache_misses.load(Ordering::Relaxed),
            clears: self.cache_clears.load(Ordering::Relaxed),
            last_cleared_ago_secs: last_ago,
            binds,
            pool_warm,
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

    async fn get_or_bind_service(&mut self) -> Result<(), LdapError> {
        // Only validates + records service creds. The resolver owns the actual
        // connection: it binds lazily on first use and pools the bound conn, so
        // there is no connect/bind to do here.
        if self.username.is_none() || self.password.is_none() {
            return Err(LdapError::Auth("no service credentials".into()));
        }
        self.last_auth_time = Some(Instant::now());
        Ok(())
    }

    fn user_filter_by_name(&self, name: &str) -> String {
        self.identity_resolver.lock().unwrap().user_filter_by_name(name)
    }

    /// Strip permission-editor values like `Alice (1000)` down to `1000` or `Alice`.
    /// The field is prefilled "Name (id)", so mid-edit fragments with an unclosed
    /// paren ("Alice (10", "Alice (UID 10", "Alice (") are normalized the same way —
    /// otherwise partial backspace-edits would match nothing.
    pub(crate) fn normalize_editor_search_query(q: Option<&str>) -> Option<String> {
        let s = q.map(str::trim).filter(|s| !s.is_empty())?;
        if let Some(open) = s.rfind('(') {
            let closed = s.ends_with(')');
            let inner = if closed { &s[open + 1..s.len() - 1] } else { &s[open + 1..] }.trim();
            let digits = inner
                .strip_prefix("UID")
                .or_else(|| inner.strip_prefix("uid"))
                .or_else(|| inner.strip_prefix("GID"))
                .or_else(|| inner.strip_prefix("gid"))
                .map(str::trim)
                .unwrap_or(inner);
            let name = s[..open].trim();
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
                return Some(digits.to_string());
            }
            if (closed || digits.is_empty()) && !name.is_empty() {
                return Some(name.to_string());
            }
        }
        Some(s.to_string())
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

    /// Pure: raw resolver rows (id, num, display, dn) → clean list rows.
    /// Drops rows without a numeric id, dedups by id, falls back empty display → id,
    /// sorts by lowercase (display, id).
    fn build_full_rows(raw: Vec<(String, Option<i32>, String, String)>) -> Vec<ListRow> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut rows: Vec<ListRow> = raw
            .into_iter()
            .filter(|(id, num, _, _)| num.is_some() && !id.is_empty())
            .filter(|(id, _, _, _)| seen.insert(id.clone()))
            .map(|(id, num, display, _dn)| {
                let display = if display.is_empty() { id.clone() } else { display };
                (id, num, display)
            })
            .collect();
        rows.sort_by(|a, b| {
            (a.2.to_lowercase(), a.0.to_lowercase()).cmp(&(b.2.to_lowercase(), b.0.to_lowercase()))
        });
        rows
    }

    /// Pure: case-insensitive substring match on id/display plus decimal-substring
    /// match on the numeric id ("300" matches 3002 and 3003); capped at `limit`.
    fn filter_list_rows(rows: &[ListRow], query: &str, limit: usize) -> Vec<ListRow> {
        let q_lower = query.to_lowercase();
        rows.iter()
            .filter(|(id, num, display)| Self::matches_list_query(&q_lower, id, display, *num))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Strict fail-closed mapping of the blocking-task outcome onto a bind
    /// verdict: only a task that ran to completion AND proved the bind is a
    /// success. Anything else (connect failure, bind failure, task panic)
    /// must authenticate as false — never trust the join result alone.
    fn bind_verdict<E>(joined: Result<bool, E>) -> bool {
        joined.unwrap_or(false)
    }

    async fn try_simple_bind(&self, dn: &str, pw: &str) -> bool {
        let uri = self.ldap_uri.clone();
        let settings = self.build_conn_settings();
        let dn = dn.to_string();
        let pw = pw.to_string();

        let joined = tokio::task::spawn_blocking(move || {
            let Ok(mut ldap) = LdapConn::with_settings(settings, &uri) else {
                return false;
            };
            // Best-effort clean TLS shutdown via unbind even on bind failure.
            let bind_ok = ldap.simple_bind(&dn, &pw).ok().and_then(|r| r.success().ok()).is_some();
            let _ = ldap.unbind();
            bind_ok
        })
        .await;
        Self::bind_verdict(joined)
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
        // Direct delegate to shared resolver (caches deduped out of UI). 1 sentence.
        let name_owned = name.to_string();
        let resolved = self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                resolver.resolve_user(&name_owned, bind_dn, bind_pw)
            })
            .await?;

        let (uid, _, display) = resolved;
        Some((uid, display))
    }

    pub async fn resolve_user_dn(&self, name: &str) -> Option<String> {
        let filter = self.user_filter_by_name(name);
        self.fetch_entry_dn(&self.user_base, &filter).await
    }

    // List/resolve (Subtree + shared PosixAttributeMapping).

    pub async fn resolve_group(&self, name: &str) -> Option<(i32, String)> {
        // Delegate to shared resolver (deduped cache). 1 sentence.
        let name_owned = name.to_string();
        self.with_identity(move |resolver, bind_dn, bind_pw| {
            resolver.resolve_group(&name_owned, bind_dn, bind_pw)
        })
        .await
    }

    /// Resolves uidNumber to a user name and fills caches via subtree search.
    pub async fn resolve_user_by_uid(&self, uid: i32) -> Option<(String, String)> {
        // Delegate uid lookup to resolver (caches deduped). 1 sentence.
        let resolved = self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                resolver.resolve_user_by_uid(uid, bind_dn, bind_pw)
            })
            .await?;

        let (id, display) = resolved;
        Some((id, display))
    }

    /// Resolves gidNumber to group name and display_name via subtree search.
    /// Uses dedicated 10m cache.
    pub async fn resolve_group_by_gid(&self, gid: i32) -> Option<(String, String)> {
        // gid cache delegated.
        let resolved = self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                resolver.resolve_group_by_gid(gid, bind_dn, bind_pw)
            })
            .await?;

        let (id, display) = resolved;
        Some((id, display))
    }

    /// Cached full list, or one LDAP fetch (presence filter). `Ok(vec![])` from the
    /// resolver (a genuinely empty directory) IS cached; a fetch error is logged and
    /// returned as `None` without caching, so a transient failure can't poison the TTL.
    async fn full_list_rows(&self, is_user: bool) -> Option<Vec<ListRow>> {
        if let Some(rows) = self.cached_full_list(is_user) {
            return Some(rows);
        }
        self.fetch_and_store_full_list(is_user).await
    }

    /// One presence-filter LDAP fetch (bypassing the cache), stored into the
    /// short-TTL full list. Shared by the cache-miss path and the periodic
    /// refresher; a fetch error is logged and returned as `None` uncached.
    async fn fetch_and_store_full_list(&self, is_user: bool) -> Option<Vec<ListRow>> {
        let raw = self
            .with_identity(move |resolver, bind_dn, bind_pw| {
                let res = if is_user {
                    resolver.search_list_users(bind_dn, bind_pw, FULL_LIST_FETCH_LIMIT)
                } else {
                    resolver.search_list_groups(bind_dn, bind_pw, FULL_LIST_FETCH_LIMIT)
                };
                match res {
                    Ok(rows) => Some(rows),
                    Err(e) => {
                        eprintln!(
                            "LDAP {} list fetch failed: {e}",
                            if is_user { "user" } else { "group" }
                        );
                        None
                    }
                }
            })
            .await?;
        let rows = Self::build_full_rows(raw);
        self.store_full_list(is_user, &rows);
        Some(rows)
    }

    /// Bulk-reload the resolver's identity caches (which keeps the pooled
    /// connection bound — this doubles as a keepalive) and force-refresh the
    /// autocomplete full lists. Returns the resolver's loaded identity count,
    /// or `None` when no service credentials are configured.
    pub async fn refresh_identity_data(&self) -> Option<usize> {
        let loaded = self
            .with_identity(|resolver, bind_dn, bind_pw| {
                Some(resolver.load_full_identities(bind_dn, bind_pw))
            })
            .await?;
        // Repopulate the autocomplete lists; tolerate an individual failure.
        let _ = self.fetch_and_store_full_list(true).await;
        let _ = self.fetch_and_store_full_list(false).await;
        *self.last_full_refresh.lock().unwrap() = Some(Instant::now());
        Some(loaded)
    }

    /// When the last full refresh completed (periodic loop skip-window check).
    pub fn last_full_refresh(&self) -> Option<Instant> {
        *self.last_full_refresh.lock().unwrap()
    }

    /// Autocomplete rows for the permission editor. Queries are matched locally
    /// (case-insensitive name substring + numeric substring) against the cached
    /// full list. `None` = LDAP unavailable; `Some(vec![])` = no match.
    pub async fn list_users(&self, filter: Option<&str>) -> Option<Vec<User>> {
        let q = Self::normalize_editor_search_query(filter).unwrap_or_default();
        let rows = self.full_list_rows(true).await?;
        Some(
            Self::filter_list_rows(&rows, &q, LIST_RESULT_LIMIT)
                .into_iter()
                .map(|(id, uid, display)| User {
                    id,
                    display_name: Some(display),
                    uid_number: uid,
                })
                .collect(),
        )
    }

    pub async fn list_groups(&self, filter: Option<&str>) -> Option<Vec<Group>> {
        let q = Self::normalize_editor_search_query(filter).unwrap_or_default();
        let rows = self.full_list_rows(false).await?;
        Some(
            Self::filter_list_rows(&rows, &q, LIST_RESULT_LIMIT)
                .into_iter()
                .map(|(id, gid, display)| Group {
                    id,
                    display_name: Some(display),
                    gid_number: gid,
                })
                .collect(),
        )
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

    #[tokio::test]
    async fn refresh_identity_data_bulk_loads_cache_offline() {
        // test-support stub: one user + one group, no live LDAP.
        std::env::set_var("TEST_REBULK_POPULATE", "u:testuser1:3002:3000;g:staff:3000");
        let mut client = crate::create_test_lldap();
        client.authenticate("uid=admin,dc=test", "pw").await.unwrap();
        assert_eq!(client.refresh_identity_data().await, Some(1), "one stub user");
        assert!(client.last_full_refresh().is_some(), "refresh must stamp the time");
        // The uid now resolves straight from the cache the bulk load filled.
        let resolved = client.resolve_user_by_uid(3002).await;
        assert_eq!(resolved.map(|(id, _)| id), Some("testuser1".to_string()));
        std::env::remove_var("TEST_REBULK_POPULATE");
    }

    #[test]
    fn stats_expose_bind_count_and_pool_state() {
        // A fresh offline client has never bound and holds no pooled connection.
        let client = crate::create_test_lldap();
        let stats = client.cache_stats_summary();
        assert_eq!(stats.binds, 0, "no binds before any LDAP op");
        assert!(!stats.pool_warm, "no pooled connection before any LDAP op");
    }

    #[test]
    fn clear_cache_keeps_resolver_instance_and_counts_clears() {
        // The pooled connection lives inside the resolver, so clear_cache must
        // empty the caches WITHOUT swapping the resolver Arc (which would drop
        // the pool). Compare the Arc pointer to prove the instance is kept.
        let client = crate::create_test_lldap();
        let before = Arc::as_ptr(&client.identity_resolver);
        client.clear_cache();
        client.clear_cache();
        let after = Arc::as_ptr(&client.identity_resolver);
        assert_eq!(before, after, "clear_cache must not rebuild the resolver");
        assert_eq!(client.cache_stats_summary().clears, 2);
    }

    #[test]
    fn bind_verdict_is_fail_closed() {
        // Regression: `.await.is_ok()` on spawn_blocking once accepted ANY
        // password because the join result is Ok unless the task panicked.
        assert!(LdapClient::bind_verdict::<()>(Ok(true)));
        assert!(!LdapClient::bind_verdict::<()>(Ok(false)));
        assert!(!LdapClient::bind_verdict(Err(())));
    }

    #[test]
    fn matches_list_query_name_and_uid_substring() {
        assert!(LdapClient::matches_list_query("ali", "alice", "Alice Smith", Some(1001)));
        assert!(LdapClient::matches_list_query("100", "bob", "Bob", Some(1001)));
        assert!(!LdapClient::matches_list_query("zzz", "alice", "Alice", Some(1001)));
        assert!(LdapClient::matches_list_query("", "any", "Any", Some(42)));
    }

    #[test]
    fn normalize_editor_search_query_handles_mid_edit_fragments() {
        // Backspace-edits of the "Name (id)" prefill leave an unclosed paren;
        // they must normalize the same way as the closed form.
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("Testuser1 (300")),
            Some("300".into())
        );
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("Test User 2 (UID 30")),
            Some("30".into())
        );
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("admins (GID 3")),
            Some("3".into())
        );
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("Testuser1 (")),
            Some("Testuser1".into())
        );
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("Testuser1 (UID ")),
            Some("Testuser1".into())
        );
        // Non-id paren content without a closing paren stays conservative.
        assert_eq!(
            LdapClient::normalize_editor_search_query(Some("foo (bar")),
            Some("foo (bar".into())
        );
    }

    fn fixture_rows() -> Vec<ListRow> {
        vec![
            ("testuser1".into(), Some(3002), "Testuser1".into()),
            ("testuser2".into(), Some(3003), "Test User 2".into()),
        ]
    }

    #[test]
    fn filter_list_rows_matches_names_and_numeric_substrings() {
        let rows = fixture_rows();
        assert_eq!(LdapClient::filter_list_rows(&rows, "test", 25).len(), 2);
        assert_eq!(LdapClient::filter_list_rows(&rows, "TEST", 25).len(), 2);
        assert_eq!(LdapClient::filter_list_rows(&rows, "300", 25).len(), 2);
        let exact = LdapClient::filter_list_rows(&rows, "3002", 25);
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].0, "testuser1");
        assert_eq!(LdapClient::filter_list_rows(&rows, "", 25).len(), 2);
        assert_eq!(LdapClient::filter_list_rows(&rows, "zzz", 25).len(), 0);
    }

    #[test]
    fn filter_list_rows_caps_at_limit() {
        let rows: Vec<ListRow> = (0..30)
            .map(|i| (format!("user{i}"), Some(1000 + i), format!("User {i}")))
            .collect();
        assert_eq!(LdapClient::filter_list_rows(&rows, "user", 25).len(), 25);
    }

    #[test]
    fn build_full_rows_drops_missing_nums_dedups_and_sorts() {
        let raw = vec![
            ("zed".into(), Some(3), "Zed".into(), "dn3".into()),
            ("noid".into(), None, "No Id".into(), "dn0".into()),
            ("".into(), Some(9), "Empty Id".into(), "dn9".into()),
            ("alice".into(), Some(1), "".into(), "dn1".into()), // empty display -> id
            ("zed".into(), Some(3), "Zed Dup".into(), "dn3b".into()),
        ];
        let rows = LdapClient::build_full_rows(raw);
        assert_eq!(rows.len(), 2, "no-num, empty-id and duplicate rows must drop: {rows:?}");
        assert_eq!(rows[0], ("alice".to_string(), Some(1), "alice".to_string()));
        assert_eq!(rows[1].0, "zed");
        assert_eq!(rows[1].2, "Zed");
    }

    #[test]
    fn prefill_label_roundtrip_selects_exact_user() {
        // Focusing the prefilled "Testuser1 (3002)" field must suggest exactly that user.
        let q = LdapClient::normalize_editor_search_query(Some("Testuser1 (3002)")).unwrap();
        let hits = LdapClient::filter_list_rows(&fixture_rows(), &q, 25);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "testuser1");
    }
}

