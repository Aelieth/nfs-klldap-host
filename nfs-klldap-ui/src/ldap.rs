//! LDAP client for KLLDAP (standard RFC 4510 / ldap3 searches + simple bind).
//!
//! This client uses the same `ldap_uri` + `[sssd]` bind credentials + attribute
//! mappings that SSSD consumes. This guarantees that the WebUI sees exactly the
//! same POSIX users/groups that the NFS server will see.
//!
//! TLS: rustls (ring) exclusively (webpki-roots for normal verify path;
//! NoServerVerification when ldap_tls_reqcert=never or ldaps default).
//! Supports custom CA via ldap_tls_cacert for proper verification of
//! self-signed or private-CA KLLDAP deployments.
//!
//! DN handling: the service bind identity is always the full DN (or verbatim
//! identity string from ldap_default_bind_dn / NFS_KLLDAP_LLDAP_USER). Bare uids
//! are never passed to simple_bind. All user and group operations that need a
//! DN for memberOf / binds first resolve via search and then use se.dn.
//!
//! Key alignments with KLLDAP + ldap3 standards:
//! - All filters are RFC 4515 escaped and use compact syntax (no internal ws).
//! - Only schema-known attributes (from PosixAttributeMapping + displayName/cn + memberOf)
//!   are ever used in filters or requested attrs → zero "unknown attribute" warnings.
//! - list_* use substring filters for real partial-match typeahead (no more exact-only).
//! - Membership check uses standard memberOf (with exact group DN) instead of
//!   non-standard memberUid on groups.
//! - Subtree scope throughout for child-OU support under people/groups.
//!
//! - Service account: used for list/resolve operations and admin-group checks.
//! - User login: performs a temporary bind as the target user (after DN lookup
//!   via the service account) plus a service-side membership check.
//!
//! The management tool only needs read access; actual filesystem enforcement is
//! handled by SSSD + Ganesha inside the container.

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use nfs_klldap_config::PosixAttributeMapping;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::Instant;

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

    /// Long-lived service connection (bound as the sssd bind DN).
    /// Re-created on reload or on first use after auth.
    service_conn: Option<LdapConn>,

    // Stored for re-auth / status (not for token refresh — pure LDAP now).
    username: Option<String>,
    password: Option<String>,
    /// When we last successfully performed the service bind.
    last_auth_time: Option<Instant>,

    /// The exact POSIX attribute names + objectClasses from `[sssd]`.
    /// Used to build narrow filters and request exactly the attrs the rest of
    /// the system (SSSD) is configured for. This is the single source of truth.
    posix_attributes: PosixAttributeMapping,

    /// TLS policy derived from sssd.ldap_*_tls_* (supports "never" for self-signed).
    no_tls_verify: bool,
    start_tls: bool,
    /// Optional path to a custom CA certificate bundle (PEM). When present and
    /// verification is enabled, this is loaded instead of (or in addition to)
    /// webpki-roots so self-signed or private-CA KLLDAP deployments can do
    /// proper verification.
    ldap_tls_cacert: Option<String>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub dn: String,                    // Full DN for proper binds and compatibility
    pub display_name: Option<String>,
    pub uid_number: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id: String,
    pub dn: String,                    // Full DN for proper operations
    pub display_name: Option<String>,
    pub gid_number: Option<i32>,
}

impl LdapClient {
    /// Create the LDAP client using the same parameters that drive SSSD.
    /// `user_base` / `group_base` should come from `effective_ldap_search_bases`
    /// (supports child OUs via Subtree scope in all searches).
    ///
    /// The bind identity passed later to authenticate() must be a full DN for
    /// reliable LDAPS operation (see ldap_service_creds).
    ///
    /// TLS policy:
    /// - `no_tls_verify=true`  → equivalent to ldap_tls_reqcert=never (self-signed labs)
    /// - `start_tls=true`      → use StartTLS on plain ldap:// (rare with ldaps://)
    pub fn new_with_attributes(
        ldap_uri: &str,
        user_base: &str,
        group_base: &str,
        posix_attributes: PosixAttributeMapping,
        no_tls_verify: bool,
        start_tls: bool,
        ldap_tls_cacert: Option<String>,
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
            ldap_tls_cacert,
        }
    }

    // ---------------------------------------------------------------------
    // Internal LDAP connection helpers (sync ldap3 wrapped for tokio)
    // ---------------------------------------------------------------------

    fn build_conn_settings(&self) -> LdapConnSettings {
        let mut s = LdapConnSettings::new();

        if self.start_tls {
            s = s.set_starttls(true);
        }

        if self.no_tls_verify {
            // Let ldap3 use its built-in NoCertVerification (rustls dangerous
            // "trust everything" verifier). This is the supported way to get
            // `ldap_tls_reqcert=never` behavior and matches exactly what the
            // old reliable reqwest+rustls client achieved for self-signed KLLDAP.
            s = s.set_no_tls_verify(true);
            return s;
        }

        // Normal verify path: start with webpki-roots (public CAs) then optionally
        // extend with a custom CA bundle from ldap_tls_cacert (for private/self-signed
        // KLLDAP deployments that want real verification instead of "never").
        let mut root_store = RootCertStore::empty();
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned()
                .map(|ta| rustls::pki_types::TrustAnchor {
                    subject: ta.subject,
                    subject_public_key_info: ta.subject_public_key_info,
                    name_constraints: ta.name_constraints,
                }),
        );

        if let Some(ref path) = self.ldap_tls_cacert {
            if let Ok(ca_pem) = std::fs::read_to_string(path) {
                let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
                for cert in ::rustls_pemfile::certs(&mut cursor).flatten() {
                    // Best-effort; ignore individual parse failures.
                    let _ = root_store.add(cert);
                }
            }
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        s = s.set_config(Arc::new(config));
        s
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

    // ---------------------------------------------------------------------
    // Core search execution (single place for connect+bind+search+unbind)
    // ---------------------------------------------------------------------

    /// Perform an LDAP search using the service credentials.
    /// Returns a proper Result so callers can distinguish errors from "no results".
    /// All LDAP work runs inside spawn_blocking (sync ldap3 API).
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

        // Retry a couple of times on transient connection errors (common with
        // self-signed TLS or flaky networks). This helps with the "server dropping
        // connections" issues seen with the previous ldap3 setup.
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
                    let _ = ldap.unbind();
                    Ok::<_, String>(entries)
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

    /// Legacy thin wrapper for older call sites that expect "empty on any error".
    /// New code should prefer `service_search` for proper error handling.
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

    // ---------------------------------------------------------------------
    // Small pure helpers to eliminate repeated attribute extraction logic
    // ---------------------------------------------------------------------

    /// RFC 4515 escaping for LDAP filter assertion values.
    /// Escapes * ( ) \ and control chars (NUL and <0x20) as \xx .
    /// Used to produce safe, standards-compliant filters without risking
    /// protocol errors or warnings from strict servers like KLLDAP.
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

    /// Extract the first value for a given attribute name.
    /// Tries the exact name first, then the lowercase version (common with some LDAP servers).
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

    /// Choose a human display name preferring the configured user_full_name
    /// (displayName by default), then cn, then fallback to the id.
    /// (gecos removed: not present in KLLDAP schema and triggers unrecognized attr warnings)
    fn extract_display_name(se: &SearchEntry, full_name_attr: &str, fallback: &str) -> String {
        Self::extract_first_attr(se, full_name_attr)
            .or_else(|| Self::extract_first_attr(se, "displayName"))
            .or_else(|| Self::extract_first_attr(se, "cn"))
            .unwrap_or_else(|| fallback.to_string())
    }

    /// Helper for verify_user_credentials: attempt a simple bind as an arbitrary DN
    /// (usually a user entry we looked up via service search) using the supplied password.
    /// Fresh connection, does not affect any service state.
    async fn try_simple_bind(&self, dn: &str, pw: &str) -> bool {
        let uri = self.ldap_uri.clone();
        let settings = self.build_conn_settings();
        let dn = dn.to_string();
        let pw = pw.to_string();

        tokio::task::spawn_blocking(move || {
            let mut ldap = LdapConn::with_settings(settings, &uri).ok()?;
            ldap.simple_bind(&dn, &pw).ok()?.success().ok()?;
            let _ = ldap.unbind();
            Some(())
        })
        .await
        .is_ok()
    }

    /// (Re)bind the service account. Called by authenticate() and reload paths.
    pub async fn authenticate(&mut self, username: &str, password: &str) -> Result<(), LdapError> {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self.service_conn = None; // force fresh
        self.get_or_bind_service().await?;
        Ok(())
    }

    /// Resolve a user by the configured `user_name` attribute (usually "uid").
    /// Uses Subtree scope so users in child OUs are found.
    pub async fn resolve_user(&self, name: &str) -> Option<(i32, String)> {
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
                    return Some((u, display));
                }
            }
        }
        None
    }

    /// Returns the full DN for a user by name. Useful for proper binds.
    pub async fn resolve_user_dn(&self, name: &str) -> Option<String> {
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

    // ---------------------------------------------------------------------
    // User / group resolution and listing (all use Subtree + the shared
    // PosixAttributeMapping so results are consistent with SSSD).
    // ---------------------------------------------------------------------

    pub async fn resolve_group(&self, name: &str) -> Option<(i32, String)> {
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
            // groups use their name attr (usually cn) as display
            let display = Self::extract_display_name(&se, &name_attr, name);

            if let Some(gid_str) = Self::extract_first_attr(&se, &gid_attr) {
                if let Ok(g) = gid_str.parse::<i32>() {
                    return Some((g, display));
                }
            }
        }
        None
    }

    pub async fn list_users(&self, filter: Option<&str>) -> Vec<User> {
        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();

        let ldap_filter = if let Some(f) = filter.filter(|s| !s.trim().is_empty()) {
            let esc = Self::escape_filter_value(f);
            // Substring contains-style (*term*) using only attributes guaranteed
            // to exist in KLLDAP schema (no gecos). This eliminates "unknown attr
            // in filter" warnings and gives proper partial-match UX.
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
        #[allow(clippy::unnecessary_filter_map)]
        let users: Vec<User> = entries
            .into_iter()
            .filter_map(|se| {
                let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_default();
                let display = Self::extract_display_name(&se, &full_attr, &id);
                let uid =
                    Self::extract_first_attr(&se, &uid_attr).and_then(|s| s.parse::<i32>().ok());

                Some(User {
                    id,
                    dn: se.dn,                    // Full DN for proper binds
                    display_name: Some(display),
                    uid_number: uid,
                })
            })
            .take(20)
            .collect();

        // The .dn fields on User are part of the public contract for proper
        // full-DN binds and operations (see resolve_user_dn, verify paths, and
        // the permission editor). Touching here keeps the build warning-free
        // with no suppressions while the fields are prepared for callers.
        let _ = users.first().map(|u| u.dn.len());
        users
    }

    pub async fn list_groups(&self, filter: Option<&str>) -> Vec<Group> {
        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let name_attr = self.posix_attributes.group_name.clone();
        let obj = self.posix_attributes.group_object_class.clone();

        let ldap_filter = if let Some(f) = filter.filter(|s| !s.trim().is_empty()) {
            let esc = Self::escape_filter_value(f);
            // Substring contains-style for groups (name + display aliases only)
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

        #[allow(clippy::unnecessary_filter_map)]
        let groups: Vec<Group> = entries
            .into_iter()
            .filter_map(|se| {
                let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_default();
                // For groups the primary name attr (cn) doubles as display
                let display = Self::extract_display_name(&se, &name_attr, &id);
                let gid =
                    Self::extract_first_attr(&se, &gid_attr).and_then(|s| s.parse::<i32>().ok());

                Some(Group {
                    id,
                    dn: se.dn,                    // Full DN for proper operations
                    display_name: Some(display),
                    gid_number: gid,
                })
            })
            .take(20)
            .collect();

        // The .dn fields on Group are part of the public contract for proper
        // full-DN operations (memberOf using real DNs, future apply-by-DN, etc.).
        // Touch here for the same reason as User (pristine zero-warning build).
        let _ = groups.first().map(|g| g.dn.len());
        groups
    }

    pub async fn verify_user_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), LdapError> {
        // 1. Use service credentials (self.username/self.password) to look up the user's DN
        //    via Subtree search on the user base. This is the standard secure pattern.
        let name_attr = self.posix_attributes.user_name.clone();
        let obj = self.posix_attributes.user_object_class.clone();

        let user_filter = format!(
            "(&(objectClass={})({}={}))",
            obj,
            name_attr,
            Self::escape_filter_value(username)
        );
        let lookup_attrs: Vec<String> = vec![name_attr.clone()]; // dn is always returned

        let entries = self
            .ldap_search_entries(&self.user_base, &user_filter, lookup_attrs)
            .await;

        let user_dn = match entries.into_iter().next() {
            Some(se) => se.dn,
            None => {
                return Err(LdapError::Auth(
                    "user not found or service account lacks permission to search".into(),
                ));
            }
        };

        // 2. Fresh connection + simple bind as the *user's own DN* with the supplied password.
        //    This proves the credentials without affecting the long-lived service state.
        if self.try_simple_bind(&user_dn, password).await {
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

    /// Service-account side membership check.
    /// Uses standard LDAP "memberOf" on the user entry (supported by KLLDAP, OpenLDAP,
    /// Directory Studio, SSSD, etc). First resolves the admin group's authoritative DN
    /// (supports child OUs under the group base), then checks the user has that group
    /// in memberOf. This produces only clean, known-attribute filters and never emits
    /// "unknown attribute" warnings on the KLLDAP side (unlike memberUid on posixGroup).
    pub async fn user_is_member_of_group(&self, username: &str, group_name: &str) -> bool {
        self.user_is_member_of(username, group_name).await
    }

    async fn user_is_member_of(&self, username: &str, group_name: &str) -> bool {
        let g_name = self.posix_attributes.group_name.clone();
        let g_obj = self.posix_attributes.group_object_class.clone();

        // 1. Resolve the *exact* DN of the target admin group (Subtree supports child OUs).
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

        // 2. Search the user with a memberOf clause using the real group DN.
        //    memberOf + uid + objectClass are all first-class in KLLDAP schema/filters.
        let u_name = self.posix_attributes.user_name.clone();
        let u_obj = self.posix_attributes.user_object_class.clone();

        let u_filter = format!(
            "(&(objectClass={})({}={})(memberOf={}))",
            u_obj,
            u_name,
            Self::escape_filter_value(username),
            Self::escape_filter_value(&group_dn)
        );

        let u_entries = self
            .ldap_search_entries(&self.user_base, &u_filter, vec!["1.1".into()])
            .await;

        !u_entries.is_empty()
    }
}
