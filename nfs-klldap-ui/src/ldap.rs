//! LDAP client for KLLDAP/LLDAP (standard RFC 4510 searches + simple bind).
//!
//! This client uses the same `ldap_uri` + `[sssd]` bind credentials + attribute
//! mappings that SSSD consumes. This guarantees that the WebUI sees exactly the
//! same POSIX users/groups that the NFS server will see.
//!
//! - Service account: used for list/resolve operations and admin-group checks.
//! - User login: performs a temporary bind as the target user (after DN lookup
//!   via the service account) plus a service-side membership check.
//! - All searches use Subtree scope (supports child OUs under ou=people/ou=groups).
//!
//! The management tool only needs read access; actual filesystem enforcement is
//! handled by SSSD + Ganesha inside the container.

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use nfs_klldap_config::PosixAttributeMapping;
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

impl LdapClient {
    /// Create the LDAP client using the same parameters that drive SSSD.
    /// `user_base` / `group_base` should come from `effective_ldap_search_bases`
    /// (supports child OUs via Subtree scope in all searches).
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
        }
    }

    // ---------------------------------------------------------------------
    // Internal LDAP connection helpers (sync ldap3 wrapped for tokio)
    // ---------------------------------------------------------------------

    fn build_conn_settings(&self) -> LdapConnSettings {
        let mut s = LdapConnSettings::new();
        if self.no_tls_verify {
            // Equivalent to LDAPTLS_REQCERT=never used in the startup probe
            s = s.set_no_tls_verify(true);
        }
        if self.start_tls {
            s = s.set_starttls(true);
        }
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

        tokio::task::spawn_blocking(move || {
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
        })
        .await
        .map_err(|e| LdapError::Network(format!("spawn_blocking join error: {}", e)))?
        .map_err(LdapError::Ldap)
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

    /// Choose a human display name preferring displayName, then cn, then gecos, then fallback.
    fn extract_display_name(se: &SearchEntry, fallback: &str) -> String {
        Self::extract_first_attr(se, "displayName")
            .or_else(|| Self::extract_first_attr(se, "cn"))
            .or_else(|| Self::extract_first_attr(se, "gecos"))
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

        let filter = format!("(& (objectClass={}) ({}={}))", obj, name_attr, name);
        let attrs: Vec<String> = vec![
            name_attr.clone(),
            uid_attr.clone(),
            "cn".into(),
            "displayName".into(),
            "gecos".into(),
        ];

        let entries = match self.service_search(&self.user_base, &filter, attrs).await {
            Ok(e) => e,
            Err(_) => return None,
        };

        for se in entries {
            let display = Self::extract_display_name(&se, name);

            if let Some(uid_str) = Self::extract_first_attr(&se, &uid_attr) {
                if let Ok(u) = uid_str.parse::<i32>() {
                    return Some((u, display));
                }
            }
        }
        None
    }

    // ---------------------------------------------------------------------
    // User / group resolution and listing (all use Subtree + the shared
    // PosixAttributeMapping so results are consistent with SSSD).
    // ---------------------------------------------------------------------

    pub async fn resolve_group(&self, name: &str) -> Option<(i32, String)> {
        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let name_attr = self.posix_attributes.group_name.clone();
        let obj = self.posix_attributes.group_object_class.clone();

        let filter = format!("(& (objectClass={}) ({}={}))", obj, name_attr, name);
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
            let display = Self::extract_display_name(&se, name);

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
            // Contains-style on login name + common display attrs (Subtree will catch child OUs)
            format!(
                "(& (objectClass={}) (| ({}={}) (cn={}) (displayName={}) (gecos={}) ))",
                obj, name_attr, f, f, f, f
            )
        } else {
            format!("(objectClass={})", obj)
        };

        let attrs: Vec<String> = vec![
            name_attr.clone(),
            uid_attr.clone(),
            "cn".into(),
            "displayName".into(),
            "gecos".into(),
        ];

        let entries = self
            .ldap_search_entries(&self.user_base, &ldap_filter, attrs)
            .await;

        #[allow(clippy::unnecessary_filter_map)]
        let users: Vec<User> = entries
            .into_iter()
            .filter_map(|se| {
                let id = Self::extract_first_attr(&se, &name_attr).unwrap_or_default();
                let display = Self::extract_display_name(&se, &id);
                let uid = Self::extract_first_attr(&se, &uid_attr)
                    .and_then(|s| s.parse::<i32>().ok());

                Some(User {
                    id,
                    display_name: Some(display),
                    uid_number: uid,
                })
            })
            .take(20)
            .collect();
        users
    }

    pub async fn list_groups(&self, filter: Option<&str>) -> Vec<Group> {
        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let name_attr = self.posix_attributes.group_name.clone();
        let obj = self.posix_attributes.group_object_class.clone();

        let ldap_filter = if let Some(f) = filter.filter(|s| !s.trim().is_empty()) {
            format!(
                "(& (objectClass={}) (| ({}={}) (cn={}) (displayName={}) ))",
                obj, name_attr, f, f, f
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
                let display = Self::extract_display_name(&se, &id);
                let gid = Self::extract_first_attr(&se, &gid_attr)
                    .and_then(|s| s.parse::<i32>().ok());

                Some(Group {
                    id,
                    display_name: Some(display),
                    gid_number: gid,
                })
            })
            .take(20)
            .collect();
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

        let user_filter = format!("(& (objectClass={}) ({}={}))", obj, name_attr, username);
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
    /// Searches the group tree (Subtree) for an entry matching the admin group that lists
    /// the username in the mapped `group_member` attribute (e.g. memberUid).
    /// Used for the webui_admin_group check during login.
    pub async fn user_is_member_of_group(&self, username: &str, group_name: &str) -> bool {
        self.user_is_member_of(username, group_name).await
    }

    async fn user_is_member_of(&self, username: &str, group_name: &str) -> bool {
        let g_name = self.posix_attributes.group_name.clone();
        let g_obj = self.posix_attributes.group_object_class.clone();
        let g_member = self.posix_attributes.group_member.clone();

        let filter = format!(
            "(& (objectClass={}) ({}={}) ({}={}) )",
            g_obj, g_name, group_name, g_member, username
        );

        let entries = self
            .ldap_search_entries(&self.group_base, &filter, vec!["cn".into()])
            .await;

        !entries.is_empty()
    }
}
