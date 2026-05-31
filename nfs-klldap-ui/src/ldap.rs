//! LdapClient (ldap3 + rustls). Shares uri/creds/PosixAttributeMapping with SSSD.
//! Fresh conn per op. All binds use full DN/verbatim identity from sssd section (or env override).

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

    service_conn: Option<LdapConn>,
    username: Option<String>,
    password: Option<String>,
    last_auth_time: Option<Instant>,
    posix_attributes: PosixAttributeMapping,
    no_tls_verify: bool,
    start_tls: bool,
    ldap_tls_cacert: Option<String>,
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

    // connection settings (sync ldap3)

    fn build_conn_settings(&self) -> LdapConnSettings {
        let mut s = LdapConnSettings::new();
        if self.start_tls {
            s = s.set_starttls(true);
        }
        if self.no_tls_verify {
            s = s.set_no_tls_verify(true);
            return s;
        }
        // Verify path: let ldap3 use its native-certs default unless a custom
        // CA bundle is supplied (layered on top of native roots).
        if let Some(ref path) = self.ldap_tls_cacert {
            match std::fs::read_to_string(path) {
                Ok(ca_pem) => {
                    let native = rustls_native_certs::load_native_certs();
                    let mut root_store = RootCertStore::empty();
                    for c in native.certs {
                        let _ = root_store.add(c);
                    }
                    let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
                    for cert in rustls_pemfile::certs(&mut cursor).flatten() {
                        let _ = root_store.add(cert);
                    }
                    if !root_store.is_empty() {
                        let cfg = ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_no_client_auth();
                        s = s.set_config(Arc::new(cfg));
                    } else {
                        eprintln!(
                            "WARNING: ldap_tls_cacert={} produced no usable certificates (native + custom). \
                             LDAPS verification may fail and cause handshake aborts (visible as 'tls handshake eof' on the server).",
                            path
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "WARNING: ldap_tls_cacert={} is configured but unreadable ({}). \
                         Outbound LDAPS will either fall back to native roots (may cause verify failures) \
                         or succeed only if no_tls_verify/reqcert=never. This is a common source of \
                         WebUI 'connection closed' symptoms and server-side LDAPS handshake errors.",
                        path, e
                    );
                }
            }
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

                    // Always attempt unbind() for any successfully connected LDAPS/TLS
                    // session (even on later bind/search failure). This sends an UnbindRequest
                    // and allows the rustls layer to perform a clean close_notify shutdown.
                    // Dropping without it is a common source of "[LDAPS] Service Error: tls
                    // handshake eof" / "peer closed without close_notify" noise on strict
                    // rustls-based servers (klldap, etc.) from both this client and external
                    // tools.
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

            // Always attempt unbind() after a successful TCP+TLS connection (even if the
            // bind itself is rejected, e.g. wrong password or bare DN). Prevents the abrupt
            // socket drop that surfaces as "tls handshake eof" / no-close_notify errors on
            // the LDAPS server.
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
        self.service_conn = None; // force fresh
        self.get_or_bind_service().await?;
        Ok(())
    }

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

    // list/resolve (Subtree + shared PosixAttributeMapping)

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

        let _ = users.first().map(|u| u.dn.len());
        users
    }

    pub async fn list_groups(&self, filter: Option<&str>) -> Vec<Group> {
        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let name_attr = self.posix_attributes.group_name.clone();
        let obj = self.posix_attributes.group_object_class.clone();

        let ldap_filter = if let Some(f) = filter.filter(|s| !s.trim().is_empty()) {
            let esc = Self::escape_filter_value(f);
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

        let _ = groups.first().map(|g| g.dn.len());
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

    pub async fn user_is_member_of_group(&self, username: &str, group_name: &str) -> bool {
        self.user_is_member_of(username, group_name).await
    }

    async fn user_is_member_of(&self, username: &str, group_name: &str) -> bool {
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
