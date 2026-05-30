//! LLDAP / KLLDAP client (GraphQL for queries, /auth/simple/login for auth).
//!
//! Supports the custom fork at github.com/Aelieth/lldap-with-kerberos
//! which has a more robust LDAP backend and built-in POSIX attributes.
//!
//! Login always uses the documented REST endpoint POST /auth/simple/login
//! (returning {token, refreshToken}). Queries and group membership checks use
//! the GraphQL API at /api/graphql with Bearer tokens.
//!
//! The management tool runs unprivileged and only needs read access to users/groups
//! (SSSD in the NFS container handles the actual POSIX directory permissions).

use nfs_klldap_config::PosixAttributeMapping;
use reqwest::Client;
use serde::Deserialize;
use std::time::Instant;

#[derive(Debug)]
pub enum LldapError {
    Network(String),
    Auth(String),
    Parse(String),
    GraphQL(String),
}

impl std::fmt::Display for LldapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LldapError::Network(e) => write!(f, "Network error: {}", e),
            LldapError::Auth(e) => write!(f, "Authentication error: {}", e),
            LldapError::Parse(e) => write!(f, "Parse error: {}", e),
            LldapError::GraphQL(e) => write!(f, "GraphQL error: {}", e),
        }
    }
}

impl std::error::Error for LldapError {}

#[derive(Debug, Clone)]
pub struct LldapClient {
    client: Client,
    graphql_url: String,
    /// Derived REST login endpoint (POST {username,password} → {token, refreshToken})
    login_url: String,
    auth_token: Option<String>,
    // Stored for automatic token refresh on 401
    username: Option<String>,
    password: Option<String>,
    /// When we last successfully authenticated (or refreshed) against LLDAP/KLLDAP.
    /// Used by the WebUI to detect stale credentials after the operator edits
    /// sssd.ldap_default_bind_* or management.lldap_graphql_url.
    last_auth_time: Option<Instant>,

    /// The exact POSIX attribute names the admin declared in `[sssd]` of nfs-klldap.conf.
    /// The client must only ever request these attributes (plus id/displayName) from LLDAP.
    /// This is the key mechanism to avoid pulling hundreds of unrelated attributes
    /// (krb*, shadow*, userAccountControl, etc.) that trigger log spam on the LLDAP side.
    posix_attributes: PosixAttributeMapping,
}

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "uidNumber")]
    pub uid_number: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "gidNumber")]
    pub gid_number: Option<i32>,
}

#[derive(Deserialize)]
struct GraphQLResponse<T> {
    data: T,
}

/// Derive the LLDAP / KLLDAP simple-login REST endpoint from whatever GraphQL URL
/// was provided (explicit override or our derived one).
/// Handles common shapes: .../api/graphql , .../graphql , or a bare base URL.
fn derive_login_url(graphql_url: &str) -> String {
    let trimmed = graphql_url.trim_end_matches('/');
    if let Some(base) = trimmed.strip_suffix("/api/graphql") {
        format!("{}/auth/simple/login", base)
    } else if let Some(base) = trimmed.strip_suffix("/graphql") {
        format!("{}/auth/simple/login", base)
    } else {
        // Treat the provided value as the management base (e.g. "http://host:17170")
        format!("{}/auth/simple/login", trimmed)
    }
}

impl LldapClient {
    /// Create a client that will only ever request the exact POSIX attributes
    /// the administrator declared in their `[sssd]` section (passed in via the mapping).
    /// This is the preferred (and now only) constructor from the WebUI.
    pub fn new_with_attributes(graphql_url: &str, posix_attributes: PosixAttributeMapping) -> Self {
        let login_url = derive_login_url(graphql_url);
        Self {
            client: Client::new(),
            graphql_url: graphql_url.to_string(),
            login_url,
            auth_token: None,
            username: None,
            password: None,
            last_auth_time: None,
            posix_attributes,
        }
    }

    /// Authenticate against KLLDAP / LLDAP using username + password.
    /// Uses the dedicated /auth/simple/login REST endpoint (not the GraphQL login mutation).
    /// Stores credentials for automatic token refresh on 401 during later queries.
    /// Works with the Kerberos-integrated fork as well as upstream LLDAP.
    pub async fn authenticate(&mut self, username: &str, password: &str) -> Result<(), LldapError> {
        let token = self._simple_login(username, password).await?;
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self.auth_token = Some(token);
        self.last_auth_time = Some(Instant::now());
        Ok(())
    }

    /// Low-level call to LLDAP's REST login endpoint. Does not mutate stored token/creds.
    async fn _simple_login(&self, username: &str, password: &str) -> Result<String, LldapError> {
        let body = serde_json::json!({
            "username": username,
            "password": password
        });

        let response = self
            .client
            .post(&self.login_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| LldapError::Network(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(LldapError::Auth(format!(
                "login failed: {} - {}",
                status, text
            )));
        }

        let v: serde_json::Value = response
            .json()
            .await
            .map_err(|e| LldapError::Parse(e.to_string()))?;

        // LLDAP returns { "token": "...", "refreshToken": "..." }
        if let Some(tok) = v.get("token").and_then(|t| t.as_str()) {
            if !tok.trim().is_empty() {
                return Ok(tok.to_string());
            }
        }
        // Some setups or future versions might return bare token string
        if let Some(tok) = v.as_str() {
            if !tok.trim().is_empty() {
                return Ok(tok.to_string());
            }
        }
        Err(LldapError::Auth(
            "no token field in /auth/simple/login response".into(),
        ))
    }

    fn auth_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = &self.auth_token {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", token).parse().unwrap(),
            );
        }
        headers
    }

    /// Internal helper to run a GraphQL query with auth.
    /// Automatically refreshes the token on 401 if credentials are available.
    async fn run_query<T: for<'de> Deserialize<'de>>(
        &mut self,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> Result<T, LldapError> {
        // Try once
        let first_result = self._execute_query::<T>(query, variables.clone()).await;

        match first_result {
            Ok(data) => Ok(data),
            Err(LldapError::Auth(_)) => {
                // Attempt refresh if we have credentials
                if let (Some(user), Some(pass)) = (self.username.clone(), self.password.clone()) {
                    match self._simple_login(&user, &pass).await {
                        Ok(token) => {
                            self.auth_token = Some(token);
                            self.last_auth_time = Some(Instant::now());
                            // Retry once after refresh
                            self._execute_query::<T>(query, variables).await
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    Err(LldapError::Auth(
                        "Token expired and no credentials for refresh".into(),
                    ))
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn _execute_query<T: for<'de> Deserialize<'de>>(
        &self,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> Result<T, LldapError> {
        let body = if let Some(vars) = variables {
            serde_json::json!({ "query": query, "variables": vars })
        } else {
            serde_json::json!({ "query": query })
        };

        let response = self
            .client
            .post(&self.graphql_url)
            .headers(self.auth_headers())
            .json(&body)
            .send()
            .await
            .map_err(|e| LldapError::Network(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            if status.as_u16() == 401 {
                return Err(LldapError::Auth(
                    "Unauthorized (token may be expired)".into(),
                ));
            }
            return Err(LldapError::GraphQL(format!("{} - {}", status, text)));
        }

        let graphql_resp: GraphQLResponse<T> = response
            .json()
            .await
            .map_err(|e| LldapError::Parse(e.to_string()))?;

        Ok(graphql_resp.data)
    }

    /// Resolve a user name to (uidNumber, display name).
    ///
    /// Only requests the single specific attribute declared by the admin in
    /// [sssd] ldap_user_uid_number. No other attributes are ever queried.
    pub async fn resolve_user(&mut self, name: &str) -> Option<(i32, String)> {
        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let alias = uid_attr.replace(|c: char| !c.is_alphanumeric() && c != '_', "_");

        // Request ONLY the exact POSIX attribute the admin configured.
        let query = format!(
            r#"
            query($userId: String!) {{
                user(userId: $userId) {{
                    id
                    displayName
                    {alias}: attribute(name: "{attr}") {{
                        value
                    }}
                }}
            }}
            "#,
            alias = alias,
            attr = uid_attr
        );

        let variables = serde_json::json!({ "userId": name });

        let data: serde_json::Value = self.run_query(&query, Some(variables)).await.ok()?;

        let user = data.get("user")?;
        let display = user
            .get("displayName")
            .and_then(|v| v.as_str())
            .unwrap_or(name)
            .to_string();

        let uid = user
            .get(&uid_attr)
            .or_else(|| user.get(&alias))
            .and_then(|a| a.get("value"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i32>().ok());

        uid.map(|u| (u, display))
    }

    /// Resolve a group name to (gidNumber, display name)
    ///
    /// Only requests the single specific attribute declared by the admin in
    /// [sssd] ldap_group_gid_number. No other attributes are ever queried.
    pub async fn resolve_group(&mut self, name: &str) -> Option<(i32, String)> {
        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let alias = gid_attr.replace(|c: char| !c.is_alphanumeric() && c != '_', "_");

        let query = format!(
            r#"
            query($groupId: String!) {{
                group(groupId: $groupId) {{
                    id
                    displayName
                    {alias}: attribute(name: "{attr}") {{
                        value
                    }}
                }}
            }}
            "#,
            alias = alias,
            attr = gid_attr
        );

        let variables = serde_json::json!({ "groupId": name });

        let data: serde_json::Value = self.run_query(&query, Some(variables)).await.ok()?;

        let group = data.get("group")?;
        let display = group
            .get("displayName")
            .and_then(|v| v.as_str())
            .unwrap_or(name)
            .to_string();

        let gid = group
            .get(&gid_attr)
            .or_else(|| group.get(&alias))
            .and_then(|a| a.get("value"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i32>().ok());

        gid.map(|g| (g, display))
    }

    /// List users (with optional filter). Returns POSIX-aware results.
    ///
    /// This version uses the server-side `users(where: RequestFilter)` resolver
    /// when a search term is provided, instead of fetching the entire directory
    /// and filtering client-side. This significantly reduces load and attribute
    /// processing on the LLDAP side.
    pub async fn list_users(&mut self, filter: Option<&str>) -> Vec<User> {
        let uid_attr = self.posix_attributes.user_uid_number.clone();
        let alias = uid_attr.replace(|c: char| !c.is_alphanumeric() && c != '_', "_");

        let (query, variables) = if let Some(f) = filter {
            let q = format!(
                r#"
                query($where: RequestFilter) {{
                    users(where: $where) {{
                        id
                        displayName
                        {alias}: attribute(name: "{attr}") {{
                            value
                        }}
                    }}
                }}
                "#,
                alias = alias,
                attr = uid_attr
            );

            let vars = serde_json::json!({
                "where": {
                    "or": [
                        { "id": { "contains": f } },
                        { "displayName": { "contains": f } }
                    ]
                }
            });

            (q, Some(vars))
        } else {
            let q = format!(
                r#"
                query {{
                    users {{
                        id
                        displayName
                        {alias}: attribute(name: "{attr}") {{
                            value
                        }}
                    }}
                }}
                "#,
                alias = alias,
                attr = uid_attr
            );
            (q, None)
        };

        let data: serde_json::Value = match self.run_query(&query, variables).await {
            Ok(d) => d,
            Err(_) => return vec![],
        };

        let users = data.get("users").and_then(|u| u.as_array()).cloned().unwrap_or_default();

        users
            .into_iter()
            .filter_map(|u| {
                let id = u.get("id")?.as_str()?.to_string();
                let display = u.get("displayName")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&id)
                    .to_string();

                let uid = u.get(&alias)
                    .or_else(|| u.get(&uid_attr))
                    .and_then(|a| a.get("value"))
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i32>().ok());

                Some(User {
                    id,
                    display_name: Some(display),
                    uid_number: uid,
                })
            })
            .collect()
    }

    /// List groups (with optional filter).
    ///
    /// Uses server-side filtering via the GraphQL `groups` / `groups(where:)` capability
    /// when a search term is provided.
    pub async fn list_groups(&mut self, filter: Option<&str>) -> Vec<Group> {
        let gid_attr = self.posix_attributes.group_gid_number.clone();
        let alias = gid_attr.replace(|c: char| !c.is_alphanumeric() && c != '_', "_");

        let (query, variables) = if let Some(f) = filter {
            let q = format!(
                r#"
                query($where: RequestFilter) {{
                    groups(where: $where) {{
                        id
                        displayName
                        {alias}: attribute(name: "{attr}") {{
                            value
                        }}
                    }}
                }}
                "#,
                alias = alias,
                attr = gid_attr
            );

            let vars = serde_json::json!({
                "where": {
                    "or": [
                        { "id": { "contains": f } },
                        { "displayName": { "contains": f } }
                    ]
                }
            });

            (q, Some(vars))
        } else {
            let q = format!(
                r#"
                query {{
                    groups {{
                        id
                        displayName
                        {alias}: attribute(name: "{attr}") {{
                            value
                        }}
                    }}
                }}
                "#,
                alias = alias,
                attr = gid_attr
            );
            (q, None)
        };

        let data: serde_json::Value = match self.run_query(&query, variables).await {
            Ok(d) => d,
            Err(_) => return vec![],
        };

        let groups = data.get("groups").and_then(|g| g.as_array()).cloned().unwrap_or_default();

        groups
            .into_iter()
            .filter_map(|g| {
                let id = g.get("id")?.as_str()?.to_string();
                let display = g.get("displayName")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&id)
                    .to_string();

                let gid = g.get(&alias)
                    .or_else(|| g.get(&gid_attr))
                    .and_then(|a| a.get("value"))
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i32>().ok());

                Some(Group {
                    id,
                    display_name: Some(display),
                    gid_number: gid,
                })
            })
            .collect()
    }

    /// Verify that a regular (non-service) LLDAP user can authenticate.
    /// Uses the dedicated /auth/simple/login REST endpoint but does **not** replace
    /// our service token. Returns Ok(()) on success. This is used by the WebUI login flow.
    pub async fn verify_user_credentials(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<(), LldapError> {
        // We intentionally do not call self.authenticate() because that would
        // replace the service-account JWT we use for searches.
        // Login is only performed on explicit user login attempts (or container startup).
        self._simple_login(username, password).await.map(|_| ())
    }

    /// Username the service client is currently authenticated as (comes from
    /// sssd.ldap_default_bind_dn or NFS_KLLDAP_LLDAP_USER at last successful auth/reload).
    pub fn authenticated_as(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// When the last successful authentication (or token refresh) occurred.
    /// Used by the WebUI to show staleness notices after editing bind credentials
    /// or the LLDAP management URL in nfs-klldap.conf.
    pub fn last_auth_time(&self) -> Option<Instant> {
        self.last_auth_time
    }

    /// Returns true if the given LLDAP username is a member of the named group.
    /// Uses the service account credentials (must be already authenticated).
    ///
    /// Prefer `user_is_in_group_with_creds` for login flows (the service account
    /// typically cannot read the `groups` relation on arbitrary users).
    #[allow(dead_code)]
    pub async fn user_is_in_group(&mut self, username: &str, group_name: &str) -> bool {
        // Preferred: ask for the user's groups directly.
        let query = r#"
            query($userId: String!) {
                user(userId: $userId) {
                    groups {
                        id
                    }
                }
            }
        "#;

        let variables = serde_json::json!({ "userId": username });

        let data: serde_json::Value = match self.run_query(query, Some(variables)).await {
            Ok(d) => d,
            Err(_) => return false,
        };

        let groups = data
            .get("user")
            .and_then(|u| u.get("groups"))
            .and_then(|g| g.as_array())
            .cloned()
            .unwrap_or_default();

        for g in groups {
            let id = g.get("id").and_then(|v| v.as_str());
            let display = g.get("displayName").and_then(|v| v.as_str());
            if id == Some(group_name) || display == Some(group_name) {
                return true;
            }
        }

        // Fallback: some LLDAP schemas put groups under attributes or have different shape.
        // As a last resort we can list all groups and check members, but the above is the common case.
        false
    }

    /// One-shot membership check performed by authenticating *as the target user*
    /// (via the simple-login REST endpoint) and then asking GraphQL for *that
    /// user's own* groups using their fresh short-lived token.
    ///
    /// This is the correct approach for the WebUI login flow. The long-lived
    /// service account (sssd.ldap_default_bind_dn) typically only has rights to
    /// read POSIX attributes for NSS, not the `groups` relation on arbitrary
    /// users. Querying as the user themselves works because users can see their
    /// own group memberships.
    pub async fn user_is_in_group_with_creds(
        &self,
        username: &str,
        password: &str,
        group_name: &str,
    ) -> bool {
        // Obtain a short-lived token for *this user* only. Does not affect the
        // long-lived service token stored on self.
        let token = match self._simple_login(username, password).await {
            Ok(t) => t,
            Err(_) => return false,
        };

        let query = r#"
            query($userId: String!) {
                user(userId: $userId) {
                    groups {
                        id
                        displayName
                    }
                }
            }
        "#;
        let variables = serde_json::json!({ "userId": username });
        let body = serde_json::json!({ "query": query, "variables": variables });

        let resp = match self
            .client
            .post(&self.graphql_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", token),
            )
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return false,
        };

        if !resp.status().is_success() {
            return false;
        }

        let envelope: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Support both the normal GraphQL envelope { data: { user: ... } }
        // and the (unlikely) case where we got the inner data directly.
        let user_obj = envelope
            .get("data")
            .and_then(|d| d.get("user"))
            .or_else(|| envelope.get("user"));

        let groups = user_obj
            .and_then(|u| u.get("groups"))
            .and_then(|g| g.as_array())
            .cloned()
            .unwrap_or_default();

        for g in groups {
            let id = g.get("id").and_then(|v| v.as_str());
            let display = g.get("displayName").and_then(|v| v.as_str());
            if id == Some(group_name) || display == Some(group_name) {
                return true;
            }
        }
        false
    }
}
