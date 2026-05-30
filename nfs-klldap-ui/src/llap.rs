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

#[derive(Deserialize)]
struct UserResponse {
    user: Option<RawUser>,
}

#[derive(Deserialize)]
struct UsersResponse {
    users: Vec<RawUser>,
}

#[derive(Deserialize)]
struct RawUser {
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    attributes: Vec<Attribute>,
}

#[derive(Deserialize)]
struct Attribute {
    name: String,
    value: Vec<String>, // LLDAP returns arrays even for single values
}

#[derive(Deserialize)]
struct GroupsResponse {
    groups: Vec<RawGroup>,
}

#[derive(Deserialize)]
struct RawGroup {
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    attributes: Vec<Attribute>,
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
    pub fn new(graphql_url: &str) -> Self {
        let login_url = derive_login_url(graphql_url);
        Self {
            client: Client::new(),
            graphql_url: graphql_url.to_string(),
            login_url,
            auth_token: None,
            username: None,
            password: None,
            last_auth_time: None,
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
    pub async fn resolve_user(&mut self, name: &str) -> Option<(i32, String)> {
        let query = r#"
            query($userId: String!) {
                user(userId: $userId) {
                    id
                    displayName
                    attributes {
                        name
                        value
                    }
                }
            }
        "#;

        let variables = serde_json::json!({ "userId": name });

        let data: UserResponse = self.run_query(query, Some(variables)).await.ok()?;

        let user = data.user?;
        let display = user.display_name.unwrap_or_else(|| user.id.clone());

        // Parse uidNumber from attributes (KLLDAP / LLDAP returns them here)
        let uid = user
            .attributes
            .iter()
            .find(|a| a.name == "uidNumber")
            .and_then(|a| a.value.first())
            .and_then(|v| v.parse::<i32>().ok());

        uid.map(|u| (u, display))
    }

    /// Resolve a group name to (gidNumber, display name)
    pub async fn resolve_group(&mut self, name: &str) -> Option<(i32, String)> {
        let query = r#"
            query($groupId: String!) {
                group(groupId: $groupId) {
                    id
                    displayName
                    attributes {
                        name
                        value
                    }
                }
            }
        "#;

        let variables = serde_json::json!({ "groupId": name });

        // Note: The exact group query name may vary slightly in forks.
        // This is the common pattern.
        let data: serde_json::Value = self.run_query(query, Some(variables)).await.ok()?;

        // Flexible parsing
        let group = data.get("group")?;
        let display = group
            .get("displayName")
            .and_then(|v| v.as_str())
            .unwrap_or(name)
            .to_string();

        let gid = group
            .get("attributes")
            .and_then(|attrs| attrs.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|a| a.get("name").and_then(|n| n.as_str()) == Some("gidNumber"))
            })
            .and_then(|a| a.get("value"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i32>().ok());

        gid.map(|g| (g, display))
    }

    /// List users (with optional filter). Returns POSIX-aware results.
    pub async fn list_users(&mut self, filter: Option<&str>) -> Vec<User> {
        let query = r#"
            query {
                users {
                    id
                    displayName
                    attributes {
                        name
                        value
                    }
                }
            }
        "#;

        let data: UsersResponse = match self.run_query(query, None).await {
            Ok(d) => d,
            Err(_) => return vec![],
        };

        data.users
            .into_iter()
            .filter(|u| {
                filter.is_none_or(|f| {
                    u.id.to_lowercase().contains(&f.to_lowercase())
                        || u.display_name
                            .as_ref()
                            .is_some_and(|d| d.to_lowercase().contains(&f.to_lowercase()))
                })
            })
            .map(|raw| {
                let uid = raw
                    .attributes
                    .iter()
                    .find(|a| a.name == "uidNumber")
                    .and_then(|a| a.value.first())
                    .and_then(|v| v.parse::<i32>().ok());

                User {
                    id: raw.id,
                    display_name: raw.display_name,
                    uid_number: uid,
                }
            })
            .collect()
    }

    /// List groups (with optional filter).
    pub async fn list_groups(&mut self, filter: Option<&str>) -> Vec<Group> {
        let query = r#"
            query {
                groups {
                    id
                    displayName
                    attributes {
                        name
                        value
                    }
                }
            }
        "#;

        let data: GroupsResponse = match self.run_query(query, None).await {
            Ok(d) => d,
            Err(_) => return vec![],
        };

        data.groups
            .into_iter()
            .filter(|g| {
                filter.is_none_or(|f| {
                    g.id.to_lowercase().contains(&f.to_lowercase())
                        || g.display_name
                            .as_ref()
                            .is_some_and(|d| d.to_lowercase().contains(&f.to_lowercase()))
                })
            })
            .map(|raw| {
                let gid = raw
                    .attributes
                    .iter()
                    .find(|a| a.name == "gidNumber")
                    .and_then(|a| a.value.first())
                    .and_then(|v| v.parse::<i32>().ok());

                Group {
                    id: raw.id,
                    display_name: raw.display_name,
                    gid_number: gid,
                }
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
            if g.get("id").and_then(|v| v.as_str()) == Some(group_name) {
                return true;
            }
        }

        // Fallback: some LLDAP schemas put groups under attributes or have different shape.
        // As a last resort we can list all groups and check members, but the above is the common case.
        false
    }
}
