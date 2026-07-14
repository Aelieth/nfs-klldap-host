//! Login handlers, session cookies, and require_auth redirects.

use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
};
use cookie::{Cookie, SameSite};
use serde::Deserialize;

/// Login page template (first-run or normal).
#[derive(Template)]
#[template(path = "login.html")]
pub(crate) struct LoginTemplate {
    pub error: Option<String>,
    pub current_user: Option<String>,
    /// First-run mode when no simple password sidecar exists yet.
    pub first_run: bool,
    pub admin_group: String,
    pub keytab_alert: Option<String>,
}

// Keytab_alert is never passed to LoginTemplate. See keytab.rs.

/// Shared form for both normal login and first-run setup.
#[derive(Deserialize)]
pub(crate) struct LoginForm {
    pub username: String,
    pub password: String,
}

/// Deserializes login-page query params including error codes from redirects.
#[derive(Deserialize, Default)]
pub(crate) struct LoginQuery {
    /// Carry the error query value from a require_auth redirect.
    error: Option<String>,
}

/// Renders the login page and surfaces error query values from redirects.
pub async fn login_page(
    State(state): State<super::AppState>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> impl IntoResponse {
    if super::setup::setup_wizard_required_with_marker(
        &state.config_path,
        state.setup_marker_override.as_deref(),
    ) {
        return Redirect::to(&super::setup::setup_redirect_for_step(&state.config_path))
            .into_response();
    }
    if validate_session_in_headers(&state, &headers).is_some() {
        return Redirect::to("/").into_response();
    }

    let first_run = !state.auth.has_simple_password();
    let admin_group = state.auth.admin_group().to_string();

    let error = login_error_message(first_run, q.error.as_deref());

    Html(
        LoginTemplate {
            error,
            current_user: None,
            first_run,
            admin_group,
            keytab_alert: None,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Handles login POST, sets a session cookie on success, or re-renders.
pub async fn login(
    State(state): State<super::AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    let username = form.username.trim();
    let password = &form.password;

    let result: Result<String, String> = if username == "localhost" {
        match state.auth.validate_simple_password(username, password) {
            Ok(()) => Ok(username.to_string()),
            Err(e) => Err(e),
        }
    } else {
        // LLDAP path — LdapClient::verify_user_is_admin under a single lock.
        let l = state.lldap.lock().await;
        match l
            .verify_user_is_admin(username, password, state.auth.admin_group())
            .await
        {
            Ok(()) => Ok(username.to_string()),
            Err(e) => {
                // Log the real inner reason for operators.
                eprintln!("LDAP admin login failed for '{}': {}", username, e);
                // Present a friendly message to the browser (hides "service.
                if e.to_string().contains("not a member of") {
                    Err(e.to_string())
                } else {
                    Err("Invalid username or password (LDAP)".to_string())
                }
            }
        }
    };

    match result {
        Ok(user) => {
            // Drops stale session tokens from prior cookies after re-login.
            for old in extract_all_session_tokens_from_headers(&headers) {
                state.auth.logout(&old);
            }
            let token = state.auth.create_privileged_session(&user);
            let mut response_headers = HeaderMap::new();
            insert_session_cookie(&state, &headers, &mut response_headers, &token);

            // Warm permission editor search caches on (web) login for instant.
            {
                let lldap = state.lldap.clone();
                tokio::spawn(async move {
                    let l = lldap.lock().await;
                    let _ = l.list_users(None).await;
                    let _ = l.list_groups(None).await;
                });
            }

            // Attach Set-Cookie explicitly on the Redirect (robust through.
            let mut response = Redirect::to("/").into_response();
            response.headers_mut().extend(response_headers);
            response
        }
        Err(e) => {
            let first_run = !state.auth.has_simple_password();
            let admin_group = state.auth.admin_group().to_string();
            let html = LoginTemplate {
                error: Some(e),
                current_user: None,
                first_run,
                admin_group,
                keytab_alert: None,
            }
            .render()
            .unwrap();
            (StatusCode::UNAUTHORIZED, Html(html)).into_response()
        }
    }
}

/// POST /setup-password: first-run localhost password and auto-login session.
pub async fn setup_password(
    State(state): State<super::AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    if super::setup::setup_wizard_required_with_marker(
        &state.config_path,
        state.setup_marker_override.as_deref(),
    ) {
        return Redirect::to(&super::setup::setup_redirect_for_step(&state.config_path))
            .into_response();
    }
    if state.auth.has_simple_password() {
        let html = LoginTemplate {
            error: Some(
                "A simple password has already been set. Use the normal login form.".to_string(),
            ),
            current_user: None,
            first_run: false,
            admin_group: state.auth.admin_group().to_string(),
            keytab_alert: None,
        }
        .render()
        .unwrap();
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    let pw = form.password.trim();
    if pw.is_empty() {
        let html = LoginTemplate {
            error: Some("Password cannot be empty".to_string()),
            current_user: None,
            first_run: true,
            admin_group: state.auth.admin_group().to_string(),
            keytab_alert: None,
        }
        .render()
        .unwrap();
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    match state.auth.set_simple_password(pw) {
        Ok(()) => {
            for old in extract_all_session_tokens_from_headers(&headers) {
                state.auth.logout(&old);
            }
            let token = state.auth.create_privileged_session("localhost");
            let mut response_headers = HeaderMap::new();
            insert_session_cookie(&state, &headers, &mut response_headers, &token);

            // Warm caches also for first-run setup (same benefit for editor.
            {
                let lldap = state.lldap.clone();
                tokio::spawn(async move {
                    let l = lldap.lock().await;
                    let _ = l.list_users(None).await;
                    let _ = l.list_groups(None).await;
                });
            }

            // Attach Set-Cookie explicitly on the Redirect (see login path).
            let mut response = Redirect::to("/?first_run=1").into_response();
            response.headers_mut().extend(response_headers);
            response
        }
        Err(e) => {
            let html = LoginTemplate {
                error: Some(e),
                current_user: None,
                first_run: true,
                admin_group: state.auth.admin_group().to_string(),
                keytab_alert: None,
            }
            .render()
            .unwrap();
            (StatusCode::BAD_REQUEST, Html(html)).into_response()
        }
    }
}


/// GET|POST /logout — clears the session server-side and the cookie.
pub async fn logout(State(state): State<super::AppState>, headers: HeaderMap) -> impl IntoResponse {
    for token in extract_all_session_tokens_from_headers(&headers) {
        state.auth.logout(&token);
    }

    let mut h = HeaderMap::new();
    insert_session_clear_cookie(&state, &headers, &mut h);

    // Explicit attachment for consistency with the login success paths.
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().extend(h);
    response
}

/// Map ?error= query values to user-visible login messages.
fn login_error_message(first_run: bool, error: Option<&str>) -> Option<String> {
    let code = error?;
    // First-run visitors are not "logged out" suppress the Session-expired.
    if first_run && matches!(code, "session" | "required" | "auth") {
        return None;
    }
    Some(match code {
        "session" | "required" | "auth" => {
            "Your session has expired or you are not logged in. Please sign in again.".to_string()
        }
        other => format!("Authentication required: {}", other),
    })
}

/// Redirect target for unauthenticated users (context-aware first-run copy).
fn auth_failure_redirect(state: &super::AppState, headers: &HeaderMap) -> Redirect {
    if !state.auth.has_simple_password() {
        return Redirect::to("/login");
    }
    if had_session_cookie(headers) {
        Redirect::to("/login?error=session")
    } else {
        Redirect::to("/login")
    }
}

fn had_session_cookie(headers: &HeaderMap) -> bool {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| !extract_all_session_tokens(s).is_empty())
}

fn insert_session_cookie(
    state: &super::AppState,
    req_headers: &HeaderMap,
    headers: &mut HeaderMap,
    token: &str,
) {
    let set = build_session_cookie(state, req_headers, token);
    headers.insert(SET_COOKIE, set.parse().expect("valid Set-Cookie"));
}

fn insert_session_clear_cookie(
    state: &super::AppState,
    req_headers: &HeaderMap,
    headers: &mut HeaderMap,
) {
    let clear = build_clear_session_cookie(state, req_headers);
    headers.insert(SET_COOKIE, clear.parse().expect("valid Set-Cookie clear"));
}

/// Chooses the cookie Secure flag and honors NFS_KLLDAP_WEBUI_COOKIE_SECURE.
fn effective_cookie_secure(state: &super::AppState, headers: &HeaderMap) -> bool {
    if let Ok(v) = std::env::var("NFS_KLLDAP_WEBUI_COOKIE_SECURE") {
        let v = v.trim().to_ascii_lowercase();
        return !(v == "0" || v == "false" || v == "off" || v == "no");
    }
    state.is_https(headers)
}

/// Session cookie builder with HttpOnly/Lax and conditional Secure.
fn build_session_cookie(state: &super::AppState, req_headers: &HeaderMap, token: &str) -> String {
    let max_age = cookie::time::Duration::seconds(12 * 3600);

    let mut cookie = Cookie::build(("session", token))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(max_age);
    if effective_cookie_secure(state, req_headers) {
        cookie = cookie.secure(true);
    }
    cookie.to_string()
}

fn build_clear_session_cookie(state: &super::AppState, req_headers: &HeaderMap) -> String {
    let mut cookie = Cookie::build(("session", ""))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(0));
    if effective_cookie_secure(state, req_headers) {
        cookie = cookie.secure(true);
    }
    cookie.to_string()
}

/// All non-empty `session=` values from a Cookie header (oldest → newest).
fn extract_all_session_tokens(cookie_header: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for part in cookie_header.split(';') {
        let kv = part.trim();
        if let Some(rest) = kv.strip_prefix("session=") {
            let token = rest.trim_matches('"');
            if !token.is_empty() {
                tokens.push(token.to_string());
            }
        }
    }
    tokens
}

fn extract_all_session_tokens_from_headers(headers: &HeaderMap) -> Vec<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(extract_all_session_tokens)
        .unwrap_or_default()
}

/// Validates session cookies and prefers the most recently set token.
fn validate_session_in_headers(
    state: &super::AppState,
    headers: &HeaderMap,
) -> Option<String> {
    let tokens = extract_all_session_tokens_from_headers(headers);
    for token in tokens.into_iter().rev() {
        if let Some(user) = state.auth.validate(&token) {
            return Some(user);
        }
    }
    None
}

// Auth guard helpers for protected routes.

#[derive(Clone)]
pub struct AuthUser(pub String);

/// Guards protected routes and ignores keytab_alert when authorizing access.
pub async fn require_auth(
    state: &super::AppState,
    headers: &HeaderMap,
) -> Result<AuthUser, Redirect> {
    if let Some(user) = validate_session_in_headers(state, headers) {
        return Ok(AuthUser(user));
    }
    Err(auth_failure_redirect(state, headers))
}

#[cfg(test)]
mod tests {
    use super::extract_all_session_tokens;

    #[test]
    fn extracts_every_session_cookie_in_order_skipping_empty_and_quotes() {
        // Duplicate session cookies happen after re-login; validation prefers the newest (last).
        let tokens = extract_all_session_tokens("session=old; theme=dark; session=\"new\"; session=");
        assert_eq!(tokens, vec!["old".to_string(), "new".to_string()]);
        assert!(extract_all_session_tokens("theme=dark").is_empty());
        assert!(extract_all_session_tokens("").is_empty());
    }
}


