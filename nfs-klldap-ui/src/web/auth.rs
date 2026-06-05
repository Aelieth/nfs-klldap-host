//! Login handlers, cookie construction (HttpOnly/Lax/Secure, 12h), require_auth + redirects.

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

/// Shared form for both normal login and first-run setup.
#[derive(Deserialize)]
pub(crate) struct LoginForm {
    pub username: String,
    pub password: String,
}

/// Optional query params for the login page (used to surface auth failure reasons
/// after a require_auth redirect).
#[derive(Deserialize, Default)]
pub(crate) struct LoginQuery {
    /// When present (e.g. "session" or "required"), login_page renders a friendly
    /// message so the user is not left wondering why they were sent back to the form.
    error: Option<String>,
}

/// GET /login — renders the form (or first-run variant).
/// Supports ?error=... from require_auth redirects so failures are visible.
pub async fn login_page(
    State(state): State<super::AppState>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> impl IntoResponse {
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
            keytab_alert: state.keytab_alert.clone(),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// POST /login — the main authentication entry point.
/// On success: creates privileged session + sets properly-formed cookie + redirects.
/// On failure: re-renders login page with error.
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
        // LLDAP path — now uses the combined helper on LdapClient so we only
        // take the lock once and get a single, clear error for non-admins.
        // The helper still benefits from the memberOf fast-path recorded during verify.
        let l = state.lldap.lock().await;
        match l
            .verify_user_is_admin(username, password, state.auth.admin_group())
            .await
        {
            Ok(()) => Ok(username.to_string()),
            Err(e) => {
                // Log the real inner reason for operators.
                eprintln!("LDAP admin login failed for '{}': {}", username, e);
                // Present a friendly message to the browser (hides "service account" details).
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
            // Drop any prior session tokens (stale browser cookies after logout/restart).
            for old in extract_all_session_tokens_from_headers(&headers) {
                state.auth.logout(&old);
            }
            let token = state.auth.create_privileged_session(&user);
            let mut response_headers = HeaderMap::new();
            insert_session_cookie(&state, &headers, &mut response_headers, &token);

            // Warm permission editor search caches on (web) login for instant
            // suggestions in UID/GID boxes (no repeated LDAP roundtrips on focus/type
            // in the Share Permissions directory editor). The list_* calls populate
            // both the 2m search cache (__all__) and the 10m identity caches.
            {
                let lldap = state.lldap.clone();
                tokio::spawn(async move {
                    let l = lldap.lock().await;
                    let _ = l.list_users(None).await;
                    let _ = l.list_groups(None).await;
                });
            }

            (response_headers, Redirect::to("/")).into_response()
        }
        Err(e) => {
            let first_run = !state.auth.has_simple_password();
            let admin_group = state.auth.admin_group().to_string();
            let html = LoginTemplate {
                error: Some(e),
                current_user: None,
                first_run,
                admin_group,
                keytab_alert: state.keytab_alert.clone(),
            }
            .render()
            .unwrap();
            (StatusCode::UNAUTHORIZED, Html(html)).into_response()
        }
    }
}

/// POST /setup-password — first-run only. Sets the initial localhost password
/// and immediately creates a session (auto-login).
pub async fn setup_password(
    State(state): State<super::AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    if state.auth.has_simple_password() {
        let html = LoginTemplate {
            error: Some(
                "A simple password has already been set. Use the normal login form.".to_string(),
            ),
            current_user: None,
            first_run: false,
            admin_group: state.auth.admin_group().to_string(),
            keytab_alert: state.keytab_alert.clone(),
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
            keytab_alert: state.keytab_alert.clone(),
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

            // Warm caches also for first-run setup (same benefit for editor UX).
            {
                let lldap = state.lldap.clone();
                tokio::spawn(async move {
                    let l = lldap.lock().await;
                    let _ = l.list_users(None).await;
                    let _ = l.list_groups(None).await;
                });
            }

            (response_headers, Redirect::to("/?first_run=1")).into_response()
        }
        Err(e) => {
            let html = LoginTemplate {
                error: Some(e),
                current_user: None,
                first_run: true,
                admin_group: state.auth.admin_group().to_string(),
                keytab_alert: state.keytab_alert.clone(),
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
    (h, Redirect::to("/login")).into_response()
}

/// Map ?error= query values to user-visible login messages.
fn login_error_message(first_run: bool, error: Option<&str>) -> Option<String> {
    let code = error?;
    // First-run visitors are not "logged out" — suppress the session-expired copy.
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

/// Where to send unauthenticated users (context-aware, avoids misleading first-run copy).
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

/// Returns the value for the Secure flag on cookies for this request.
/// Prefers explicit NFS_KLLDAP_WEBUI_COOKIE_SECURE (escape hatch for setups that
/// need to force the bit off even when TLS was on). When absent,
/// delegates to the smart detection (direct TLS or X-Forwarded-Proto: https).
fn effective_cookie_secure(state: &super::AppState, headers: &HeaderMap) -> bool {
    if let Ok(v) = std::env::var("NFS_KLLDAP_WEBUI_COOKIE_SECURE") {
        let v = v.trim().to_ascii_lowercase();
        return !(v == "0" || v == "false" || v == "off" || v == "no");
    }
    state.is_https(headers)
}

/// Centralized session cookie builder (single source of truth).
/// Secure bit is now conditional on effective https (direct or via proxy header),
/// while still honoring the NFS_KLLDAP_WEBUI_COOKIE_SECURE override.
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

/// Env-only decider for the Secure cookie bit (still used by unit test).
/// The primary logic now lives in `effective_cookie_secure` (which respects this
/// env when present, else delegates to `AppState::is_https` for direct_tls or
/// X-Forwarded-Proto). Kept so existing tests continue to work.
#[allow(dead_code)]
fn cookie_secure() -> bool {
    std::env::var("NFS_KLLDAP_WEBUI_COOKIE_SECURE")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        })
        .unwrap_or(true)
}

/// All non-empty `session=` values from a Cookie header (oldest → newest).
pub(crate) fn extract_all_session_tokens(cookie_header: &str) -> Vec<String> {
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

/// Validate any session cookie on the request; prefers the last (most recently set) token.
pub(crate) fn validate_session_in_headers(
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

// === Auth guard used by protected handlers ===

#[derive(Clone)]
pub struct AuthUser(pub String);

/// Guard used by (almost) every protected route handler.
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
    use super::*;

    #[test]
    fn extract_all_session_tokens_collects_duplicates() {
        let raw = "foo=bar; session=old; session=new";
        let t = extract_all_session_tokens(raw);
        assert_eq!(t, vec!["old".to_string(), "new".to_string()]);
    }

    #[test]
    fn login_error_message_suppresses_session_copy_on_first_run() {
        assert!(login_error_message(true, Some("session")).is_none());
        assert!(login_error_message(true, Some("required")).is_none());
        assert!(
            login_error_message(false, Some("session"))
                .unwrap()
                .contains("expired")
        );
    }

    #[test]
    fn cookie_secure_defaults_true() {
        assert!(cookie_secure());
    }
}
