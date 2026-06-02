//! Web-layer authentication (login flows, session cookies, protected-route guard).
//!
//! This module isolates all HTTP auth concerns for the UI:
//! - `localhost` sidecar password (via AuthManager)
//! - LLDAP users that are members of the configured admin group
//! - Session cookie creation / parsing (now using the `cookie` crate)
//! - `require_auth` guard used by protected handlers
//!
//! Fixes incorporated from audit:
//! - Proper typed cookie construction (centralized, `SameSite=Lax` + `Secure` where appropriate)
//! - Eliminated duplication of cookie strings and LoginTemplate error rendering
//! - More diagnostic error paths for service-account vs. password failures
//!
//! Long-term: this is the natural home for evolving `AuthUser` into a real
//! `axum::extract::FromRequestParts` extractor.

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
    pub keytab_status_message: String,
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
    Query(q): Query<LoginQuery>,
) -> impl IntoResponse {
    let first_run = !state.auth.has_simple_password();
    let admin_group = state.auth.admin_group().to_string();

    let error = q.error.map(|e| match e.as_str() {
        "session" | "required" | "auth" => {
            "Your session has expired or you are not logged in. Please sign in again.".to_string()
        }
        other => format!("Authentication required: {}", other),
    });

    Html(
        LoginTemplate {
            error,
            current_user: None,
            first_run,
            admin_group,
            keytab_status_message: state.keytab_status_message.clone(),
        }
        .render()
        .unwrap(),
    )
}

/// POST /login — the main authentication entry point.
/// On success: creates privileged session + sets properly-formed cookie + redirects.
/// On failure: re-renders login page with error.
pub async fn login(
    State(state): State<super::AppState>,
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
            let token = state.auth.create_privileged_session(&user);
            let cookie = build_session_cookie(&token);

            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, cookie.parse().unwrap());

            // Warm permission editor search caches on (web) login for instant
            // suggestions in UID/GID boxes (no repeated LDAP roundtrips on focus/type
            // in the Share Permissions directory editor). The list_* calls populate
            // both the 30s search cache (__all__) and the 10m identity caches.
            {
                let lldap = state.lldap.clone();
                tokio::spawn(async move {
                    let l = lldap.lock().await;
                    let _ = l.list_users(None).await;
                    let _ = l.list_groups(None).await;
                });
            }

            (headers, Redirect::to("/")).into_response()
        }
        Err(e) => {
            let first_run = !state.auth.has_simple_password();
            let admin_group = state.auth.admin_group().to_string();
            let html = LoginTemplate {
                error: Some(e),
                current_user: None,
                first_run,
                admin_group,
                keytab_status_message: state.keytab_status_message.clone(),
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
            keytab_status_message: state.keytab_status_message.clone(),
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
            keytab_status_message: state.keytab_status_message.clone(),
        }
        .render()
        .unwrap();
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    match state.auth.set_simple_password(pw) {
        Ok(()) => {
            let token = state.auth.create_privileged_session("localhost");
            let cookie = build_session_cookie(&token);

            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, cookie.parse().unwrap());

            // Warm caches also for first-run setup (same benefit for editor UX).
            {
                let lldap = state.lldap.clone();
                tokio::spawn(async move {
                    let l = lldap.lock().await;
                    let _ = l.list_users(None).await;
                    let _ = l.list_groups(None).await;
                });
            }

            (headers, Redirect::to("/?first_run=1")).into_response()
        }
        Err(e) => {
            let html = LoginTemplate {
                error: Some(e),
                current_user: None,
                first_run: true,
                admin_group: state.auth.admin_group().to_string(),
                keytab_status_message: state.keytab_status_message.clone(),
            }
            .render()
            .unwrap();
            (StatusCode::BAD_REQUEST, Html(html)).into_response()
        }
    }
}

/// GET|POST /logout — clears the session server-side and the cookie.
pub async fn logout(State(state): State<super::AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(cookie) = headers.get("cookie") {
        if let Ok(s) = cookie.to_str() {
            if let Some(token) = extract_session_token(s) {
                state.auth.logout(&token);
            }
        }
    }

    // Expire the cookie immediately (still HttpOnly etc. for safety).
    let clear = build_clear_session_cookie();
    let mut h = HeaderMap::new();
    h.insert(SET_COOKIE, clear.parse().unwrap());
    (h, Redirect::to("/login")).into_response()
}

/// Centralized, correct session cookie builder (the single source of truth).
///
/// Uses the `cookie` crate (already a dependency, previously unused).
/// Policy chosen for long-term viability:
/// - SameSite=Lax (works reliably with our POST→303→GET login flow)
/// - HttpOnly + Path=/ + 12h Max-Age
/// - Secure=true by default (correct for the rustls listener). Can be relaxed via
///   WEBUI_COOKIE_SECURE=false for local dev, direct IP access, or certain
///   reverse-proxy setups where the browser sees a non-https origin.
fn build_session_cookie(token: &str) -> String {
    // 12 hours in seconds (matches previous Max-Age and SESSION_TTL intent).
    let max_age = cookie::time::Duration::seconds(12 * 3600);

    Cookie::build(("session", token))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(max_age)
        .secure(cookie_secure())
        .to_string()
}

/// Matching clearer for logout.
fn build_clear_session_cookie() -> String {
    Cookie::build(("session", ""))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(0))
        .secure(cookie_secure())
        .to_string()
}

/// Returns whether session cookies should be marked Secure.
/// Defaults to true (correct for the always-rustls UI listener).
/// Set WEBUI_COOKIE_SECURE=false (or 0/false/off/no) to relax for
/// local development or proxy scenarios where the browser origin is not https.
fn cookie_secure() -> bool {
    std::env::var("WEBUI_COOKIE_SECURE")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        })
        .unwrap_or(true)
}

/// Robust-ish extraction of the session token from a Cookie header value.
/// (Improved from the original hand-rolled splitter; still simple because
/// we control the cookie we emit.)
pub(crate) fn extract_session_token(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let kv = part.trim();
        if let Some(rest) = kv.strip_prefix("session=") {
            // Trim any quotes the browser might have added (defensive).
            let token = rest.trim_matches('"');
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

// === Auth guard used by protected handlers ===

#[derive(Clone)]
pub struct AuthUser(pub String);

/// Guard used by (almost) every protected route handler.
/// Returns the username on success or a Redirect to /login on failure.
///
/// Callers typically do:
///   let user = require_auth(&state, &headers).await?;
///
/// This is the current clean form (no State clone per call). A full
/// `FromRequestParts` extractor is a natural long-term evolution.
pub async fn require_auth(
    state: &super::AppState,
    headers: &HeaderMap,
) -> Result<AuthUser, Redirect> {
    if let Some(cookie) = headers.get("cookie") {
        if let Ok(s) = cookie.to_str() {
            if let Some(token) = extract_session_token(s) {
                if let Some(user) = state.auth.validate(&token) {
                    return Ok(AuthUser(user));
                }
            }
        }
    }
    // Surface a visible reason on the login page instead of a completely silent bounce.
    Err(Redirect::to("/login?error=session"))
}