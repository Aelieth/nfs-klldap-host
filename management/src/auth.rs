//! Minimal local-machine admin authentication.
//!
//! Goal: Only people who can actually do privileged operations on *this host*
//! (root or users who can `sudo` / are in the wheel group) may use the management UI.
//!
//! Design (easy + matches the rest of the project):
//! - Login form: username + password.
//! - Validation: attempt a non-destructive `sudo -S` test as that user.
//!   This respects the real sudoers policy (wheel group + any custom rules).
//! - On success: issue a random opaque session token.
//! - Store the token server-side (in-memory map with expiry).
//! - Set a HttpOnly session cookie.
//! - All sensitive routes require a valid session.
//!
//! The web server itself does **not** need to run as root.
//! Passwords only live in memory during the login POST.

use rand::Rng;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::RwLock;
use std::time::{Duration, Instant};

const SESSION_TTL: Duration = Duration::from_secs(12 * 3600); // 12 hours

#[derive(Clone)]
pub struct Session {
    pub username: String,
    pub created: Instant,
}

pub struct AuthManager {
    /// token -> session
    sessions: RwLock<HashMap<String, Session>>,
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Attempt to authenticate a local user as someone who can do real sudo.
    /// Returns Ok(()) on success.
    pub fn validate_local_admin(&self, username: &str, password: &str) -> Result<(), String> {
        // Fast path: root is always allowed (no password check needed for the concept,
        // but we still do the sudo dance for consistency).
        if username == "root" {
            return self.try_sudo_test("root", password);
        }

        // Check if the user is in wheel (or root). This is a quick filter.
        // We still do the real sudo test below because that is authoritative.
        if !user_can_sudo(username) {
            return Err(format!(
                "User '{}' is not root and not in the wheel (or sudo) group on this machine.",
                username
            ));
        }

        self.try_sudo_test(username, password)
    }

    fn try_sudo_test(&self, username: &str, password: &str) -> Result<(), String> {
        // Run:   echo "$password" | timeout 8 sudo -S -u "$username" /bin/true
        // If exit 0 → the user successfully authenticated to sudo.
        let mut child = Command::new("timeout")
            .args(["8", "sudo", "-S", "-u", username, "/bin/true"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn sudo test: {}", e))?;

        // Write password to stdin (followed by newline)
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = writeln!(stdin, "{}", password);
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed to wait for sudo test: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Common sudo failure messages are intentionally vague for security.
            Err(format!("sudo authentication failed for user '{}'.", username))
        }
    }

    /// Create a new session for the user.
    pub fn create_session(&self, username: &str) -> String {
        let token: String = (0..32)
            .map(|_| {
                let c = rand::thread_rng().gen_range(0..62);
                match c {
                    0..=9 => (b'0' + c) as char,
                    10..=35 => (b'a' + c - 10) as char,
                    _ => (b'A' + c - 36) as char,
                }
            })
            .collect();

        let session = Session {
            username: username.to_string(),
            created: Instant::now(),
        };

        let mut map = self.sessions.write().unwrap();
        map.insert(token.clone(), session);

        // Opportunistic cleanup of expired sessions
        let now = Instant::now();
        map.retain(|_, s| now.duration_since(s.created) < SESSION_TTL);

        token
    }

    /// Validate a token. Returns the username if valid and not expired.
    pub fn validate(&self, token: &str) -> Option<String> {
        let mut map = self.sessions.write().unwrap();
        if let Some(session) = map.get(token) {
            if Instant::now().duration_since(session.created) < SESSION_TTL {
                return Some(session.username.clone());
            } else {
                map.remove(token);
            }
        }
        None
    }

    pub fn logout(&self, token: &str) {
        let mut map = self.sessions.write().unwrap();
        map.remove(token);
    }
}

fn user_can_sudo(username: &str) -> bool {
    // Check if user is in wheel (RHEL/Alma) or sudo (Debian/Ubuntu) group.
    // This is a fast pre-check. The real sudo -S test is authoritative.
    if let Ok(output) = Command::new("id").args(["-Gn", username]).output() {
        let groups = String::from_utf8_lossy(&output.stdout).to_lowercase();
        if groups.contains("wheel") || groups.contains("sudo") || groups.contains("admin") {
            return true;
        }
    }

    // Fallback: root is always ok
    username == "root"
}
