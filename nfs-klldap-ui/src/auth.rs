//! Hybrid auth uses a localhost sidecar password or LLDAP admin group.
//! Sessions last twelve hours with HttpOnly cookies and SHA-256 hashing.

use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

// Twelve hours is the session TTL.
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const SIMPLE_PW_FILENAME: &str = "webui-password";

#[derive(Clone, Debug)]
pub struct Session {
    pub username: String,
    pub created: Instant,
}

pub struct AuthManager {
    /// This map holds active sessions keyed by opaque bearer token.
    sessions: RwLock<HashMap<String, Session>>,
    /// This is the absolute path to the webui-password sidecar file.
    simple_pw_path: PathBuf,
    /// This names the LDAP admin group from webui_admin_group.
    admin_group: String,
}

impl AuthManager {
    /// This constructs a new manager beside nfs-klldap.conf.
    pub fn new(config_path: impl AsRef<Path>, admin_group: Option<String>) -> Self {
        let config_path = config_path.as_ref();
        let simple_pw_path = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(SIMPLE_PW_FILENAME);

        Self {
            sessions: RwLock::new(HashMap::new()),
            simple_pw_path,
            admin_group: admin_group.unwrap_or_else(|| "lldap_admin".to_string()),
        }
    }

    pub fn admin_group(&self) -> &str {
        &self.admin_group
    }

    // These tests cover simple password (localhost) handling.

    /// Return true when the simple password sidecar already exists.
    pub fn has_simple_password(&self) -> bool {
        self.simple_pw_path.exists()
    }

    /// Set or overwrite the localhost simple password file with mode 0600.
    pub fn set_simple_password(&self, password: &str) -> Result<(), String> {
        if password.trim().is_empty() {
            return Err("Password cannot be empty".to_string());
        }
        if password.len() < 8 {
            return Err("Password must be at least 8 characters".to_string());
        }

        // Use sixteen bytes of random salt.
        let mut salt = [0u8; 16];
        rand::thread_rng().fill(&mut salt);

        let hash = hash_password(&salt, password.as_bytes());

        let line = format!("{}:{}\n", hex_encode(&salt), hex_encode(&hash));

        // Ensure parent directory exists (usually /config). May be the.
        if let Some(parent) = self.simple_pw_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Write atomically-ish: create + write + set perms.
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.simple_pw_path)
            .map_err(|e| format!("failed to open {}: {}", self.simple_pw_path.display(), e))?;

        // Set 0600 before writing the secret (best effort on Unix).
        let mut perms = file
            .metadata()
            .map_err(|e| format!("metadata: {}", e))?
            .permissions();
        perms.set_mode(0o600);
        let _ = file.set_permissions(perms);

        file.write_all(line.as_bytes())
            .map_err(|e| format!("write failed: {}", e))?;
        file.sync_all().ok();

        Ok(())
    }

    /// Validate the special "localhost" user against the lightweight sidecar.
    /// All other usernames must go through the LLDAP path.
    pub fn validate_simple_password(&self, username: &str, password: &str) -> Result<(), String> {
        if username != "localhost" {
            return Err(
                "Only the special 'localhost' user can use the simple password path".to_string(),
            );
        }
        if !self.has_simple_password() {
            return Err(
                "No simple password has been set yet. Use the first-run setup form.".to_string(),
            );
        }

        let stored = fs::read_to_string(&self.simple_pw_path)
            .map_err(|e| format!("failed to read simple password file: {}", e))?
            .trim()
            .to_string();

        let (salt_hex, hash_hex) = stored
            .split_once(':')
            .ok_or_else(|| "corrupt simple password file (bad format)".to_string())?;

        let salt = hex_decode(salt_hex)
            .ok_or_else(|| "corrupt simple password file (bad salt)".to_string())?;
        let expected_hash = hex_decode(hash_hex)
            .ok_or_else(|| "corrupt simple password file (bad hash)".to_string())?;

        let computed = hash_password(&salt, password.as_bytes());

        // Constant-time comparison to avoid leaking timing information.
        if computed.ct_eq(&expected_hash).into() {
            Ok(())
        } else {
            Err("Invalid password for 'localhost'".to_string())
        }
    }

    // These tests cover session management (used after either auth path.

    /// Create session after localhost simple-pw or LLDAP+group auth.
    pub fn create_privileged_session(&self, username: &str) -> String {
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

        // Opportunistic cleanup.
        let now = Instant::now();
        map.retain(|_, s| now.duration_since(s.created) < SESSION_TTL);

        token
    }

    /// Validate token → username (for require_auth compatibility).
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

// Iterated SHA-256 for local sidecar pw (protection is 0600 + root container).

const PW_HASH_ITERATIONS: u32 = 100_000;

/// Compute salt || pw iterated with SHA-256.
fn hash_password(salt: &[u8], pw: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(pw);

    let mut current = hasher.finalize();

    for _ in 1..PW_HASH_ITERATIONS {
        let mut h = Sha256::new();
        h.update(current);
        current = h.finalize();
    }

    current.into()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = from_hex_digit(b[i])?;
        let lo = from_hex_digit(b[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn from_hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + c - b'a'),
        b'A'..=b'F' => Some(10 + c - b'A'),
        _ => None,
    }
}
