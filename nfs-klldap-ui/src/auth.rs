//! Hybrid auth uses a localhost sidecar password or LLDAP admin group.
//! Sessions use HttpOnly cookies and SHA-256 hashing; their TTL defaults to
//! twelve hours and follows [webui] session_timeout_minutes.

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;

// Twelve hours when no session_timeout_minutes is configured.
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const SIMPLE_PW_FILENAME: &str = "webui-password";
const SESSIONS_FILENAME: &str = "webui-sessions";

#[derive(Clone, Debug)]
pub struct Session {
    pub username: String,
    pub expires_at: SystemTime,
}

/// On-disk session entry. The map key is SHA-256(token) hex, so the sidecar
/// never contains a usable bearer token.
#[derive(Serialize, Deserialize)]
struct PersistedSession {
    username: String,
    expires_unix: u64,
}

pub struct AuthManager {
    /// Active sessions keyed by SHA-256 of the opaque bearer token, mirrored
    /// to the webui-sessions sidecar so service recycles keep users logged in.
    sessions: RwLock<HashMap<String, Session>>,
    /// The webui-password sidecar file lives beside nfs-klldap.conf.
    simple_pw_path: PathBuf,
    /// The webui-sessions sidecar file lives beside nfs-klldap.conf.
    sessions_path: PathBuf,
    /// Names the LDAP admin group from webui_admin_group.
    admin_group: String,
    /// Lifetime of newly created sessions (and the cookie Max-Age).
    session_ttl: Duration,
}

/// SHA-256 hex of a bearer token: the only form sessions are keyed/stored by.
fn token_hash(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex_encode(&h.finalize())
}

/// Loads unexpired sessions from the sidecar; any read/parse failure means
/// starting empty (users just log in again).
fn load_sessions(path: &Path) -> HashMap<String, Session> {
    let Ok(raw) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    let Ok(entries) = serde_json::from_str::<HashMap<String, PersistedSession>>(&raw) else {
        eprintln!(
            "WARN: ignoring unreadable session store at {}",
            path.display()
        );
        return HashMap::new();
    };
    let now = SystemTime::now();
    entries
        .into_iter()
        .filter_map(|(key, p)| {
            let expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(p.expires_unix);
            (expires_at > now).then_some((
                key,
                Session {
                    username: p.username,
                    expires_at,
                },
            ))
        })
        .collect()
}

impl AuthManager {
    /// Builds a manager using paths derived from nfs-klldap.conf.
    /// Sessions persisted by a previous WebUI process are picked up here so a
    /// service recycle (first-run setup, settings apply) never logs users out.
    pub fn new(
        config_path: impl AsRef<Path>,
        admin_group: Option<String>,
        session_ttl: Option<Duration>,
    ) -> Self {
        let config_path = config_path.as_ref();
        let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
        let simple_pw_path = parent.join(SIMPLE_PW_FILENAME);
        let sessions_path = parent.join(SESSIONS_FILENAME);

        Self {
            sessions: RwLock::new(load_sessions(&sessions_path)),
            simple_pw_path,
            sessions_path,
            admin_group: admin_group.unwrap_or_else(|| "lldap_admin".to_string()),
            session_ttl: session_ttl.unwrap_or(DEFAULT_SESSION_TTL),
        }
    }

    /// Best-effort mirror of the live map to the sessions sidecar (0600,
    /// write + rename). A failed save only shortens sessions to this
    /// process's lifetime.
    fn persist_sessions(&self, map: &HashMap<String, Session>) {
        let out: HashMap<&String, PersistedSession> = map
            .iter()
            .map(|(key, s)| {
                (
                    key,
                    PersistedSession {
                        username: s.username.clone(),
                        expires_unix: s
                            .expires_at
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    },
                )
            })
            .collect();
        let Ok(json) = serde_json::to_string(&out) else {
            return;
        };
        let tmp = self.sessions_path.with_extension("saving");
        if fs::write(&tmp, json.as_bytes()).is_err() {
            return;
        }
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        if let Err(e) = fs::rename(&tmp, &self.sessions_path) {
            eprintln!(
                "WARN: failed to persist sessions to {}: {e}",
                self.sessions_path.display()
            );
        }
    }

    pub fn admin_group(&self) -> &str {
        &self.admin_group
    }

    /// Session lifetime for new sessions; cookie Max-Age must use the same
    /// value so browser and server expire together.
    pub fn session_ttl(&self) -> Duration {
        self.session_ttl
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

        // Ensure the parent directory exists (usually /config) before writing.
        if let Some(parent) = self.simple_pw_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Tmp sibling + rename so a crash mid-write can never truncate the
        // live sidecar and lock the localhost account out.
        let tmp = self.simple_pw_path.with_extension("saving");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("failed to open {}: {}", tmp.display(), e))?;
        // mode() only applies on create; force 0600 in case a stale tmp existed.
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));

        file.write_all(line.as_bytes())
            .map_err(|e| format!("write failed: {}", e))?;
        file.sync_all().ok();
        drop(file);

        fs::rename(&tmp, &self.simple_pw_path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!(
                "failed to move password file into place at {}: {}",
                self.simple_pw_path.display(),
                e
            )
        })
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
            expires_at: SystemTime::now() + self.session_ttl,
        };

        let mut map = self.sessions.write().unwrap();
        map.insert(token_hash(&token), session);

        // Drops expired sessions opportunistically while holding the lock.
        let now = SystemTime::now();
        map.retain(|_, s| s.expires_at > now);
        self.persist_sessions(&map);

        token
    }

    /// Validate token → username (for require_auth compatibility).
    pub fn validate(&self, token: &str) -> Option<String> {
        let key = token_hash(token);
        let mut map = self.sessions.write().unwrap();
        match map.get(&key) {
            Some(session) if session.expires_at > SystemTime::now() => {
                Some(session.username.clone())
            }
            Some(_) => {
                map.remove(&key);
                self.persist_sessions(&map);
                None
            }
            None => None,
        }
    }

    pub fn logout(&self, token: &str) {
        let mut map = self.sessions.write().unwrap();
        if map.remove(&token_hash(token)).is_some() {
            self.persist_sessions(&map);
        }
    }

    /// Drop every session belonging to `username` except the one keyed by
    /// `keep_token` (the acting session, e.g. after a password change).
    /// Returns the number of sessions dropped.
    pub fn invalidate_sessions_for_user_except(&self, username: &str, keep_token: &str) -> usize {
        let keep_key = token_hash(keep_token);
        let mut map = self.sessions.write().unwrap();
        let before = map.len();
        map.retain(|key, s| s.username != username || *key == keep_key);
        let dropped = before - map.len();
        if dropped > 0 {
            self.persist_sessions(&map);
        }
        dropped
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_survive_a_new_manager_and_store_only_hashes() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        let mgr = AuthManager::new(&conf, None, None);
        let token = mgr.create_privileged_session("localhost");
        assert_eq!(mgr.validate(&token).as_deref(), Some("localhost"));

        let store = tmp.path().join(SESSIONS_FILENAME);
        let raw = fs::read_to_string(&store).unwrap();
        assert!(
            !raw.contains(&token),
            "sidecar must not hold usable bearer tokens: {raw}"
        );
        let mode = fs::metadata(&store).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "session store must be private");

        // A recycled WebUI builds a fresh manager over the same config dir;
        // the browser's cookie must stay valid across it.
        let mgr2 = AuthManager::new(&conf, None, None);
        assert_eq!(mgr2.validate(&token).as_deref(), Some("localhost"));

        mgr2.logout(&token);
        let mgr3 = AuthManager::new(&conf, None, None);
        assert!(mgr3.validate(&token).is_none(), "logout must persist");
    }

    #[test]
    fn expired_persisted_sessions_are_dropped_on_load() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        let store = tmp.path().join(SESSIONS_FILENAME);
        fs::write(
            &store,
            r#"{"deadbeef":{"username":"localhost","expires_unix":1}}"#,
        )
        .unwrap();
        let mgr = AuthManager::new(&conf, None, None);
        let _ = mgr.create_privileged_session("localhost");
        let raw = fs::read_to_string(&store).unwrap();
        assert!(!raw.contains("deadbeef"), "expired entry must be pruned");
    }

    #[test]
    fn corrupt_session_store_falls_back_to_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        fs::write(tmp.path().join(SESSIONS_FILENAME), "not-json").unwrap();
        let mgr = AuthManager::new(&conf, None, None);
        assert!(mgr.validate("whatever").is_none());
        let token = mgr.create_privileged_session("localhost");
        assert_eq!(mgr.validate(&token).as_deref(), Some("localhost"));
    }

    #[test]
    fn password_change_is_atomic_keeps_0600_and_rotates_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        let mgr = AuthManager::new(&conf, None, None);

        mgr.set_simple_password("oldpassword").unwrap();
        assert!(mgr.validate_simple_password("localhost", "oldpassword").is_ok());

        mgr.set_simple_password("newpassword").unwrap();
        assert!(mgr.validate_simple_password("localhost", "newpassword").is_ok());
        assert!(mgr.validate_simple_password("localhost", "oldpassword").is_err());

        let pw_file = tmp.path().join(SIMPLE_PW_FILENAME);
        let mode = fs::metadata(&pw_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "password sidecar must stay private");
        assert!(
            !pw_file.with_extension("saving").exists(),
            "tmp sibling must be renamed away"
        );
    }

    #[test]
    fn invalidation_keeps_the_acting_token_and_other_users() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        let mgr = AuthManager::new(&conf, None, None);
        let acting = mgr.create_privileged_session("localhost");
        let other_local = mgr.create_privileged_session("localhost");
        let ldap_admin = mgr.create_privileged_session("someadmin");

        assert_eq!(mgr.invalidate_sessions_for_user_except("localhost", &acting), 1);
        assert_eq!(mgr.validate(&acting).as_deref(), Some("localhost"));
        assert!(mgr.validate(&other_local).is_none());
        assert_eq!(mgr.validate(&ldap_admin).as_deref(), Some("someadmin"));

        // The drop must persist: a recycled manager over the same dir agrees.
        let mgr2 = AuthManager::new(&conf, None, None);
        assert!(mgr2.validate(&other_local).is_none());
        assert_eq!(mgr2.validate(&acting).as_deref(), Some("localhost"));
    }

    #[test]
    fn configured_session_ttl_governs_new_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        let mgr = AuthManager::new(&conf, None, Some(Duration::ZERO));
        assert_eq!(mgr.session_ttl(), Duration::ZERO);
        let token = mgr.create_privileged_session("localhost");
        assert!(
            mgr.validate(&token).is_none(),
            "a zero TTL session must be expired on arrival"
        );

        let mgr = AuthManager::new(&conf, None, None);
        assert_eq!(mgr.session_ttl(), DEFAULT_SESSION_TTL);
    }
}
