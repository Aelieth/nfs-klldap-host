//! Hybrid authentication for the in-container WebUI (v0.5+).
//!
//! Auth model (exactly as specified):
//! 1. Special immutable username "localhost" + bcrypt-hashed sidecar file
//!    next to nfs-klldap.conf (named `webui-password`, mode 0600).
//!    This user is the local machine admin — can create/manage shares on *this* host.
//! 2. Any other username → real LLDAP login (GraphQL) + membership in the
//!    configured `webui_admin_group` (default "lldap_admin").
//!    These users are network admins and can modify shares/settings on any machine.
//!
//! No sudo, no wheel, no host-side delegation. The container runs as root for
//! the services it owns; the WebUI performs direct FS operations via libc::chown.
//!
//! First-run: when the simple password sidecar does not exist, a special
//! setup form is shown that lets the operator set the initial "localhost" password.

use bcrypt::{hash, verify, DEFAULT_COST};
use rand::Rng;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant};

const SESSION_TTL: Duration = Duration::from_secs(12 * 3600); // 12 hours
const SIMPLE_PW_FILENAME: &str = "webui-password";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthRole {
    /// Logged in via the special "localhost" + simple sidecar password.
    /// This user can manage shares on the local machine only.
    LocalAdmin,
    /// Real LLDAP user who is a member of the webui_admin_group.
    /// Can manage shares/settings on any machine (network admin).
    LldapAdmin { username: String },
}

#[derive(Clone, Debug)]
pub struct Session {
    pub username: String,
    pub role: AuthRole,
    pub created: Instant,
}

impl Session {
    #[allow(dead_code)]
    pub fn is_privileged(&self) -> bool {
        matches!(
            self.role,
            AuthRole::LocalAdmin | AuthRole::LldapAdmin { .. }
        )
    }
}

pub struct AuthManager {
    /// token -> session
    sessions: RwLock<HashMap<String, Session>>,
    /// Absolute path to the simple password sidecar (next to nfs-klldap.conf)
    simple_pw_path: PathBuf,
    /// Effective admin group name (from [management] webui_admin_group)
    admin_group: String,
}

impl AuthManager {
    #[allow(dead_code)]
    /// Create a new manager.
    /// `config_path` is the path to nfs-klldap.conf; the sidecar lives beside it.
    /// `admin_group` comes from the loaded config (falls back to "lldap_admin").
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

    #[allow(dead_code)]
    pub fn simple_pw_path(&self) -> &Path {
        &self.simple_pw_path
    }

    // ---------------------------------------------------------------------
    // Simple password (localhost) handling
    // ---------------------------------------------------------------------

    /// Returns true if a simple password sidecar already exists (first-run is over).
    pub fn has_simple_password(&self) -> bool {
        self.simple_pw_path.exists()
    }

    /// Set (or overwrite) the simple "localhost" password.
    /// The file is written with mode 0600 and contains a bcrypt hash.
    /// This is the only way the initial local admin password is ever stored.
    pub fn set_simple_password(&self, password: &str) -> Result<(), String> {
        if password.trim().is_empty() {
            return Err("Password cannot be empty".to_string());
        }
        if password.len() < 8 {
            return Err("Password must be at least 8 characters".to_string());
        }

        let hash =
            hash(password, DEFAULT_COST).map_err(|e| format!("failed to hash password: {}", e))?;

        // Ensure parent directory exists (usually /config or the dir containing the .conf)
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

        file.write_all(hash.as_bytes())
            .map_err(|e| format!("write failed: {}", e))?;
        file.write_all(b"\n")
            .map_err(|e| format!("write failed: {}", e))?;
        file.sync_all().ok();

        Ok(())
    }

    /// Validate the special "localhost" user against the bcrypt sidecar.
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

        if verify(password, &stored).unwrap_or(false) {
            Ok(())
        } else {
            Err("Invalid password for 'localhost'".to_string())
        }
    }

    // ---------------------------------------------------------------------
    // Session management (used after either auth path succeeds)
    // ---------------------------------------------------------------------

    /// Create a privileged session. The caller has already performed the
    /// appropriate authentication (simple pw for localhost, or LLDAP+group for others).
    pub fn create_privileged_session(&self, username: &str, role: AuthRole) -> String {
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
            role,
            created: Instant::now(),
        };

        let mut map = self.sessions.write().unwrap();
        map.insert(token.clone(), session);

        // Opportunistic cleanup
        let now = Instant::now();
        map.retain(|_, s| now.duration_since(s.created) < SESSION_TTL);

        token
    }

    /// Legacy-friendly wrapper: creates a LocalAdmin session for "localhost".
    #[allow(dead_code)]
    pub fn create_session(&self, username: &str) -> String {
        // Treat unknown callers as LocalAdmin for backward compatibility during transition.
        // Real LLDAP sessions should go through create_privileged_session with the correct role.
        let role = if username == "localhost" {
            AuthRole::LocalAdmin
        } else {
            AuthRole::LldapAdmin {
                username: username.to_string(),
            }
        };
        self.create_privileged_session(username, role)
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

    /// Return the full role for a valid session (used for privilege gating).
    #[allow(dead_code)]
    pub fn validate_with_role(&self, token: &str) -> Option<AuthRole> {
        let mut map = self.sessions.write().unwrap();
        if let Some(session) = map.get(token) {
            if Instant::now().duration_since(session.created) < SESSION_TTL {
                return Some(session.role.clone());
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

    /// Quick check: does this token belong to a privileged user?
    #[allow(dead_code)]
    pub fn is_privileged(&self, token: &str) -> bool {
        if let Some(role) = self.validate_with_role(token) {
            matches!(role, AuthRole::LocalAdmin | AuthRole::LldapAdmin { .. })
        } else {
            false
        }
    }
}
