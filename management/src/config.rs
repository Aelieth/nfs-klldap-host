//! Simple configuration for the management tool.
//!
//! Keeps things small and file-driven (no heavy frameworks).
//! The config controls security boundaries and how we invoke the privileged helper.

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Directories the tool is allowed to manage (security boundary)
    #[serde(default)]
    pub allowed_roots: Vec<PathBuf>,

    /// Path to the small privileged helper binary
    #[serde(default = "default_helper_path")]
    pub helper_path: PathBuf,

    /// Whether to prefix helper invocations with `sudo`
    /// (recommended when the helper is not setuid root)
    #[serde(default = "default_use_sudo")]
    pub use_sudo: bool,

    /// LLDAP / KLLDAP GraphQL endpoint (example)
    #[serde(default)]
    pub lldap_graphql_url: Option<String>,
}

fn default_helper_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/nfs-perm-helper")
}

fn default_use_sudo() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allowed_roots: vec![],
            helper_path: default_helper_path(),
            use_sudo: default_use_sudo(),
            lldap_graphql_url: None,
        }
    }
}

impl Config {
    /// Load from a TOML file. Falls back to defaults if file is missing.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config {}: {}", path.display(), e))?;

        let mut cfg: Self = toml::from_str(&contents)
            .map_err(|e| format!("Failed to parse config {}: {}", path.display(), e))?;

        // Ensure at least some roots are configured
        if cfg.allowed_roots.is_empty() {
            // Sensible defaults for development — override in production config
            cfg.allowed_roots = vec![
                PathBuf::from("/media"),
                PathBuf::from("/srv/nfs"),
            ];
        }

        Ok(cfg)
    }
}
