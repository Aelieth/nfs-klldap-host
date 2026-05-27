//! Simple configuration for the management tool.
//!
//! Keeps things small and file-driven (no heavy frameworks).
//! The config controls security boundaries and how we invoke the privileged helper.

use serde::Deserialize;
use std::path::PathBuf;

/// A single NFS share managed by the tool.
/// Each share corresponds to one top-level Ganesha EXPORT block.
#[derive(Debug, Clone, Deserialize)]
pub struct Share {
    /// Human-friendly name for the share (used for filenames and UI)
    pub name: String,

    /// Absolute path on the *host* where the data lives.
    /// The management tool will only manage directories under this path.
    pub host_path: PathBuf,

    /// The NFS pseudo path clients will see (e.g. "/projectalpha" or "/export/projectalpha").
    /// This becomes the `Pseudo` (and usually `Path` inside the container) in the EXPORT block.
    pub export_path: String,

}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Directories the tool is allowed to manage (security boundary).
    /// Kept for backward compatibility; new configs should prefer the `shares` list.
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

    // ---------------------------------------------------------------------
    // Ganesha-specific settings (new in the Ganesha-only world)
    // ---------------------------------------------------------------------

    /// Name of the running Ganesha container (used for `docker exec` / `podman exec`)
    #[serde(default = "default_ganesha_container_name")]
    pub ganesha_container_name: String,

    /// Host-side directory that is bind-mounted into the container at
    /// /etc/ganesha/exports.d/. The tool writes native Ganesha EXPORT {} blocks here.
    #[serde(default = "default_ganesha_exports_dir")]
    pub ganesha_exports_dir: PathBuf,

    /// Explicit list of shares. This is the preferred model going forward.
    /// Each share gets its own Ganesha EXPORT block and a browsable tree
    /// in the management UI.
    #[serde(default)]
    pub shares: Vec<Share>,
}

fn default_helper_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/nfs-perm-helper")
}

fn default_use_sudo() -> bool {
    true
}

fn default_ganesha_container_name() -> String {
    "alma-nfs-kerb".to_string()
}

fn default_ganesha_exports_dir() -> PathBuf {
    // Sensible default that matches the example docker-compose.yml
    PathBuf::from("./ganesha-exports.d")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allowed_roots: vec![],
            helper_path: default_helper_path(),
            use_sudo: default_use_sudo(),
            lldap_graphql_url: None,
            ganesha_container_name: default_ganesha_container_name(),
            ganesha_exports_dir: default_ganesha_exports_dir(),
            shares: vec![],
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

        // Backward-compat / convenience: if no explicit shares are configured
        // but we have allowed_roots, synthesize simple shares from them.
        // This lets old configs keep working during the transition.
        if cfg.shares.is_empty() && !cfg.allowed_roots.is_empty() {
            for (i, root) in cfg.allowed_roots.iter().enumerate() {
                let name = root
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("share")
                    .to_string();

                cfg.shares.push(Share {
                    name: format!("{}-{}", name, i + 1),
                    host_path: root.clone(),
                    export_path: format!("/{}", name),
                });
            }
        }

        // Ensure we still have at least something for security boundaries
        if cfg.allowed_roots.is_empty() && !cfg.shares.is_empty() {
            cfg.allowed_roots = cfg.shares.iter().map(|s| s.host_path.clone()).collect();
        }

        if cfg.allowed_roots.is_empty() && cfg.shares.is_empty() {
            // Last-resort dev defaults — realistic for attached-drive only environments
            cfg.allowed_roots = vec![
                PathBuf::from("/media"),
            ];
            cfg.shares = vec![
                Share {
                    name: "project-alpha".to_string(),
                    host_path: PathBuf::from("/media/SSD-01/project-alpha"),
                    export_path: "/project-alpha".to_string(),
                },
                Share {
                    name: "backups".to_string(),
                    host_path: PathBuf::from("/media/SSD-01/backups"),
                    export_path: "/backups".to_string(),
                },
            ];
        }

        Ok(cfg)
    }

    /// Return all host paths that are considered managed roots (union of
    /// explicit allowed_roots and the host_path of every share).
    pub fn all_managed_roots(&self) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = self.allowed_roots.clone();
        for s in &self.shares {
            if !roots.contains(&s.host_path) {
                roots.push(s.host_path.clone());
            }
        }
        roots
    }
}
