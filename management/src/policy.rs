//! Lightweight declarative policy for directories.
//!
//! Stored as small files next to the share (or in a parallel tree).
//! This gives the "save and apply" + repeatability the user wants,
//! while still reading the *actual* state live from the filesystem.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryPolicy {
    /// Human-friendly names (resolved via LLDAP at apply time)
    pub owner: String,
    pub group: String,

    /// Unix permission bits as octal string, e.g. "770"
    pub mode: String,

    /// Apply recursively to subdirectories and files?
    #[serde(default)]
    pub recursive: bool,

    /// Optional free-form note
    #[serde(default)]
    pub note: Option<String>,
}

impl DirectoryPolicy {
    pub fn policy_path_for_share(share_path: &PathBuf) -> PathBuf {
        // Simple convention: next to the directory or in a sidecar location
        let mut p = share_path.clone();
        p.set_extension("policy.toml");
        p
    }
}
