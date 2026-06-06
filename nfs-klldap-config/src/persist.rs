//! is_persistent_config (dev inode diff) + load_host_paths_only (tolerant for UI allow-list).

use std::path::{Path, PathBuf};

use crate::ConfigError;

/// Returns true if the given config path is on a persistent volume (i.e. a real
/// host bind mount) rather than living inside the container's own filesystem layer.
///
/// This is used for the guided first-run experience: we refuse to do meaningful
/// work until the user has mounted a real volume at /config (or wherever
/// NFS_CONFIG points).
#[cfg(unix)]
pub fn is_persistent_config(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }

    use std::os::unix::fs::MetadataExt;

    let config_meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let root_meta = match std::fs::metadata("/") {
        Ok(m) => m,
        Err(_) => return false,
    };

    // dev != root => host volume (not container rootfs)
    config_meta.dev() != root_meta.dev()
}

#[cfg(not(unix))]
pub fn is_persistent_config(_path: &Path) -> bool {
    // Conservative (assume persistent) on non-Unix.
    true
}

/// Load only the [[shares]] host_path entries from a config file.
///
/// This is intentionally tolerant of missing credentials / incomplete config
/// so the privileged permission helper can still enforce its allow-list even
/// if the rest of the TOML is in a transitional state. Only well-formed
/// absolute host_path values are returned.
pub fn load_host_paths_only(path: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let contents = std::fs::read_to_string(path).map_err(ConfigError::Io)?;

    #[derive(serde::Deserialize)]
    struct SharesOnly {
        #[serde(default)]
        shares: Vec<RawShare>,
    }
    #[derive(serde::Deserialize)]
    struct RawShare {
        host_path: Option<PathBuf>,
    }

    let partial: SharesOnly = toml::from_str(&contents).map_err(|e| ConfigError::Parse {
        path: path.display().to_string(),
        msg: e.to_string(),
    })?;

    Ok(partial
        .shares
        .into_iter()
        .filter_map(|s| s.host_path)
        .filter(|p| !p.as_os_str().is_empty())
        .collect())
}
