//! Persistent config detection and tolerant host_path-only loading.

use std::path::{Path, PathBuf};

use crate::ConfigError;

/// True when config path is on a host bind mount, not container rootfs.
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

    // Dev != root => host volume (not container rootfs).
    config_meta.dev() != root_meta.dev()
}

#[cfg(not(unix))]
pub fn is_persistent_config(_path: &Path) -> bool {
    // Conservative (assume persistent) on non-Unix.
    true
}

/// Loads [[shares]] host_path entries only and tolerates incomplete config.
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
