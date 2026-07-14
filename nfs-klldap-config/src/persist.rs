//! Persistent config detection is tolerant.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::ConfigError;

/// Writes `bytes` to `path` atomically: a same-directory temp file is written,
/// fsync'd, then renamed over the target so a crash mid-write can never leave a
/// truncated config behind. The rename is atomic because the temp sits on the
/// same filesystem as `path`.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = tmp_sibling(path);
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        let _ = f.sync_all();
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// A temp path beside `path` on the same filesystem (keeps the rename atomic).
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".klldap-tmp");
    path.with_file_name(name)
}

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

    config_meta.dev() != root_meta.dev()
}

#[cfg(not(unix))]
pub fn is_persistent_config(_path: &Path) -> bool {
    true
}

/// Loads [[shares]] host_path entries only and tolerates incomplete config.
#[cfg(test)]
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
