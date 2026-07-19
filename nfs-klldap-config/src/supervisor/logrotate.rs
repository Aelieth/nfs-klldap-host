//! Size-capped copytruncate rotation for ganesha/webui/idhelper logs.
//! Copytruncate (not reopen): writers hold O_APPEND fds; truncating in place
//! needs no coordination. A ganesha SIGHUP would reread exports, so rotation
//! must never signal the daemon. Lines between copy and truncate may be lost.

use std::io;
use std::path::{Path, PathBuf};

/// One retained generation: `<log>.1` is overwritten on each rotation.
pub(crate) fn rotate_if_oversized(path: &Path, cap_bytes: u64) -> io::Result<bool> {
    if cap_bytes == 0 {
        return Ok(false);
    }
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return Ok(false),
    };
    if len <= cap_bytes {
        return Ok(false);
    }
    let rotated = PathBuf::from(format!("{}.1", path.display()));
    std::fs::copy(path, &rotated)?;
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?
        .sync_all()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_log_rotates_and_truncates() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("svc.log");
        std::fs::write(&log, vec![b'x'; 4096]).unwrap();
        assert!(rotate_if_oversized(&log, 1024).unwrap(), "over cap rotates");
        assert_eq!(std::fs::metadata(&log).unwrap().len(), 0, "log truncated");
        let kept = std::fs::metadata(tmp.path().join("svc.log.1")).unwrap();
        assert_eq!(kept.len(), 4096, "previous generation retained");
    }

    #[test]
    fn under_cap_missing_and_disabled_are_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("svc.log");
        std::fs::write(&log, b"small").unwrap();
        assert!(!rotate_if_oversized(&log, 1024).unwrap(), "under cap: no-op");
        assert!(!rotate_if_oversized(&log, 0).unwrap(), "cap 0 disables");
        assert_eq!(std::fs::read(&log).unwrap(), b"small");
        assert!(
            !rotate_if_oversized(&tmp.path().join("absent.log"), 1024).unwrap(),
            "missing file: no-op"
        );
    }
}
