//! Hostname derivation and detection helpers.
//!
//! Includes the recommended "-nfs" insertion convention and detection of
//! Docker's default short container IDs.

/// Compute the recommended container hostname for Kerberized NFS.
///
/// The container hostname must match the `nfs/<hostname>@REALM` principal in the keytab.
/// Because Docker's `--hostname` is used for both the system hostname and Kerberos
/// principal derivation, we need a stable, DNS-resolvable name.
///
/// Recommended convention: take the host's short name and insert "-nfs" before the
/// first dot (or append if there is no dot).
///
/// Examples:
/// - "aurora.satomlin.com" → "aurora-nfs.satomlin.com"
/// - "myserver"            → "myserver-nfs"
/// - "foo.bar.baz.co.uk"   → "foo-nfs.bar.baz.co.uk"
///
/// This is the value users should pass to `--hostname` (or compose `hostname:`).
pub fn suggested_nfs_hostname(host: &str) -> String {
    let h = host.trim();
    if h.is_empty() || h == "." {
        return "nfs-server".to_string();
    }
    // Remove any leading/trailing dots for safety
    let h = h.trim_matches('.');
    if h.is_empty() {
        return "nfs-server".to_string();
    }
    if let Some((first, rest)) = h.split_once('.') {
        if first.is_empty() {
            // Should not happen after trim, but be defensive
            format!("{}-nfs", h)
        } else {
            format!("{}-nfs.{}", first, rest)
        }
    } else {
        // No dot: simple hostname, just append
        format!("{}-nfs", h)
    }
}

/// Returns true if the string looks like a Docker auto-assigned default hostname
/// (the short container ID). These are 8-20 lowercase hex digits with no dot.
/// When we see one, we know the user did not pass --hostname and we should
/// (historical note — hostname handling is now based on --uts=host)
pub fn looks_like_docker_default_hostname(h: &str) -> bool {
    let h = h.trim();
    if h.contains('.') {
        return false;
    }
    let len = h.len();
    if !(8..=20).contains(&len) {
        return false;
    }
    h.chars().all(|c| c.is_ascii_hexdigit())
}

// Small hostname helper (no extra deps)
// Used by effective_hostname() in validate.rs
pub(crate) mod internal {
    pub fn get() -> Result<std::ffi::OsString, std::io::Error> {
        // Simple /proc/sys/kernel/hostname or env fallback
        if let Ok(h) = std::env::var("HOSTNAME") {
            return Ok(h.into());
        }
        let p = "/proc/sys/kernel/hostname";
        if let Ok(s) = std::fs::read_to_string(p) {
            return Ok(s.trim().to_string().into());
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine hostname",
        ))
    }
}
