//! TLS certificate management for the WebUI.
//!
//! This module provides robust handling of the WebUI's HTTPS certificates.
//! It supports:
//! - Using externally provided certificates (via paths from the launcher).
//! - Automatically generating self-signed certificates when none are present
//!   (replacing the previous shell script generation for the self-signed case).
//!
//! The goal is to make the TLS setup fully testable in Rust and eliminate
//! fragile shell logic for the common self-signed path.

use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, DistinguishedName, DnType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

/// Errors that can occur while ensuring or loading WebUI TLS material.
#[derive(Debug, Error)]
pub enum CertError {
    #[error("failed to generate self-signed certificate: {0}")]
    Generation(#[from] rcgen::Error),

    #[error("I/O error while writing or reading certificate files: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse PEM certificate or key")]
    Pem,

    #[error("invalid or incomplete certificate material")]
    Invalid,
}

/// Result of ensuring TLS certificates exist.
#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Ensure that valid certificate and key files exist at the given paths.
///
/// - If both files already exist and are readable, they are returned as-is.
/// - Otherwise, a fresh self-signed certificate is generated (using the
///   provided hostname for the CN and SANs) and written to the locations.
///
/// This is safe to call on every startup. Generation only happens when needed.
pub fn ensure_webui_tls_certs(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsPaths, CertError> {
    let cert_path = cert_path.as_ref().to_path_buf();
    let key_path = key_path.as_ref().to_path_buf();

    // Fast path: both files already exist
    if cert_path.exists() && key_path.exists() {
        // Basic sanity: try to load them
        if load_cert_and_key(&cert_path, &key_path).is_ok() {
            return Ok(TlsPaths {
                cert: cert_path,
                key: key_path,
            });
        }
        // If loading fails, we fall through and regenerate.
    }

    // Generate a new self-signed certificate
    let (cert_pem, key_pem) = generate_self_signed(hostname)?;

    // Ensure parent directory exists
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&cert_path, &cert_pem)?;
    std::fs::write(&key_path, &key_pem)?;

    // Set restrictive permissions on the private key when possible.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_path, perms)?;
    }

    Ok(TlsPaths {
        cert: cert_path,
        key: key_path,
    })
}

/// Generate a self-signed certificate + private key as PEM strings.
fn generate_self_signed(hostname: &str) -> Result<(String, String), CertError> {
    // CertificateParams::new accepts subjectAltNames as strings and auto-detects DNS vs IP
    let mut params = CertificateParams::new(vec![
        hostname.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    params.distinguished_name = dn;

    // Validity period: now until ~10 years in the future
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(3650);

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok((cert_pem, key_pem))
}

/// Load a certificate and private key from PEM files on disk.
/// Returns the raw DER forms suitable for rustls.
pub fn load_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), CertError> {
    let cert_pem = std::fs::read_to_string(cert_path)?;
    let key_pem = std::fs::read_to_string(key_path)?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CertError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| CertError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?
        .ok_or(CertError::Pem)?;

    if certs.is_empty() {
        return Err(CertError::Invalid);
    }

    Ok((certs, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_self_signed_cert_when_files_missing() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("webui.crt");
        let key_path = dir.path().join("webui.key");

        let paths = ensure_webui_tls_certs(&cert_path, &key_path, "test-host.example.com").unwrap();

        assert!(paths.cert.exists());
        assert!(paths.key.exists());

        // Should be loadable
        let (certs, _key) = load_cert_and_key(&paths.cert, &paths.key).unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn reuses_existing_valid_certs() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("webui.crt");
        let key_path = dir.path().join("webui.key");

        // First call generates
        let first = ensure_webui_tls_certs(&cert_path, &key_path, "host1").unwrap();

        // Second call with same paths should reuse (no regeneration)
        let second = ensure_webui_tls_certs(&cert_path, &key_path, "host2").unwrap();

        assert_eq!(first.cert, second.cert);
        assert_eq!(first.key, second.key);
    }

    #[test]
    fn load_fails_on_missing_files() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("does-not-exist.crt");
        let key_path = dir.path().join("does-not-exist.key");

        let result = load_cert_and_key(&cert_path, &key_path);
        assert!(matches!(result, Err(CertError::Io(_))));
    }
}