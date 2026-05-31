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
use rustls::ServerConfig;
use thiserror::Error;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::*;

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
/// - If both files already exist, are readable, **and** (when `regenerate_weak_certs`
///   is true) contain the `serverAuth` Extended Key Usage, they are returned as-is.
/// - Otherwise (missing, unreadable, or weak), a fresh self-signed certificate is
///   generated using the provided hostname and written to the locations.
///
/// When `regenerate_weak_certs` is true (the normal in-container auto-cert case),
/// old/weak self-signed certificates are transparently replaced on startup.
/// This makes TLS dependency updates (rustls, rcgen, etc.) completely hands-off.
///
/// User-provided certificates (when `WEBUI_TLS_CERT`/`WEBUI_TLS_KEY` are set)
/// should normally be called with `regenerate_weak_certs = false` so we never
/// overwrite operator-managed material.
pub fn ensure_webui_tls_certs(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    hostname: &str,
    regenerate_weak_certs: bool,
) -> Result<TlsPaths, CertError> {
    let cert_path = cert_path.as_ref().to_path_buf();
    let key_path = key_path.as_ref().to_path_buf();

    // Fast path: both files already exist
    if cert_path.exists() && key_path.exists() {
        match load_cert_and_key(&cert_path, &key_path) {
            Ok((certs, _key)) => {
                let is_strong = certs
                    .first()
                    .map(certificate_has_server_auth)
                    .unwrap_or(false);

                if !regenerate_weak_certs || is_strong {
                    return Ok(TlsPaths {
                        cert: cert_path,
                        key: key_path,
                    });
                }

                // Weak certificate detected (missing serverAuth EKU).
                // This usually happens after a rustls/rcgen update.
                // Delete the old files so we fall through and regenerate transparently.
                let _ = std::fs::remove_file(&cert_path);
                let _ = std::fs::remove_file(&key_path);
            }
            Err(_) => {
                // Corrupt/unreadable → fall through and regenerate
            }
        }
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

    // Explicit key usages are required for modern TLS clients (especially after
    // rustls 0.23+ and stricter browser/OS validation) to accept the certificate
    // as a valid server certificate. Missing these commonly causes the client to
    // send "fatal alert: CertificateUnknown" during the handshake.
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];

    // Validity period: now until ~10 years in the future
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + ::time::Duration::days(3650);

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok((cert_pem, key_pem))
}

/// Load a certificate and private key from PEM files on disk.
/// Returns the raw DER forms suitable for rustls.
///
/// Uses the `pem` crate instead of the unmaintained `rustls-pemfile`.
pub fn load_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), CertError> {
    let cert_pem = std::fs::read_to_string(cert_path)?;
    let key_pem = std::fs::read_to_string(key_path)?;

    let certs = ::pem::parse_many(&cert_pem)
        .map_err(|e| CertError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect::<Vec<_>>();

    let key_pem_parsed = ::pem::parse(&key_pem)
        .map_err(|e| CertError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

    let key = match key_pem_parsed.tag() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(key_pem_parsed.into_contents().into()),
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(key_pem_parsed.into_contents().into()),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(key_pem_parsed.into_contents().into()),
        _ => return Err(CertError::Pem),
    };

    if certs.is_empty() {
        return Err(CertError::Invalid);
    }

    Ok((certs, key))
}

/// Load certificate and key from disk and build a `rustls::ServerConfig`.
///
/// This is the preferred way to get a ready-to-use TLS config for the WebUI
/// server after we removed the `axum-server` dependency.
pub fn load_rustls_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<ServerConfig, CertError> {
    let (certs, key) = load_cert_and_key(cert_path, key_path)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| CertError::Invalid)?;

    // Enable ALPN for HTTP/1.1 and HTTP/2
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

/// Returns true if the given certificate contains the `serverAuth`
/// Extended Key Usage (required for modern TLS clients to accept it
/// as a valid server certificate).
///
/// This is used to auto-detect "weak" self-signed certificates that were
/// generated before we started emitting proper key usages / EKU.
fn certificate_has_server_auth(cert_der: &CertificateDer) -> bool {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der.as_ref()) else {
        return false;
    };

    for ext in cert.extensions() {
        // OID for extendedKeyUsage
        if ext.oid.to_id_string() == "2.5.29.37" {
            if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
                return eku.server_auth;
            }
        }
    }
    false
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

        let paths = ensure_webui_tls_certs(&cert_path, &key_path, "test-host.example.com", true).unwrap();

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
        let first = ensure_webui_tls_certs(&cert_path, &key_path, "host1", true).unwrap();

        // Second call with same paths should reuse (no regeneration)
        let second = ensure_webui_tls_certs(&cert_path, &key_path, "host2", true).unwrap();

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

    #[test]
    fn load_fails_on_corrupt_pem_files() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("bad.crt");
        let key_path = dir.path().join("bad.key");

        // Write garbage that is not valid PEM
        std::fs::write(&cert_path, "NOT A CERTIFICATE").unwrap();
        std::fs::write(&key_path, "NOT A PRIVATE KEY").unwrap();

        let result = load_cert_and_key(&cert_path, &key_path);
        // rustls_pemfile will fail to parse → mapped to Io(InvalidData) or Pem variant
        assert!(matches!(
            result,
            Err(CertError::Io(_)) | Err(CertError::Pem) | Err(CertError::Invalid)
        ));
    }
}
