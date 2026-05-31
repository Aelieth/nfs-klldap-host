//! WebUI TLS certificate handling (restored axum-server path).
//!
//! Supports:
//! - Externally provided certificates via WEBUI_TLS_CERT + WEBUI_TLS_KEY env vars.
//! - Automatic self-signed certificate generation when no certs are present.
//!
//! This restores the original direct HTTPS serving capability using axum-server.

use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, DistinguishedName, DnType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

/// Errors that can occur while ensuring or loading WebUI TLS material.
#[derive(Debug, Error)]
pub enum CertError {
    #[error("failed to generate self-signed certificate: {0}")]
    Generation(#[from] rcgen::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse PEM certificate or key")]
    Pem,

    #[error("invalid or incomplete certificate material")]
    Invalid,
}

/// Paths to the certificate and private key files.
#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Ensure valid WebUI TLS certificates exist.
///
/// Priority:
/// 1. If WEBUI_TLS_CERT and WEBUI_TLS_KEY env vars are set, use those paths.
/// 2. Otherwise, use the provided `cert_path` / `key_path`.
/// 3. If the files don't exist or are invalid, generate a fresh self-signed cert.
pub fn ensure_webui_tls_certs(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsPaths, CertError> {
    // Allow external certificates via environment (common in container deployments)
    if let (Ok(cert), Ok(key)) = (
        std::env::var("WEBUI_TLS_CERT"),
        std::env::var("WEBUI_TLS_KEY"),
    ) {
        let cert = PathBuf::from(cert);
        let key = PathBuf::from(key);
        if cert.exists() && key.exists() && load_cert_and_key(&cert, &key).is_ok() {
            return Ok(TlsPaths { cert, key });
        }
        // Fall through to provided paths / generation if external ones are missing/invalid
    }

    let cert_path = cert_path.as_ref().to_path_buf();
    let key_path = key_path.as_ref().to_path_buf();

    if cert_path.exists() && key_path.exists() && load_cert_and_key(&cert_path, &key_path).is_ok() {
        return Ok(TlsPaths {
            cert: cert_path,
            key: key_path,
        });
    }

    // Generate self-signed certificate
    let (cert_pem, key_pem) = generate_self_signed(hostname)?;

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&cert_path, &cert_pem)?;
    std::fs::write(&key_path, &key_pem)?;

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

fn generate_self_signed(hostname: &str) -> Result<(String, String), CertError> {
    let mut params = CertificateParams::new(vec![
        hostname.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    params.distinguished_name = dn;

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(3650);

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Load cert + key from PEM files into rustls DER types.
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
