//! Ensure WebUI TLS: env override (WEBUI_TLS_*) or self-signed via rcgen (SANs: host+localhost).
//! Self-signed written to stable /var/lib/... path (0600 key).

use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, DistinguishedName, DnType};
use thiserror::Error;

/// Errors that can occur while ensuring or loading WebUI TLS material.
#[derive(Debug, Error)]
pub enum CertError {
    #[error("failed to generate self-signed certificate: {0}")]
    Generation(#[from] rcgen::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WebUI TLS is disabled (WEBUI_TLS=off)")]
    TlsDisabled,
}

/// Paths to the certificate and private key files.
#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Returns true when WEBUI_TLS=off (case-insensitive). In this mode the WebUI
/// must not attempt to serve TLS or generate/require cert material; a reverse
/// proxy is expected in front (supplying X-Forwarded-Proto etc.).
pub fn webui_tls_disabled() -> bool {
    std::env::var("WEBUI_TLS")
        .map(|v| v.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
}

/// Priority: WEBUI_TLS_* env > provided paths > generate self-signed.
pub fn ensure_webui_tls_certs(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsPaths, CertError> {
    if webui_tls_disabled() {
        return Err(CertError::TlsDisabled);
    }

    // Allow external certificates via environment (common in container deployments)
    if let (Ok(cert), Ok(key)) = (
        std::env::var("WEBUI_TLS_CERT"),
        std::env::var("WEBUI_TLS_KEY"),
    ) {
        let cert = PathBuf::from(cert);
        let key = PathBuf::from(key);
        if cert.exists() && key.exists() && pem_files_are_parsable(&cert, &key) {
            return Ok(TlsPaths { cert, key });
        }
        // Fall through to provided paths / generation if external ones are missing/invalid
    }

    let cert_path = cert_path.as_ref().to_path_buf();
    let key_path = key_path.as_ref().to_path_buf();

    if cert_path.exists() && key_path.exists() && pem_files_are_parsable(&cert_path, &key_path) {
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

/// Cheap validation: can we at least parse the PEM files as cert(s) + private key?
/// (Actual serving is done by axum-server which does its own robust loading.)
fn pem_files_are_parsable(cert_path: &Path, key_path: &Path) -> bool {
    let Ok(cert_pem) = std::fs::read_to_string(cert_path) else {
        return false;
    };
    let Ok(key_pem) = std::fs::read_to_string(key_path) else {
        return false;
    };

    let certs_ok = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map(|c| !c.is_empty())
        .unwrap_or(false);

    let key_ok = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .ok()
        .flatten()
        .is_some();

    certs_ok && key_ok
}
