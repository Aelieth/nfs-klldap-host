//! Ensure WebUI TLS: env override (NFS_KLLDAP_WEBUI_TLS_*) or rcgen.
//! Self-signed. Self-signed certs use SANs for host and localhost.

use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, DistinguishedName, DnType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::Item;
use thiserror::Error;

const DEFAULT_CERT_PATH: &str = "/var/lib/nfs-klldap/webui-certs/webui.crt";
const DEFAULT_KEY_PATH: &str = "/var/lib/nfs-klldap/webui-certs/webui.key";
const MAX_SANS: usize = 10;

/// Errors that can occur while ensuring or loading WebUI TLS material.
#[derive(Debug, Error)]
pub enum CertError {
    #[error("failed to generate self-signed certificate: {0}")]
    Generation(#[from] rcgen::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WebUI TLS is disabled (NFS_KLLDAP_WEBUI_TLS=off)")]
    TlsDisabled,
}

/// Paths to the certificate and private key files.
#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// True when NFS_KLLDAP_WEBUI_TLS=off; reverse proxy serves TLS instead.
pub fn webui_tls_disabled() -> bool {
    if let Ok(v) = std::env::var("NFS_KLLDAP_WEBUI_TLS") {
        let t = v.trim().to_ascii_lowercase();
        if t == "off" || t == "false" || t == "0" || t == "no" {
            return true;
        }
        if t == "on" || t == "true" || t == "1" || t == "yes" {
            return false;
        }
    }
    false
}

/// SAN entries used for the self-signed WebUI certificate (for startup banners).
pub fn cert_sans_for_host(hostname: &str) -> Vec<String> {
    collect_cert_sans(hostname)
}

/// Ensures WebUI TLS certs from env paths or generates self-signed ones.
pub fn ensure_webui_tls_certs(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsPaths, CertError> {
    if webui_tls_disabled() {
        return Err(CertError::TlsDisabled);
    }

    let cert_path = cert_path.as_ref().to_path_buf();
    let key_path = key_path.as_ref().to_path_buf();
    let external_env = external_tls_env_set();
    let managed_self_signed = is_managed_self_signed_path(&cert_path, &key_path);

    // Operator-provided material via NFS_KLLDAP_WEBUI_TLS_* env (both must be set).
    if external_env {
        if let (Ok(cert), Ok(key)) = (
            std::env::var("NFS_KLLDAP_WEBUI_TLS_CERT"),
            std::env::var("NFS_KLLDAP_WEBUI_TLS_KEY"),
        ) {
            let cert = PathBuf::from(cert);
            let key = PathBuf::from(key);
            if cert.exists() && key.exists() && existing_material_usable(&cert, &key, hostname, false)
            {
                return Ok(TlsPaths { cert, key });
            }
        }
    }

    if cert_path.exists()
        && key_path.exists()
        && existing_material_usable(&cert_path, &key_path, hostname, managed_self_signed)
    {
        return Ok(TlsPaths {
            cert: cert_path,
            key: key_path,
        });
    }

    write_self_signed_material(&cert_path, &key_path, hostname)
}

/// Deletes existing material and writes a fresh self-signed cert/key pair.
pub fn regenerate_webui_tls_certs(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsPaths, CertError> {
    let cert_path = cert_path.as_ref();
    let key_path = key_path.as_ref();
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(san_metadata_path(cert_path));
    let _ = std::fs::remove_file(hostname_metadata_path(cert_path));
    write_self_signed_material(cert_path, key_path, hostname)
}

fn write_self_signed_material(
    cert_path: &Path,
    key_path: &Path,
    hostname: &str,
) -> Result<TlsPaths, CertError> {
    let sans = collect_cert_sans(hostname);
    let (cert_pem, key_pem) = generate_self_signed(hostname, &sans)?;

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(cert_path, &cert_pem)?;
    std::fs::write(key_path, &key_pem)?;
    write_hostname_metadata(cert_path, hostname)?;
    write_san_metadata(cert_path, &sans)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(key_path, perms)?;
    }

    Ok(TlsPaths {
        cert: cert_path.to_path_buf(),
        key: key_path.to_path_buf(),
    })
}

fn external_tls_env_set() -> bool {
    std::env::var("NFS_KLLDAP_WEBUI_TLS_CERT").is_ok()
        && std::env::var("NFS_KLLDAP_WEBUI_TLS_KEY").is_ok()
}

fn is_managed_self_signed_path(cert_path: &Path, key_path: &Path) -> bool {
    !external_tls_env_set()
        && cert_path == Path::new(DEFAULT_CERT_PATH)
        && key_path == Path::new(DEFAULT_KEY_PATH)
}

fn existing_material_usable(
    cert_path: &Path,
    key_path: &Path,
    hostname: &str,
    check_sans: bool,
) -> bool {
    let Ok(cert_pem) = std::fs::read_to_string(cert_path) else {
        return false;
    };
    let Ok(key_pem) = std::fs::read_to_string(key_path) else {
        return false;
    };
    if !tls_material_valid(&cert_pem, &key_pem) {
        return false;
    }

    if let Some(stored_host) = read_hostname_metadata(cert_path) {
        return hosts_equivalent(&stored_host, hostname);
    }

    if let Some(stored) = read_san_metadata(cert_path) {
        let current = collect_cert_sans(hostname);
        return stored == current;
    }

    if check_sans {
        // Legacy managed self-signed material without metadata — regenerate once.
        return false;
    }

    true
}

fn hosts_equivalent(left: &str, right: &str) -> bool {
    let l = left.trim().trim_matches('.').to_ascii_lowercase();
    let r = right.trim().trim_matches('.').to_ascii_lowercase();
    !l.is_empty() && l == r
}

fn collect_cert_sans(hostname: &str) -> Vec<String> {
    let mut sans = Vec::new();
    let mut add = |value: &str| {
        let t = value.trim().trim_matches('.');
        if t.is_empty() || sans.iter().any(|s| s == t) {
            return;
        }
        if sans.len() < MAX_SANS {
            sans.push(t.to_string());
        }
    };

    for host in nfs_klldap_config::nfs_keytab_host_variants(hostname) {
        add(&host);
        if let Ok(addrs) = (host.as_str(), 0).to_socket_addrs() {
            for addr in addrs {
                match addr.ip() {
                    std::net::IpAddr::V4(v4) => add(&v4.to_string()),
                    std::net::IpAddr::V6(v6) => add(&v6.to_string()),
                }
            }
        }
    }

    add("localhost");
    add("127.0.0.1");

    if let Some(ip) = nfs_klldap_config::container_primary_ipv4() {
        if !nfs_klldap_config::is_docker_bridge_ipv4(&ip) {
            add(&ip);
        }
    }

    sans
}

fn generate_self_signed(hostname: &str, sans: &[String]) -> Result<(String, String), CertError> {
    let mut params = CertificateParams::new(sans.to_vec())?;

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

/// Validates PEM material the same way axum-server loads it at serve time.
fn tls_material_valid(cert_pem: &str, key_pem: &str) -> bool {
    let certs: Vec<Vec<u8>> = match rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(certs) if !certs.is_empty() => certs.into_iter().map(|c| c.to_vec()).collect(),
        _ => return false,
    };

    let mut key_vec: Vec<Vec<u8>> = rustls_pemfile::read_all(&mut key_pem.as_bytes())
        .filter_map(|item| match item.ok()? {
            Item::Sec1Key(key) => Some(key.secret_sec1_der().to_vec()),
            Item::Pkcs1Key(key) => Some(key.secret_pkcs1_der().to_vec()),
            Item::Pkcs8Key(key) => Some(key.secret_pkcs8_der().to_vec()),
            _ => None,
        })
        .collect();

    if key_vec.len() != 1 {
        return false;
    }

    let cert_chain: Vec<CertificateDer<'static>> =
        certs.into_iter().map(CertificateDer::from).collect();
    let key = match PrivateKeyDer::try_from(key_vec.pop().unwrap()) {
        Ok(k) => k,
        Err(_) => return false,
    };

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .is_ok()
}

fn san_metadata_path(cert_path: &Path) -> PathBuf {
    metadata_sidecar_path(cert_path, "sans")
}

fn hostname_metadata_path(cert_path: &Path) -> PathBuf {
    metadata_sidecar_path(cert_path, "host")
}

fn metadata_sidecar_path(cert_path: &Path, suffix: &str) -> PathBuf {
    let stem = cert_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "webui".to_string());
    cert_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.{suffix}"))
}

fn write_hostname_metadata(cert_path: &Path, hostname: &str) -> Result<(), CertError> {
    std::fs::write(hostname_metadata_path(cert_path), format!("{hostname}\n"))?;
    Ok(())
}

fn read_hostname_metadata(cert_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(hostname_metadata_path(cert_path)).ok()?;
    let host = text.lines().next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn write_san_metadata(cert_path: &Path, sans: &[String]) -> Result<(), CertError> {
    let body = sans.join("\n");
    std::fs::write(san_metadata_path(cert_path), format!("{body}\n"))?;
    Ok(())
}

fn read_san_metadata(cert_path: &Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(san_metadata_path(cert_path)).ok()?;
    let sans: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if sans.is_empty() {
        None
    } else {
        Some(sans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_test_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn generates_self_signed_cert_when_files_missing() {
        install_test_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("webui.crt");
        let key_path = dir.path().join("webui.key");

        let paths =
            ensure_webui_tls_certs(&cert_path, &key_path, "test-host.example.com").unwrap();

        assert!(paths.cert.exists());
        assert!(paths.key.exists());
        let cert_pem = std::fs::read_to_string(&paths.cert).unwrap();
        let key_pem = std::fs::read_to_string(&paths.key).unwrap();
        assert!(tls_material_valid(&cert_pem, &key_pem));
        let sans = read_san_metadata(&paths.cert).unwrap();
        assert!(sans.iter().any(|s| s == "test-host.example.com"));
    }

    #[test]
    fn reuses_existing_valid_certs() {
        install_test_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("webui.crt");
        let key_path = dir.path().join("webui.key");

        let first = ensure_webui_tls_certs(&cert_path, &key_path, "host1.example.com").unwrap();
        let second = ensure_webui_tls_certs(&cert_path, &key_path, "host1.example.com").unwrap();

        assert_eq!(first.cert, second.cert);
        assert_eq!(first.key, second.key);
        assert_eq!(
            std::fs::read(&first.cert).unwrap(),
            std::fs::read(&second.cert).unwrap()
        );
    }

    #[test]
    fn regenerates_when_hostname_changes() {
        install_test_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("webui.crt");
        let key_path = dir.path().join("webui.key");

        ensure_webui_tls_certs(&cert_path, &key_path, "alpha.unique.test").unwrap();
        assert_eq!(
            read_hostname_metadata(&cert_path).as_deref(),
            Some("alpha.unique.test")
        );
        let first_cert = std::fs::read(&cert_path).unwrap();

        ensure_webui_tls_certs(&cert_path, &key_path, "beta.unique.test").unwrap();
        assert_eq!(
            read_hostname_metadata(&cert_path).as_deref(),
            Some("beta.unique.test")
        );
        let second_cert = std::fs::read(&cert_path).unwrap();
        assert_ne!(first_cert, second_cert);
    }

    #[test]
    fn cert_sans_include_hostname_variants() {
        let sans = cert_sans_for_host("nfs-server.example.com");
        assert!(sans.iter().any(|s| s == "nfs-server"));
        assert!(sans.iter().any(|s| s == "nfs-server.example.com"));
        assert!(sans.iter().any(|s| s == "localhost"));
        assert!(sans.iter().any(|s| s == "127.0.0.1"));
    }

    #[test]
    fn tls_material_valid_rejects_mismatched_pair() {
        install_test_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert_a = dir.path().join("a.crt");
        let key_a = dir.path().join("a.key");
        let cert_b = dir.path().join("b.crt");
        let key_b = dir.path().join("b.key");

        ensure_webui_tls_certs(&cert_a, &key_a, "host-a").unwrap();
        ensure_webui_tls_certs(&cert_b, &key_b, "host-b").unwrap();

        let cert_pem = std::fs::read_to_string(&cert_a).unwrap();
        let key_pem = std::fs::read_to_string(&key_b).unwrap();
        assert!(!tls_material_valid(&cert_pem, &key_pem));
    }

    #[test]
    fn regenerate_clears_stale_material() {
        install_test_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("webui.crt");
        let key_path = dir.path().join("webui.key");

        ensure_webui_tls_certs(&cert_path, &key_path, "old-host").unwrap();
        let first = std::fs::read(&cert_path).unwrap();

        regenerate_webui_tls_certs(&cert_path, &key_path, "new-host").unwrap();
        let second = std::fs::read(&cert_path).unwrap();
        assert_ne!(first, second);
        let sans = read_san_metadata(&cert_path).unwrap();
        assert!(sans.iter().any(|s| s == "new-host"));
    }
}