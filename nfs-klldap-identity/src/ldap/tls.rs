//! Single source of truth for LDAP TLS policy and custom-CA connection settings.

use std::sync::Arc;

use ldap3::LdapConnSettings;

/// (no_tls_verify, start_tls) from [sssd] TLS fields and ldap_uri scheme.
/// A custom CA cert means "verify against it" unless reqcert=never explicitly opts out.
pub fn ldap_tls_policy(
    ldap_uri: &str,
    reqcert: Option<&str>,
    cacert: Option<&str>,
    id_use_start_tls: Option<bool>,
) -> (bool, bool) {
    let has_custom = cacert.is_some_and(|s| !s.trim().is_empty());
    let no_verify = if has_custom {
        reqcert.is_some_and(|v| v.eq_ignore_ascii_case("never"))
    } else if ldap_uri.starts_with("ldaps://") {
        reqcert.is_none_or(|v| v.eq_ignore_ascii_case("never"))
    } else {
        reqcert.is_some_and(|v| v.eq_ignore_ascii_case("never"))
    };
    (no_verify, id_use_start_tls.unwrap_or(false))
}

/// rustls ClientConfig trusting the system roots plus the PEM certs in `cacert_path`.
fn client_config_with_cacert(cacert_path: &str) -> std::io::Result<Arc<rustls::ClientConfig>> {
    let mut store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = store.add(cert);
    }
    let pem = std::fs::read(cacert_path)?;
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut pem.as_slice()).flatten() {
        if store.add(cert).is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("no usable PEM certificates in {cacert_path}"),
        ));
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// LdapConnSettings honoring the shared policy; loads the custom CA when verifying.
pub fn ldap_conn_settings(
    no_tls_verify: bool,
    start_tls: bool,
    tls_cacert: Option<&str>,
) -> LdapConnSettings {
    // Bounded connect so a dead/filtered LDAP host cannot hang a resolver
    // worker thread (pooled-connection path has no other watchdog).
    let mut s = LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_secs(10));
    if start_tls {
        s = s.set_starttls(true);
    }
    if no_tls_verify {
        s = s.set_no_tls_verify(true);
    } else if let Some(ca) = tls_cacert.filter(|c| !c.trim().is_empty()) {
        match client_config_with_cacert(ca) {
            Ok(cfg) => s = s.set_config(cfg),
            Err(e) => eprintln!(
                "WARN [nfs-klldap-identity] ldap_tls_cacert '{ca}' unusable ({e}); \
                 falling back to system trust roots"
            ),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cacert_enables_verification_on_ldaps_without_reqcert() {
        let (no_verify, _) = ldap_tls_policy("ldaps://kl.example:636", None, Some("/ca.pem"), None);
        assert!(!no_verify, "custom CA must enable verification");
        // Without a CA, bare ldaps:// keeps the self-signed-friendly default.
        let (no_verify, _) = ldap_tls_policy("ldaps://kl.example:636", None, None, None);
        assert!(no_verify);
    }

    #[test]
    fn reqcert_never_wins_even_with_cacert() {
        let (no_verify, start) =
            ldap_tls_policy("ldaps://kl:636", Some("never"), Some("/ca.pem"), Some(true));
        assert!(no_verify);
        assert!(start);
    }

    #[test]
    fn plain_ldap_verifies_unless_reqcert_never() {
        assert!(!ldap_tls_policy("ldap://kl:389", None, None, None).0);
        assert!(ldap_tls_policy("ldap://kl:389", Some("NEVER"), None, None).0);
    }

    #[test]
    fn client_config_rejects_missing_or_empty_pem() {
        assert!(client_config_with_cacert("/nonexistent/ca.pem").is_err());
        let tmp = tempfile::NamedTempFile::new().unwrap();
        assert!(client_config_with_cacert(tmp.path().to_str().unwrap()).is_err());
    }
}
