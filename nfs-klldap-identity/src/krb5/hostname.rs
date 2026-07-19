//! NFS keytab hostname helpers (short/FQDN variants and alignment checks).
//!
//! When the system UTS name is short, the FQDN is synthesized as
//! `{short}.{realm_lower}` so keytab reminders, Navahi SRV targets, and cert
//! SANs match the Kerberos DNS domain convention used by generated
//! `[domain_realm]` maps. An already-dotted hostname is never re-qualified.

/// Short name plus optional FQDN for NFS service principals and adverts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsHostIdentity {
    /// First DNS label (or the full undotted name).
    pub short: String,
    /// Observed FQDN if the host already had a dot, else `{short}.{realm}` when
    /// the realm yields a usable DNS domain.
    pub fqdn: Option<String>,
}

impl NfsHostIdentity {
    /// Short first, then FQDN when it differs (keytab / SAN list order).
    pub fn variants(&self) -> Vec<String> {
        match &self.fqdn {
            Some(f) if !f.eq_ignore_ascii_case(&self.short) => {
                vec![self.short.clone(), f.clone()]
            }
            _ => {
                if self.short.is_empty() {
                    vec![]
                } else {
                    vec![self.short.clone()]
                }
            }
        }
    }

    /// Prefer the FQDN when known (display, avahi `<host-name>`, cert CN).
    pub fn preferred(&self) -> &str {
        self.fqdn.as_deref().unwrap_or(&self.short)
    }
}

/// DNS domain for FQDN synthesis: lowercased Kerberos realm (same string used
/// in generated `[domain_realm]` maps). Empty / placeholder-only → `None`.
fn realm_dns_domain(realm: &str) -> Option<String> {
    let r = realm.trim().trim_matches('.');
    if r.is_empty() {
        return None;
    }
    // Wizard / banner placeholders must not invent host.your.realm.
    if r.eq_ignore_ascii_case("YOUR.REALM") || r.eq_ignore_ascii_case("YOUR") {
        return None;
    }
    Some(r.to_ascii_lowercase())
}

/// Resolve short + FQDN from an observed host and Kerberos realm.
///
/// - Dotted host → short = first label, fqdn = host as observed (not re-qualified).
/// - Short host + multi-label realm → fqdn = `{short}.{realm_lower}`.
/// - Short host without a usable realm → fqdn = `None`.
pub fn resolve_nfs_host_identity(host: &str, realm: &str) -> NfsHostIdentity {
    let h = host.trim().trim_matches('.');
    if h.is_empty() {
        return NfsHostIdentity {
            short: String::new(),
            fqdn: None,
        };
    }

    let short = h.split('.').next().unwrap_or(h).to_string();

    if h.contains('.') {
        return NfsHostIdentity {
            short,
            fqdn: Some(h.to_string()),
        };
    }

    let fqdn = realm_dns_domain(realm).map(|domain| format!("{short}.{domain}"));
    NfsHostIdentity { short, fqdn }
}

/// Short and FQDN host variants for NFS service principals in the keytab.
///
/// When `host` is undotted and `realm` is a multi-label Kerberos realm, the
/// FQDN is synthesized as `{short}.{realm_lower}`.
pub fn nfs_keytab_host_variants(host: &str, realm: &str) -> Vec<String> {
    resolve_nfs_host_identity(host, realm).variants()
}

/// Formats recommended `nfs/<host>@REALM` principals for operator messaging.
pub fn format_nfs_principal_list(host: &str, realm: &str) -> String {
    nfs_keytab_host_variants(host, realm)
        .into_iter()
        .map(|h| format!("nfs/{}@{}", h, realm))
        .collect::<Vec<_>>()
        .join(", ")
}

/// True when `keytab_host` (from klist) matches container hostname.
/// Comparison accepts short names and FQDNs.
pub fn nfs_keytab_host_matches(keytab_host: &str, container_host: &str) -> bool {
    let k = keytab_host.trim().to_lowercase();
    let c = container_host.trim().to_lowercase();
    if k.is_empty() || c.is_empty() {
        return false;
    }
    if k == c {
        return true;
    }
    let k_short = k.split('.').next().unwrap_or(&k);
    let c_short = c.split('.').next().unwrap_or(&c);
    k_short == c_short
}

/// Returns true for 8-20 hex digits with no dot.
/// Typical of a Docker short container ID.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_short_plus_realm_synthesizes_fqdn() {
        let id = resolve_nfs_host_identity("aurora", "EXAMPLE.COM");
        assert_eq!(id.short, "aurora");
        assert_eq!(id.fqdn.as_deref(), Some("aurora.example.com"));
        assert_eq!(id.preferred(), "aurora.example.com");
        assert_eq!(
            id.variants(),
            vec!["aurora".to_string(), "aurora.example.com".to_string()]
        );
    }

    #[test]
    fn identity_already_fqdn_not_requalified() {
        let id = resolve_nfs_host_identity("aurora.other.net", "EXAMPLE.COM");
        assert_eq!(id.short, "aurora");
        assert_eq!(id.fqdn.as_deref(), Some("aurora.other.net"));
        assert_eq!(
            id.variants(),
            vec!["aurora".to_string(), "aurora.other.net".to_string()]
        );
    }

    #[test]
    fn identity_empty_or_placeholder_realm_stays_short() {
        let empty = resolve_nfs_host_identity("myserver", "");
        assert_eq!(empty.fqdn, None);
        assert_eq!(empty.variants(), vec!["myserver".to_string()]);

        let placeholder = resolve_nfs_host_identity("myserver", "YOUR.REALM");
        assert_eq!(placeholder.fqdn, None);
        assert_eq!(placeholder.variants(), vec!["myserver".to_string()]);
    }

    #[test]
    fn identity_single_label_realm_still_synthesizes() {
        // Matches derive_realm_from_uri("ldaps://klldap.test") → TEST and
        // generated [domain_realm] `.test = TEST`.
        let id = resolve_nfs_host_identity("myserver", "TEST");
        assert_eq!(id.fqdn.as_deref(), Some("myserver.test"));
    }

    #[test]
    fn identity_multi_label_realm_domain() {
        let id = resolve_nfs_host_identity("nas", "KRB.LAB.EXAMPLE.COM");
        assert_eq!(id.fqdn.as_deref(), Some("nas.krb.lab.example.com"));
    }

    #[test]
    fn variants_short_and_fqdn() {
        assert_eq!(
            nfs_keytab_host_variants("aurora.testdomain.com", "TESTDOMAIN.COM"),
            vec!["aurora".to_string(), "aurora.testdomain.com".to_string()]
        );
        assert_eq!(
            nfs_keytab_host_variants("myserver", "EXAMPLE.COM"),
            vec!["myserver".to_string(), "myserver.example.com".to_string()]
        );
        assert_eq!(
            nfs_keytab_host_variants("myserver", ""),
            vec!["myserver".to_string()]
        );
    }

    #[test]
    fn format_list_includes_synthesized_fqdn() {
        let list = format_nfs_principal_list("aurora", "EXAMPLE.COM");
        assert_eq!(
            list,
            "nfs/aurora@EXAMPLE.COM, nfs/aurora.example.com@EXAMPLE.COM"
        );
    }

    #[test]
    fn host_matches_short_or_fqdn() {
        assert!(nfs_keytab_host_matches("aurora", "aurora.testdomain.com"));
        assert!(nfs_keytab_host_matches("aurora.testdomain.com", "aurora"));
        assert!(!nfs_keytab_host_matches("other", "aurora.testdomain.com"));
    }

    #[test]
    fn docker_id_detection() {
        assert!(looks_like_docker_default_hostname("d81b4e782f65"));
        assert!(!looks_like_docker_default_hostname("aurora.testdomain.com"));
    }
}
