// ! NFS keytab hostname helpers (short/FQDN variants and alignment checks).

/// Short and FQDN host variants for NFS service principals in the keytab.
pub fn nfs_keytab_host_variants(host: &str) -> Vec<String> {
    let h = host.trim().trim_matches('.');
    if h.is_empty() {
        return vec![];
    }
    let short = h.split('.').next().unwrap_or(h).to_string();
    if short.eq_ignore_ascii_case(h) {
        vec![h.to_string()]
    } else {
        vec![short, h.to_string()]
    }
}

/// Formats recommended `nfs/<host>@REALM` principals for operator messaging.
pub fn format_nfs_principal_list(host: &str, realm: &str) -> String {
    nfs_keytab_host_variants(host)
        .into_iter()
        .map(|h| format!("nfs/{}@{}", h, realm))
        .collect::<Vec<_>>()
        .join(", ")
}

/// True if `keytab_host` (from klist) matches the container hostname (...
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

/// Returns true for 8-20 hex digits with no dot (typical Docker short...
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
    fn variants_short_and_fqdn() {
        assert_eq!(
            nfs_keytab_host_variants("aurora.testdomain.com"),
            vec!["aurora".to_string(), "aurora.testdomain.com".to_string()]
        );
        assert_eq!(nfs_keytab_host_variants("myserver"), vec!["myserver".to_string()]);
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