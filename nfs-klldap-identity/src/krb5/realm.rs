// ! Kerberos realm derivation from ldap/ldaps URIs.

/// Extract host from ldap/ldaps URI.
pub fn extract_host_from_uri(uri: &str) -> String {
    let after = uri.split("://").nth(1).unwrap_or(uri);
    if let Some(rest) = after.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    after
        .split([':', '/'])
        .next()
        .unwrap_or("localhost")
        .to_string()
}

/// Derive a Kerberos realm from an ldap/ldaps URI host.
/// Example: ldaps://kllap.example.com:6360 → "EXAMPLE.COM"
pub fn derive_realm_from_uri(uri: &str) -> Option<String> {
    let host = extract_host_from_uri(uri);
    if host.is_empty() {
        return None;
    }
    let domain = host.split_once('.').map(|(_, d)| d).unwrap_or(&host);
    Some(domain.to_uppercase())
}

/// Returns true if the host portion is a literal IP address (v4 or v6).
pub fn host_is_ip(host: &str) -> bool {
    let h = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    h.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_ipv4_and_port() {
        assert_eq!(
            extract_host_from_uri("ldaps://kllap.example.com:6360"),
            "kllap.example.com"
        );
    }

    #[test]
    fn extract_host_ipv6_literal() {
        assert_eq!(
            extract_host_from_uri("ldaps://[2001:db8::1]:636"),
            "2001:db8::1"
        );
    }

    #[test]
    fn derive_realm_from_fqdn() {
        assert_eq!(
            derive_realm_from_uri("ldaps://kllap.example.com:6360"),
            Some("EXAMPLE.COM".into())
        );
    }

    #[test]
    fn host_is_ip_detects_v4_and_v6() {
        assert!(host_is_ip("192.168.1.1"));
        assert!(host_is_ip("[::1]"));
        assert!(!host_is_ip("ldap.example.com"));
    }
}