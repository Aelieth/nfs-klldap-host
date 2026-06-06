//! URI parsing helpers (ldap/ldaps).
//!
//! These are pure functions with no side effects and are used both by
//! validation/derivation and by the generation engine + startup TUI.

/// Extract host from ldap/ldaps URI (used by validate + TUI).
pub fn extract_host_from_uri(uri: &str) -> String {
    let after = uri.split("://").nth(1).unwrap_or(uri);
    // IPv6 literal: ldaps://[2001:db8::1]:636  or ldaps://[::1]/...
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

/// Attempt to derive a Kerberos realm from an ldap/ldaps URI.
/// Used by both the generator and the guided startup TUI for display purposes.
/// Example: ldaps://kllap.example.com:6360 → "EXAMPLE.COM"
pub fn derive_realm_from_uri(uri: &str) -> Option<String> {
    // ldaps://kllap.example.com:6360 → EXAMPLE.COM
    // ldaps://sub.host.example.co.uk:636 → EXAMPLE.CO.UK (current behavior)
    let host = extract_host_from_uri(uri);
    if host.is_empty() {
        return None;
    }
    let domain = host.split_once('.').map(|(_, d)| d).unwrap_or(&host);
    Some(domain.to_uppercase())
}

/// Returns true if the host portion (from ldap_uri) is a literal IP address (v4 or v6).
/// Used to reject IP-based ldap_uri (DNS forward+reverse required for Kerberos NFS principals).
pub(crate) fn host_is_ip(host: &str) -> bool {
    let h = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    h.parse::<std::net::IpAddr>().is_ok()
}
