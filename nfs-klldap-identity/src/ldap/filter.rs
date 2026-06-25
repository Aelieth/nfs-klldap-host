//! LDAP filter escaping (identical semantics to nfs-klldap-ui LdapClient).

/// Escape an LDAP filter value.
pub fn escape_ldap_filter(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            0..=31 | 127 => out.push_str(&format!("\\{:02x}", b)),
            _ => out.push(b as char),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_filter_matches_expected() {
        assert_eq!(escape_ldap_filter("alice"), "alice");
        assert_eq!(escape_ldap_filter("a(b)c*\\"), "a\\28b\\29c\\2a\\5c");
        assert_eq!(escape_ldap_filter("user*name"), "user\\2aname");
    }
}