//! Kerberos principal classification (hybrid user TGT + machine keytab).

use crate::constants::MACHINE_PRINCIPAL_PREFIXES;

/// Returns the local part of a Kerberos principal before @.
/// Returns the whole string when the principal is unqualified.
pub fn principal_local_part(p: &str) -> &str {
    let p = p.trim();
    p.split('@').next().unwrap_or(p)
}

/// Returns the trailing segment of a machine principal local part.
/// For host/client@REALM the function returns client.
pub fn machine_short_name(principal: &str) -> &str {
    let local = principal_local_part(principal);
    local.rsplit('/').next().unwrap_or(local)
}

/// Classify machine vs user principals for Ganesha Root_Kerberos_Principal.
pub fn classify_principal(principal: &str, realm: &str, server_variants: &[String]) -> (bool, String) {
    let principal = principal.trim();
    let realm_u = realm.trim().to_ascii_uppercase();
    if !realm_u.is_empty() && principal.contains('@') {
        let p_realm = principal
            .rsplit_once('@')
            .map(|(_, r)| r.trim().to_ascii_uppercase())
            .unwrap_or_default();
        if !p_realm.is_empty() && p_realm != realm_u {
            return (
                false,
                format!("principal realm {} != configured {}", p_realm, realm_u),
            );
        }
    }

    let local = principal_local_part(principal).to_ascii_lowercase();

    if MACHINE_PRINCIPAL_PREFIXES
        .iter()
        .any(|pref| local.starts_with(pref))
    {
        return (true, format!("matches well-known machine prefix in {}", local));
    }

    for v in server_variants {
        let v_l = v.to_ascii_lowercase();
        if local == format!("host/{}", v_l) || local == format!("nfs/{}", v_l) {
            return (true, format!("matches server host principal for {}", v));
        }
    }

    if local == "host" || local == "nfs" || local == "root" {
        return (true, "bare machine service name".to_string());
    }

    (false, "treated as regular user principal".to_string())
}

/// Normalize principal for cache lookup. Uppercase realm, trim local part.
pub fn normalize_principal(p: &str) -> String {
    let p = p.trim();
    if let Some(at) = p.find('@') {
        let local = principal_local_part(p);
        let realm = p[at + 1..].trim();
        format!("{}@{}", local, realm.to_ascii_uppercase())
    } else {
        p.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_local_part_strips_realm() {
        assert_eq!(principal_local_part("alice@REALM"), "alice");
        assert_eq!(principal_local_part("host/client@REALM"), "host/client");
    }

    #[test]
    fn machine_short_name_takes_trailing_segment() {
        assert_eq!(machine_short_name("host/blue-lt@REALM"), "blue-lt");
        assert_eq!(machine_short_name("alice@REALM"), "alice");
    }

    #[test]
    fn principal_local_part_and_machine_short_name_trim_input() {
        assert_eq!(principal_local_part(" alice@REALM "), "alice");
        assert_eq!(machine_short_name(" host/blue-lt@REALM "), "blue-lt");
    }

    #[test]
    fn classify_machine_user_and_realm_rules() {
        let variants = vec!["myserver.example.com".to_string()];
        assert!(classify_principal("host/client@REALM", "REALM", &[]).0);
        assert!(classify_principal("nfs/client@REALM", "REALM", &[]).0);
        assert!(classify_principal("root/client@REALM", "REALM", &[]).0);
        assert!(classify_principal("host/myserver.example.com@REALM", "REALM", &variants).0);
        for name in ["host", "nfs", "root"] {
            assert!(classify_principal(name, "REALM", &[]).0, "{name}");
        }
        let (u, r) = classify_principal("alice@REALM", "REALM", &[]);
        assert!(!u);
        assert!(r.contains("regular user"));
        assert!(!classify_principal("app/hostbackup@REALM", "REALM", &[]).0);
        let (u2, r2) = classify_principal("alice@OTHER.REALM", "MY.REALM", &[]);
        assert!(!u2);
        assert!(r2.contains("OTHER.REALM"));
    }

    #[test]
    fn normalize_keeps_local_preserves_upper_realm() {
        assert_eq!(normalize_principal("alice@exAmPle.com"), "alice@EXAMPLE.COM");
        assert_eq!(normalize_principal(" alice@exAmPle.com "), "alice@EXAMPLE.COM");
        assert_eq!(normalize_principal("host/box"), "host/box");
    }
}
