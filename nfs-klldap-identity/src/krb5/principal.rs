//! Kerberos principal classification (hybrid user TGT + machine keytab).

use crate::constants::MACHINE_PRINCIPAL_PREFIXES;

/// Classify machine (host/nfs/root) vs user principals; prefixes align with Ganesha Root_Kerberos_Principal.
pub fn classify_principal(principal: &str, _realm: &str, server_variants: &[String]) -> (bool, String) {
    let p = principal.trim();
    let lower = p.to_ascii_lowercase();

    let local = if let Some(at) = lower.rfind('@') {
        &lower[..at]
    } else {
        &lower
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_prefixes_classify_as_machine() {
        let (is_machine, _) = classify_principal("host/client.example.com@REALM", "REALM", &[]);
        assert!(is_machine);

        let (is_machine, _) = classify_principal("nfs/client@REALM", "REALM", &[]);
        assert!(is_machine);

        let (is_machine, _) = classify_principal("root/client@REALM", "REALM", &[]);
        assert!(is_machine);
    }

    #[test]
    fn user_principal_classifies_as_user() {
        let (is_machine, reason) = classify_principal("alice@REALM", "REALM", &[]);
        assert!(!is_machine);
        assert!(reason.contains("regular user"));
    }

    #[test]
    fn server_variant_host_principal() {
        let variants = vec!["myserver.example.com".to_string()];
        let (is_machine, _) =
            classify_principal("host/myserver.example.com@REALM", "REALM", &variants);
        assert!(is_machine);
    }

    #[test]
    fn bare_service_names_are_machine() {
        for name in ["host", "nfs", "root"] {
            let (is_machine, _) = classify_principal(name, "REALM", &[]);
            assert!(is_machine, "expected machine for {}", name);
        }
    }

    #[test]
    fn host_substring_in_username_does_not_classify_as_machine() {
        let (is_machine, _) = classify_principal("app/hostbackup@REALM", "REALM", &[]);
        assert!(!is_machine);
    }
}