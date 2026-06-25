//! Keytab status banner for WebUI; display-only, never gates auth.

pub use nfs_klldap_config::KeytabInfo;

/// Return a warning when the keytab does not match the container hostname.
pub fn compute_keytab_alert(expected_host: &str, expected_realm: &str) -> Option<String> {
    nfs_klldap_config::get_keytab_info(expected_host, expected_realm).alert
}

/// Rich keytab status for the settings page.
pub fn get_keytab_info(expected_host: &str, expected_realm: &str) -> KeytabInfo {
    nfs_klldap_config::get_keytab_info(expected_host, expected_realm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_mentions_principal_list_when_keytab_unreadable_or_missing() {
        let msg = compute_keytab_alert("aurora.test.com", "TEST.COM");
        assert!(msg.is_some());
        let text = msg.unwrap();
        assert!(text.contains("nfs/") || text.contains("unable to read"));
    }
}
