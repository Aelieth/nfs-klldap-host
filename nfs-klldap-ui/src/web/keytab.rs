//! Supplies a display-only keytab banner that never gates authentication.

pub use nfs_klldap_config::KeytabInfo;

/// Return a warning when the keytab does not match the container hostname.
pub fn compute_keytab_alert(expected_host: &str, expected_realm: &str) -> Option<String> {
    nfs_klldap_config::get_keytab_info(expected_host, expected_realm).alert
}

/// Rich keytab status for the settings page.
pub fn get_keytab_info(expected_host: &str, expected_realm: &str) -> KeytabInfo {
    nfs_klldap_config::get_keytab_info(expected_host, expected_realm)
}


