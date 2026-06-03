//! NFS keytab principal status for the WebUI (startup banner + settings).

use std::process::Command;

use nfs_klldap_config::{format_nfs_principal_list, nfs_keytab_host_matches};

/// Rich keytab status for the settings page (list of nfs/* principals + whether any match the expected host).
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct KeytabInfo {
    pub expected_host: String,
    pub expected_realm: String,
    pub found_nfs_principals: Vec<String>,
    /// If Some, a warning string (no matching principal, or read failure). If None, at least one match was present.
    pub alert: Option<String>,
}

/// User-visible warning when the on-disk keytab does not match the container hostname.
/// Returns `None` when a matching nfs/* principal is present (no banner needed).
pub fn compute_keytab_alert(expected_host: &str, expected_realm: &str) -> Option<String> {
    let expected_list = format_nfs_principal_list(expected_host, expected_realm);

    match read_keytab_nfs_principals() {
        Ok(principals) => {
            let matching: Vec<&String> = principals
                .iter()
                .filter(|p| principal_matches_host(p, expected_host, expected_realm))
                .collect();

            if !matching.is_empty() {
                None
            } else {
                let found = if principals.is_empty() {
                    "none found".to_string()
                } else {
                    principals.join(", ")
                };
                Some(format!(
                    "Keytab: no match for {}. Found: {}.",
                    expected_list, found
                ))
            }
        }
        Err(err) => Some(format!(
            "Keytab: expected {} (unable to read keytab: {}).",
            expected_list, err
        )),
    }
}

fn principal_matches_host(principal: &str, expected_host: &str, expected_realm: &str) -> bool {
    let Some(rest) = principal.strip_prefix("nfs/") else {
        return false;
    };
    let Some((host_part, realm_part)) = rest.split_once('@') else {
        return false;
    };
    if !realm_part.eq_ignore_ascii_case(expected_realm) {
        return false;
    }
    nfs_keytab_host_matches(host_part, expected_host)
}

fn read_keytab_nfs_principals() -> Result<Vec<String>, String> {
    let output = Command::new("klist")
        .args(["-k", "-t", "/etc/krb5.keytab"])
        .output()
        .map_err(|e| format!("klist not available: {}", e))?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut found = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(last_token) = trimmed.split_whitespace().last() {
            if last_token.starts_with("nfs/") && last_token.contains('@') {
                found.push(last_token.to_string());
            }
        }
    }

    Ok(found)
}

/// Return rich keytab info (always includes the list of found nfs principals) for display
/// in System Settings. Underline/highlight logic is done in the template using the expected_host.
pub fn get_keytab_info(expected_host: &str, expected_realm: &str) -> KeytabInfo {
    let alert = compute_keytab_alert(expected_host, expected_realm);
    let found = read_keytab_nfs_principals().unwrap_or_default();
    KeytabInfo {
        expected_host: expected_host.to_string(),
        expected_realm: expected_realm.to_string(),
        found_nfs_principals: found,
        alert,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_mentions_principal_list_when_keytab_unreadable_or_missing() {
        let msg = compute_keytab_alert("aurora.test.com", "TEST.COM");
        // In CI there is usually no keytab — expect a warning, not silence.
        assert!(msg.is_some());
        let text = msg.unwrap();
        assert!(text.contains("nfs/") || text.contains("unable to read"));
    }
}