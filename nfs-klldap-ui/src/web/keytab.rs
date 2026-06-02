//! NFS keytab principal status for the WebUI (startup banner + settings).

use std::process::Command;

use nfs_klldap_config::{format_nfs_principal_list, nfs_keytab_host_matches};

/// Whether the on-disk keytab contains an nfs/* principal matching the container hostname.
pub fn compute_keytab_status_message(expected_host: &str, expected_realm: &str) -> String {
    let expected_list = format_nfs_principal_list(expected_host, expected_realm);

    match read_keytab_nfs_principals() {
        Ok(principals) => {
            let matching: Vec<&String> = principals
                .iter()
                .filter(|p| principal_matches_host(p, expected_host, expected_realm))
                .collect();

            if !matching.is_empty() {
                let actual = matching
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("Keytab: matched {} (expected one of: {}).", actual, expected_list)
            } else {
                let found = if principals.is_empty() {
                    "none found".to_string()
                } else {
                    principals.join(", ")
                };
                format!(
                    "Keytab: no match for {}. Found: {}.",
                    expected_list, found
                )
            }
        }
        Err(err) => format!(
            "Keytab: expected {} (unable to read keytab: {}).",
            expected_list, err
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_message_mentions_principal_list() {
        let msg = compute_keytab_status_message("aurora.test.com", "TEST.COM");
        assert!(msg.contains("nfs/") || msg.contains("unable to read"));
    }
}