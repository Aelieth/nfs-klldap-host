//! Small pure helpers for displaying NFS keytab principal status in the UI.
//! Originally lived at the top of the monolithic web.rs (lines 21-126).
//! Only used at startup (main.rs) and stored in AppState for templates.

use std::process::Command;

/// Returns a user-friendly message describing whether the on-disk keytab
/// contains the expected `nfs/<host>@REALM` principal.
///
/// This version supports keytabs containing multiple principals for the same
/// host (e.g. both the short hostname and the FQDN, as is recommended).
pub fn compute_keytab_status_message(expected_host: &str, expected_realm: &str) -> String {
    let expected = format!("nfs/{}@{}", expected_host, expected_realm);

    match read_keytab_nfs_principals() {
        Ok(principals) => {
            let matching: Vec<&String> = principals
                .iter()
                .filter(|p| principal_host_matches(p, expected_host, expected_realm))
                .collect();

            if !matching.is_empty() {
                let actual = matching
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("Keytab principal: {} principal matches.", actual)
            } else {
                let found = if principals.is_empty() {
                    "none found".to_string()
                } else {
                    principals.join(", ")
                };
                format!(
                    "Keytab principal: {} principal does not match expected {}",
                    found, expected
                )
            }
        }
        Err(err) => {
            format!(
                "Keytab principal: {} (unable to read keytab: {})",
                expected, err
            )
        }
    }
}

fn principal_host_matches(principal: &str, expected_host: &str, expected_realm: &str) -> bool {
    let Some(rest) = principal.strip_prefix("nfs/") else {
        return false;
    };

    let Some((host_part, realm_part)) = rest.split_once('@') else {
        return false;
    };

    if !realm_part.eq_ignore_ascii_case(expected_realm) {
        return false;
    }

    let p = host_part.to_lowercase();
    let e = expected_host.to_lowercase();

    if p == e {
        return true;
    }

    let p_short = p.split('.').next().unwrap_or(&p);
    let e_short = e.split('.').next().unwrap_or(&e);

    p_short == e_short
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