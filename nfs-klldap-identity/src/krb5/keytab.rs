//! Unified keytab inspection via klist output parsing.

use std::path::Path;
use std::process::Command;

use super::hostname::{format_nfs_principal_list, nfs_keytab_host_matches};

const DEFAULT_KEYTAB_PATH: &str = "/etc/krb5.keytab";

/// Parse nfs/* service principals from klist stdout.
/// Handles both `klist -k` (principal in column 2) and `klist -k -t` (principal as last token).
pub fn parse_klist_nfs_principals(stdout: &str) -> Vec<String> {
    let mut found = Vec::new();

    for line in stdout.lines() {
        if !line.contains("nfs/") {
            continue;
        }
        for token in line.split_whitespace() {
            if token.starts_with("nfs/") && token.contains('@') {
                found.push(token.to_string());
            }
        }
    }

    found.sort();
    found.dedup();
    found
}

/// Extract unique host portions from nfs/<host>@REALM principals (startup TUI style).
pub fn parse_klist_nfs_hosts(stdout: &str) -> Vec<String> {
    let mut hosts: Vec<String> = parse_klist_nfs_principals(stdout)
        .into_iter()
        .filter_map(|p| {
            p.strip_prefix("nfs/")?
                .split_once('@')
                .map(|(host, _)| host.to_string())
        })
        .collect();

    hosts.sort();
    hosts.dedup();
    hosts
}

/// Run klist against a keytab and return nfs/* principals.
pub fn read_keytab_nfs_principals(
    keytab_path: &Path,
    include_timestamps: bool,
) -> Result<Vec<String>, String> {
    if !keytab_path.exists() {
        return Err(format!("keytab not found at {}", keytab_path.display()));
    }

    let mut args = vec!["-k"];
    if include_timestamps {
        args.push("-t");
    }
    let path_str = keytab_path.to_string_lossy();
    args.push(&path_str);

    let output = Command::new("klist")
        .args(&args)
        .output()
        .map_err(|e| format!("klist not available: {}", e))?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_klist_nfs_principals(&text))
}

/// Convenience wrapper using the default container keytab path.
pub fn read_default_keytab_nfs_principals(include_timestamps: bool) -> Result<Vec<String>, String> {
    read_keytab_nfs_principals(Path::new(DEFAULT_KEYTAB_PATH), include_timestamps)
}

/// Rich keytab status for operator UIs and diagnostics.
#[derive(Debug, Clone, Default)]
pub struct KeytabInfo {
    pub keytab_path: String,
    pub expected_host: String,
    pub expected_realm: String,
    pub found_nfs_principals: Vec<String>,
    pub alert: Option<String>,
}

/// Build keytab info and optional user-visible alert.
pub fn get_keytab_info(expected_host: &str, expected_realm: &str) -> KeytabInfo {
    let expected_list = format_nfs_principal_list(expected_host, expected_realm);
    let path = DEFAULT_KEYTAB_PATH;

    let (found, alert) = match read_default_keytab_nfs_principals(true) {
        Ok(principals) => {
            let matching: Vec<&String> = principals
                .iter()
                .filter(|p| principal_matches_host(p, expected_host, expected_realm))
                .collect();

            let alert = if !matching.is_empty() {
                None
            } else {
                let found_str = if principals.is_empty() {
                    "none found".to_string()
                } else {
                    principals.join(", ")
                };
                Some(format!(
                    "Keytab: no match for {}. Found: {}.",
                    expected_list, found_str
                ))
            };
            (principals, alert)
        }
        Err(err) => (
            vec![],
            Some(format!(
                "Keytab: expected {} (unable to read keytab: {}).",
                expected_list, err
            )),
        ),
    };

    KeytabInfo {
        keytab_path: path.to_string(),
        expected_host: expected_host.to_string(),
        expected_realm: expected_realm.to_string(),
        found_nfs_principals: found,
        alert,
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

#[cfg(test)]
mod tests {
    use super::*;

    const KLIST_K: &str = r#"Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- ----------
   2 nfs/aurora@TEST.COM
   1 nfs/aurora.test.com@TEST.COM
"#;

    const KLIST_KT: &str = r#"Keytab name: FILE:/etc/krb5.keytab
KVNO Timestamp           Principal
---- ------------------- ----------
   2 01/01/70 00:00:00   nfs/aurora@TEST.COM
   1 01/01/70 00:00:00   host/aurora@TEST.COM
"#;

    #[test]
    fn parse_klist_k_format() {
        let princs = parse_klist_nfs_principals(KLIST_K);
        assert_eq!(princs.len(), 2);
        assert!(princs.iter().any(|p| p == "nfs/aurora@TEST.COM"));
    }

    #[test]
    fn parse_klist_kt_format_uses_last_nfs_token() {
        let princs = parse_klist_nfs_principals(KLIST_KT);
        assert_eq!(princs, vec!["nfs/aurora@TEST.COM"]);
    }

    #[test]
    fn parse_hosts_extracts_host_portion() {
        let hosts = parse_klist_nfs_hosts(KLIST_K);
        assert!(hosts.contains(&"aurora".to_string()));
        assert!(hosts.contains(&"aurora.test.com".to_string()));
    }

    #[test]
    fn principal_matches_host_checks_realm() {
        assert!(principal_matches_host(
            "nfs/aurora@TEST.COM",
            "aurora.test.com",
            "TEST.COM"
        ));
        assert!(!principal_matches_host(
            "nfs/aurora@OTHER.COM",
            "aurora",
            "TEST.COM"
        ));
    }
}