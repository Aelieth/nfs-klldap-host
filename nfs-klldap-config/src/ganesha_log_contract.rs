//! Classify Ganesha 9.6 ganesha.log NFS4ERR_NOTSUPP: ACL-path vs identity-path.

use std::path::{Path, PathBuf};

/// Diagnosis string for Ganesha 9.6 ACL-path defect (still relevant for staging analysis or
/// misconfig where enable_acl=true on noacl or pre-0.9.70 fragments). NOACL path now uses
/// 0.9.40 simple Disable_ACL + Manage_Gids=false without Read_Access_Check_Policy.
pub const GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB: &str =
    "Ganesha 9.6: Disable_ACL on noacl still lets nfs_access_op see ACL mask in some paths; \
     use ganesha_path staging on acl-capable tree for full compatibility.";

/// Researched V9.6 EXPORT keys: no mode-only OP_ACCESS/GETATTR knob when Disable_ACL=true.
pub fn ganesha_96_has_mode_only_access_knob() -> bool {
    false
}

/// Failure path for NFS4ERR_NOTSUPP in ganesha.log compounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotsuppFailurePath {
    /// OP_ACCESS ACL mask or GETATTR Permission check for ACL on noacl FS (export flags insufficient).
    AclPath,
    /// uid2grp/principal mapping broken (_MSPAC stub, missing getpwuid_r/getgrouplist).
    IdentityPath,
    Unknown,
}

/// Path to repo-root logs.txt (runtime fixture for classification tests).
pub fn logs_txt_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../logs.txt")
}

/// Load repo-root logs.txt; fails if the reference transcript is missing.
pub fn load_logs_txt_fixture() -> std::io::Result<String> {
    std::fs::read_to_string(logs_txt_fixture_path())
}

fn line_is_identity_failure(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("unsupported code path for principal")
        || line.contains("Could not map")
        || (line.contains("uid2grp_allocate_by_principal") && lower.contains("unsupported"))
}

/// True when log shows uid2grp/principal identity chain failure (not ACL-path).
pub fn log_shows_identity_failure(content: &str) -> bool {
    content.lines().any(line_is_identity_failure)
}

fn window_has_op_access_notsupp(window: &[&str]) -> bool {
    window.iter().any(|l| {
        l.contains("Status of OP_ACCESS") && l.contains("NFS4ERR_NOTSUPP")
    })
}

/// True when OP_ACCESS ACL mask is followed within a few lines by OP_ACCESS NFS4ERR_NOTSUPP.
pub fn log_shows_acl_path_op_access_notsupp(content: &str) -> bool {
    if log_shows_identity_failure(content) {
        return false;
    }
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("access_mask = mode") && line.contains("ACL(") {
            let end = (i + 6).min(lines.len());
            if window_has_op_access_notsupp(&lines[i..end]) {
                return true;
            }
        }
    }
    false
}

fn window_has_getattr_notsupp(window: &[&str]) -> bool {
    window.iter().any(|l| {
        l.contains("Status of OP_GETATTR") && l.contains("NFS4ERR_NOTSUPP")
    })
}

/// True when Permission check for ACL fails with NOTSUPP on the same GETATTR compound.
pub fn log_shows_acl_path_getattr_notsupp(content: &str) -> bool {
    if log_shows_identity_failure(content) {
        return false;
    }
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("Permission check for ACL") && !line.contains("No permission check") {
            let end = (i + 8).min(lines.len());
            let window = &lines[i..end];
            let acl_fail = window
                .iter()
                .any(|l| l.contains("failed with Operation not supported"));
            if acl_fail && window_has_getattr_notsupp(window) {
                return true;
            }
        }
    }
    false
}

/// True when GETATTR skips ACL permission check (posix-only getattr path OK).
pub fn log_shows_posix_ok_getattr(content: &str) -> bool {
    content.contains("No permission check for ACL") && content.contains("OP_GETATTR")
}

/// True when identity/principal failure and NOTSUPP occur in the same line window.
pub fn log_shows_identity_path_notsupp(content: &str) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line_is_identity_failure(line) {
            let end = (i + 10).min(lines.len());
            let window = &lines[i..end];
            if window_has_op_access_notsupp(window) || window_has_getattr_notsupp(window) {
                return true;
            }
        }
    }
    false
}

/// Classify NOTSUPP root cause from a ganesha.log excerpt or full file.
pub fn classify_notsupp_failure_path(content: &str) -> NotsuppFailurePath {
    if log_shows_acl_path_op_access_notsupp(content) || log_shows_acl_path_getattr_notsupp(content) {
        return NotsuppFailurePath::AclPath;
    }
    if log_shows_identity_path_notsupp(content) {
        return NotsuppFailurePath::IdentityPath;
    }
    NotsuppFailurePath::Unknown
}

/// Three signature lines from logs.txt for diagnosis evidence (OP_ACCESS ACL, GETATTR ACL fail, GETATTR OK).
pub fn logs_txt_diagnosis_signatures(content: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut op_access = None;
    let mut getattr_acl = None;
    let mut getattr_ok = None;
    for line in content.lines() {
        if op_access.is_none() && line.contains("access_mask = mode") && line.contains("ACL(") {
            op_access = Some(line.to_string());
        }
        if getattr_acl.is_none()
            && line.contains("Permission check for ACL")
            && line.contains("failed with Operation not supported")
        {
            getattr_acl = Some(line.to_string());
        }
        if getattr_ok.is_none() && line.contains("No permission check for ACL") {
            getattr_ok = Some(line.to_string());
        }
    }
    (op_access, getattr_acl, getattr_ok)
}

/// Validate logs.txt fixture exists and carries the three known failure/OK signatures.
pub fn validate_logs_txt_fixture(path: &Path) -> Result<(), String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let (op, ga_acl, ga_ok) = logs_txt_diagnosis_signatures(&content);
    if op.is_none() {
        return Err("logs.txt missing OP_ACCESS ACL mask line".into());
    }
    if ga_acl.is_none() {
        return Err("logs.txt missing GETATTR Permission check for ACL NOTSUPP line".into());
    }
    if ga_ok.is_none() {
        return Err("logs.txt missing No permission check for ACL getattr OK line".into());
    }
    if classify_notsupp_failure_path(&content) != NotsuppFailurePath::AclPath {
        return Err("logs.txt full transcript must classify as ACL-path NOTSUPP".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_txt_fixture_classifies_acl_path_notsupp() {
        let content = load_logs_txt_fixture().expect("repo logs.txt must exist");
        assert!(log_shows_acl_path_op_access_notsupp(&content));
        assert!(log_shows_acl_path_getattr_notsupp(&content));
        assert!(log_shows_posix_ok_getattr(&content));
        assert!(!log_shows_identity_failure(&content));
        assert_eq!(
            classify_notsupp_failure_path(&content),
            NotsuppFailurePath::AclPath
        );
        validate_logs_txt_fixture(&logs_txt_fixture_path()).expect("logs.txt signatures");
        let (op, ga_acl, ga_ok) = logs_txt_diagnosis_signatures(&content);
        eprintln!("logs-diagnosis OP_ACCESS: {}", op.unwrap());
        eprintln!("logs-diagnosis GETATTR ACL: {}", ga_acl.unwrap());
        eprintln!("logs-diagnosis GETATTR OK: {}", ga_ok.unwrap());
    }

    #[test]
    fn getattr_acl_path_requires_permission_check_window_not_loose_contains() {
        let decoy = r#"
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4ERR_NOTSUPP
file_To_Fattr :NFS4 ACL :DEBUG :No permission check for ACL for obj 0x1
"#;
        assert!(!log_shows_acl_path_getattr_notsupp(decoy));
        let real = r#"
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
file_To_Fattr :NFS4 ACL :DEBUG :Permission check for ACL for obj 0x562dbefc2da8
file_To_Fattr :NFS4 ACL :DEBUG :Permission check for ACL for obj 0x562dbefc2da8 failed with Operation not supported
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4ERR_NOTSUPP
"#;
        assert!(log_shows_acl_path_getattr_notsupp(real));
    }

    #[test]
    fn identity_path_requires_principal_window_not_loose_opcode_contains() {
        let decoy = r#"
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4ERR_NOTSUPP
uid2grp_allocate_by_principal :ID MAPPER :WARN :Could not map user elsewhere
"#;
        assert_eq!(classify_notsupp_failure_path(decoy), NotsuppFailurePath::Unknown);
        let real = r#"
uid2grp_allocate_by_principal :ID MAPPER :WARN :Unsupported code path for principal host/blue-lt@SATOMLIN.COM
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4ERR_NOTSUPP
"#;
        assert_eq!(classify_notsupp_failure_path(real), NotsuppFailurePath::IdentityPath);
    }

    #[test]
    fn ganesha_96_no_mode_only_knob_documented_and_false() {
        assert!(!ganesha_96_has_mode_only_access_knob());
        assert!(GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB.contains("nfs_access_op"));
        assert!(GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB.contains("ganesha_path"));
    }
}