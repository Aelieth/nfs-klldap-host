//! Classify Ganesha 9.6 ganesha.log NFS4ERR_NOTSUPP: ACL-path vs identity-path.

use std::path::{Path, PathBuf};

/// V9.6 export config has no knob for mode-only OP_ACCESS when Disable_ACL=true.
pub const GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB: &str =
    "Ganesha 9.6: Disable_ACL + Read_Access_Check_Policy=post do not force mode-only OP_ACCESS/GETATTR; \
     nfs_access_op still logs ACL(list_dir,...); use ganesha_path staging on noacl btrfs.";

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

/// True when log shows uid2grp/principal identity chain failure (not ACL-path).
pub fn log_shows_identity_failure(content: &str) -> bool {
    let lower = content.to_lowercase();
    lower.contains("unsupported code path for principal")
        || content.contains("Could not map")
        || (content.contains("uid2grp_allocate_by_principal")
            && lower.contains("unsupported"))
}

/// True when OP_ACCESS uses ACL mask and returns NFS4ERR_NOTSUPP without identity errors.
pub fn log_shows_acl_path_op_access_notsupp(content: &str) -> bool {
    if log_shows_identity_failure(content) {
        return false;
    }
    content.contains("OP_ACCESS")
        && content.contains("access_mask = mode")
        && content.contains("ACL(")
        && content.contains("NFS4ERR_NOTSUPP")
}

/// True when GETATTR runs Permission check for ACL → Operation not supported → NOTSUPP.
pub fn log_shows_acl_path_getattr_notsupp(content: &str) -> bool {
    if log_shows_identity_failure(content) {
        return false;
    }
    content.contains("Permission check for ACL")
        && content.contains("Operation not supported")
        && content.contains("OP_GETATTR")
        && content.contains("NFS4ERR_NOTSUPP")
}

/// True when GETATTR skips ACL permission check (posix-only getattr path OK).
pub fn log_shows_posix_ok_getattr(content: &str) -> bool {
    content.contains("No permission check for ACL") && content.contains("OP_GETATTR")
}

/// Classify NOTSUPP root cause from a ganesha.log excerpt or full file.
pub fn classify_notsupp_failure_path(content: &str) -> NotsuppFailurePath {
    if log_shows_identity_failure(content)
        && content.contains("NFS4ERR_NOTSUPP")
        && (content.contains("OP_GETATTR") || content.contains("OP_ACCESS"))
    {
        return NotsuppFailurePath::IdentityPath;
    }
    if log_shows_acl_path_op_access_notsupp(content) || log_shows_acl_path_getattr_notsupp(content) {
        return NotsuppFailurePath::AclPath;
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
        if getattr_acl.is_none() && line.contains("Permission check for ACL") && line.contains("failed with Operation not supported") {
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
    fn ganesha_96_no_mode_only_knob_used_in_export_note() {
        assert!(GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB.contains("nfs_access_op"));
        assert!(GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB.contains("ganesha_path"));
    }
}