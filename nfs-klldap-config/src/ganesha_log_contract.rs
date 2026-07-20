//! Classify Ganesha log NOTSUPP.

#[cfg(test)]
use std::path::{Path, PathBuf};

/// Diagnosis for Ganesha 9.6 ACL-path defect on staging.
#[cfg(test)]
pub const GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB: &str =
    "Ganesha 9.6: Disable_ACL on noacl still lets nfs_access_op see ACL mask in some paths; \
     use container_path staging on acl-capable tree for full compatibility.";

/// Researched V9.6 EXPORT keys: no mode-only OP_ACCESS/GETATTR knob when Disa.
pub fn ganesha_96_has_mode_only_access_knob() -> bool {
    false
}

/// Failure path for NFS4ERR_NOTSUPP in ganesha.log compounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotsuppFailurePath {
    // OP_ACCESS ACL mask or GETATTR Permission check for ACL on noacl FS (e.
    AclPath,
    // Uid2grp/principal mapping broken (_MSPAC stub, missing getpwuid_r/get.
    IdentityPath,
    Unknown,
}

/// Path to the committed ACL-NOTSUPP reference transcript (classification tests).
#[cfg(test)]
pub fn acl_notsupp_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ganesha-acl-notsupp.log")
}

/// Load the committed ACL-NOTSUPP reference transcript.
#[cfg(test)]
pub fn load_acl_notsupp_fixture() -> std::io::Result<String> {
    std::fs::read_to_string(acl_notsupp_fixture_path())
}

fn line_is_identity_failure(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("unsupported code path for principal")
        || line.contains("Could not map")
        || (line.contains("uid2grp_allocate_by_principal") && lower.contains("unsupported"))
}

/// True when log shows uid2grp/principal identity chain failure (not ACL-path.
pub(crate) fn log_shows_identity_failure(content: &str) -> bool {
    content.lines().any(line_is_identity_failure)
}

fn window_has_op_access_notsupp(window: &[&str]) -> bool {
    window.iter().any(|l| {
        l.contains("Status of OP_ACCESS") && l.contains("NFS4ERR_NOTSUPP")
    })
}

/// True when OP_ACCESS ACL mask is followed within a few lines by OP_ACCESS N.
pub(crate) fn log_shows_acl_path_op_access_notsupp(content: &str) -> bool {
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

/// True when Permission check for ACL fails with NOTSUPP on the same GETATTR.
pub(crate) fn log_shows_acl_path_getattr_notsupp(content: &str) -> bool {
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

/// True when GETATTR skips ACL permission check (posix-only getattr path OK)
#[cfg(test)]
pub fn log_shows_posix_ok_getattr(content: &str) -> bool {
    content.contains("No permission check for ACL") && content.contains("OP_GETATTR")
}

/// Diagnosis for a clean client abort after successful session setup.
#[cfg(test)]
pub const CLIENT_ABORT_BEFORE_NAMESPACE_DIAGNOSIS: &str =
    "Server-side Kerberos auth and NFSv4.1 session setup succeeded; the client destroyed the \
     session before any namespace op (PUTROOTFH/LOOKUP/GETATTR). Failure is client-side: check \
     rpc.gssd logs, /etc/krb5.keytab, mount options (vers=4.2,sec=krb5*), and the client journal.";

#[cfg(test)]
fn op_status_ok(content: &str, op: &str) -> bool {
    let needle = format!("Status of {op} in position");
    content
        .lines()
        .any(|l| l.contains(&needle) && l.contains("NFS4_OK"))
}

/// True when EXCHANGE_ID/CREATE_SESSION/RECLAIM_COMPLETE all succeeded, the client then
/// destroyed session+clientid, and no namespace traversal op was ever attempted.
#[cfg(test)]
pub fn log_shows_client_abort_before_namespace(content: &str) -> bool {
    let namespace_attempted = [
        "OP_PUTROOTFH",
        "OP_PUTFH",
        "OP_LOOKUP",
        "OP_GETATTR",
        "OP_SECINFO",
        "OP_READDIR",
    ]
    .iter()
    .any(|op| content.contains(op));
    op_status_ok(content, "OP_EXCHANGE_ID")
        && op_status_ok(content, "OP_CREATE_SESSION")
        && op_status_ok(content, "OP_RECLAIM_COMPLETE")
        && op_status_ok(content, "OP_DESTROY_SESSION")
        && op_status_ok(content, "OP_DESTROY_CLIENTID")
        && !namespace_attempted
}

/// True when identity/principal failure and NOTSUPP occur in the same line wi.
pub(crate) fn log_shows_identity_path_notsupp(content: &str) -> bool {
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

/// Three signature lines from a ganesha.log for diagnosis evidence (OP_ACCESS ACL,
#[cfg(test)]
pub fn acl_notsupp_diagnosis_signatures(content: &str) -> (Option<String>, Option<String>, Option<String>) {
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

/// Validate an ACL-NOTSUPP transcript carries the three known failure/OK signatures.
#[cfg(test)]
pub fn validate_acl_notsupp_fixture(path: &Path) -> Result<(), String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let (op, ga_acl, ga_ok) = acl_notsupp_diagnosis_signatures(&content);
    if op.is_none() {
        return Err("fixture missing OP_ACCESS ACL mask line".into());
    }
    if ga_acl.is_none() {
        return Err("fixture missing GETATTR Permission check for ACL NOTSUPP line".into());
    }
    if ga_ok.is_none() {
        return Err("fixture missing No permission check for ACL getattr OK line".into());
    }
    if classify_notsupp_failure_path(&content) != NotsuppFailurePath::AclPath {
        return Err("fixture transcript must classify as ACL-path NOTSUPP".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_fixture_classifies_acl_path_notsupp() {
        let content = load_acl_notsupp_fixture().expect("committed ACL-NOTSUPP fixture must exist");
        assert!(log_shows_acl_path_op_access_notsupp(&content));
        assert!(log_shows_acl_path_getattr_notsupp(&content));
        assert!(log_shows_posix_ok_getattr(&content));
        assert!(!log_shows_identity_failure(&content));
        assert_eq!(
            classify_notsupp_failure_path(&content),
            NotsuppFailurePath::AclPath
        );
        validate_acl_notsupp_fixture(&acl_notsupp_fixture_path()).expect("fixture signatures");
        let (op, ga_acl, ga_ok) = acl_notsupp_diagnosis_signatures(&content);
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
uid2grp_allocate_by_principal :ID MAPPER :WARN :Unsupported code path for principal host/client-a@TESTLAB.LOCAL
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4ERR_NOTSUPP
"#;
        assert_eq!(classify_notsupp_failure_path(real), NotsuppFailurePath::IdentityPath);
    }

    // Condensed from a real 2026-07-08 capture: krb5 session up, torn down, no namespace ops.
    const CLEAN_ABORT_LOG: &str = r#"
nfs_null :NFS3 :DEBUG :REQUEST PROCESSING: Calling NFS_NULL
process_one_op :NFS4 :DEBUG :Request 0: opcode 42 is OP_EXCHANGE_ID
complete_op :NFS4 :DEBUG :Status of OP_EXCHANGE_ID in position 0 = NFS4_OK, op response size is 0 total response size is 36
process_one_op :NFS4 :DEBUG :Request 0: opcode 43 is OP_CREATE_SESSION
complete_op :NFS4 :DEBUG :Status of OP_CREATE_SESSION in position 0 = NFS4_OK, op response size is 112 total response size is 148
process_one_op :NFS4 :DEBUG :Request 0: opcode 53 is OP_SEQUENCE
complete_op :NFS4 :DEBUG :Status of OP_SEQUENCE in position 0 = NFS4_OK, op response size is 40 total response size is 76
process_one_op :NFS4 :DEBUG :Request 1: opcode 58 is OP_RECLAIM_COMPLETE
complete_op :NFS4 :DEBUG :Status of OP_RECLAIM_COMPLETE in position 1 = NFS4_OK, op response size is 4 total response size is 84
process_one_op :NFS4 :DEBUG :Request 0: opcode 44 is OP_DESTROY_SESSION
complete_op :NFS4 :DEBUG :Status of OP_DESTROY_SESSION in position 0 = NFS4_OK, op response size is 4 total response size is 40
process_one_op :NFS4 :DEBUG :Request 0: opcode 57 is OP_DESTROY_CLIENTID
complete_op :NFS4 :DEBUG :Status of OP_DESTROY_CLIENTID in position 0 = NFS4_OK, op response size is 4 total response size is 40
"#;

    #[test]
    fn clean_client_abort_detected_when_session_destroyed_without_namespace_ops() {
        assert!(log_shows_client_abort_before_namespace(CLEAN_ABORT_LOG));
        assert!(CLIENT_ABORT_BEFORE_NAMESPACE_DIAGNOSIS.contains("client-side"));
    }

    #[test]
    fn clean_client_abort_not_flagged_when_namespace_traversal_happened() {
        // A successful mount reaches GETATTR/PUTROOTFH before any later session teardown.
        let successful = format!(
            "{CLEAN_ABORT_LOG}\nprocess_one_op :NFS4 :DEBUG :Request 1: opcode 9 is OP_GETATTR\n\
             complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 1 = NFS4_OK"
        );
        assert!(!log_shows_client_abort_before_namespace(&successful));
        // Session still open (no DESTROY yet) is not an abort either.
        let in_flight: String = CLEAN_ABORT_LOG
            .lines()
            .filter(|l| !l.contains("OP_DESTROY_CLIENTID"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!log_shows_client_abort_before_namespace(&in_flight));
    }

    #[test]
    fn ganesha_96_no_mode_only_knob_documented_and_false() {
        assert!(!ganesha_96_has_mode_only_access_knob());
        assert!(GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB.contains("nfs_access_op"));
        assert!(GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB.contains("container_path"));
    }
}