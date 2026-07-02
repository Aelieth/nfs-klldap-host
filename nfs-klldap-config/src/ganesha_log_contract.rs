//! Classify Ganesha 9.6 ganesha.log NFS4ERR_NOTSUPP: ACL-path vs identity-path.
//! Signatures from logs.txt: Disable_ACL=true still runs nfs_access_op ACL mask and file_To_Fattr ACL checks.

/// V9.6 export config has no knob for mode-only OP_ACCESS when Disable_ACL=true.
/// Read_Access_Check_Policy only controls read timing; it does not skip nfs_access_op ACL(list_dir,...).
pub const GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB: &str =
    "Ganesha 9.6 V9.6: Disable_ACL + Read_Access_Check_Policy=post do not force mode-only OP_ACCESS/GETATTR; \
     nfs_access_op still logs ACL(list_dir,...) and file_To_Fattr may run Permission check for ACL.";

/// Failure path for NFS4ERR_NOTSUPP in ganesha.log compounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotsuppFailurePath {
    /// OP_ACCESS ACL mask or GETATTR Permission check for ACL on noacl FS (export flags insufficient).
    AclPath,
    /// uid2grp/principal mapping broken (_MSPAC stub, missing getpwuid_r/getgrouplist).
    IdentityPath,
    Unknown,
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

#[cfg(test)]
mod tests {
    use super::*;

    const LOGS_TXT_OP_ACCESS: &str = r#"
get_gsh_export :EXPORT :DEBUG :Found Export pseudo (/users) perms (options=07310000/4001f007 no_root_squash,     ,    ,               , No Manage_Gids,         ,                ,                ,                , krb5p) Read_Access_Check_Policy (post)
process_one_op :NFS4 :DEBUG :Request 2: opcode 3 is OP_ACCESS
nfs_access_op :NFS3 :DEBUG :access_mask = mode(rwx) ACL(list_dir,add_file,execute,add_subdirectory,delete_child)
complete_op :NFS4 :DEBUG :Status of OP_ACCESS in position 2 = NFS4ERR_NOTSUPP, op response size is 4 total response size is 92
"#;

    const LOGS_TXT_GETATTR_ACL: &str = r#"
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
file_To_Fattr :NFS4 ACL :DEBUG :Permission check for ACL for obj 0x562dbefc2da8
file_To_Fattr :NFS4 ACL :DEBUG :Permission check for ACL for obj 0x562dbefc2da8 failed with Operation not supported
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4ERR_NOTSUPP, op response size is 4 total response size is 92
"#;

    const LOGS_TXT_GETATTR_OK: &str = r#"
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
file_To_Fattr :NFS4 ACL :DEBUG :No permission check for ACL for obj 0x562dbefc2da8
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4_OK, op response size is 56 total response size is 144
"#;

    const IDENTITY_GETATTR_NOTSUPP: &str = r#"
uid2grp_allocate_by_principal :ID MAPPER :WARN :Unsupported code path for principal host/blue-lt@SATOMLIN.COM
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4ERR_NOTSUPP
"#;

    #[test]
    fn logs_txt_op_access_is_acl_path() {
        assert!(log_shows_acl_path_op_access_notsupp(LOGS_TXT_OP_ACCESS));
        assert_eq!(
            classify_notsupp_failure_path(LOGS_TXT_OP_ACCESS),
            NotsuppFailurePath::AclPath
        );
    }

    #[test]
    fn logs_txt_getattr_acl_check_is_acl_path() {
        assert!(log_shows_acl_path_getattr_notsupp(LOGS_TXT_GETATTR_ACL));
        assert_eq!(
            classify_notsupp_failure_path(LOGS_TXT_GETATTR_ACL),
            NotsuppFailurePath::AclPath
        );
    }

    #[test]
    fn logs_txt_getattr_no_acl_check_is_posix_ok() {
        assert!(log_shows_posix_ok_getattr(LOGS_TXT_GETATTR_OK));
        assert_eq!(classify_notsupp_failure_path(LOGS_TXT_GETATTR_OK), NotsuppFailurePath::Unknown);
    }

    #[test]
    fn identity_getattr_notsupp_is_identity_path() {
        assert!(log_shows_identity_failure(IDENTITY_GETATTR_NOTSUPP));
        assert_eq!(
            classify_notsupp_failure_path(IDENTITY_GETATTR_NOTSUPP),
            NotsuppFailurePath::IdentityPath
        );
    }

    #[test]
    fn acl_path_not_misclassified_as_identity() {
        assert!(!log_shows_identity_failure(LOGS_TXT_OP_ACCESS));
        assert!(!log_shows_identity_failure(LOGS_TXT_GETATTR_ACL));
    }
}