//! Validate 9.x idmap logs: Manage_Gids + UseGetpwnam=true drives uid2grp_allocate_by_uid for user@ TGT; getgrouplist via idhelper materialization.
//! B1 contract: OP_GETATTR/NOTSUPP on readdir compounds ties to broken identity (B2/B3), not export flags alone.

use std::fs;
use std::path::Path;

#[cfg(test)]
pub fn validate_user_tgt_idmap_log(log_path: &Path, user_at: &str) -> Result<(), Vec<&'static str>> {
    let content = fs::read_to_string(log_path).unwrap_or_default();
    let lower = content.to_lowercase();
    let user_lower = user_at.to_lowercase();
    let mut errs = vec![];
    if content.contains("ADDED UID2GRP") || (content.contains("getgrouplist for user:") && !content.contains("my_getgrouplist_alloc")) {
        errs.push("fabricated or non-live getgrouplist line present");
    }
    if !content.contains("principal2uid") || !content.contains(user_at) {
        errs.push("missing principal2uid for user@REALM");
    }
    // User TGT under UseGetpwnam=true: rpcsec_gss_fetch_managed_groups uses uid2grp(uid).
    if !content.contains("uid2grp_allocate_by_uid") {
        errs.push("missing uid2grp_allocate_by_uid for user TGT managed groups");
    }
    if lower.contains("unsupported code path for principal") && lower.contains(&user_lower) {
        errs.push("Unsupported code path for user@ TGT principal (UseGetpwnam=false or _MSPAC stub)");
    }
    if !content.contains("getgrouplist") || !content.contains("returned 2 groups") {
        errs.push("missing getgrouplist result with groups for TGT");
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

/// B1 diagnostic contract: NOTSUPP on OP_GETATTR follows identity failure (uid2grp unsupported).
#[cfg(test)]
pub fn validate_readdir_getattr_not_notsupp_when_identity_ok(log_path: &Path) -> Result<(), Vec<&'static str>> {
    let content = fs::read_to_string(log_path).unwrap_or_default();
    let mut errs = vec![];
    let identity_broken = content.contains("Unsupported code path for principal")
        || content.contains("Could not map");
    let getattr_notsupp = content.contains("OP_GETATTR") && content.contains("NFS4ERR_NOTSUPP");
    if getattr_notsupp && identity_broken {
        errs.push("OP_GETATTR NOTSUPP co-occurs with identity mapping failure (fix B2/B3 first)");
    }
    if getattr_notsupp && !identity_broken {
        errs.push("OP_GETATTR NOTSUPP without identity failure — export posix guard insufficient");
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

/// Export fragment must emit posix guard before SecType (measurable B1 change vs diagnostic 0.9.57).
#[cfg(test)]
pub fn validate_posix_only_export_fragment(frag: &str) -> Result<(), Vec<&'static str>> {
    let mut errs = vec![];
    if !frag.contains("Disable_ACL = true;") {
        errs.push("missing Disable_ACL");
    }
    if !frag.contains("Read_Access_Check_Policy = \"post\";") {
        errs.push("missing Read_Access_Check_Policy=post");
    }
    if !frag.contains("POSIX_ONLY_EXPORT") {
        errs.push("missing POSIX_ONLY_EXPORT marker");
    }
    let disable = frag.find("Disable_ACL = true;");
    let sec = frag.find("SecType =");
    if disable.is_none() || sec.is_none() || disable.unwrap() >= sec.unwrap() {
        errs.push("Disable_ACL must precede SecType");
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_tampered() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("bad.log");
        std::fs::write(&p, "ADDED UID2GRP foo\ngetgrouplist for user: testuser1@X\n").unwrap();
        assert!(validate_user_tgt_idmap_log(&p, "testuser1@X").is_err());
    }
    /// Ganesha 9.6 RPCSEC_GSS still calls uid2grp when export Manage_Gids=false (nfs_creds.c:581-584).
    #[test]
    fn krb5_uid2grp_still_required_when_export_manage_gids_false() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("manage-false.log");
        let log = r#"
principal2uid :ID MAPPER :DEBUG :Get uid for testuser1@TESTLABBY.LOCAL using pw func
name_to_uid :ID MAPPER :INFO :getpwnam_r for uname: testuser1@TESTLABBY.LOCAL, uid: 3001, gid: 3005
uid2grp_allocate_by_uid uid: 3001
my_getgrouplist_alloc :ID MAPPER :INFO :getgrouplist for uname: testuser1, returned 2 groups
"#;
        std::fs::write(&p, log).unwrap();
        assert!(validate_user_tgt_idmap_log(&p, "testuser1@TESTLABBY.LOCAL").is_ok());
    }

    #[test]
    fn accepts_live_9_6_use_getpwnam_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("live.log");
        let log = r#"
principal2uid :ID MAPPER :DEBUG :Get uid for testuser1@TESTLABBY.LOCAL using pw func
name_to_uid :ID MAPPER :INFO :getpwnam_r for uname: testuser1@TESTLABBY.LOCAL, uid: 3001, gid: 3005
getpwuid_r for uid: 3001, gid: 3005, uname: testuser1
uid2grp_allocate_by_uid uid: 3001
my_getgrouplist_alloc :ID MAPPER :INFO :getgrouplist for uname: testuser1, returned 2 groups
"#;
        std::fs::write(&p, log).unwrap();
        assert!(validate_user_tgt_idmap_log(&p, "testuser1@TESTLABBY.LOCAL").is_ok());
    }

    #[test]
    fn rejects_unsupported_principal_path_for_user_tgt() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("mspam.log");
        let log = r#"
principal2uid :ID MAPPER :DEBUG :Get uid for testuser1@TESTLABBY.LOCAL using pw func
uid2grp_allocate_by_principal :ID MAPPER :WARN :Unsupported code path for principal testuser1@TESTLABBY.LOCAL
getgrouplist for uname: testuser1, returned 2 groups
"#;
        std::fs::write(&p, log).unwrap();
        assert!(validate_user_tgt_idmap_log(&p, "testuser1@TESTLABBY.LOCAL").is_err());
    }

    #[test]
    fn posix_only_export_fragment_contract_matches_b1_guard() {
        let frag = r#"EXPORT {
    Disable_ACL = true;
    Manage_Gids = false;
    Read_Access_Check_Policy = "post";
    # POSIX_ONLY_EXPORT: posix getattr/access only (no ACL mask)
    SecType = krb5p;
}"#;
        assert!(validate_posix_only_export_fragment(frag).is_ok());
    }

    #[test]
    fn diagnostic_b1_notsupp_tied_to_identity_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("diag.log");
        let log = r#"
uid2grp_allocate_by_principal :ID MAPPER :WARN :Unsupported code path for principal host/blue-lt@SATOMLIN.COM
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4ERR_NOTSUPP
"#;
        std::fs::write(&p, log).unwrap();
        let res = validate_readdir_getattr_not_notsupp_when_identity_ok(&p);
        assert!(res.is_err(), "diagnostic log must flag identity+NOTSUPP coupling");
        assert!(res.unwrap_err()[0].contains("B2/B3"));
    }

    #[test]
    fn validate_from_env_idmap_log_if_set() {
        if let Ok(p) = std::env::var("IDMAP_LOG") {
            let res = validate_user_tgt_idmap_log(Path::new(&p), "testuser1@TESTLABBY.LOCAL");
            if let Err(e) = &res {
                eprintln!("contract errs: {:?}", e);
            }
            assert!(res.is_ok(), "live log must pass uid2grp_allocate_by_uid + getgrouplist contract for user TGT");
        }
    }
}