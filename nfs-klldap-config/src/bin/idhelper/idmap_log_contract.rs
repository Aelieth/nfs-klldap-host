//! Validate 9.x idmap logs: UseGetpwnam=true krb5 TGT chain via getpwnam_r → getpwuid_r → getgrouplist.
//! Markers derived from Ganesha V9.6 uid2grp.c / idmapper.c LogInfo strings (not C symbol names).
//! NOTSUPP classification: ACL-path (OP_ACCESS ACL mask / GETATTR Permission check for ACL) vs identity-path.

use std::fs;
use std::path::Path;

/// True when log shows uid→groups fetch via NSS (uid2grp_allocate_by_uid path).
/// Ganesha logs `getpwuid_r for uid: N, gid: M, uname: …` (uid2grp.c) — not the C symbol name.
#[cfg(test)]
pub fn log_shows_uid_to_groups_nss_fetch(content: &str) -> bool {
    content.contains("getpwuid_r for uid:")
}

/// True when log shows successful supplemental group resolution.
/// Ganesha logs `getgrouplist for uname: NAME, returned N groups` (uid2grp.c my_getgrouplist_alloc).
#[cfg(test)]
pub fn log_shows_getgrouplist_success(content: &str) -> bool {
    content.contains("getgrouplist for uname:") && content.contains("returned") && content.contains("groups")
}

#[cfg(test)]
pub fn validate_user_tgt_idmap_log(log_path: &Path, user_at: &str) -> Result<(), Vec<&'static str>> {
    let content = fs::read_to_string(log_path).unwrap_or_default();
    let lower = content.to_lowercase();
    let user_lower = user_at.to_lowercase();
    let short = user_at.split('@').next().unwrap_or(user_at);
    let mut errs = vec![];

    // Reject known fabricated / operator-injected markers (not Ganesha LogInfo output).
    if content.contains("ADDED UID2GRP") {
        errs.push("fabricated ADDED UID2GRP marker");
    }
    if content.contains("getgrouplist for user:") {
        errs.push("fabricated getgrouplist for user: (Ganesha uses getgrouplist for uname:)");
    }
    if content.contains("uid2grp_allocate_by_uid uid:") {
        errs.push("fabricated uid2grp_allocate_by_uid uid: line (C symbol not logged)");
    }

    // principal2uid → getpwnam_r (idmapper.c / principal2uid use_getpwnam branch).
    let principal_mapped = (content.contains("principal2uid") || content.contains("Get uid for"))
        && content.contains(user_at);
    if !principal_mapped {
        errs.push("missing principal2uid / Get uid for user@REALM");
    }
    if !content.contains("getpwnam_r for uname:") || !content.contains(user_at) {
        errs.push("missing getpwnam_r for uname with full principal");
    }

    // uid2grp via uid path (uid2grp_allocate_by_uid internally; observable as getpwuid_r LogInfo).
    if !log_shows_uid_to_groups_nss_fetch(&content) {
        errs.push("missing getpwuid_r for uid (uid2grp NSS fetch via UseGetpwnam=true)");
    }

    if lower.contains("unsupported code path for principal") && lower.contains(&user_lower) {
        errs.push("Unsupported code path for user@ TGT principal (UseGetpwnam=false or _MSPAC stub)");
    }

    if !log_shows_getgrouplist_success(&content) {
        errs.push("missing getgrouplist for uname with returned N groups");
    }

    // Sanity: getgrouplist should reference short or @ form of the user.
    if !content.contains(short) && !content.contains(user_at) {
        errs.push("getgrouplist chain missing user short or @ principal name");
    }

    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

/// Classify NOTSUPP in a log file: ACL-path vs identity-path (see ganesha_log_contract).
#[cfg(test)]
pub fn classify_log_notsupp_path(log_path: &Path) -> nfs_klldap_config::NotsuppFailurePath {
    let content = fs::read_to_string(log_path).unwrap_or_default();
    nfs_klldap_config::classify_notsupp_failure_path(&content)
}

/// Export fragment must emit NOACL (0.9.40-style) before SecType for limited shares.
/// Read_Access_Check_Policy must be pre (if present) for noacl; never post. (No quotes around the value.)
#[cfg(test)]
pub fn validate_posix_only_export_fragment(frag: &str) -> Result<(), Vec<&'static str>> {
    let mut errs = vec![];
    if !frag.contains("Disable_ACL = true;") {
        errs.push("missing Disable_ACL");
    }
    if !frag.contains("Manage_Gids = true;") && !frag.contains("Manage_Gids = false;") {
        errs.push("missing Manage_Gids line for NOACL");
    }
    if frag.contains("Read_Access_Check_Policy = post;") {
        errs.push("NOACL must not contain Read_Access_Check_Policy = post;");
    }
    // If Read is present for noacl, it must be pre (new requirement)
    if frag.contains("Read_Access_Check_Policy") && !frag.contains("Read_Access_Check_Policy = pre;") {
        errs.push("NOACL Read_Access_Check_Policy (if present) must be pre (no quotes)");
    }
    if frag.contains("POSIX_ONLY_EXPORT") {
        errs.push("NOACL must not contain POSIX_ONLY_EXPORT marker");
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

    /// Authentic Ganesha 9.6 LogInfo strings from uid2grp.c / idmapper.c (V9.6 upstream).
    const AUTHENTIC_KRB5_USE_GETPWNAM_LOG: &str = r#"
principal2uid :ID MAPPER :DEBUG :Get uid for testuser1@TESTLABBY.LOCAL using pw func
name_to_uid :ID MAPPER :INFO :getpwnam_r for uname: testuser1@TESTLABBY.LOCAL, uid: 3001, gid: 3005
uid2grp :ID MAPPER :INFO :getpwuid_r for uid: 3001, gid: 3005, uname: testuser1
uid2grp :ID MAPPER :INFO :getgrouplist for uname: testuser1, returned 2 groups
"#;

    #[test]
    fn rejects_tampered() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("bad.log");
        std::fs::write(&p, "ADDED UID2GRP foo\ngetgrouplist for user: testuser1@X\n").unwrap();
        assert!(validate_user_tgt_idmap_log(&p, "testuser1@X").is_err());
    }

    #[test]
    fn rejects_fabricated_uid2grp_allocate_by_uid_line() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("fabricated.log");
        let log = r#"
principal2uid :ID MAPPER :DEBUG :Get uid for testuser1@TESTLABBY.LOCAL using pw func
name_to_uid :ID MAPPER :INFO :getpwnam_r for uname: testuser1@TESTLABBY.LOCAL, uid: 3001, gid: 3005
uid2grp_allocate_by_uid uid: 3001
getgrouplist for uname: testuser1, returned 2 groups
"#;
        std::fs::write(&p, log).unwrap();
        assert!(validate_user_tgt_idmap_log(&p, "testuser1@TESTLABBY.LOCAL").is_err());
    }

    /// Ganesha 9.6 RPCSEC_GSS still calls uid2grp(uid) when export Manage_Gids=false (nfs_creds.c:581-584).
    /// Observable markers are getpwuid_r + getgrouplist LogInfo, not export Manage_Gids flag.
    #[test]
    fn krb5_uid2grp_still_required_when_export_manage_gids_false() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("manage-false.log");
        std::fs::write(&p, AUTHENTIC_KRB5_USE_GETPWNAM_LOG).unwrap();
        assert!(validate_user_tgt_idmap_log(&p, "testuser1@TESTLABBY.LOCAL").is_ok());
        assert!(log_shows_uid_to_groups_nss_fetch(AUTHENTIC_KRB5_USE_GETPWNAM_LOG));
    }

    #[test]
    fn accepts_live_9_6_use_getpwnam_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("live.log");
        std::fs::write(&p, AUTHENTIC_KRB5_USE_GETPWNAM_LOG).unwrap();
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
    fn noacl_0_9_40_export_fragment_contract_matches_simple_guard() {
        let frag = r#"EXPORT {
    Disable_ACL = true;
    Manage_Gids = true;
    SecType = krb5p;
}"#;
        assert!(validate_posix_only_export_fragment(frag).is_ok());
    }

    #[test]
    fn idmap_log_contract_identity_getattr_notsupp_is_identity_path() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("diag.log");
        let log = r#"
uid2grp_allocate_by_principal :ID MAPPER :WARN :Unsupported code path for principal host/client-a@TESTLAB.LOCAL
process_one_op :NFS4 :DEBUG :Request 2: opcode 9 is OP_GETATTR
complete_op :NFS4 :DEBUG :Status of OP_GETATTR in position 2 = NFS4ERR_NOTSUPP
"#;
        std::fs::write(&p, log).unwrap();
        assert_eq!(
            classify_log_notsupp_path(&p),
            nfs_klldap_config::NotsuppFailurePath::IdentityPath
        );
    }

    #[test]
    fn validate_from_env_idmap_log_if_set() {
        if let Ok(p) = std::env::var("IDMAP_LOG") {
            let res = validate_user_tgt_idmap_log(Path::new(&p), "testuser1@TESTLABBY.LOCAL");
            if let Err(e) = &res {
                eprintln!("contract errs: {:?}", e);
            }
            assert!(res.is_ok(), "live log must pass getpwuid_r + getgrouplist contract for user TGT");
        }
    }
}