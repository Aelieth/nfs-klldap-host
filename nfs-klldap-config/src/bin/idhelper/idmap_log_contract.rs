//! Single-source validator for live Ganesha 9.x idmap logs under Manage_Gids for user TGTs.
//! With UseGetpwnam=false (to take principal path), principal2uid + principal2grp calls uid2grp_allocate_by_principal for full 'user@' ; getgrouplist succeeds via nss/extrausers materialization for @ entries (Pwutils). See generate.rs.

use std::fs;
use std::path::Path;

#[allow(dead_code)]
pub fn validate_user_tgt_idmap_log(log_path: &Path, user_at: &str) -> Result<(), Vec<&'static str>> {
    let content = fs::read_to_string(log_path).unwrap_or_default();
    let mut errs = vec![];
    if content.contains("ADDED UID2GRP") || (content.contains("getgrouplist for user:") && !content.contains("my_getgrouplist_alloc")) {
        errs.push("fabricated or non-live getgrouplist line present");
    }
    if !content.contains("principal2uid") || !content.contains(user_at) {
        errs.push("missing principal2uid for user@REALM");
    }
    // Require uid2grp_allocate_by_principal was invoked for the user TGT principal (AC3)
    if !content.contains("uid2grp_allocate_by_principal") || !content.to_lowercase().contains(&user_at.to_lowercase()) {
        errs.push("missing uid2grp_allocate_by_principal call for user@ TGT principal");
    }
    if !content.contains("getgrouplist") || !content.contains("returned 2 groups") {
        errs.push("missing getgrouplist result with groups for TGT");
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
    #[test]
    fn accepts_live_9_6_use_getpwnam_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("live.log");
        let log = r#"
principal2uid :ID MAPPER :DEBUG :Get uid for testuser1@TESTLABBY.LOCAL using pw func
name_to_uid :ID MAPPER :INFO :getpwnam_r for uname: testuser1@TESTLABBY.LOCAL, uid: 3001, gid: 3005
Resolve principal testuser1@TESTLABBY.LOCAL to groups
uid2grp_allocate_by_principal testuser1@TESTLABBY.LOCAL uid 3001
my_getgrouplist_alloc :ID MAPPER :INFO :getgrouplist for uname: testuser1, returned 2 groups
"#;
        std::fs::write(&p, log).unwrap();
        assert!(validate_user_tgt_idmap_log(&p, "testuser1@TESTLABBY.LOCAL").is_ok());
    }

    #[test]
    fn validate_from_env_idmap_log_if_set() {
        if let Ok(p) = std::env::var("IDMAP_LOG") {
            let res = validate_user_tgt_idmap_log(Path::new(&p), "testuser1@TESTLABBY.LOCAL");
            if let Err(e) = &res {
                eprintln!("contract errs: {:?}", e);
            }
            assert!(res.is_ok(), "live log must pass uid2grp_allocate_by_principal + getgrouplist contract for user TGT");
        }
    }
}