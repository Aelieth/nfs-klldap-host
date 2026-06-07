//! Curated ignore lists for KLLDAP + SSSD (and dirsync clients).
//! Emitted into generated sssd.conf when kllldap_ignored_attributes = true (default).
//! See docs/ldap-integration.md for server-side application.

/// Attributes commonly requested by SSSD, dirsync tools, and AD-compat clients
/// on *user* entries that KLLDAP does not (and should not need to) provide.
pub const RECOMMENDED_IGNORED_USER_ATTRIBUTES: &[&str] = &[
    "accountexpires",
    "authorizedservice",
    "gecos",
    "host",
    "krblastpwdchange",
    "krbpasswordexpiration",
    "loginallowedtimemap",
    "logindisabled",
    "loginexpirationtime",
    "nsaccountlock",
    "passkey",
    "pwdattribute",
    "rhost",
    "shadowexpire",
    "shadowflag",
    "shadowinactive",
    "shadowlastchange",
    "shadowmax",
    "shadowmin",
    "shadowwarning",
    "sudohost",
    "useraccountcontrol",
    "usercertificate;binary",
    "userpassword",
];

/// Attributes commonly requested by SSSD and sync tools on *group* entries.
pub const RECOMMENDED_IGNORED_GROUP_ATTRIBUTES: &[&str] = &["memberuid", "userpassword", "sudohost"];

/// The recommended group membership attribute to use with KLLDAP when
/// ldap_schema = rfc2307bis. KLLDAP populates `member` (and `uniqueMember`)
/// with DNs automatically.
pub const RECOMMENDED_KLLDAP_GROUP_MEMBER: &str = "member";

/// Returns the recommended lists formatted as TOML array literals
/// ready to paste into a KLLDAP server configuration.
pub fn get_kllldap_ignored_attributes_toml() -> (String, String) {
    let user_list = RECOMMENDED_IGNORED_USER_ATTRIBUTES
        .iter()
        .map(|s| format!("\"{}\"", s))
        .collect::<Vec<_>>()
        .join(", ");

    let group_list = RECOMMENDED_IGNORED_GROUP_ATTRIBUTES
        .iter()
        .map(|s| format!("\"{}\"", s))
        .collect::<Vec<_>>()
        .join(", ");

    (format!("[{}]", user_list), format!("[{}]", group_list))
}

/// Verbose comment block appended to generated sssd.conf when ignores are enabled.
pub fn get_kllldap_ignored_attributes_comment_block() -> String {
    let (users, groups) = get_kllldap_ignored_attributes_toml();
    format!(
        r#"# -----------------------------------------------------------------------------
# KLLDAP server-side ignored attributes
# -----------------------------------------------------------------------------
# SSSD and similar clients request many AD-compat attributes KLLDAP does not store.
# Without server-side ignores, logs fill with "unknown attribute" noise and some
# clients retry aggressively (TLS disconnects, high CPU).
# Keep [sssd] kllldap_ignored_attributes = true (default) in nfs-klldap.conf.
#
# ldap_group_member = "{member}" when ignores are enabled (not legacy memberUid).
#
# To disable this setting add: "kllldap_ignored_attributes = false" in nfs-klldap.conf
# -----------------------------------------------------------------------------
ignored_user_attributes = {users}
ignored_group_attributes = {groups}
"#,
        users = users,
        groups = groups,
        member = RECOMMENDED_KLLDAP_GROUP_MEMBER,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_non_empty() {
        assert!(!RECOMMENDED_IGNORED_USER_ATTRIBUTES.is_empty());
        assert!(!RECOMMENDED_IGNORED_GROUP_ATTRIBUTES.is_empty());
    }

    #[test]
    fn toml_output_is_valid_array_syntax() {
        let (users, groups) = get_kllldap_ignored_attributes_toml();
        assert!(users.starts_with('[') && users.ends_with(']'));
        assert!(groups.starts_with('[') && groups.ends_with(']'));
        assert!(users.contains("gecos"));
        assert!(groups.contains("memberuid"));
    }

    #[test]
    fn comment_block_contains_guidance() {
        let block = get_kllldap_ignored_attributes_comment_block();
        assert!(block.contains("kllldap_ignored_attributes = false"));
        assert!(block.contains("ignored_user_attributes"));
        assert!(block.contains("member"));
    }
}
