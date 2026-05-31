//! Recommended ignored attributes for KLLDAP servers.
//!
//! When using SSSD (and especially AD-style directory sync tools) against
//! KLLDAP, clients request a very large number of attributes that a minimal
//! KLLDAP instance will never have (shadow*, krb*, userAccountControl,
//! nsAccountLock, gecos, etc.).
//!
//! KLLDAP supports `ignored_user_attributes` and `ignored_group_attributes`
//! precisely to suppress the resulting warning spam without affecting real
//! POSIX attribute handling.
//!
//! This module provides the curated list derived from real production logs
//! (SSSD + dirsync-type clients) so the generator can emit ready-to-use
//! recommendations.

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
    "useraccountcontrol",
    "usercertificate;binary",
    "userpassword",
];

/// Attributes commonly requested by SSSD and sync tools on *group* entries.
pub const RECOMMENDED_IGNORED_GROUP_ATTRIBUTES: &[&str] = &["memberuid", "userpassword"];

/// The recommended group membership attribute to use with KLLDAP when
/// ldap_schema = rfc2307bis. KLLDAP populates `member` (and `uniqueMember`)
/// with DNs automatically. Using "member" here is much cleaner than the
/// legacy "memberUid" approach for pure KLLDAP deployments.
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

/// Returns a complete, copy-paste ready comment block for the end of
/// a generated sssd.conf (or as a standalone helper file).
pub fn get_kllldap_ignored_attributes_comment_block() -> String {
    let (users, groups) = get_kllldap_ignored_attributes_toml();

    format!(
        r#"# =============================================================================
# KLLDAP SERVER-SIDE IGNORED ATTRIBUTES (recommended)
# =============================================================================
# SSSD and many directory synchronization tools (AD-style "dirsync", etc.)
# request dozens of attributes that a minimal KLLDAP instance will never
# have. This produces a flood of "Ignoring unrecognized ... attribute"
# warnings on the KLLDAP side.
#
# KLLDAP supports server-side ignore lists exactly for this situation.
# Copy the two lines below into your KLLDAP server configuration
# (typically under the [ldap] or root section in lldap.toml or equivalent).
#
# For group membership with KLLDAP + rfc2307bis, we strongly recommend
# using "member" (or "uniqueMember") instead of the legacy "memberUid".
# The generator now defaults ldap_group_member accordingly when this
# KLLDAP mode is active.
#
# Special note for dedicated service accounts used as the SSSD bind DN
# (e.g. uid=dirsync,ou=sync,dc=... while normal users live under ou=people):
# These accounts frequently trigger the worst attribute spam because SSSD
# performs many internal operations against them. The ignores below + the
# generator's switch to "member" for groups are the primary defense against
# the spam → TLS hard-close → mangled base DN symptoms.
#
# See docs/ldap-integration.md for full instructions.
#
# To stop the generator from emitting this block, set in your nfs-klldap.conf:
#     [sssd]
#     kllldap_ignored_attributes = false
# =============================================================================
# Copy these two lines into your KLLDAP server config (lldap.toml or equivalent):
ignored_user_attributes = {users}
ignored_group_attributes = {groups}
#
# Also consider in your KLLDAP config (if not already set):
# ldap_group_member = "member"     # or "uniqueMember"
"#,
        users = users, groups = groups
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
        assert!(users.contains("useraccountcontrol"));
        assert!(groups.contains("memberuid"));
    }

    #[test]
    fn comment_block_contains_guidance() {
        let block = get_kllldap_ignored_attributes_comment_block();
        assert!(block.contains("kllldap_ignored_attributes = false"));
        assert!(block.contains("docs/ldap-integration.md"));
        assert!(block.contains("member")); // group membership recommendation
    }
}
