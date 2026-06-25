//! POSIX LDAP attribute mapping and search-base derivation (no TOML/serde.
//! Deps).

use crate::constants::{
    DEFAULT_GROUP_GID_ATTR, DEFAULT_GROUP_MEMBER_ATTR_KLLDAP, DEFAULT_GROUP_MEMBER_ATTR_LEGACY,
    DEFAULT_GROUP_NAME_ATTR, DEFAULT_GROUP_OBJECT_CLASS, DEFAULT_USER_FULLNAME_ATTR,
    DEFAULT_USER_GID_ATTR, DEFAULT_USER_HOME_ATTR, DEFAULT_USER_NAME_ATTR,
    DEFAULT_USER_OBJECT_CLASS, DEFAULT_USER_PRINCIPAL_ATTR, DEFAULT_USER_SHELL_ATTR,
    DEFAULT_USER_UID_ATTR,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PosixAttributeMapping {
    pub user_object_class: String,
    pub group_object_class: String,
    pub user_name: String,
    pub user_uid_number: String,
    pub user_gid_number: String,
    pub user_home_directory: String,
    pub user_shell: String,
    pub user_full_name: String,
    pub group_name: String,
    pub group_gid_number: String,
    pub group_member: String,
    pub user_principal_name: String,
}

/// Plain inputs for resolving POSIX attribute names.
/// Mirrors [sssd] TOML fields.
#[derive(Debug, Clone, Default)]
pub struct PosixMappingInput {
    pub ldap_user_object_class: Option<String>,
    pub ldap_group_object_class: Option<String>,
    pub ldap_user_name: Option<String>,
    pub ldap_user_uid_number: Option<String>,
    pub ldap_user_gid_number: Option<String>,
    pub ldap_user_home_directory: Option<String>,
    pub ldap_user_shell: Option<String>,
    pub ldap_user_fullname: Option<String>,
    pub ldap_group_name: Option<String>,
    pub ldap_group_gid_number: Option<String>,
    pub ldap_group_member: Option<String>,
    pub ldap_user_principal_name: Option<String>,
    pub kllldap_ignored_attributes: Option<bool>,
}

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|v| !v.trim().is_empty())
}

/// Resolves POSIX attribute names from optional overrides.
/// Uses built-in defaults when overrides are absent.
pub fn resolve_posix_attribute_mapping(input: &PosixMappingInput) -> PosixAttributeMapping {
    let user_obj = non_empty(&input.ldap_user_object_class)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_USER_OBJECT_CLASS.to_string());

    let group_obj = non_empty(&input.ldap_group_object_class)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_GROUP_OBJECT_CLASS.to_string());

    let u_name = non_empty(&input.ldap_user_name)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_USER_NAME_ATTR.to_string());

    let u_uid = non_empty(&input.ldap_user_uid_number)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_USER_UID_ATTR.to_string());

    let u_gid = non_empty(&input.ldap_user_gid_number)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_USER_GID_ATTR.to_string());

    let u_home = non_empty(&input.ldap_user_home_directory)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_USER_HOME_ATTR.to_string());

    let u_shell = non_empty(&input.ldap_user_shell)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_USER_SHELL_ATTR.to_string());

    let u_full = non_empty(&input.ldap_user_fullname)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_USER_FULLNAME_ATTR.to_string());

    let g_name = non_empty(&input.ldap_group_name)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_GROUP_NAME_ATTR.to_string());

    let g_gid = non_empty(&input.ldap_group_gid_number)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_GROUP_GID_ATTR.to_string());

    let kllldap_mode = input.kllldap_ignored_attributes.unwrap_or(true);

    let g_member = non_empty(&input.ldap_group_member)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            if kllldap_mode {
                DEFAULT_GROUP_MEMBER_ATTR_KLLDAP.to_string()
            } else {
                DEFAULT_GROUP_MEMBER_ATTR_LEGACY.to_string()
            }
        });

    let u_principal = non_empty(&input.ldap_user_principal_name)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| DEFAULT_USER_PRINCIPAL_ATTR.to_string());

    PosixAttributeMapping {
        user_object_class: user_obj,
        group_object_class: group_obj,
        user_name: u_name,
        user_uid_number: u_uid,
        user_gid_number: u_gid,
        user_home_directory: u_home,
        user_shell: u_shell,
        user_full_name: u_full,
        group_name: g_name,
        group_gid_number: g_gid,
        group_member: g_member,
        user_principal_name: u_principal,
    }
}

/// Plain inputs for LDAP search base derivation.
#[derive(Debug, Clone, Default)]
pub struct LdapSearchBasesInput {
    pub ldap_search_base: Option<String>,
    pub ldap_user_search_base: Option<String>,
    pub ldap_group_search_base: Option<String>,
}

/// Effective user/group search bases (Subtree) from overrides.
/// Realm-derived defaults apply when overrides are absent.
pub fn effective_ldap_search_bases(input: &LdapSearchBasesInput, realm: &str) -> (String, String) {
    let search_base = input
        .ldap_search_base
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("dc={}", realm.to_lowercase().replace('.', ",dc=")));

    let user_base = input
        .ldap_user_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&search_base)
        .to_string();

    let group_base = input
        .ldap_group_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&search_base)
        .to_string();

    (user_base, group_base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_principal_attr_is_krb_principal_name() {
        let mapping = resolve_posix_attribute_mapping(&PosixMappingInput::default());
        assert_eq!(mapping.user_principal_name, DEFAULT_USER_PRINCIPAL_ATTR);
    }

    #[test]
    fn search_bases_use_explicit_user_ou() {
        let (user, _) = effective_ldap_search_bases(
            &LdapSearchBasesInput {
                ldap_user_search_base: Some("ou=people,dc=ex,dc=com".into()),
                ..Default::default()
            },
            "ex.com",
        );
        assert!(user.contains("people"));
    }
}
