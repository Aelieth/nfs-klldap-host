//! Bridges config to IdLdapResolver.

use crate::SssdSection;

pub use nfs_klldap_identity::{
    classify_principal, machine_short_name,
    normalize_principal, parse_getent_passwd, parse_group_row,
    parse_passwd_row, principal_local_part,
    IdLdapResolver, IdMapSnapshot,
    LdapResolverInputs, LdapSearchBasesInput, PosixGroupEntry, PosixMappingInput, PosixUserEntry,
};

/// Build LdapResolverInputs from ldap_uri, [sssd], and Kerberos realm.
pub fn sssd_resolver_inputs(ldap_uri: &str, sssd: &SssdSection, realm: &str) -> LdapResolverInputs {
    LdapResolverInputs {
        ldap_uri: ldap_uri.to_string(),
        realm: realm.to_string(),
        search_bases: LdapSearchBasesInput {
            ldap_search_base: sssd.ldap_search_base.clone(),
            ldap_user_search_base: sssd.ldap_user_search_base.clone(),
            ldap_group_search_base: sssd.ldap_group_search_base.clone(),
        },
        posix_mapping: PosixMappingInput {
            ldap_user_object_class: sssd.ldap_user_object_class.clone(),
            ldap_group_object_class: sssd.ldap_group_object_class.clone(),
            ldap_user_name: sssd.ldap_user_name.clone(),
            ldap_user_uid_number: sssd.ldap_user_uid_number.clone(),
            ldap_user_gid_number: sssd.ldap_user_gid_number.clone(),
            ldap_user_home_directory: sssd.ldap_user_home_directory.clone(),
            ldap_user_shell: sssd.ldap_user_shell.clone(),
            ldap_user_fullname: sssd.ldap_user_fullname.clone(),
            ldap_group_name: sssd.ldap_group_name.clone(),
            ldap_group_gid_number: sssd.ldap_group_gid_number.clone(),
            ldap_group_member: sssd.ldap_group_member.clone(),
            ldap_user_principal_name: sssd.ldap_user_principal_name.clone(),
            kllldap_ignored_attributes: sssd.kllldap_ignored_attributes,
        },
        ldap_tls_reqcert: sssd.ldap_tls_reqcert.clone(),
        ldap_tls_cacert: sssd.ldap_tls_cacert.clone(),
        ldap_id_use_start_tls: sssd.ldap_id_use_start_tls,
    }
}

/// Build IdLdapResolver from ldap_uri + [sssd] + Kerberos realm.
pub fn from_sssd_section(ldap_uri: &str, sssd: &SssdSection, realm: &str) -> IdLdapResolver {
    IdLdapResolver::from_inputs(&sssd_resolver_inputs(ldap_uri, sssd, realm))
}

/// Resolved POSIX attribute names from one sssd_resolver_inputs pass.
pub fn posix_mapping_from_sssd(
    ldap_uri: &str,
    sssd: &SssdSection,
    realm: &str,
) -> nfs_klldap_identity::PosixAttributeMapping {
    nfs_klldap_identity::resolve_posix_attribute_mapping(
        &sssd_resolver_inputs(ldap_uri, sssd, realm).posix_mapping,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SssdSection;

    #[test]
    fn resolver_constructs_from_minimal_sssd_section() {
        let s = SssdSection {
            ldap_default_bind_dn: "uid=admin,ou=people,dc=ex,dc=com".into(),
            ldap_default_authtok: "secret".into(),
            ldap_user_search_base: Some("ou=people,dc=ex,dc=com".into()),
            ..Default::default()
        };
        let r = from_sssd_section("ldaps://ldap.example:636", &s, "ex.com");
        assert!(r.user_base().contains("people"));
    }


}