//! Thin adapter over nfs-klldap-identity with SssdSection convenience helpers.

use crate::SssdSection;

pub use nfs_klldap_identity::{
    classify_principal, escape_ldap_filter, extract_first_attr_value, parse_getent_group,
    parse_getent_passwd, IdLdapResolver, IdMapSnapshot, LdapResolverInputs, LdapSearchBasesInput,
    PosixGroupEntry, PosixMappingInput, PosixUserEntry,
};

/// Build IdLdapResolver from ldap_uri + [sssd].
pub fn from_sssd_section(ldap_uri: &str, sssd: &SssdSection) -> IdLdapResolver {
    IdLdapResolver::from_inputs(&resolver_inputs_from_sssd(ldap_uri, sssd))
}

pub(crate) fn posix_mapping_input_from_sssd(sssd: &SssdSection) -> PosixMappingInput {
    PosixMappingInput {
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
    }
}

pub(crate) fn search_bases_input_from_sssd(sssd: &SssdSection) -> LdapSearchBasesInput {
    LdapSearchBasesInput {
        ldap_search_base: sssd.ldap_search_base.clone(),
        ldap_user_search_base: sssd.ldap_user_search_base.clone(),
        ldap_group_search_base: sssd.ldap_group_search_base.clone(),
    }
}

fn resolver_inputs_from_sssd(ldap_uri: &str, sssd: &SssdSection) -> LdapResolverInputs {
    let realm = sssd
        .ldap_search_base
        .as_deref()
        .and_then(|s| s.split(',').next().and_then(|p| p.strip_prefix("dc=")))
        .map(|d| d.to_string())
        .unwrap_or_else(|| "example.com".to_string());

    LdapResolverInputs {
        ldap_uri: ldap_uri.to_string(),
        realm,
        search_bases: search_bases_input_from_sssd(sssd),
        posix_mapping: posix_mapping_input_from_sssd(sssd),
        ldap_tls_reqcert: sssd.ldap_tls_reqcert.clone(),
        ldap_id_use_start_tls: sssd.ldap_id_use_start_tls,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{resolve_posix_attribute_mapping, DEFAULT_USER_PRINCIPAL_ATTR, SssdSection};

    #[test]
    fn resolver_constructs_from_minimal_sssd_section() {
        let s = SssdSection {
            ldap_default_bind_dn: "uid=admin,ou=people,dc=ex,dc=com".into(),
            ldap_default_authtok: "secret".into(),
            ldap_user_search_base: Some("ou=people,dc=ex,dc=com".into()),
            ..Default::default()
        };
        let r = from_sssd_section("ldaps://ldap.example:636", &s);
        assert!(r.user_base().contains("people"));
    }

    #[test]
    fn dc_base_extraction_covers_nested_under_users() {
        let r = from_sssd_section(
            "ldaps://ldap.example:636",
            &SssdSection {
                ldap_user_search_base: Some("ou=testing,ou=users,dc=example,dc=com".into()),
                ..SssdSection::default()
            },
        );
        assert!(r.user_base().contains("testing"));
    }

    #[test]
    fn principal_attr_default_is_krb_principal_name_and_dual_lookup_works_in_mapping() {
        let s = SssdSection::default();
        let mapping = resolve_posix_attribute_mapping(&s);
        assert_eq!(mapping.user_principal_name, DEFAULT_USER_PRINCIPAL_ATTR);

        let r = from_sssd_section("ldaps://ex", &s);
        assert_eq!(
            r.posix_attributes().user_principal_name,
            DEFAULT_USER_PRINCIPAL_ATTR
        );
    }
}