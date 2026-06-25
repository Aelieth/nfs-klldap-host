//! Bridges nfs-klldap.conf [sssd] fields to the shared IdLdapResolver in nfs-klldap-identity.

use crate::SssdSection;

pub use nfs_klldap_identity::{
    classify_principal, escape_ldap_filter, extract_first_attr_value, machine_short_name,
    parse_getent_group, parse_getent_passwd, principal_local_part, IdLdapResolver, IdMapSnapshot,
    LdapResolverInputs, LdapSearchBasesInput, PosixGroupEntry, PosixMappingInput, PosixUserEntry,
};

/// Build IdLdapResolver from ldap_uri + [sssd] + Kerberos realm (not ldap_search_base RDN).
pub fn from_sssd_section(ldap_uri: &str, sssd: &SssdSection, realm: &str) -> IdLdapResolver {
    IdLdapResolver::from_inputs(&resolver_inputs_from_sssd(ldap_uri, sssd, realm))
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

fn resolver_inputs_from_sssd(ldap_uri: &str, sssd: &SssdSection, realm: &str) -> LdapResolverInputs {
    LdapResolverInputs {
        ldap_uri: ldap_uri.to_string(),
        realm: realm.to_string(),
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
        let r = from_sssd_section("ldaps://ldap.example:636", &s, "ex.com");
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
            "example.com",
        );
        assert!(r.user_base().contains("testing"));
    }

    #[test]
    fn explicit_realm_drives_default_search_base_not_first_rdn() {
        let r = from_sssd_section(
            "ldaps://ldap.example:636",
            &SssdSection {
                ldap_user_search_base: Some("ou=testing,ou=users,dc=example,dc=com".into()),
                ..SssdSection::default()
            },
            "my.corp",
        );
        assert!(r.user_base().contains("testing"));
        let r2 = from_sssd_section("ldaps://ex", &SssdSection::default(), "my.corp");
        assert_eq!(r2.user_base(), "dc=my,dc=corp");
    }

    #[test]
    fn principal_attr_default_is_krb_principal_name_and_dual_lookup_works_in_mapping() {
        let s = SssdSection::default();
        let mapping = resolve_posix_attribute_mapping(&s);
        assert_eq!(mapping.user_principal_name, DEFAULT_USER_PRINCIPAL_ATTR);

        let r = from_sssd_section("ldaps://ex", &s, "ex.com");
        assert_eq!(
            r.posix_attributes().user_principal_name,
            DEFAULT_USER_PRINCIPAL_ATTR
        );
    }
}