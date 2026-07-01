#![deny(unsafe_code, dead_code)]

//! Shared LDAP/Kerberos identity for config, idhelper, and WebUI.
//! Covers Ganesha 9.6 hybrid user-TGT and machine-keytab principals.

pub mod constants;
pub mod krb5;
pub mod ldap;
pub mod nss;

pub use constants::{
    DEFAULT_GROUP_GID_ATTR, DEFAULT_GROUP_MEMBER_ATTR_KLLDAP, DEFAULT_GROUP_MEMBER_ATTR_LEGACY,
    DEFAULT_GROUP_NAME_ATTR, DEFAULT_GROUP_OBJECT_CLASS, DEFAULT_USER_FULLNAME_ATTR,
    DEFAULT_USER_GID_ATTR, DEFAULT_USER_HOME_ATTR, DEFAULT_USER_NAME_ATTR,
    DEFAULT_USER_OBJECT_CLASS, DEFAULT_USER_PRINCIPAL_ATTR, DEFAULT_USER_SHELL_ATTR,
    DEFAULT_USER_UID_ATTR, FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID, IDENTITY_CACHE_TTL_SECS,
    MACHINE_GID, MACHINE_PRINCIPAL_PREFIXES, MACHINE_UID,
};
pub use krb5::{
    classify_principal, derive_realm_from_uri, extract_host_from_uri, format_nfs_principal_list,
    get_keytab_info, host_is_ip, looks_like_docker_default_hostname, machine_short_name,
    nfs_keytab_host_matches, nfs_keytab_host_variants, parse_klist_nfs_hosts,
    canonicalize_principal, is_numeric_local_principal, parse_klist_nfs_principals,
    normalize_principal, principal_has_realm, principal_local_part,
    supplemental_gids_for_machine_principal,
    read_default_keytab_nfs_principals,
    read_keytab_nfs_principals, KeytabInfo,
};
pub use ldap::{
    effective_ldap_search_bases, escape_ldap_filter, extract_first_attr_value, IdLdapResolver,
    IdMapSnapshot, LdapResolverInputs, LdapSearchBasesInput, machine_group_gids_for_principal,
    machine_supplemental_gids_from_snapshot, PosixAttributeMapping, PosixGroupEntry,
    PosixMappingInput, PosixUserEntry, resolve_groups_for_principal, resolve_posix_attribute_mapping,
};
pub use nss::{parse_getent_group, parse_getent_passwd};
