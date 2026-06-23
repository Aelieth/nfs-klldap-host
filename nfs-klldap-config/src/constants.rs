//! Constants for nfs-klldap-config (Ganesha 9.6 trixie + identity re-exports).

pub use nfs_klldap_identity::{
    DEFAULT_GROUP_GID_ATTR, DEFAULT_GROUP_MEMBER_ATTR_KLLDAP, DEFAULT_GROUP_MEMBER_ATTR_LEGACY,
    DEFAULT_GROUP_NAME_ATTR, DEFAULT_GROUP_OBJECT_CLASS, DEFAULT_USER_FULLNAME_ATTR,
    DEFAULT_USER_GID_ATTR, DEFAULT_USER_HOME_ATTR, DEFAULT_USER_NAME_ATTR,
    DEFAULT_USER_OBJECT_CLASS, DEFAULT_USER_PRINCIPAL_ATTR, DEFAULT_USER_SHELL_ATTR,
    DEFAULT_USER_UID_ATTR, FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID, MACHINE_GID,
    MACHINE_PRINCIPAL_PREFIXES, MACHINE_UID,
};

/// Ganesha 9.6 / trixie specific safe values.
pub const GANESHA_PROTOCOLS: &str = "4";
pub const GANESHA_PWNAM_IMPL: &str = "nsswitch";
pub const GANESHA_ROOT_KRB_PRINCIPALS: &str = "host, nfs";
pub const GANESHA_DEFAULT_SECTYPE: &str = "krb5p";
pub const GANESHA_DEFAULT_SQUASH: &str = "no_root_squash";
pub const GANESHA_ALLOWED_SECTYPES: &[&str] = &["krb5p", "krb5i", "krb5"];
pub const GANESHA_ALLOWED_SQUASH: &[&str] = &[
    "no_root_squash",
    "root_squash",
    "root_id_squash",
    "all_squash",
    "all_root_squash",
    "all_root_id_squash",
];

/// idmapd.conf values for Ganesha 9.6 + libnfsidmap shim.
pub const IDMAPD_TRANSLATION_METHOD: &str = "nsswitch";
pub const IDMAPD_GSS_METHODS: &str = "nsswitch";
pub const IDMAPD_NOBODY_USER: &str = "nobody";
pub const IDMAPD_NOBODY_GROUP: &str = "nogroup";

/// Ganesha log observer noise tokens (exact match, lowercased).
pub const LOG_NOISE_TOKENS: &[&str] = &[
    "nil", "null", "clientid", "unique", "counter", "created", "client", "id", "name", "addr",
    "refcount", "cr", "conf", "unconf", "debug", "info", "warning", "error", "ffff", "linux",
    "nfsv4",
];