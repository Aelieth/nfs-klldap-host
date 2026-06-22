//! Centralized constants for nfs-klldap-config.
//!
//! Single source of truth for hard-coded values used across auto-derivation,
//! LDAP resolution (idmap + UI parity), idhelper classification/lookup,
//! generation of sssd/krb5/ganesha/idmapd artifacts, and Ganesha 9.6 trixie
//! specific configuration.
//!
//! All values here are chosen for Debian Trixie + Ganesha 9.6 (trixie-backports)
//! compatibility. No deprecated options are included.

/// Machine / host / service principal prefixes (local part before /).
/// Used by classification (idhelper), materialization, observer guards,
/// and "short-circuit to 0:0" logic.
/// These are matched case-insensitively after stripping realm.
pub const MACHINE_PRINCIPAL_PREFIXES: &[&str] = &["host/", "nfs/", "root/"];

/// Default objectClass for POSIX users (LLDAP + rfc2307bis common).
pub const DEFAULT_USER_OBJECT_CLASS: &str = "posixAccount";

/// Default objectClass for POSIX groups.
pub const DEFAULT_GROUP_OBJECT_CLASS: &str = "posixGroup";

/// Default user name attribute.
pub const DEFAULT_USER_NAME_ATTR: &str = "uid";

/// Default uidNumber attribute.
pub const DEFAULT_USER_UID_ATTR: &str = "uidNumber";

/// Default gidNumber attribute (user primary + groups).
pub const DEFAULT_USER_GID_ATTR: &str = "gidNumber";
pub const DEFAULT_GROUP_GID_ATTR: &str = "gidNumber";

/// Default homeDirectory attribute.
pub const DEFAULT_USER_HOME_ATTR: &str = "homeDirectory";

/// Default loginShell attribute.
pub const DEFAULT_USER_SHELL_ATTR: &str = "loginShell";

/// Default display/full name attribute (fallback chain includes cn/displayName).
pub const DEFAULT_USER_FULLNAME_ATTR: &str = "displayName";

/// Default group name attribute.
pub const DEFAULT_GROUP_NAME_ATTR: &str = "cn";

/// Kerberos principal attribute used for direct "user@REALM" lookups
/// in addition to name match (supports krbPrincipalName in LLDAP).
pub const DEFAULT_USER_PRINCIPAL_ATTR: &str = "krbPrincipalName";

/// When kllldap_ignored_attributes (default true), prefer "member" (DNs)
/// over legacy "memberUid". Aligns with rfc2307bis + LLDAP.
pub const DEFAULT_GROUP_MEMBER_ATTR_KLLDAP: &str = "member";
pub const DEFAULT_GROUP_MEMBER_ATTR_LEGACY: &str = "memberUid";

/// Ganesha 9.6 / trixie specific safe values.
/// These are emitted verbatim; adding other keys may be fatal at parser time.
pub const GANESHA_PROTOCOLS: &str = "4";
pub const GANESHA_PWNAM_IMPL: &str = "nsswitch";
pub const GANESHA_ROOT_KRB_PRINCIPALS: &str = "host, nfs";
pub const GANESHA_READ_ACCESS_CHECK_POLICY: &str = "pre";
pub const GANESHA_DEFAULT_SECTYPE: &str = "krb5p";

/// idmapd.conf (libnfsidmap / nfsidmap shim / client rpc.idmapd) values.
/// Domain + Local-Realms come from effective_realm(); these are the
/// Translation/Method values for consistent GSS + nsswitch principal handling.
pub const IDMAPD_TRANSLATION_METHOD: &str = "nsswitch";
pub const IDMAPD_GSS_METHODS: &str = "nsswitch";
pub const IDMAPD_NOBODY_USER: &str = "nobody";
pub const IDMAPD_NOBODY_GROUP: &str = "nogroup";

/// Common noise tokens for Ganesha log observer (exact match, lowercased).
/// Prevents "host/nil", "host/Unique", clientid blobs, etc. from becoming
/// synthetic host principals. Keep in sync with is_noise_hostname + lists.
pub const LOG_NOISE_TOKENS: &[&str] = &[
    "nil", "null", "clientid", "unique", "counter", "created", "client",
    "id", "name", "addr", "refcount", "cr", "conf", "unconf", "debug",
    "info", "warning", "error", "ffff", "linux", "nfsv4",
];

/// Fallback nobody-ish ids when no mapping is possible (last resort).
pub const FALLBACK_NOBODY_UID: u32 = 65534;
pub const FALLBACK_NOBODY_GID: u32 = 65534;

/// Machine principals always resolve to root (0:0). Used for short-circuit.
pub const MACHINE_UID: u32 = 0;
pub const MACHINE_GID: u32 = 0;
