// ! Identity-related constants shared across nfs-klldap-host binaries.

/// Machine principal prefixes; match Ganesha Root_Kerberos_Principal.
pub const MACHINE_PRINCIPAL_PREFIXES: &[&str] = &["host/", "nfs/", "root/"];

pub const DEFAULT_USER_OBJECT_CLASS: &str = "posixAccount";
pub const DEFAULT_GROUP_OBJECT_CLASS: &str = "posixGroup";
pub const DEFAULT_USER_NAME_ATTR: &str = "uid";
pub const DEFAULT_USER_UID_ATTR: &str = "uidNumber";
pub const DEFAULT_USER_GID_ATTR: &str = "gidNumber";
pub const DEFAULT_GROUP_GID_ATTR: &str = "gidNumber";
pub const DEFAULT_USER_HOME_ATTR: &str = "homeDirectory";
pub const DEFAULT_USER_SHELL_ATTR: &str = "loginShell";
pub const DEFAULT_USER_FULLNAME_ATTR: &str = "displayName";
pub const DEFAULT_GROUP_NAME_ATTR: &str = "cn";
pub const DEFAULT_USER_PRINCIPAL_ATTR: &str = "krbPrincipalName";
pub const DEFAULT_GROUP_MEMBER_ATTR_KLLDAP: &str = "member";
pub const DEFAULT_GROUP_MEMBER_ATTR_LEGACY: &str = "memberUid";

pub const FALLBACK_NOBODY_UID: u32 = 65534;
pub const FALLBACK_NOBODY_GID: u32 = 65534;
pub const MACHINE_UID: u32 = 0;
pub const MACHINE_GID: u32 = 0;

pub const IDENTITY_CACHE_TTL_SECS: u64 = 10 * 60;