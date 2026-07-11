//! Constants for nfs-klldap-config (Ganesha 9.6 trixie + identi.

pub use nfs_klldap_identity::{
    DEFAULT_GROUP_GID_ATTR, DEFAULT_GROUP_MEMBER_ATTR_KLLDAP, DEFAULT_GROUP_MEMBER_ATTR_LEGACY,
    DEFAULT_GROUP_NAME_ATTR, DEFAULT_GROUP_OBJECT_CLASS, DEFAULT_USER_FULLNAME_ATTR,
    DEFAULT_USER_GID_ATTR, DEFAULT_USER_HOME_ATTR, DEFAULT_USER_NAME_ATTR,
    DEFAULT_USER_OBJECT_CLASS, DEFAULT_USER_PRINCIPAL_ATTR, DEFAULT_USER_SHELL_ATTR,
    DEFAULT_USER_UID_ATTR, FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID, MACHINE_GID,
    MACHINE_PRINCIPAL_PREFIXES, MACHINE_UID,
};

/// Linux TASK_COMM_LEN — process names longer than this need cmdline matching.
pub const PROC_COMM_NAME_MAX: usize = 15;

/// Ganesha 9.6 / trixie specific safe values.
pub const GANESHA_PROTOCOLS: &str = "4";
pub const GANESHA_PWNAM_IMPL: &str = "nsswitch";
/// Root_Kerberos_Principal default deliberately excludes `host` (upstream default
/// is `all`): enrolled client machines hold host/ keytabs and must not act as
/// root on exports. host/ principals map through normal idmapping → anonymous.
pub const GANESHA_ROOT_KRB_PRINCIPALS: &str = "nfs, root";
/// Valid Root_Kerberos_Principal tokens (Ganesha 9.6 nfs_read_conf.c);
/// `none` in the list overrides every other token.
pub const GANESHA_ROOT_KRB_PRINCIPAL_TOKENS: &[&str] = &["none", "nfs", "root", "host", "all"];
/// DIRECTORY_SERVICES Idmapped_*_Time_Validity seconds: identity lookups AND
/// the getgroups() trust window — 9.13 routes the old core param
/// Manage_Gids_Expiration here (it now warns and is no longer emitted).
pub const GANESHA_IDMAPPED_VALIDITY_SECS: u32 = 600;
/// Sanity cap for the manage-gids TOML knobs (Ganesha capped the old core
/// param at 7 days; the values now feed Idmapped_*_Time_Validity).
pub const GANESHA_MANAGE_GIDS_EXPIRATION_MAX: u64 = 7 * 24 * 60 * 60;
/// DIRECTORY_SERVICES Negative_Cache_Time_Validity (upstream default 300s):
/// 60s so users/groups newly added in LDAP stop being negative-cached quickly.
pub const GANESHA_NEGATIVE_CACHE_VALIDITY_SECS: u32 = 60;
/// NFS_CORE_PARAM Max_Uid_To_Group_Reqs (upstream 0 = unlimited): bound the
/// concurrent uid→groups resolutions hitting SSSD/LLDAP on cache-cold storms.
pub const GANESHA_MAX_UID_TO_GROUP_REQS: u32 = 64;
/// NFS_CORE_PARAM Readdir_Res_Size bytes (upstream default, emitted explicitly;
/// tune from the 1.5 baseline numbers). Valid range 4096..=64 MiB.
pub const GANESHA_READDIR_RES_SIZE: u32 = 32 * 1024;
pub const GANESHA_READDIR_RES_SIZE_MIN: u32 = 4096;
pub const GANESHA_READDIR_RES_SIZE_MAX: u32 = 64 * 1024 * 1024;
/// NFS_CORE_PARAM Readdir_Max_Count entry bounds (emit only when configured).
pub const GANESHA_READDIR_MAX_COUNT_MIN: u32 = 32;
pub const GANESHA_READDIR_MAX_COUNT_MAX: u32 = 1024 * 1024;
/// Malloc_trim_MinThreshold is in MB. Upstream default is 15360 MB — above the
/// 4 GB container limit, so trim would never fire; 1024 MB makes it real.
pub const GANESHA_MALLOC_TRIM_MIN_MB: u32 = 1024;
/// NFSv4 RecoveryRoot (fs backend) — must be volume-backed so clients ride
/// through grace/reclaim across container recreation (see nfs-klldap-host.yaml).
pub const GANESHA_RECOVERY_ROOT: &str = "/var/lib/nfs/ganesha";
pub const GANESHA_DEFAULT_SECTYPE: &str = "krb5p";
pub const GANESHA_DEFAULT_SQUASH: &str = "no_root_squash";
pub const GANESHA_ALLOWED_SECTYPES: &[&str] = &["krb5p", "krb5i", "krb5"];
pub const GANESHA_ALLOWED_SQUASH: &[&str] = &[
    "no_root_squash",
    "root_squash",
    "root_id_squash",
    "all_squash",
];

// Ganesha 9.6 EXPORT Read_Access_Check_Policy values (ganesha-export-co.
pub const GANESHA_READ_ACCESS_POLICIES: &[&str] = &["pre", "post"];

/// Default idmapd.conf values for Ganesha 9.6 (idmapping uses libnfsidmap + nss_wrapper in-process).
pub const IDMAPD_TRANSLATION_METHOD: &str = "nsswitch";
pub const IDMAPD_GSS_METHODS: &str = "nsswitch";
pub const IDMAPD_NOBODY_USER: &str = "nobody";
/// The default idmapd Nobody-Group matches nss FALLBACK_NOBODY_GID (65534)
pub const IDMAPD_NOBODY_GROUP: &str = "nogroup";

/// Ganesha log observer noise tokens (exact match, lowercased)
pub const LOG_NOISE_TOKENS: &[&str] = &[
    "nil", "null", "clientid", "unique", "counter", "created", "client", "id", "name", "addr",
    "refcount", "cr", "conf", "unconf", "debug", "info", "warning", "error", "ffff", "linux",
    "nfsv4",
];
