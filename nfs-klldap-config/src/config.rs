//! Data model for nfs-klldap.conf (single source of truth).
//!
//! Validation, derivation and generation live in validate.rs / generate.rs.
//! Shared with the in-container WebUI via the re-exported types.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level config (nfs-klldap.conf)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NfsKlldapConfig {
    pub ldap_uri: String,

    #[serde(default)]
    pub storage: StorageSection,

    #[serde(default)]
    pub server: ServerSection,

    #[serde(default)]
    pub sssd: SssdSection,

    #[serde(default)]
    pub kerberos: KerberosSection,

    #[serde(default)]
    pub ganesha: GaneshaSection,

    #[serde(default)]
    pub management: ManagementSection,

    #[serde(default)]
    pub shares: Vec<Share>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageSection {
    #[serde(default = "default_container_root")]
    pub container_root: String,
}

fn default_container_root() -> String {
    "/export".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerSection {
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SssdSection {
    pub ldap_default_bind_dn: String,
    pub ldap_default_authtok: String,
    pub port: Option<u16>,
    pub ldap_user_search_base: Option<String>,
    pub ldap_group_search_base: Option<String>,

    /// Optional explicit override for the main ldap_search_base.
    /// When unset, it is derived from the Kerberos realm (recommended).
    pub ldap_search_base: Option<String>,

    // TLS / connection security options (for both ldaps:// and plain ldap:// + STARTTLS).
    // These are emitted verbatim into the generated [domain/default] section.
    // Common values for self-signed LLDAP:
    //   ldap_tls_reqcert = "never"
    // For insecure ldap:// with opportunistic STARTTLS upgrade:
    //   ldap_id_use_start_tls = true
    //   ldap_tls_reqcert = "never"
    pub ldap_tls_reqcert: Option<String>,
    pub ldap_tls_cacert: Option<String>,
    pub ldap_id_use_start_tls: Option<bool>,

    // === Rich LLDAP + POSIX attribute mapping (broad spectrum support) ===
    // These have excellent defaults for typical LLDAP deployments with POSIX attributes.
    // Override only when your LLDAP schema differs.
    pub enumerate: Option<bool>,

    // Object classes (user often has inetOrgPerson + posixAccount auxiliary in LLDAP)
    pub ldap_user_object_class: Option<String>,
    pub ldap_group_object_class: Option<String>,

    // User attribute mappings (highly recommended for correct UID/GID + home/shell)
    pub ldap_user_name: Option<String>,
    pub ldap_user_uid_number: Option<String>,
    pub ldap_user_gid_number: Option<String>,
    pub ldap_user_home_directory: Option<String>,
    pub ldap_user_shell: Option<String>,
    pub ldap_user_fullname: Option<String>,

    // Group attribute mappings
    pub ldap_group_name: Option<String>,
    pub ldap_group_gid_number: Option<String>,
    /// Attribute used to list group members.
    /// For modern KLLDAP + rfc2307bis setups the recommended value is "member"
    /// (or "uniqueMember"). The resolver will default to "member" when
    /// kllldap_ignored_attributes is active (the default), and "memberUid" only
    /// when that feature is explicitly disabled.
    pub ldap_group_member: Option<String>,

    // === Advanced / production knobs from real deployments ===
    /// Name of the SSSD domain section. Defaults to "default".
    /// Setting this to "lldap" produces [domain/lldap] which some people prefer.
    pub domain: Option<String>,

    /// When true (the default), the config generator emits a recommended block
    /// of `ignored_user_attributes` / `ignored_group_attributes` that you can
    /// copy into your KLLDAP server configuration. This dramatically reduces
    /// the "Ignoring unrecognized ... attribute" warning spam from SSSD and
    /// AD-style sync tools.
    ///
    /// Set to false only if you are intentionally managing the ignore lists
    /// yourself on the KLLDAP side or do not want the recommendations.
    /// See docs/ldap-integration.md for details.
    pub kllldap_ignored_attributes: Option<bool>,

    /// Authentication provider. Common values: "ldap" or "krb5".
    /// For Kerberized NFS environments, many people prefer auth_provider = krb5
    /// while still using LDAP for POSIX identity (uidNumber/gidNumber etc.).
    pub auth_provider: Option<String>,

    /// chpass_provider when using Kerberos auth (usually also "krb5").
    pub chpass_provider: Option<String>,

    /// LDAP schema. Common with modern LLDAP + POSIX: "rfc2307bis".
    pub ldap_schema: Option<String>,

    /// Explicitly disable ID mapping (recommended when LLDAP provides real uidNumber/gidNumber).
    pub ldap_id_mapping: Option<bool>,

    /// Very important safety flag when using plain ldap:// (non-TLS).
    /// The generator will automatically set this to true for ldap:// URIs unless overridden.
    pub ldap_auth_disable_tls_never_use_in_production: Option<bool>,

    /// Access control. "permit" is common and simple for trusted internal setups.
    pub access_provider: Option<String>,

    /// Whether to use fully qualified names (user@REALM). Usually false for homelab/small setups.
    pub use_fully_qualified_names: Option<bool>,

    /// Optional explicit Kerberos settings for the domain (when auth_provider = krb5).
    /// If not set, they are derived from ldap_uri host + the effective realm.
    pub krb5_server: Option<String>,
    pub krb5_kpasswd: Option<String>,

    // Additional Kerberos tuning seen in real ldaps production configs
    pub krb5_validate: Option<bool>,
    pub krb5_store_password_if_offline: Option<bool>,
}

/// Resolved POSIX attribute names used for both SSSD generation and targeted
/// LDAP searches by the management WebUI (and by SSSD itself).
///
/// All values come from the admin's input in `[sssd]` (with the same documented
/// defaults the generator uses). This ensures the WebUI only ever asks LLDAP
/// for the exact attributes the rest of the system is configured to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixAttributeMapping {
    pub user_object_class: String,
    pub group_object_class: String,
    pub user_name: String,
    pub user_uid_number: String,
    pub user_gid_number: String,
    pub user_home_directory: String,
    pub user_shell: String,
    /// Attribute used for display / gecos / full name in listings and UI (e.g. displayName, cn).
    /// Shared so WebUI LDAP client requests the same display attr SSSD is configured for.
    pub user_full_name: String,
    pub group_name: String,
    pub group_gid_number: String,
    /// The attribute used for group membership (e.g. "member", "uniqueMember", or "memberUid").
    /// See the resolver logic and docs for KLLDAP recommendations.
    pub group_member: String,
}

/// Resolve the POSIX attribute names the system should use, based on admin
/// configuration in the `[sssd]` section (user overrides always win).
///
/// This is the single source of truth for "which attributes matter for POSIX"
/// and is shared between the SSSD config generator and the WebUI's LLDAP client.
pub fn resolve_posix_attribute_mapping(sssd: &SssdSection) -> PosixAttributeMapping {
    let user_obj = sssd
        .ldap_user_object_class
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "posixAccount".to_string());

    let group_obj = sssd
        .ldap_group_object_class
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "posixGroup".to_string());

    let u_name = sssd
        .ldap_user_name
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "uid".to_string());

    let u_uid = sssd
        .ldap_user_uid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "uidNumber".to_string());

    let u_gid = sssd
        .ldap_user_gid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "gidNumber".to_string());

    let u_home = sssd
        .ldap_user_home_directory
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "homeDirectory".to_string());

    let u_shell = sssd
        .ldap_user_shell
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "loginShell".to_string());

    let u_full = sssd
        .ldap_user_fullname
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "displayName".to_string());

    let g_name = sssd
        .ldap_group_name
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "cn".to_string());

    let g_gid = sssd
        .ldap_group_gid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "gidNumber".to_string());

    // For KLLDAP (when using the recommended ignored attributes feature, which
    // is active by default), we prefer the modern "member" attribute (DNs) over
    // the legacy "memberUid" (which KLLDAP does not synthesize by default).
    // This works excellently with ldap_schema = rfc2307bis.
    // Users can still force the old behavior by setting ldap_group_member explicitly
    // or by disabling kllldap_ignored_attributes.
    let kllldap_mode = sssd.kllldap_ignored_attributes.unwrap_or(true);

    let g_member = sssd
        .ldap_group_member
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            if kllldap_mode {
                "member".to_string()
            } else {
                "memberUid".to_string()
            }
        });

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
    }
}

/// Compute the effective user and group LDAP search bases from [sssd] overrides
/// (or fall back to the standard ou=people/ou=groups under the main search_base
/// or a realm-derived dc=... base). This logic is shared by the SSSD generator,
/// the WebUI's LDAP permission client (for subtree searches that discover users
/// in child OUs), and startup diagnostics.
///
/// KLLDAP supports placing users/groups in a single level of child OUs under
/// the primary ou=people / ou=groups; using Subtree scope from these bases
/// ensures list/resolve operations find them without requiring a higher base.
pub fn effective_ldap_search_bases(sssd: &SssdSection, realm: &str) -> (String, String) {
    let search_base = sssd
        .ldap_search_base
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("dc={}", realm.to_lowercase().replace('.', ",dc=")));

    let default_user_base = format!("ou=people,{}", search_base);
    let default_group_base = format!("ou=groups,{}", search_base);

    let user_base = sssd
        .ldap_user_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&default_user_base)
        .to_string();

    let group_base = sssd
        .ldap_group_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&default_group_base)
        .to_string();

    (user_base, group_base)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KerberosSection {
    pub realm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GaneshaSection {
    #[serde(default = "default_security")]
    pub default_security: String,
}

fn default_security() -> String {
    "krb5p".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManagementSection {
    pub lldap_graphql_url: Option<String>,
    pub helper_path: Option<PathBuf>,
    pub use_sudo: Option<bool>,
    pub ganesha_container_name: Option<String>,
    /// Group whose members (plus the special "localhost" simple-password user) are allowed
    /// to make changes via the WebUI. Defaults to "lldap_admin".
    pub webui_admin_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    /// Full absolute path on the *Docker host* (the "real" location the admin sees and configures).
    /// This is the value used by the WebUI for the allow-list, the share cards, and the
    /// directory tree browser. Inside the container the data is visible under
    /// `storage.container_root` + this share's `name` (the bind mount contract).
    /// The WebUI translates at the syscall boundary only; Ganesha exports use the container view.
    pub host_path: PathBuf,
    /// Optional explicit NFS pseudo path. Defaults to "/" + name (short + clean)
    pub export_path: Option<String>,
    pub security: Option<String>,
    pub rw: Option<bool>,
    pub squash: Option<String>,
}

impl Default for Share {
    fn default() -> Self {
        Self {
            name: String::new(),
            host_path: PathBuf::new(),
            export_path: None,
            security: None,
            rw: Some(true),
            squash: Some("no_root_squash".to_string()),
        }
    }
}

/// Paths the generator will write to (container view)
#[derive(Debug, Clone)]
pub struct GenerationPaths {
    pub sssd_conf: PathBuf,
    pub krb5_conf: PathBuf,
    pub ganesha_conf: PathBuf,
    pub exports_dir: PathBuf,
}

impl Default for GenerationPaths {
    fn default() -> Self {
        Self {
            sssd_conf: PathBuf::from("/etc/sssd/sssd.conf"),
            krb5_conf: PathBuf::from("/etc/krb5.conf"),
            ganesha_conf: PathBuf::from("/etc/ganesha/ganesha.conf"),
            exports_dir: PathBuf::from("/etc/ganesha/exports.d"),
        }
    }
}
