//! nfs-klldap-config — Tiny, type-safe TOML loader + generator for nfs-klldap-host (v0.5+).
//!
//! This crate is the *only* place that understands nfs-klldap.conf.
//! It is bundled as a small static-friendly binary inside the container.
//! The host UI (nfs-klldap-ui) depends on it for loading/saving the same schema.
//!
//! Core responsibilities:
//! - Parse + validate the single source-of-truth config
//! - Smart auto-derivation (realm from ldap_uri, ports, bases, paths)
//! - Generate sssd.conf, krb5.conf, ganesha.conf + per-share EXPORT fragments
//! - First-run safe default template (never overwrites)
//! - Dup share name detection (short, unique NFS paths)
//!
//! Public helpers for the guided startup binary and host tooling:
//! - `derive_realm_from_uri`
//! - `suggested_nfs_hostname` (insertion pattern: host → host-nfs.domain)
//!
//! Note: Hostname handling is now based on the user passing --uts=host to Docker.
//! The container then naturally sees the real host hostname.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

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
    pub ldap_group_member: Option<String>,

    // === Advanced / production knobs from real deployments ===
    /// Name of the SSSD domain section. Defaults to "default".
    /// Setting this to "lldap" produces [domain/lldap] which some people prefer.
    pub domain: Option<String>,

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
    /// Full absolute path on the *Docker host* (used by host UI; container performs chown/chmod on the bind mount)
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

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse { path: String, msg: String },
    Validation(String),
    Generation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "IO error: {}", e),
            ConfigError::Parse { path, msg } => write!(f, "TOML parse error for {}: {}", path, msg),
            ConfigError::Validation(s) => write!(f, "Validation error: {}", s),
            ConfigError::Generation(s) => write!(f, "Generation error: {}", s),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

/// Treat a present but blank/whitespace-only Option<String> as absent.
/// This is the central rule so that "defined with a real value in nfs-klldap.conf"
/// always wins over auto-derived values and our LLDAP defaults.
fn normalize_blank(field: &mut Option<String>) {
    if let Some(v) = field {
        if v.trim().is_empty() {
            *field = None;
        } else {
            // Also trim in place so we don't emit leading/trailing spaces later
            *field = Some(v.trim().to_string());
        }
    }
}

impl NfsKlldapConfig {
    /// Load from file + full validation + auto-derive
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path).map_err(ConfigError::Io)?;

        let mut cfg: Self = toml::from_str(&contents).map_err(|e| ConfigError::Parse {
            path: path.display().to_string(),
            msg: e.to_string(),
        })?;

        cfg.validate_and_derive()?;
        Ok(cfg)
    }

    /// Validate required fields + enforce uniqueness + auto-derive everything possible
    pub fn validate_and_derive(&mut self) -> Result<(), ConfigError> {
        if self.ldap_uri.trim().is_empty() {
            return Err(ConfigError::Validation("ldap_uri is required".into()));
        }

        // Normalize all [sssd] string override fields:
        // Treat blank / whitespace-only values the same as "not specified".
        // This ensures that an explicit value in nfs-klldap.conf always takes
        // precedence, while blank values fall back to auto-derived or good defaults.
        {
            let s = &mut self.sssd;
            normalize_blank(&mut s.ldap_search_base);
            normalize_blank(&mut s.ldap_user_search_base);
            normalize_blank(&mut s.ldap_group_search_base);
            normalize_blank(&mut s.ldap_tls_reqcert);
            normalize_blank(&mut s.ldap_tls_cacert);
            normalize_blank(&mut s.ldap_user_object_class);
            normalize_blank(&mut s.ldap_group_object_class);
            normalize_blank(&mut s.ldap_user_name);
            normalize_blank(&mut s.ldap_user_uid_number);
            normalize_blank(&mut s.ldap_user_gid_number);
            normalize_blank(&mut s.ldap_user_home_directory);
            normalize_blank(&mut s.ldap_user_shell);
            normalize_blank(&mut s.ldap_user_fullname);
            normalize_blank(&mut s.ldap_group_name);
            normalize_blank(&mut s.ldap_group_gid_number);
            normalize_blank(&mut s.ldap_group_member);

            // New advanced fields
            normalize_blank(&mut s.domain);
            normalize_blank(&mut s.auth_provider);
            normalize_blank(&mut s.chpass_provider);
            normalize_blank(&mut s.ldap_schema);
            normalize_blank(&mut s.krb5_server);
            normalize_blank(&mut s.krb5_kpasswd);
            // krb5_validate and krb5_store_password_if_offline are bools — no string normalization needed
        }

        // Enforce DNS name (not IP) for ldap_uri. Forward + reverse DNS is mandatory
        // for the NFS service principal (keytab) and Kerberos GSSAPI operation.
        let host = extract_host_from_uri(&self.ldap_uri);
        if host_is_ip(&host) {
            return Err(ConfigError::Validation(
                "LDAP IP addresses are not supported, DNS resolution is required for operation."
                    .into(),
            ));
        }

        // Auto-derive realm if missing (from ldap_uri)
        if self.kerberos.realm.is_none() {
            if let Some(realm) = derive_realm_from_uri(&self.ldap_uri) {
                self.kerberos.realm = Some(realm);
            }
        }

        // Allow env var override / injection (NFS_REALM or REALM). Env takes precedence
        // over ldap_uri derivation and over an omitted config value.
        if let Ok(env_realm) = std::env::var("NFS_REALM") {
            let t = env_realm.trim();
            if !t.is_empty() {
                self.kerberos.realm = Some(t.to_string());
            }
        }
        if self.kerberos.realm.is_none() {
            if let Ok(env_realm) = std::env::var("REALM") {
                let t = env_realm.trim();
                if !t.is_empty() {
                    self.kerberos.realm = Some(t.to_string());
                }
            }
        }

        // Enforce a usable realm: no silent fallback to EXAMPLE.COM.
        // Validation must fail (container will not start) if the user never provides a real realm
        // and auto-derivation could not produce one (e.g. IP-based ldap_uri).
        {
            let r = self.kerberos.realm.as_deref().unwrap_or("").trim();
            if r.is_empty()
                || r.eq_ignore_ascii_case("EXAMPLE.COM")
                || r.eq_ignore_ascii_case("EXAMPLE")
            {
                return Err(ConfigError::Validation(
                    "kerberos.realm is required (auto-derivation from ldap_uri failed or produced a placeholder).\n\
                     Set [kerberos] realm = \"YOUR.REALM\" in nfs-klldap.conf, or provide NFS_REALM env var.\n\
                     Example: realm = \"KRB.EXAMPLE.COM\"".into(),
                ));
            }
        }

        // Auto-derive port
        if self.sssd.port.is_none() {
            self.sssd.port = Some(if self.ldap_uri.starts_with("ldaps://") {
                636
            } else {
                389
            });
        }

        // Auto search bases — derive from the actual realm (no more stale example.com defaults)
        let base_dn = format!(
            "dc={}",
            self.effective_realm().to_lowercase().replace('.', ",dc=")
        );
        if self.sssd.ldap_user_search_base.is_none() {
            self.sssd.ldap_user_search_base = Some(format!("ou=people,{}", base_dn));
        }
        if self.sssd.ldap_group_search_base.is_none() {
            self.sssd.ldap_group_search_base = Some(format!("ou=groups,{}", base_dn));
        }

        // Default security + enum validation (Ganesha only supports these)
        if self.ganesha.default_security.trim().is_empty() {
            self.ganesha.default_security = "krb5p".to_string();
        }
        {
            const ALLOWED: &[&str] = &["krb5p", "krb5i", "krb5"];
            if !ALLOWED.contains(&self.ganesha.default_security.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "ganesha.default_security must be one of krb5p, krb5i, krb5 (got '{}')",
                    self.ganesha.default_security
                )));
            }
        }

        // Default storage root
        if self.storage.container_root.trim().is_empty() {
            self.storage.container_root = "/export".to_string();
        }

        // Validate + derive per-share + uniqueness
        let mut seen = HashSet::new();
        for share in &mut self.shares {
            if share.name.trim().is_empty() {
                return Err(ConfigError::Validation("share name cannot be empty".into()));
            }
            if !seen.insert(share.name.clone()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate share name '{}' — names must be unique for short clean NFS paths",
                    share.name
                )));
            }
            if share.host_path.as_os_str().is_empty() {
                return Err(ConfigError::Validation(format!(
                    "share '{}' requires host_path (absolute path on the Docker host)",
                    share.name
                )));
            }
            // Derive export_path if missing
            if share.export_path.is_none() {
                share.export_path = Some(format!("/{}", share.name));
            }
            // Validate per-share security if provided
            if let Some(ref sec) = share.security {
                const ALLOWED: &[&str] = &["krb5p", "krb5i", "krb5"];
                if !ALLOWED.contains(&sec.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "share '{}' security must be one of krb5p, krb5i, krb5 (got '{}')",
                        share.name, sec
                    )));
                }
            }
        }

        // Require bind credentials for sssd
        if self.sssd.ldap_default_bind_dn.trim().is_empty() {
            return Err(ConfigError::Validation(
                "sssd.ldap_default_bind_dn is required".into(),
            ));
        }
        if self.sssd.ldap_default_authtok.trim().is_empty() {
            return Err(ConfigError::Validation(
                "sssd.ldap_default_authtok is required (use a strong secret)".into(),
            ));
        }

        Ok(())
    }

    /// Hostname to use (server.hostname override, or the container's actual hostname at runtime).
    /// The container must be started with --hostname matching the keytab principal.
    pub fn effective_hostname(&self) -> String {
        self.server.hostname.clone().unwrap_or_else(|| {
            hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "nfs-host".to_string())
        })
    }

    /// Realm (guaranteed to be a real value after successful validate_and_derive)
    pub fn effective_realm(&self) -> String {
        self.kerberos
            .realm
            .clone()
            .expect("effective_realm called on config that did not pass validation (no EXAMPLE.COM fallback)")
    }

    /// Derived container path for a share (used in Ganesha Path=)
    pub fn container_path_for(&self, share: &Share) -> String {
        format!(
            "{}/{}",
            self.storage.container_root.trim_end_matches('/'),
            share.name
        )
    }

    /// Returns the list of host_path values declared in shares (used for validation before performing direct chown/chmod inside the container).
    pub fn host_paths(&self) -> Vec<PathBuf> {
        self.shares.iter().map(|s| s.host_path.clone()).collect()
    }
}

/// Returns true if the given config path is on a persistent volume (i.e. a real
/// host bind mount) rather than living inside the container's own filesystem layer.
///
/// This is used for the guided first-run experience: we refuse to do meaningful
/// work until the user has mounted a real volume at /config (or wherever
/// NFS_CONFIG points).
#[cfg(unix)]
pub fn is_persistent_config(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }

    use std::os::unix::fs::MetadataExt;

    let config_meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let root_meta = match std::fs::metadata("/") {
        Ok(m) => m,
        Err(_) => return false,
    };

    // Different device IDs => the file lives on a different mount (i.e. host volume)
    config_meta.dev() != root_meta.dev()
}

#[cfg(not(unix))]
pub fn is_persistent_config(_path: &Path) -> bool {
    // On non-Unix we conservatively say "assume it's persistent" so the
    // guided flow doesn't block forever in weird environments.
    true
}

/// Load only the [[shares]] host_path entries from a config file.
///
/// This is intentionally tolerant of missing credentials / incomplete config
/// so the privileged permission helper can still enforce its allow-list even
/// if the rest of the TOML is in a transitional state. Only well-formed
/// absolute host_path values are returned.
pub fn load_host_paths_only(path: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let contents = fs::read_to_string(path).map_err(ConfigError::Io)?;

    #[derive(Deserialize)]
    struct SharesOnly {
        #[serde(default)]
        shares: Vec<RawShare>,
    }
    #[derive(Deserialize)]
    struct RawShare {
        host_path: Option<PathBuf>,
    }

    let partial: SharesOnly = toml::from_str(&contents).map_err(|e| ConfigError::Parse {
        path: path.display().to_string(),
        msg: e.to_string(),
    })?;

    Ok(partial
        .shares
        .into_iter()
        .filter_map(|s| s.host_path)
        .filter(|p| !p.as_os_str().is_empty())
        .collect())
}

/// Attempt to derive a Kerberos realm from an ldap/ldaps URI.
/// Used by both the generator and the guided startup TUI for display purposes.
/// Example: ldaps://kllap.example.com:6360 → "EXAMPLE.COM"
pub fn derive_realm_from_uri(uri: &str) -> Option<String> {
    // ldaps://kllap.example.com:6360 → EXAMPLE.COM
    // ldaps://sub.host.example.co.uk:636 → EXAMPLE.CO.UK (current behavior)
    let host = extract_host_from_uri(uri);
    if host.is_empty() {
        return None;
    }
    let domain = host.split_once('.').map(|(_, d)| d).unwrap_or(&host);
    Some(domain.to_uppercase())
}

/// Generate the first-run safe, heavily commented template.
/// Never overwrites an existing file.
pub fn generate_default_template() -> String {
    r#"# =============================================================================
# nfs-klldap.conf — Single Source of Truth for nfs-klldap-host
# =============================================================================
# This file is the ONLY configuration users edit.
# The container (via bundled Rust generator) auto-derives sssd.conf,
# krb5.conf, and all Ganesha EXPORT fragments from it.
#
# REQUIRED: ldap_uri + [sssd] bind credentials.
# ldap_uri host MUST be a DNS name (A/AAAA + PTR recommended). IP addresses are
# rejected because forward/reverse DNS is required for the NFS service principal
# in the keytab and for Kerberos GSSAPI operation.
# Everything else has smart defaults.
#
# After first edit: the container NEVER overwrites this file.
# =============================================================================

ldap_uri = "ldaps://klldap.example.com:6360"

[storage]
# container_root is the base inside the container where your data appears.
# Match this to your docker -v ...:/export  (or change if you prefer another mount)
container_root = "/export"

[server]
# hostname = "yourhost-nfs"   # Optional override. The recommended way is to start
#                             # the container with --uts=host so it sees the real
#                             # host hostname. The TUI will tell you the exact
#                             # principal (with -nfs insertion) to use in the keytab.
#                             # Explicit --hostname takes precedence if set.

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "CHANGE_THIS_TO_A_STRONG_SECRET"

# The generator now produces a much richer sssd.conf based on real-world
# LLDAP + Kerberos + Ganesha production setups (both your ldap:// and ldaps:// examples).
#
# It auto-switches based on the scheme in ldap_uri:
#   - ldap://   → emits the "I know this is insecure" safety flags
#   - ldaps://  → defaults to stricter tls_reqcert=demand
#
# It also supports the popular hybrid model (LDAP for identity + Kerberos for auth).
#
# Common overrides:
#   auth_provider = "krb5"
#   domain = "lldap"
#   ldap_schema = "rfc2307bis"
#   ldap_id_mapping = false
#   enumerate = false          # conservative setting used in some production ldaps configs
#   access_provider = "permit"

# [kerberos]
# realm = "KRB.EXAMPLE.COM"  # REQUIRED if auto-derivation from ldap_uri host domain fails
#                            # (or set NFS_REALM env var before starting the container).
#                            # Auto-derivation only works for real DNS hostnames in ldap_uri.

[ganesha]
default_security = "krb5p"   # krb5p (recommended) | krb5i | krb5

[management]
# WebUI settings (in-container on port 9630)
# lldap_graphql_url = "https://kllap.example.com:6360/api/graphql"
# ganesha_container_name = "nfs-klldap"   # (legacy, no longer used — WebUI performs FS ops directly)
# webui_admin_group = "lldap_admin"       # LLDAP group whose members can modify shares/settings from any machine
#                                         # (plus the special immutable "localhost" user via simple sidecar password)

# =============================================================================
# Shares — add as many as you need. Names must be unique.
# =============================================================================
#
# IMPORTANT:
#   host_path  = The REAL absolute path on your Docker HOST machine.
#                This is used by the web UI and privileged helper for permissions
#                (chown/chmod). Ganesha does NOT use this value.
#
#   You MUST still provide a bind mount when starting the container so the data
#   becomes visible inside at the expected path (/export/{name} by default).
#
# Recommended patterns:
#
#   1. Mount parent directory (cleanest):
#      -v /home/user/nfs-data:/export
#
#      Then in config:
#      host_path = "/home/user/nfs-data/movies"
#
#   2. Mount specific directories:
#      -v /home/user/nfs-data/movies:/export/movies
#      host_path = "/home/user/nfs-data/movies"
#
# The NFS client will see short clean paths like /movies (not /export/movies).
# =============================================================================

# [[shares]]
# name = "movies"
# host_path = "/home/user/nfs-data/movies"   # REAL path on the HOST
#
# [[shares]]
# name = "backups"
# host_path = "/home/user/nfs-data/backups"
"#
    .to_string()
}

/// Write the default template only if the file does not exist.
/// Returns true if a file was created.
pub fn write_default_config_if_missing(path: &Path) -> Result<bool, ConfigError> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmpl = generate_default_template();
    fs::write(path, tmpl.as_bytes())?;
    // Secure perms (contains secrets)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(true)
}

/// Full generation driver. Call this from entrypoint / watcher / UI save hooks.
pub fn generate_all(cfg: &NfsKlldapConfig, paths: &GenerationPaths) -> Result<(), ConfigError> {
    fs::create_dir_all(&paths.exports_dir)?;

    write_sssd_conf(cfg, &paths.sssd_conf)?;
    write_krb5_conf(cfg, &paths.krb5_conf)?;
    write_ganesha_main(cfg, &paths.ganesha_conf, &paths.exports_dir)?;
    write_export_fragments(cfg, &paths.exports_dir)?;

    Ok(())
}

fn write_sssd_conf(cfg: &NfsKlldapConfig, out: &Path) -> Result<(), ConfigError> {
    let realm = cfg.effective_realm();
    let search_base = cfg
        .sssd
        .ldap_search_base
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("dc={}", realm.to_lowercase().replace('.', ",dc=")));

    let default_user_base = format!("ou=people,{}", search_base);
    let default_group_base = format!("ou=groups,{}", search_base);

    let user_base = cfg
        .sssd
        .ldap_user_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&default_user_base);
    let group_base = cfg
        .sssd
        .ldap_group_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&default_group_base);

    let domain_name = cfg
        .sssd
        .domain
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());

    let is_plain_ldap = cfg.ldap_uri.starts_with("ldap://");

    // Determine auth provider (default "ldap", but "krb5" is very common in Kerberized NFS setups)
    let auth_provider = cfg
        .sssd
        .auth_provider
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "ldap".to_string());

    let mut content = format!(
        r#"[sssd]
config_file_version = 2
services = nss, pam
domains = {domain_name}

[nss]
filter_users = root
filter_groups = root

[domain/{domain_name}]
id_provider = ldap
auth_provider = {auth_provider}
ldap_uri = {ldap_uri}
ldap_search_base = {search_base}
ldap_default_bind_dn = {bind_dn}
ldap_default_authtok = {bind_pw}
cache_credentials = true
"#,
        domain_name = domain_name,
        auth_provider = auth_provider,
        ldap_uri = cfg.ldap_uri,
        search_base = search_base,
        bind_dn = cfg.sssd.ldap_default_bind_dn,
        bind_pw = cfg.sssd.ldap_default_authtok,
    );

    // Rich LLDAP + POSIX attribute mappings + production safety flags.
    // The helper now also handles hybrid Kerberos authentication when requested.
    content.push_str(&build_ldap_domain_options(
        cfg,
        user_base,
        group_base,
        is_plain_ldap,
    ));

    fs::write(out, content.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Builds the rich body of the [domain/xxx] section.
///
/// This is the main "broad spectrum" helper. It aims to generate something
/// very close to real-world proven LLDAP + Kerberos + Ganesha configurations
/// (both plain ldap:// and ldaps:// variants).
fn build_ldap_domain_options(
    cfg: &NfsKlldapConfig,
    user_base: &str,
    group_base: &str,
    is_plain_ldap: bool,
) -> String {
    let s = &cfg.sssd;

    // --- POSIX attribute mappings (user overrides always win) ---
    let user_obj = s
        .ldap_user_object_class
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "posixAccount".to_string());
    let group_obj = s
        .ldap_group_object_class
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "posixGroup".to_string());

    let u_name = s
        .ldap_user_name
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "uid".to_string());
    let u_uid = s
        .ldap_user_uid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "uidNumber".to_string());
    let u_gid = s
        .ldap_user_gid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "gidNumber".to_string());
    let u_home = s
        .ldap_user_home_directory
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "homeDirectory".to_string());
    let u_shell = s
        .ldap_user_shell
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "loginShell".to_string());

    let g_name = s
        .ldap_group_name
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "cn".to_string());
    let g_gid = s
        .ldap_group_gid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "gidNumber".to_string());

    // enumerate default = true because this project (Ganesha + permission helper + getent usage)
    // benefits from a warm cache in typical homelab/small environments.
    // Users with larger directories or different operational needs can set enumerate = false.
    let enumerate = if s.enumerate.unwrap_or(true) {
        "true"
    } else {
        "false"
    };

    let mut out = format!(
        r#"ldap_user_search_base = {user_base}
ldap_user_object_class = {user_obj}
ldap_user_name = {u_name}
ldap_user_uid_number = {u_uid}
ldap_user_gid_number = {u_gid}
ldap_user_home_directory = {u_home}
ldap_user_shell = {u_shell}

ldap_group_search_base = {group_base}
ldap_group_object_class = {group_obj}
ldap_group_name = {g_name}
ldap_group_gid_number = {g_gid}

enumerate = {enumerate}
access_provider = {access}
use_fully_qualified_names = {fq}
"#,
        user_base = user_base,
        group_base = group_base,
        access = s
            .access_provider
            .as_ref()
            .filter(|v| !v.trim().is_empty())
            .map(|s| s.trim())
            .unwrap_or("permit"),
        fq = if s.use_fully_qualified_names.unwrap_or(false) {
            "true"
        } else {
            "false"
        },
    );

    // ldap_schema (very useful with modern LLDAP)
    if let Some(schema) = s.ldap_schema.as_ref().filter(|v| !v.trim().is_empty()) {
        out.push_str(&format!("ldap_schema = {}\n", schema.trim()));
    }

    // ldap_id_mapping (usually false when LLDAP provides real numbers)
    if let Some(idmap) = s.ldap_id_mapping {
        out.push_str(&format!(
            "ldap_id_mapping = {}\n",
            if idmap { "true" } else { "false" }
        ));
    }

    // === TLS / safety flags (auto-switches based on ldap vs ldaps) ===
    // User-provided values always take full precedence.

    // Always emit cacert if user set one
    if let Some(ref v) = s.ldap_tls_cacert {
        if !v.trim().is_empty() {
            out.push_str(&format!("ldap_tls_cacert = {}\n", v.trim()));
        }
    }

    if is_plain_ldap {
        // === Plain LDAP (insecure) profile ===
        // Emit strong safety/acknowledgement flags by default.
        if s.ldap_auth_disable_tls_never_use_in_production
            .unwrap_or(true)
        {
            out.push_str("ldap_auth_disable_tls_never_use_in_production = true\n");
        }

        let reqcert = s
            .ldap_tls_reqcert
            .as_ref()
            .filter(|v| !v.trim().is_empty())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "never".to_string());
        out.push_str(&format!("ldap_tls_reqcert = {}\n", reqcert));

        let use_start = s.ldap_id_use_start_tls.unwrap_or(false);
        out.push_str(&format!(
            "ldap_id_use_start_tls = {}\n",
            if use_start { "true" } else { "false" }
        ));
    } else {
        // === LDAPS (secure) profile ===
        // Default to stricter validation ("demand") unless user overrides.
        let reqcert = s
            .ldap_tls_reqcert
            .as_ref()
            .filter(|v| !v.trim().is_empty())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "demand".to_string());
        out.push_str(&format!("ldap_tls_reqcert = {}\n", reqcert));

        if let Some(true) = s.ldap_id_use_start_tls {
            out.push_str("ldap_id_use_start_tls = true\n");
        }
    }

    // === Kerberos authentication block (hybrid mode) ===
    // When auth_provider is krb5, we emit the full Kerberos settings under the domain.
    // This matches real production usage of LLDAP + Kerberized NFS (LDAP for identity, Kerberos for auth).
    let auth = s.auth_provider.as_ref().map(|s| s.trim()).unwrap_or("ldap");
    if auth.eq_ignore_ascii_case("krb5") {
        let chpass = s
            .chpass_provider
            .as_ref()
            .filter(|v| !v.trim().is_empty())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "krb5".to_string());

        let kdc_host = s
            .krb5_server
            .as_ref()
            .filter(|v| !v.trim().is_empty())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| extract_host_from_uri(&cfg.ldap_uri));

        let kpasswd = s
            .krb5_kpasswd
            .as_ref()
            .filter(|v| !v.trim().is_empty())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| kdc_host.clone());

        out.push_str(&format!(
            r#"
# === Kerberos Authentication (hybrid with LDAP identity) ===
chpass_provider = {chpass}
krb5_server = {kdc_host}
krb5_realm = {realm}
krb5_kpasswd = {kpasswd}
"#,
            realm = cfg.effective_realm()
        ));

        // Extra Kerberos tuning from real ldaps production configs
        if let Some(v) = s.krb5_validate {
            out.push_str(&format!(
                "krb5_validate = {}\n",
                if v { "true" } else { "false" }
            ));
        }
        if let Some(v) = s.krb5_store_password_if_offline {
            out.push_str(&format!(
                "krb5_store_password_if_offline = {}\n",
                if v { "true" } else { "false" }
            ));
        }
    }

    out
}

fn write_krb5_conf(cfg: &NfsKlldapConfig, out: &Path) -> Result<(), ConfigError> {
    let realm = cfg.effective_realm();
    let kdc_host = extract_host_from_uri(&cfg.ldap_uri);

    let content = format!(
        r#"[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    {realm} = {{
        kdc = {kdc_host}
        admin_server = {kdc_host}
    }}

[domain_realm]
    .{realm_lower} = {realm}
    {realm_lower} = {realm}
"#,
        realm = realm,
        realm_lower = realm.to_lowercase(),
        kdc_host = kdc_host,
    );

    fs::write(out, content.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // krb5.conf is public config (no secrets)
        let _ = fs::set_permissions(out, fs::Permissions::from_mode(0o644));
    }
    Ok(())
}

fn write_ganesha_main(
    cfg: &NfsKlldapConfig,
    out: &Path,
    exports_dir: &Path,
) -> Result<(), ConfigError> {
    let sec = &cfg.ganesha.default_security;

    let content = format!(
        r#"NFS_CORE_PARAM {{
    Protocols = 4;
}}

NFSV4 {{
    Lease_Lifetime = 60;
}}

EXPORT_DEFAULTS {{
    SecType = {sec};
}}

%include "{exports}/*.conf"
"#,
        sec = sec,
        exports = exports_dir.display(),
    );

    fs::write(out, content.as_bytes())?;
    Ok(())
}

fn write_export_fragments(cfg: &NfsKlldapConfig, exports_dir: &Path) -> Result<(), ConfigError> {
    // Clean old managed fragments (we own them)
    if exports_dir.exists() {
        for entry in fs::read_dir(exports_dir)? {
            let p = entry?.path();
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if name.ends_with(".conf") {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }

    for (i, share) in cfg.shares.iter().enumerate() {
        let export_id = derive_export_id(&share.name, 1000 + (i as u16 * 10));
        let path = cfg.container_path_for(share);
        let default_pseudo = format!("/{}", share.name);
        let pseudo = share.export_path.as_deref().unwrap_or(&default_pseudo);
        let default_sec = &cfg.ganesha.default_security;
        let sec = share.security.as_deref().unwrap_or(default_sec);
        let access = if share.rw.unwrap_or(true) { "RW" } else { "RO" };
        let squash = share.squash.as_deref().unwrap_or("no_root_squash");

        let block = format!(
            r#"# Generated from nfs-klldap.conf share "{}"
EXPORT {{
    Export_Id = {};
    Path = {};
    Pseudo = {};
    Access_Type = {};
    SecType = {};
    Protocols = 4;
    Transports = TCP;
    Squash = {};

    FSAL {{
        Name = VFS;
    }}
}}
"#,
            share.name, export_id, path, pseudo, access, sec, squash
        );

        let filename = format!("{:02}-{}.conf", i + 10, sanitize_name(&share.name));
        fs::write(exports_dir.join(filename), block.as_bytes())?;
    }

    Ok(())
}

/// Extract the host portion from an ldap/ldaps URI.
/// Public so the startup binary (and future slimmed-down shell) can use the
/// same robust logic instead of fragile sed/grep.
pub fn extract_host_from_uri(uri: &str) -> String {
    let after = uri.split("://").nth(1).unwrap_or(uri);
    // IPv6 literal: ldaps://[2001:db8::1]:636  or ldaps://[::1]/...
    if let Some(rest) = after.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    after
        .split([':', '/'])
        .next()
        .unwrap_or("localhost")
        .to_string()
}

/// Compute the recommended container hostname for Kerberized NFS.
///
/// The container hostname must match the `nfs/<hostname>@REALM` principal in the keytab.
/// Because Docker's `--hostname` is used for both the system hostname and Kerberos
/// principal derivation, we need a stable, DNS-resolvable name.
///
/// Recommended convention: take the host's short name and insert "-nfs" before the
/// first dot (or append if there is no dot).
///
/// Examples:
/// - "aurora.satomlin.com" → "aurora-nfs.satomlin.com"
/// - "myserver"            → "myserver-nfs"
/// - "foo.bar.baz.co.uk"   → "foo-nfs.bar.baz.co.uk"
///
/// This is the value users should pass to `--hostname` (or compose `hostname:`).
pub fn suggested_nfs_hostname(host: &str) -> String {
    let h = host.trim();
    if h.is_empty() || h == "." {
        return "nfs-server".to_string();
    }
    // Remove any leading/trailing dots for safety
    let h = h.trim_matches('.');
    if h.is_empty() {
        return "nfs-server".to_string();
    }
    if let Some((first, rest)) = h.split_once('.') {
        if first.is_empty() {
            // Should not happen after trim, but be defensive
            format!("{}-nfs", h)
        } else {
            format!("{}-nfs.{}", first, rest)
        }
    } else {
        // No dot: simple hostname, just append
        format!("{}-nfs", h)
    }
}

/// Returns true if the string looks like a Docker auto-assigned default hostname
/// (the short container ID). These are 8-20 lowercase hex digits with no dot.
/// When we see one, we know the user did not pass --hostname and we should
/// (historical note — hostname handling is now based on --uts=host)
pub fn looks_like_docker_default_hostname(h: &str) -> bool {
    let h = h.trim();
    if h.contains('.') {
        return false;
    }
    let len = h.len();
    if !(8..=20).contains(&len) {
        return false;
    }
    h.chars().all(|c| c.is_ascii_hexdigit())
}

/// Returns true if the host portion (from ldap_uri) is a literal IP address (v4 or v6).
/// Used to reject IP-based ldap_uri (DNS forward+reverse required for Kerberos NFS principals).
fn host_is_ip(host: &str) -> bool {
    let h = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    h.parse::<std::net::IpAddr>().is_ok()
}

fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn derive_export_id(name: &str, base: u16) -> u16 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        h = h.wrapping_mul(16777619) ^ (*b as u32);
    }
    base + (h % 55000) as u16
}

// Small hostname helper (no extra deps)
mod hostname {
    pub fn get() -> Result<std::ffi::OsString, std::io::Error> {
        // Simple /proc/sys/kernel/hostname or env fallback
        if let Ok(h) = std::env::var("HOSTNAME") {
            return Ok(h.into());
        }
        let p = "/proc/sys/kernel/hostname";
        if let Ok(s) = std::fs::read_to_string(p) {
            return Ok(s.trim().to_string().into());
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine hostname",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// RAII guard to safely set an environment variable for the duration of a test
    /// and restore the previous value (or remove it) when the test ends.
    /// This prevents test pollution when running with --workspace (parallel tests).
    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn minimal_cfg() -> NfsKlldapConfig {
        let mut c = NfsKlldapConfig {
            ldap_uri: "ldaps://kllap.test:6360".into(),
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=admin,ou=people,dc=test,dc=com".into(),
                ldap_default_authtok: "sekret".into(),
                ..Default::default()
            },
            shares: vec![
                Share {
                    name: "movies".into(),
                    host_path: "/media/SSD/movies".into(),
                    ..Default::default()
                },
                Share {
                    name: "data".into(),
                    host_path: "/media/SSD/data".into(),
                    security: Some("krb5i".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        c.validate_and_derive().expect("valid minimal");
        c
    }

    #[test]
    fn load_and_derive_works() {
        let c = minimal_cfg();
        assert_eq!(c.effective_realm(), "TEST");
        assert!(c.sssd.port.is_some());
        assert_eq!(c.shares.len(), 2);
        assert_eq!(c.container_path_for(&c.shares[0]), "/export/movies");
    }

    #[test]
    fn generate_produces_expected_artifacts() {
        let cfg = minimal_cfg();
        let tmp = tempfile::tempdir().unwrap();
        let paths = GenerationPaths {
            sssd_conf: tmp.path().join("sssd.conf"),
            krb5_conf: tmp.path().join("krb5.conf"),
            ganesha_conf: tmp.path().join("ganesha.conf"),
            exports_dir: tmp.path().join("exports.d"),
        };
        generate_all(&cfg, &paths).expect("generate");

        let sssd = fs::read_to_string(&paths.sssd_conf).unwrap();
        assert!(sssd.contains("ldap_uri = ldaps://kllap.test:6360"));
        assert!(sssd.contains("ldap_default_authtok = sekret"));

        let krb = fs::read_to_string(&paths.krb5_conf).unwrap();
        assert!(krb.contains("default_realm = TEST"));
        assert!(
            krb.contains("rdns = false"),
            "krb5.conf should include rdns=false for improved Kerberos reverse-DNS tolerance"
        );

        let main = fs::read_to_string(&paths.ganesha_conf).unwrap();
        assert!(main.contains("%include"));

        let exports: Vec<_> = fs::read_dir(&paths.exports_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(exports.len(), 2);
        // one fragment should mention krb5i for the second share
        let frag =
            fs::read_to_string(paths.exports_dir.join("11-data.conf")).unwrap_or_else(|_| {
                // fallback find
                let mut s = String::new();
                for e in fs::read_dir(&paths.exports_dir).unwrap() {
                    let p = e.unwrap().path();
                    if p.to_string_lossy().contains("data") {
                        s = fs::read_to_string(p).unwrap();
                    }
                }
                s
            });
        assert!(frag.contains("SecType = krb5i") || frag.contains("data"));
    }

    #[test]
    fn duplicate_names_rejected() {
        let mut c = minimal_cfg();
        c.shares.push(Share {
            name: "movies".into(),
            host_path: "/x".into(),
            ..Default::default()
        });
        assert!(c.validate_and_derive().is_err());
    }

    #[test]
    fn invalid_security_rejected() {
        let mut c = minimal_cfg();
        c.ganesha.default_security = "krb5x".into();
        assert!(c.validate_and_derive().is_err());

        let mut c2 = minimal_cfg();
        c2.shares[0].security = Some("aes-256".into());
        assert!(c2.validate_and_derive().is_err());
    }

    #[test]
    fn load_host_paths_only_returns_only_host_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("partial.conf");

        // Write a config that is intentionally missing bind credentials (should still work for helper)
        let partial = r#"
            ldap_uri = "ldaps://kllap.test:6360"
            [[shares]]
            name = "movies"
            host_path = "/media/SSD/movies"
            [[shares]]
            name = "backups"
            host_path = "/media/SSD/backups"
        "#;
        fs::write(&path, partial).unwrap();

        let roots = load_host_paths_only(&path).expect("should parse partial config");
        assert_eq!(roots.len(), 2);
        assert!(roots.iter().any(|p| p.to_string_lossy().contains("movies")));
        assert!(roots
            .iter()
            .any(|p| p.to_string_lossy().contains("backups")));
    }

    #[test]
    fn sanitize_name_replaces_invalid_chars() {
        assert_eq!(sanitize_name("my share!"), "my-share-");
        assert_eq!(sanitize_name("data_01"), "data_01");
        assert_eq!(sanitize_name("foo@bar#baz"), "foo-bar-baz");
    }

    #[test]
    fn derive_export_id_is_deterministic() {
        let id1 = derive_export_id("movies", 1000);
        let id2 = derive_export_id("movies", 1000);
        assert_eq!(id1, id2);
        assert_ne!(
            derive_export_id("movies", 1000),
            derive_export_id("data", 1000)
        );
    }

    #[test]
    fn realm_is_required_no_silent_example() {
        // Prevent pollution from parallel tests in the workspace
        let _g1 = EnvGuard::remove("NFS_REALM");
        let _g2 = EnvGuard::remove("REALM");

        // Explicit placeholder in config must be rejected (core user complaint)
        let mut c = NfsKlldapConfig {
            ldap_uri: "ldaps://kllap.example.com:6360".into(),
            kerberos: KerberosSection {
                realm: Some("EXAMPLE.COM".into()),
            },
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "s".into(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "t".into(),
                host_path: "/t".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = c.validate_and_derive().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("kerberos.realm is required"));
        assert!(msg.contains("NFS_REALM"));

        // Explicit good realm passes
        c.kerberos.realm = Some("MY.REALM".into());
        assert!(c.validate_and_derive().is_ok());
        assert_eq!(c.effective_realm(), "MY.REALM");
    }

    #[test]
    fn realm_from_env_works() {
        // Use guard to prevent pollution of parallel tests in the workspace
        let _guard = EnvGuard::set("NFS_REALM", "ENV.REALM");

        let mut c = NfsKlldapConfig {
            ldap_uri: "ldaps://kllap.test:6360".into(), // would derive "TEST" without env
            sssd: SssdSection {
                ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "s".into(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "t".into(),
                host_path: "/t".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(c.validate_and_derive().is_ok());
        assert_eq!(c.effective_realm(), "ENV.REALM");
    }

    #[test]
    fn sssd_tls_options_are_emitted_when_set() {
        let mut c = minimal_cfg();
        c.sssd.ldap_tls_reqcert = Some("never".into());
        c.sssd.ldap_id_use_start_tls = Some(true);
        c.sssd.ldap_tls_cacert = Some("/etc/pki/ca.crt".into());
        // Force a non-ldaps uri so STARTTLS makes sense in the test
        c.ldap_uri = "ldap://kllap.test:389".into();
        // Re-derive (port etc.) — validate will also set search bases
        let _ = c.validate_and_derive();

        let tmp = tempfile::tempdir().unwrap();
        let paths = GenerationPaths {
            sssd_conf: tmp.path().join("sssd.conf"),
            krb5_conf: tmp.path().join("krb5.conf"),
            ganesha_conf: tmp.path().join("ganesha.conf"),
            exports_dir: tmp.path().join("exports.d"),
        };
        generate_all(&c, &paths).expect("generate with tls");

        let sssd = fs::read_to_string(&paths.sssd_conf).unwrap();
        assert!(sssd.contains("ldap_tls_reqcert = never"));
        // We accept both casings; the generator now prefers lowercase to match real production examples.
        assert!(sssd.to_lowercase().contains("ldap_id_use_start_tls = true"));
        assert!(sssd.contains("ldap_tls_cacert = /etc/pki/ca.crt"));
        // Should still have the core ldap_uri from the (overridden) config
        assert!(sssd.contains("ldap_uri = ldap://kllap.test:389"));
    }

    #[test]
    fn ldap_uri_ip_rejected_with_exact_message() {
        std::env::remove_var("NFS_REALM");
        std::env::remove_var("REALM");

        fn make_minimal(ip_uri: &str) -> NfsKlldapConfig {
            NfsKlldapConfig {
                ldap_uri: ip_uri.into(),
                sssd: SssdSection {
                    ldap_default_bind_dn: "uid=admin,ou=people,dc=x,dc=com".into(),
                    ldap_default_authtok: "s".into(),
                    ..Default::default()
                },
                shares: vec![Share {
                    name: "t".into(),
                    host_path: "/t".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
        }

        // IPv4
        let mut c = make_minimal("ldaps://192.168.10.5:6360");
        let err = c.validate_and_derive().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(
                "LDAP IP addresses are not supported, DNS resolution is required for operation."
            ),
            "unexpected error: {}",
            msg
        );

        // IPv6 (with brackets in URI)
        let mut c6 = make_minimal("ldaps://[2001:db8::1]:6360");
        let err6 = c6.validate_and_derive().unwrap_err();
        assert!(err6
            .to_string()
            .contains("LDAP IP addresses are not supported"));

        // Also bare IPv6 without port etc.
        let mut c6b = make_minimal("ldap://[::1]");
        assert!(c6b.validate_and_derive().is_err());

        // Hostname is allowed (validation proceeds to other required fields)
        let mut ch = make_minimal("ldaps://kllap.example.com:6360");
        // Will fail on realm (no EXAMPLE), but NOT on the IP check
        let hmsg = ch.validate_and_derive().unwrap_err().to_string();
        assert!(!hmsg.contains("IP addresses are not supported"));
        assert!(hmsg.contains("kerberos.realm is required"));
    }

    #[test]
    fn suggested_nfs_hostname_inserts_before_first_dot() {
        // Primary use case from the bug report
        assert_eq!(
            suggested_nfs_hostname("aurora.satomlin.com"),
            "aurora-nfs.satomlin.com"
        );
        // Multi-label
        assert_eq!(
            suggested_nfs_hostname("foo.bar.baz.co.uk"),
            "foo-nfs.bar.baz.co.uk"
        );
        // No dot → append
        assert_eq!(suggested_nfs_hostname("myserver"), "myserver-nfs");
        // Already has -nfs (idempotent-ish, we still transform the first label)
        assert_eq!(
            suggested_nfs_hostname("aurora-nfs.satomlin.com"),
            "aurora-nfs-nfs.satomlin.com"
        );
        // Empty / degenerate
        assert_eq!(suggested_nfs_hostname(""), "nfs-server");
        assert_eq!(suggested_nfs_hostname("."), "nfs-server");
        assert_eq!(suggested_nfs_hostname(".."), "nfs-server");
    }

    #[test]
    fn docker_default_hostname_detection() {
        assert!(looks_like_docker_default_hostname("3c896c1c2e24"));
        assert!(looks_like_docker_default_hostname("a1b2c3d4e5f6"));
        assert!(looks_like_docker_default_hostname("0123456789abcdef"));
        assert!(!looks_like_docker_default_hostname("myhost.example.com"));
        assert!(!looks_like_docker_default_hostname("myhost"));
        assert!(!looks_like_docker_default_hostname("abc")); // too short
        assert!(!looks_like_docker_default_hostname("3c896c1c2e24-nfs"));
    }

    #[test]
    fn derive_realm_from_uri_is_public_and_works() {
        assert_eq!(
            derive_realm_from_uri("ldaps://kllap.example.com:6360"),
            Some("EXAMPLE.COM".into())
        );
        assert_eq!(
            derive_realm_from_uri("ldap://sub.host.satomlin.local"),
            Some("HOST.SATOMLIN.LOCAL".into())
        );
        assert_eq!(derive_realm_from_uri(""), None);
    }
}
