//! nfs-klldap-config — Tiny, type-safe TOML loader + generator for nfs-klldap-host (v0.23+).
//!
//! This crate is the *only* place that understands nfs-klldap.conf.
//! It is bundled as a small static-friendly binary inside the container.
//! The host UI (nfs-klldap-ui) depends on it for loading/saving the same schema.
//!
//! Core responsibilities:
//! - Parse + validate the single source-of-truth config
//! - Smart auto-derivation (realm, ports, bases, paths)
//! - Generate sssd.conf, krb5.conf, ganesha.conf + per-share EXPORT fragments
//! - First-run safe default template (never overwrites)
//! - Dup share name detection (short, unique NFS paths)

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
            if r.is_empty() || r.eq_ignore_ascii_case("EXAMPLE.COM") || r.eq_ignore_ascii_case("EXAMPLE") {
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

        // Auto search bases (simple but effective)
        if self.sssd.ldap_user_search_base.is_none() {
            self.sssd.ldap_user_search_base = Some("ou=people,dc=example,dc=com".to_string());
        }
        if self.sssd.ldap_group_search_base.is_none() {
            self.sssd.ldap_group_search_base = Some("ou=groups,dc=example,dc=com".to_string());
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

    /// Returns the list of host-side paths declared in shares (used by host UI for validation before asking the container to perform chown/chmod).
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

fn derive_realm_from_uri(uri: &str) -> Option<String> {
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

ldap_uri = "ldaps://kllap.example.com:6360"

[storage]
# container_root is the base inside the container where your data appears.
# Match this to your docker -v ...:/export  (or change if you prefer another mount)
container_root = "/export"

[server]
# hostname = "yourhost-nfs"   # Optional override. The actual container hostname
#                             # (set via --hostname at docker run time) must match
#                             # the NFS principal in your keytab.

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "CHANGE_THIS_TO_A_STRONG_SECRET"

# [kerberos]
# realm = "KRB.EXAMPLE.COM"  # REQUIRED if auto-derivation from ldap_uri host domain fails
#                            # (or set NFS_REALM env var before starting the container).
#                            # Auto-derivation only works for real DNS hostnames in ldap_uri.

[ganesha]
default_security = "krb5p"   # krb5p (recommended) | krb5i | krb5

[management]
# Host-side UI settings (container ignores most of this section)
lldap_graphql_url = "https://kllap.example.com:6360/api/graphql"
# ganesha_container_name = "nfs-klldap"   # used when the UI asks the container to perform chown/chmod on exported data

# =============================================================================
# Shares — add as many as you need. Names must be unique.
# NFS path will be short and clean: /<name>
# =============================================================================

# [[shares]]
# name = "movies"
# host_path = "/media/SSD-01/movies"   # absolute on the Docker *host*
# # export_path = "/movies"            # defaults to / + name (recommended)
# security = "krb5p"
# rw = true
# squash = "no_root_squash"

# [[shares]]
# name = "backups"
# host_path = "/media/SSD-01/backups"
# security = "krb5i"
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
    let search_base = format!("dc={}", realm.to_lowercase().replace('.', ",dc="));

    let content = format!(
        r#"[sssd]
config_file_version = 2
services = nss, pam
domains = default

[domain/default]
id_provider = ldap
auth_provider = ldap
ldap_uri = {ldap_uri}
ldap_search_base = {search_base}
ldap_default_bind_dn = {bind_dn}
ldap_default_authtok = {bind_pw}
ldap_user_search_base = {user_base}
ldap_group_search_base = {group_base}
cache_credentials = True
enumerate = False
"#,
        ldap_uri = cfg.ldap_uri,
        search_base = search_base,
        bind_dn = cfg.sssd.ldap_default_bind_dn,
        bind_pw = cfg.sssd.ldap_default_authtok,
        user_base = cfg
            .sssd
            .ldap_user_search_base
            .as_deref()
            .unwrap_or("ou=people,dc=example,dc=com"),
        group_base = cfg
            .sssd
            .ldap_group_search_base
            .as_deref()
            .unwrap_or("ou=groups,dc=example,dc=com"),
    );

    fs::write(out, content.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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
        assert!(krb.contains("rdns = false"), "krb5.conf should include rdns=false for improved Kerberos reverse-DNS tolerance");

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
        // Ensure no env var leakage from parallel tests (NFS_REALM/REALM can override)
        std::env::remove_var("NFS_REALM");
        std::env::remove_var("REALM");

        // Explicit placeholder in config must be rejected (core user complaint)
        let mut c = NfsKlldapConfig {
            ldap_uri: "ldaps://kllap.example.com:6360".into(),
            kerberos: KerberosSection { realm: Some("EXAMPLE.COM".into()) },
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
        // Save/restore to avoid polluting other tests (parallel execution)
        let prior = std::env::var("NFS_REALM").ok();
        std::env::set_var("NFS_REALM", "ENV.REALM");
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
        match prior {
            Some(v) => std::env::set_var("NFS_REALM", v),
            None => std::env::remove_var("NFS_REALM"),
        }
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
            msg.contains("LDAP IP addresses are not supported, DNS resolution is required for operation."),
            "unexpected error: {}",
            msg
        );

        // IPv6 (with brackets in URI)
        let mut c6 = make_minimal("ldaps://[2001:db8::1]:6360");
        let err6 = c6.validate_and_derive().unwrap_err();
        assert!(err6.to_string().contains("LDAP IP addresses are not supported"));

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
}
