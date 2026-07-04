//! Validates config and builds realm, bases.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::{
    config::{ShareFieldWarning, SHARE_KNOWN_KEYS},
    ConfigError, NfsKlldapConfig, Share,
};

/// True for empty realm or uppercase placeholder sentinels (EXAMPLE.COM / EXA.
/// Lowercase FQDN-style realms (e.g. example.com) are real values, not placeh.
pub(crate) fn is_kerberos_placeholder_realm(r: &str) -> bool {
    let t = r.trim();
    if t.is_empty() {
        return true;
    }
    if t.chars().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    t.eq_ignore_ascii_case("EXAMPLE.COM") || t.eq_ignore_ascii_case("EXAMPLE")
}

/// Scan raw TOML for unrecognized keys in `[[shares]]` tables.
pub fn detect_share_unknown_keys(contents: &str) -> Vec<ShareFieldWarning> {
    let root: toml::Value = match toml::from_str(contents) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let Some(shares) = root.get("shares").and_then(|s| s.as_array()) else {
        return vec![];
    };

    let mut warnings = Vec::new();
    for (idx, entry) in shares.iter().enumerate() {
        let Some(table) = entry.as_table() else {
            continue;
        };
        let unknown_keys: Vec<String> = table
            .keys()
            .filter(|k| !SHARE_KNOWN_KEYS.contains(&k.as_str()))
            .cloned()
            .collect();
        if unknown_keys.is_empty() {
            continue;
        }
        let share_name = table
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        warnings.push(ShareFieldWarning {
            share_index: idx,
            share_name,
            unknown_keys,
        });
    }
    warnings
}

fn normalize_blank(field: &mut Option<String>) {
    if let Some(v) = field {
        if v.trim().is_empty() {
            *field = None;
        } else {
            *field = Some(v.trim().to_string());
        }
    }
}

impl NfsKlldapConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let mut cfg = Self::load_unchecked(path)?;
        cfg.validate_and_derive()?;
        Ok(cfg)
    }

    /// Parse nfs-klldap.conf without validation.
    /// For first-run WebUI before realm/bind are set.
    pub fn load_unchecked(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(ConfigError::Io)?;

        let mut cfg: Self = toml::from_str(&contents).map_err(|e| ConfigError::Parse {
            path: path.display().to_string(),
            msg: e.to_string(),
        })?;

        cfg.share_warnings = detect_share_unknown_keys(&contents);
        Ok(cfg)
    }

    pub fn validate_and_derive(&mut self) -> Result<(), ConfigError> {
        self.apply_core_env_overrides();

        if self.ldap_uri.trim().is_empty() {
            return Err(ConfigError::Validation("ldap_uri is required".into()));
        }

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

            normalize_blank(&mut s.domain);
            normalize_blank(&mut s.auth_provider);
            normalize_blank(&mut s.chpass_provider);
            normalize_blank(&mut s.ldap_schema);
            normalize_blank(&mut s.krb5_server);
            normalize_blank(&mut s.krb5_kpasswd);
        }

        normalize_blank(&mut self.webui.tls_cert);
        normalize_blank(&mut self.webui.tls_key);

        let host = crate::extract_host_from_uri(&self.ldap_uri);
        if nfs_klldap_identity::host_is_ip(&host) {
            return Err(ConfigError::Validation(
                "LDAP IP addresses are not supported, DNS resolution is required for operation."
                    .into(),
            ));
        }

        if self.kerberos.realm.is_none() {
            if let Some(realm) = crate::derive_realm_from_uri(&self.ldap_uri) {
                self.kerberos.realm = Some(realm);
            }
        }
        if let Ok(env_realm) = std::env::var("NFS_KLLDAP_KERBEROS_REALM") {
            let t = env_realm.trim();
            if !t.is_empty() {
                self.kerberos.realm = Some(t.to_string());
            }
        }

        {
            let r = self.kerberos.realm.as_deref().unwrap_or("").trim();
            if is_kerberos_placeholder_realm(r) {
                return Err(ConfigError::Validation(
                    "kerberos.realm is required (auto-derivation from ldap_uri failed or produced a placeholder).\n\
                     Set [kerberos] realm = \"YOUR.REALM\" in nfs-klldap.conf, or provide NFS_KLLDAP_KERBEROS_REALM env var.\n\
                     Example: realm = \"KRB.EXAMPLE.COM\"".into(),
                ));
            }
        }

        if self.sssd.port.is_none() {
            self.sssd.port = Some(if self.ldap_uri.starts_with("ldaps:// ") {
                636
            } else {
                389
            });
        }

        let base_dn = format!(
            "dc={}",
            self.effective_realm().to_lowercase().replace('.', ",dc=")
        );
        let main_search_base = self
            .sssd
            .ldap_search_base
            .clone()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| base_dn.clone());

        if self.sssd.ldap_user_search_base.is_none() {
            self.sssd.ldap_user_search_base = Some(main_search_base.clone());
        }
        if self.sssd.ldap_group_search_base.is_none() {
            self.sssd.ldap_group_search_base = Some(main_search_base);
        }

        if self.ganesha.default_security.trim().is_empty() {
            self.ganesha.default_security = crate::constants::GANESHA_DEFAULT_SECTYPE.to_string();
        }
        if !crate::constants::GANESHA_ALLOWED_SECTYPES
            .contains(&self.ganesha.default_security.as_str())
        {
            return Err(ConfigError::Validation(format!(
                "ganesha.default_security must be one of {} (got '{}')",
                crate::constants::GANESHA_ALLOWED_SECTYPES.join(", "),
                self.ganesha.default_security
            )));
        }

        if self.storage.container_root.trim().is_empty() {
            self.storage.container_root = "/export".to_string();
        }

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
            normalize_blank(&mut share.ganesha_path);
            {
                let ep = share.export_path.take();
                let normalized = match ep {
                    Some(v) => {
                        let t = v.trim();
                        if t.is_empty() {
                            format!("/{}", share.name)
                        } else if t.starts_with('/') {
                            t.to_string()
                        } else {
                            format!("/{}", t)
                        }
                    }
                    None => format!("/{}", share.name),
                };
                share.export_path = Some(normalized);
            }
            if let Some(ref sec) = share.security {
                if !crate::constants::GANESHA_ALLOWED_SECTYPES.contains(&sec.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "share '{}' security must be one of {} (got '{}')",
                        share.name,
                        crate::constants::GANESHA_ALLOWED_SECTYPES.join(", "),
                        sec
                    )));
                }
            }
            if let Some(ref sq) = share.squash {
                if !crate::constants::GANESHA_ALLOWED_SQUASH.contains(&sq.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "share '{}' squash must be one of {} (got '{}')",
                        share.name,
                        crate::constants::GANESHA_ALLOWED_SQUASH.join(", "),
                        sq
                    )));
                }
            }
            if let Some(v) = share.pref_read {
                const MIN: u64 = 512;
                const MAX: u64 = 64 * 1024 * 1024;
                if !(MIN..=MAX).contains(&v) {
                    return Err(ConfigError::Validation(format!(
                        "share '{}' pref_read must be between {} and {} bytes (got {}) — use e.g. 1048576 for 1 MiB (Min/ISO) or 16777216 for 16 MiB (Max/streaming)",
                        share.name, MIN, MAX, v
                    )));
                }
            }
            if let Some(v) = share.pref_write {
                const MIN: u64 = 512;
                const MAX: u64 = 64 * 1024 * 1024;
                if !(MIN..=MAX).contains(&v) {
                    return Err(ConfigError::Validation(format!(
                        "share '{}' pref_write must be between {} and {} bytes (got {})",
                        share.name, MIN, MAX, v
                    )));
                }
            }
            if let Some(p) = &share.cache_profile {
                if crate::resolve_cache_profile(p).is_none() {
                    return Err(ConfigError::Validation(format!(
                        "share '{}' cache_profile must be one of: {} (got '{}')",
                        share.name,
                        crate::CACHE_PROFILES.join(", "),
                        p
                    )));
                }
            }
        }

        for share in &self.shares {
            if let Some(ref rap) = share.read_access_policy {
                let policy = rap.trim().to_ascii_lowercase();
                if !crate::constants::GANESHA_READ_ACCESS_POLICIES.contains(&policy.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "share '{}' read_access_policy must be one of {} (got '{}')",
                        share.name,
                        crate::constants::GANESHA_READ_ACCESS_POLICIES.join(", "),
                        rap
                    )));
                }
                if policy == "post" {
                    let serve = self.serve_path_for(share);
                    let caps = crate::probe_fs_capabilities(std::path::Path::new(&serve))
                        .unwrap_or(crate::FsCapabilities {
                            fstype: "unknown".into(),
                            mount_options: vec![],
                            acl_capable: true,
                        });
                    let eff = crate::compute_effective_flags(share, &caps);
                    if !eff.enable_acl {
                        return Err(ConfigError::Validation(format!(
                            "share '{}': read_access_policy = post is not allowed on NOACL exports (limited FS or enable_acl=false); use pre or auto",
                            share.name
                        )));
                    }
                }
            }
        }

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

    /// Hostname from [server] or best-effort container value.
    /// Prefer get_consistent_hostname for production.
    pub fn effective_hostname(&self) -> String {
        self.server.hostname.clone().unwrap_or_else(|| {
            crate::hostname::internal::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "nfs-host".to_string())
        })
    }

    pub fn effective_realm(&self) -> String {
        self.kerberos
            .realm
            .clone()
            .expect("effective_realm called on config that did not pass validation")
    }

    /// Uppercase NFSv4 domain for ganesha.conf DomainName and idmapd.conf.
    /// Realm strings must match case because libnfsidmap is case-sensitive.
    pub fn nfsv4_domain(&self) -> String {
        self.effective_realm().to_ascii_uppercase()
    }

    /// Returns the realm string shown in banners after validation completes.
    pub fn display_realm(&self) -> String {
        self.kerberos
            .realm
            .as_deref()
            .map(str::trim)
            .filter(|r| {
                !r.is_empty()
                    && !r.eq_ignore_ascii_case("EXAMPLE.COM")
                    && !r.eq_ignore_ascii_case("EXAMPLE")
            })
            .map(|r| r.to_string())
            .unwrap_or_else(|| "YOUR.REALM".to_string())
    }

    /// Apply NFS_KLLDAP_* env overrides for core options (env wins)
    fn apply_core_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("NFS_KLLDAP_LDAP_URI") {
            let t = v.trim();
            if !t.is_empty() {
                self.ldap_uri = t.to_string();
            }
        }

        if let Ok(v) = std::env::var("NFS_KLLDAP_KERBEROS_REALM") {
            let t = v.trim();
            if !t.is_empty() {
                self.kerberos.realm = Some(t.to_string());
            }
        }

        if let Ok(v) = std::env::var("NFS_KLLDAP_SSSD_LDAP_DEFAULT_BIND_DN") {
            let t = v.trim();
            if !t.is_empty() {
                self.sssd.ldap_default_bind_dn = t.to_string();
            }
        }
        if let Ok(v) = std::env::var("NFS_KLLDAP_LLDAP_USER") {
            let t = v.trim();
            if !t.is_empty() {
                self.sssd.ldap_default_bind_dn = t.to_string();
            }
        }
        if let Ok(v) = std::env::var("NFS_KLLDAP_SSSD_LDAP_DEFAULT_AUTHTOK") {
            let t = v.trim();
            if !t.is_empty() {
                self.sssd.ldap_default_authtok = t.to_string();
            }
        }
        if let Ok(v) = std::env::var("NFS_KLLDAP_LLDAP_PW") {
            let t = v.trim();
            if !t.is_empty() {
                self.sssd.ldap_default_authtok = t.to_string();
            }
        }

        if let Ok(v) = std::env::var("NFS_KLLDAP_SERVER_HOSTNAME") {
            let t = v.trim();
            self.server.hostname = if t.is_empty() { None } else { Some(t.to_string()) };
        }

        if let Some(val) = crate::host_nfs_from_env() {
            self.host.host_nfs = Some(val);
        }

        if let Ok(v) = std::env::var("NFS_KLLDAP_STORAGE_CONTAINER_ROOT") {
            let t = v.trim();
            if !t.is_empty() {
                self.storage.container_root = t.to_string();
            }
        }

        if let Ok(v) = std::env::var("NFS_KLLDAP_GANESHA_DEFAULT_SECURITY") {
            let t = v.trim();
            if !t.is_empty() {
                self.ganesha.default_security = t.to_string();
            }
        }
        if let Ok(v) = std::env::var("NFS_KLLDAP_POST_GENERATE_HOOK") {
            let t = v.trim();
            self.ganesha.post_generate_hook = if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            };
        }

        if let Ok(v) = std::env::var("NFS_KLLDAP_MANAGEMENT_WEBUI_ADMIN_GROUP") {
            let t = v.trim();
            self.management.webui_admin_group = if t.is_empty() { None } else { Some(t.to_string()) };
        }

        if let Ok(v) = std::env::var("NFS_KLLDAP_SSSD_KLLLDAP_IGNORED_ATTRIBUTES") {
            let t = v.trim().to_ascii_lowercase();
            self.sssd.kllldap_ignored_attributes = Some(t == "true" || t == "1" || t == "yes" || t == "on");
        }

        if let Ok(v) = std::env::var("NFS_KLLDAP_SSSD_LDAP_TLS_REQCERT") {
            let t = v.trim();
            if !t.is_empty() {
                self.sssd.ldap_tls_reqcert = Some(t.to_string());
            }
        }
        if let Ok(v) = std::env::var("NFS_KLLDAP_SSSD_LDAP_TLS_CACERT") {
            let t = v.trim();
            if !t.is_empty() {
                self.sssd.ldap_tls_cacert = Some(t.to_string());
            }
        }
        if let Ok(v) = std::env::var("NFS_KLLDAP_SSSD_LDAP_ID_USE_START_TLS") {
            let t = v.trim().to_ascii_lowercase();
            self.sssd.ldap_id_use_start_tls = Some(t == "true" || t == "1" || t == "yes" || t == "on");
        }

        if let Ok(v) = std::env::var("NFS_KLLDAP_WEBUI_TLS") {
            let t = v.trim().to_ascii_lowercase();
            let disabled = t == "off" || t == "false" || t == "0" || t == "no";
            self.webui.tls = Some(!disabled);
        }
        if let Ok(v) = std::env::var("NFS_KLLDAP_WEBUI_TLS_CERT") {
            let t = v.trim();
            if !t.is_empty() {
                self.webui.tls_cert = Some(t.to_string());
            }
        }
        if let Ok(v) = std::env::var("NFS_KLLDAP_WEBUI_TLS_KEY") {
            let t = v.trim();
            if !t.is_empty() {
                self.webui.tls_key = Some(t.to_string());
            }
        }
    }

    /// Builds the FsManager path from container_root and the host_path tail.
    pub fn container_path_for(&self, share: &Share) -> String {
        let root = self.storage.container_root.trim_end_matches('/');

        let hp = share.host_path.to_string_lossy();
        let hp_trim = hp.trim_end_matches('/');

        let segments: Vec<&str> = hp_trim
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        if !segments.is_empty() {
            let tail = if segments.len() > 1 {
                segments[1..].join("/")
            } else {
                String::new()
            };
            let sub = if tail.is_empty() {
                String::new()
            } else {
                format!("/{}", tail)
            };
            return format!("{}{}", root, sub);
        }

        let ep_owned: String = share
            .export_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("/{}", share.name));
        let ep = if ep_owned.starts_with('/') {
            ep_owned
        } else {
            format!("/{}", ep_owned)
        };
        format!("{}{}", root, ep)
    }

    /// Returns the Ganesha EXPORT Path and fs probe target for a share.
    pub fn serve_path_for(&self, share: &Share) -> String {
        if let Some(ref gp) = share.ganesha_path {
            let t = gp.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
        self.container_path_for(share)
    }

    pub fn host_paths(&self) -> Vec<PathBuf> {
        self.shares.iter().map(|s| s.host_path.clone()).collect()
    }

    /// True when HOST_NFS sidecar mode is enabled.
    /// Container generates configs and runs WebUI + SSSD; host runs Ganesha.
    pub fn is_host_nfs(&self) -> bool {
        self.host.host_nfs.unwrap_or(false)
    }
}
