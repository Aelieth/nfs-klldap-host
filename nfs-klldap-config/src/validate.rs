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

/// Scan a parsed TOML document for unrecognized keys in `[[shares]]` tables
/// (single-parse load path).
fn detect_share_unknown_keys_value(root: &toml::Value) -> Vec<ShareFieldWarning> {
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
            .filter(|k| {
                let ks = k.as_str();
                !SHARE_KNOWN_KEYS.contains(&ks) && ks != "export_path"
            })
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
        Self::parse_str(&path.display().to_string(), &contents)
    }

    /// Parse + env overrides, no validation, for wizard-stage consumers
    /// (step gating, bind probes). The first-run config is deliberately
    /// incomplete, so the strict `load` would reject it for missing the very
    /// fields the wizard is about to supply.
    pub fn load_lenient(path: &std::path::Path) -> Result<Self, ConfigError> {
        let mut cfg = Self::load_unchecked(path)?;
        cfg.apply_core_env_overrides();
        Ok(cfg)
    }

    /// Parse config text without validation (no file read): one string parse
    /// serves both the struct and the unknown-key scan. A failed tree
    /// deserialize re-parses the string only to keep the span-rich message.
    pub fn parse_str(path_label: &str, contents: &str) -> Result<Self, ConfigError> {
        let root: toml::Value = toml::from_str(contents).map_err(|e| ConfigError::Parse {
            path: path_label.to_string(),
            msg: e.to_string(),
        })?;
        let share_warnings = detect_share_unknown_keys_value(&root);
        let mut cfg: Self = match root.try_into() {
            Ok(c) => c,
            Err(_) => toml::from_str(contents).map_err(|e| ConfigError::Parse {
                path: path_label.to_string(),
                msg: e.to_string(),
            })?,
        };
        cfg.share_warnings = share_warnings;
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

        if let Some(m) = self.webui.session_timeout_minutes {
            if m < 5 {
                return Err(ConfigError::Validation(
                    "webui.session_timeout_minutes must be at least 5 (minutes)".into(),
                ));
            }
        }

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
            self.sssd.port = Some(if self.ldap_uri.starts_with("ldaps://") {
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
            share.container_path = share.container_path.trim().to_string();
            {
                let ep = share.pseudo_path.take();
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
                share.pseudo_path = Some(normalized);
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
                if crate::config::resolve_cache_profile(p).is_none() {
                    return Err(ConfigError::Validation(format!(
                        "share '{}' cache_profile must be one of: {} (got '{}')",
                        share.name,
                        crate::config::CACHE_PROFILES.join(", "),
                        p
                    )));
                }
            }
            if let Some(v) = share.attr_expiration_secs {
                if v < 0 {
                    return Err(ConfigError::Validation(format!(
                        "share '{}' attr_expiration_secs must be >= 0 (0 = attribute caching off), got {}",
                        share.name, v
                    )));
                }
                if v == 0 {
                    eprintln!(
                        "WARN [nfs-klldap-config] share '{}': attr_expiration_secs = 0 disables \
                         attribute caching on this export — every operation stats (and on ACL \
                         paths getfacls) the backing filesystem. Deliberate for coherency-critical \
                         shares; measurable cost elsewhere.",
                        share.name
                    );
                }
            }
        }

        let container_root = self.storage.container_root.trim_end_matches('/').to_string();
        for share in &mut self.shares {
            if share.container_path.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "share '{}' requires container_path (absolute path inside the container; maps to Ganesha Path=)",
                    share.name
                )));
            }
            if !share.container_path.starts_with('/') {
                return Err(ConfigError::Validation(format!(
                    "share '{}' container_path must be absolute (got '{}')",
                    share.name, share.container_path
                )));
            }
            let under_root = share.container_path == container_root
                || share.container_path.starts_with(&format!("{container_root}/"));
            if !under_root {
                return Err(ConfigError::Validation(format!(
                    "share '{}' container_path '{}' must be under storage.container_root '{}'",
                    share.name, share.container_path, container_root
                )));
            }
            if let Some(src) = share.source_path.as_mut() {
                *src = src.trim().to_string();
                if src.is_empty() {
                    share.source_path = None;
                } else {
                    if !src.starts_with('/') {
                        return Err(ConfigError::Validation(format!(
                            "share '{}' source_path must be absolute (got '{}')",
                            share.name, src
                        )));
                    }
                    let src_under_root = *src == container_root
                        || src.starts_with(&format!("{container_root}/"));
                    if !src_under_root {
                        return Err(ConfigError::Validation(format!(
                            "share '{}' source_path '{}' must be under storage.container_root '{}'",
                            share.name, src, container_root
                        )));
                    }
                }
            }
        }

        // Reject duplicate effective Pseudo paths and duplicate serve paths: both collide
        // in Ganesha's NFSv4 pseudo-fs / export table and prevent the second export from
        // loading. Also reject Pseudo "/" (reserved for the auto-synthesized pseudo root).
        let mut seen_pseudo = HashSet::new();
        let mut seen_serve = HashSet::new();
        for share in &self.shares {
            let pseudo = crate::derive_share_pseudo(share);
            if pseudo == "/" {
                return Err(ConfigError::Validation(format!(
                    "share '{}': pseudo_path '/' collides with the NFSv4 pseudo-fs root; use a distinct path like /{}",
                    share.name, share.name
                )));
            }
            if !seen_pseudo.insert(pseudo.clone()) {
                return Err(ConfigError::Validation(format!(
                    "share '{}': duplicate Pseudo path '{}' — each export needs a unique pseudo_path",
                    share.name, pseudo
                )));
            }
            let serve = self.serve_path_for(share);
            if !seen_serve.insert(serve.clone()) {
                return Err(ConfigError::Validation(format!(
                    "share '{}': duplicate container_path '{}' — two exports cannot serve the same Path",
                    share.name, serve
                )));
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
                            acl_capable: false,
                        });
                    let eff = crate::compute_effective_flags(share, &caps);
                    if !eff.enable_acl {
                        // Not fatal: the share is NOACL (ACL is opt-in), so
                        // `read_access_policy = post` is meaningless here and is
                        // normalized to `pre` at emit time. Warn loudly so the operator
                        // can set `enable_acl = true` if they actually wanted the ACL path.
                        eprintln!(
                            "WARN [nfs-klldap-config] share '{}': read_access_policy = post \
                             only applies to ACL exports; this share is NOACL (enable_acl is not \
                             true), so post is ignored and pre is emitted. Set enable_acl = true \
                             (and an ACL-capable serve path) to use post.",
                            share.name
                        );
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

        self.validate_ganesha_tuning()?;

        Ok(())
    }

    /// Validates [ganesha] identity/runtime tuning fields against Ganesha 9.6
    /// parameter ranges (nfs_read_conf.c ground truth; see constants.rs).
    fn validate_ganesha_tuning(&mut self) -> Result<(), ConfigError> {
        normalize_blank(&mut self.ganesha.root_kerberos_principals);
        if let Some(ref raw) = self.ganesha.root_kerberos_principals {
            let tokens: Vec<String> = raw
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect();
            if tokens.is_empty() {
                return Err(ConfigError::Validation(
                    "ganesha.root_kerberos_principals must contain at least one token \
                     (none|nfs|root|host|all); use \"none\" to grant root to no principal"
                        .into(),
                ));
            }
            for t in &tokens {
                if !crate::constants::GANESHA_ROOT_KRB_PRINCIPAL_TOKENS.contains(&t.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "ganesha.root_kerberos_principals token '{}' invalid — allowed: {}",
                        t,
                        crate::constants::GANESHA_ROOT_KRB_PRINCIPAL_TOKENS.join(", ")
                    )));
                }
            }
            if tokens.iter().any(|t| t == "host" || t == "all") {
                eprintln!(
                    "WARN [nfs-klldap-config] ganesha.root_kerberos_principals includes \
                     '{}' — every enrolled client machine keytab (host/...) can act as \
                     root on all exports. Default \"nfs, root\" closes this.",
                    if tokens.iter().any(|t| t == "all") { "all" } else { "host" }
                );
            }
            // Canonical comma-space form for the emitted directive.
            self.ganesha.root_kerberos_principals = Some(tokens.join(", "));
        }
        if let Some(v) = self.ganesha.attr_expiration_secs {
            if v < 0 {
                return Err(ConfigError::Validation(format!(
                    "ganesha.attr_expiration_secs must be >= 0 (0 = attribute caching off), got {}",
                    v
                )));
            }
        }
        if let Some(v) = self.ganesha.manage_gids_expiration_secs {
            if v > crate::constants::GANESHA_MANAGE_GIDS_EXPIRATION_MAX {
                return Err(ConfigError::Validation(format!(
                    "ganesha.manage_gids_expiration_secs must be <= {} (7 days), got {}",
                    crate::constants::GANESHA_MANAGE_GIDS_EXPIRATION_MAX,
                    v
                )));
            }
        }
        if let Some(v) = self.ganesha.readdir_res_size {
            let (min, max) = (
                crate::constants::GANESHA_READDIR_RES_SIZE_MIN,
                crate::constants::GANESHA_READDIR_RES_SIZE_MAX,
            );
            if !(min..=max).contains(&v) {
                return Err(ConfigError::Validation(format!(
                    "ganesha.readdir_res_size must be between {} and {} bytes, got {}",
                    min, max, v
                )));
            }
        }
        if let Some(v) = self.ganesha.readdir_max_count {
            let (min, max) = (
                crate::constants::GANESHA_READDIR_MAX_COUNT_MIN,
                crate::constants::GANESHA_READDIR_MAX_COUNT_MAX,
            );
            if !(min..=max).contains(&v) {
                return Err(ConfigError::Validation(format!(
                    "ganesha.readdir_max_count must be between {} and {} entries, got {}",
                    min, max, v
                )));
            }
        }
        if self.ganesha.malloc_trim_min_threshold_mb == Some(0) {
            return Err(ConfigError::Validation(
                "ganesha.malloc_trim_min_threshold_mb must be >= 1 (value is in MB)".into(),
            ));
        }
        for share in &self.shares {
            if share.manage_gids_expiration.is_some() {
                eprintln!(
                    "WARN [nfs-klldap-config] share '{}': manage_gids_expiration is \
                     deprecated here — the group-trust window is global (Ganesha 9.13 \
                     routes it through DIRECTORY_SERVICES Idmapped_*_Time_Validity). \
                     Move it to [ganesha] manage_gids_expiration_secs; until then the \
                     smallest share value seeds the global.",
                    share.name
                );
            }
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

    /// Short + FQDN for keytab / Navahi / certs (synthesizes FQDN from realm when UTS is short).
    pub fn effective_nfs_host_identity(&self) -> nfs_klldap_identity::NfsHostIdentity {
        nfs_klldap_identity::resolve_nfs_host_identity(
            &self.effective_hostname(),
            &self.effective_realm(),
        )
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
    pub(crate) fn apply_core_env_overrides(&mut self) {
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

        if std::env::var("NFS_KLLDAP_WEBUI_TLS").is_ok() {
            let disabled = crate::webui_tls_disabled();
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

    /// Returns the Ganesha EXPORT Path and fs probe target for a share.
    pub fn serve_path_for(&self, share: &Share) -> String {
        share.container_path.trim().to_string()
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

#[cfg(test)]
mod container_path_validation_tests {
    use super::*;
    use std::path::PathBuf;

    fn minimal_share() -> Share {
        Share {
            name: "movies".into(),
            host_path: PathBuf::from("/media/movies"),
            container_path: "/export/movies".into(),
            ..Default::default()
        }
    }

    fn minimal_cfg_with_share(share: Share) -> NfsKlldapConfig {
        NfsKlldapConfig {
            ldap_uri: "ldaps://klldap.test:6360".into(),
            sssd: crate::SssdSection {
                ldap_default_bind_dn: "uid=admin,ou=people,dc=test,dc=com".into(),
                ldap_default_authtok: "sekret".into(),
                ..Default::default()
            },
            shares: vec![share],
            ..Default::default()
        }
    }

    #[test]
    fn container_path_required() {
        let mut share = minimal_share();
        share.container_path.clear();
        let mut cfg = minimal_cfg_with_share(share);
        let err = cfg.validate_and_derive().unwrap_err().to_string();
        assert!(err.contains("container_path"));
    }

    #[test]
    fn container_path_must_be_under_container_root() {
        let mut share = minimal_share();
        share.container_path = "/other/movies".into();
        let mut cfg = minimal_cfg_with_share(share);
        assert!(cfg.validate_and_derive().is_err());
    }

    #[test]
    fn serve_path_for_returns_container_path() {
        let share = minimal_share();
        let mut cfg = minimal_cfg_with_share(share);
        cfg.validate_and_derive().expect("valid");
        assert_eq!(cfg.serve_path_for(&cfg.shares[0]), "/export/movies");
    }

    #[test]
    fn session_timeout_minutes_enforces_minimum() {
        let mut cfg = minimal_cfg_with_share(minimal_share());
        cfg.webui.session_timeout_minutes = Some(4);
        let err = cfg.validate_and_derive().unwrap_err().to_string();
        assert!(err.contains("session_timeout_minutes"), "{err}");

        cfg.webui.session_timeout_minutes = Some(5);
        cfg.validate_and_derive().expect("5 minutes is the floor");

        cfg.webui.session_timeout_minutes = None;
        cfg.validate_and_derive().expect("unset means the default");
    }
}
