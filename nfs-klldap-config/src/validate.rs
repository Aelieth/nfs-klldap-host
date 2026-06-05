//! Validation and auto-derivation for NfsKlldapConfig (DNS ldap_uri, realm, shares, etc.).

use std::collections::HashSet;
use std::path::PathBuf;

use crate::{ConfigError, NfsKlldapConfig, Share};

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
        let contents = std::fs::read_to_string(path).map_err(ConfigError::Io)?;

        let mut cfg: Self = toml::from_str(&contents).map_err(|e| ConfigError::Parse {
            path: path.display().to_string(),
            msg: e.to_string(),
        })?;

        cfg.validate_and_derive()?;
        Ok(cfg)
    }

    pub fn validate_and_derive(&mut self) -> Result<(), ConfigError> {
        // Apply env overrides for core nfs-klldap.conf options FIRST (env wins over file or absence).
        // This enables NFS_KLLDAP_* (and WEBUI_*) injection for secrets/compose without requiring
        // values in the TOML (parse uses #[serde(default)], validate enforces after apply).
        // Only core options (per task); not every [sssd] advanced field.
        self.apply_core_env_overrides();

        if self.ldap_uri.trim().is_empty() {
            return Err(ConfigError::Validation("ldap_uri is required".into()));
        }

        // Normalize blank [sssd] overrides to None so explicit values win over derivation.
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

            // kllldap_ignored_attributes is Option<bool> — default handled in generator
            // (we still want to allow explicit false in the TOML)

            // New advanced fields
            normalize_blank(&mut s.domain);
            normalize_blank(&mut s.auth_provider);
            normalize_blank(&mut s.chpass_provider);
            normalize_blank(&mut s.ldap_schema);
            normalize_blank(&mut s.krb5_server);
            normalize_blank(&mut s.krb5_kpasswd);
            // krb5_validate and krb5_store_password_if_offline are bools — no string normalization needed
        }

        // Normalize webui string paths (tls bool needs no string norm).
        normalize_blank(&mut self.webui.tls_cert);
        normalize_blank(&mut self.webui.tls_key);

        // ldap_uri must be DNS (not IP) — forward+reverse required for Kerberos principals.
        let host = crate::extract_host_from_uri(&self.ldap_uri);
        if crate::uri::host_is_ip(&host) {
            return Err(ConfigError::Validation(
                "LDAP IP addresses are not supported, DNS resolution is required for operation."
                    .into(),
            ));
        }

        // Derive realm from ldap_uri if absent; NFS_REALM/REALM env overrides.
        if self.kerberos.realm.is_none() {
            if let Some(realm) = crate::derive_realm_from_uri(&self.ldap_uri) {
                self.kerberos.realm = Some(realm);
            }
        }
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

        // Require real realm (no EXAMPLE.COM placeholder or empty).
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

        // Derive informational port from ldap_uri scheme.
        if self.sssd.port.is_none() {
            self.sssd.port = Some(if self.ldap_uri.starts_with("ldaps://") {
                636
            } else {
                389
            });
        }

        // Derive search bases from effective realm.
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
            // Validate optional pref_read (read-ahead size for streaming/large files)
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
            // Validate optional pref_write (symmetric to pref_read)
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
            // Validate cache_profile (the primary UI-driven field for the 5 tuning profiles)
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

    /// Hostname from [server] or best-effort container value (prefer get_consistent_hostname for production).
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

    /// Realm for banners (real after validation; placeholder otherwise).
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

    /// Apply env var overrides for *core* nfs-klldap.conf options (env wins).
    /// Called early in validate_and_derive. Prefixed names for new options (NFS_KLLDAP_*);
    /// preserves legacy NFS_REALM/REALM and NFS_KLLDAP_LLDAP_* for bind.
    /// Also supports WEBUI_* (for [webui] alignment) and optional NFS_KLLDAP_SSSD_LDAP_TLS_* for cert options.
    fn apply_core_env_overrides(&mut self) {
        // ldap_uri (top-level core)
        if let Ok(v) = std::env::var("NFS_KLLDAP_LDAP_URI") {
            let t = v.trim();
            if !t.is_empty() {
                self.ldap_uri = t.to_string();
            }
        }

        // [kerberos] realm — support new prefixed + keep existing logic later for REALM
        if let Ok(v) = std::env::var("NFS_KLLDAP_KERBEROS_REALM") {
            let t = v.trim();
            if !t.is_empty() {
                self.kerberos.realm = Some(t.to_string());
            }
        }

        // [sssd] bind creds — core + secret path (LLDAP_* kept for UI compat; also honored for generate/TUI now)
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

        // [server]
        if let Ok(v) = std::env::var("NFS_KLLDAP_SERVER_HOSTNAME") {
            let t = v.trim();
            self.server.hostname = if t.is_empty() { None } else { Some(t.to_string()) };
        }

        // [storage]
        if let Ok(v) = std::env::var("NFS_KLLDAP_STORAGE_CONTAINER_ROOT") {
            let t = v.trim();
            if !t.is_empty() {
                self.storage.container_root = t.to_string();
            }
        }

        // [ganesha]
        if let Ok(v) = std::env::var("NFS_KLLDAP_GANESHA_DEFAULT_SECURITY") {
            let t = v.trim();
            if !t.is_empty() {
                self.ganesha.default_security = t.to_string();
            }
        }

        // [management]
        if let Ok(v) = std::env::var("NFS_KLLDAP_MANAGEMENT_WEBUI_ADMIN_GROUP") {
            let t = v.trim();
            self.management.webui_admin_group = if t.is_empty() { None } else { Some(t.to_string()) };
        }

        // [sssd] core toggle (bool tolerant)
        if let Ok(v) = std::env::var("NFS_KLLDAP_SSSD_KLLLDAP_IGNORED_ATTRIBUTES") {
            let t = v.trim().to_ascii_lowercase();
            self.sssd.kllldap_ignored_attributes = Some(t == "true" || t == "1" || t == "yes" || t == "on");
        }

        // [sssd] TLS cert/ssl options ("cert options for ssl")
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

        // [webui] — align WEBUI_TLS=false etc. (under [webui] in conf per review)
        if let Ok(v) = std::env::var("WEBUI_TLS") {
            let t = v.trim().to_ascii_lowercase();
            let disabled = t == "off" || t == "false" || t == "0" || t == "no";
            self.webui.tls = Some(!disabled);
        }
        if let Ok(v) = std::env::var("WEBUI_TLS_CERT") {
            let t = v.trim();
            if !t.is_empty() {
                self.webui.tls_cert = Some(t.to_string());
            }
        }
        if let Ok(v) = std::env::var("WEBUI_TLS_KEY") {
            let t = v.trim();
            if !t.is_empty() {
                self.webui.tls_key = Some(t.to_string());
            }
        }
        // Also allow prefixed variants for webui (rare, but consistent)
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

    pub fn container_path_for(&self, share: &Share) -> String {
        format!(
            "{}/{}",
            self.storage.container_root.trim_end_matches('/'),
            share.name
        )
    }

    pub fn host_paths(&self) -> Vec<PathBuf> {
        self.shares.iter().map(|s| s.host_path.clone()).collect()
    }
}
