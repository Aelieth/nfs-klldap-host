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

        // Enforce DNS name (not IP) for ldap_uri. Forward + reverse DNS is mandatory
        // for the NFS service principal (keytab) and Kerberos GSSAPI operation.
        let host = crate::extract_host_from_uri(&self.ldap_uri);
        if crate::uri::host_is_ip(&host) {
            return Err(ConfigError::Validation(
                "LDAP IP addresses are not supported, DNS resolution is required for operation."
                    .into(),
            ));
        }

        // Auto-derive realm if missing (from ldap_uri)
        if self.kerberos.realm.is_none() {
            if let Some(realm) = crate::derive_realm_from_uri(&self.ldap_uri) {
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

        // Informational port (636/389) — ldap_uri must include the port used by SSSD.
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
