//! Shared runtime env helpers for HOST_NFS, hostname, and realm resolution.

use std::path::Path;

use nfs_klldap_identity::nfs_keytab_host_variants;

use crate::NfsKlldapConfig;

fn config_path() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string()),
    )
}

fn load_runtime_config() -> Option<NfsKlldapConfig> {
    NfsKlldapConfig::load(&config_path()).ok()
}

/// True when a HOST_NFS env string enables sidecar mode.
pub fn parse_host_nfs_env_value(value: &str) -> bool {
    let t = value.trim().to_ascii_lowercase();
    t == "true" || t == "1" || t == "yes" || t == "on"
}

/// HOST_NFS / NFS_KLLDAP_HOST_NFS env override, if set.
pub fn host_nfs_from_env() -> Option<bool> {
    std::env::var("HOST_NFS")
        .or_else(|_| std::env::var("NFS_KLLDAP_HOST_NFS"))
        .ok()
        .map(|v| parse_host_nfs_env_value(&v))
}

/// Env wins over TOML; used by supervisor at startup and on recycle.
pub fn resolve_host_nfs_mode(config_path: &Path) -> bool {
    if let Some(val) = host_nfs_from_env() {
        return val;
    }
    NfsKlldapConfig::load(config_path)
        .map(|cfg| cfg.is_host_nfs())
        .unwrap_or(false)
}

/// Effective HOST_NFS for UI and validate after env overlay.
pub fn host_nfs_active(config: &NfsKlldapConfig) -> bool {
    host_nfs_from_env().unwrap_or_else(|| config.is_host_nfs())
}

/// Hostname for idhelper/keytab: config override, env, then /proc.
pub fn runtime_hostname(cfg: Option<&NfsKlldapConfig>) -> String {
    if let Some(h) = cfg
        .and_then(|c| c.server.hostname.as_ref())
        .filter(|h| !h.trim().is_empty())
    {
        return h.trim().to_string();
    }
    if let Ok(h) = std::env::var("NFS_KLLDAP_SERVER_HOSTNAME") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    "localhost".to_string()
}

/// Kerberos realm for idhelper: validated config, env, krb5.conf scrape
/// then fallback.
pub fn runtime_realm(cfg: Option<&NfsKlldapConfig>) -> String {
    if let Some(c) = cfg {
        let r = c.effective_realm();
        if !r.trim().is_empty() && !r.trim().eq_ignore_ascii_case("example.com") {
            return r.to_uppercase();
        }
    }
    if let Ok(r) = std::env::var("NFS_KLLDAP_KERBEROS_REALM") {
        if !r.trim().is_empty() {
            return r.trim().to_uppercase();
        }
    }
    if let Ok(content) = std::fs::read_to_string("/etc/krb5.conf") {
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with("default_realm") {
                if let Some(eq) = t.find('=') {
                    let r = t[eq + 1..].trim().to_string();
                    if !r.is_empty() {
                        return r.to_uppercase();
                    }
                }
            }
        }
    }
    "EXAMPLE.COM".to_string()
}

/// Keytab host variants for principal classification.
pub fn runtime_server_variants(cfg: Option<&NfsKlldapConfig>) -> Vec<String> {
    let variants = nfs_keytab_host_variants(&runtime_hostname(cfg));
    if variants.is_empty() {
        vec!["localhost".to_string()]
    } else {
        variants
    }
}

/// Convenience for idhelper when NFS_CONFIG is the only source.
pub fn runtime_realm_from_disk() -> String {
    runtime_realm(load_runtime_config().as_ref())
}

/// Convenience for idhelper when NFS_CONFIG is the only source.
pub fn runtime_server_variants_from_disk() -> Vec<String> {
    runtime_server_variants(load_runtime_config().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_hostname_falls_back_without_config() {
        let h = runtime_hostname(None);
        assert!(!h.is_empty());
    }

    #[test]
    fn runtime_realm_falls_back_without_config() {
        let r = runtime_realm(None);
        assert!(!r.is_empty());
    }

    #[test]
    fn parse_host_nfs_env_accepts_common_truthy_values() {
        assert!(parse_host_nfs_env_value("true"));
        assert!(parse_host_nfs_env_value("1"));
        assert!(parse_host_nfs_env_value("YES"));
        assert!(!parse_host_nfs_env_value("false"));
        assert!(!parse_host_nfs_env_value("0"));
    }
}
