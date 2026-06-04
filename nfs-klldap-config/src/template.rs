//! Default first-run nfs-klldap.conf template.

use std::fs;
use std::path::Path;

use crate::ConfigError;

/// Generate the first-run safe, heavily commented template.
/// Never overwrites an existing file.
pub fn generate_default_template() -> String {
    r#"# =============================================================================
# nfs-klldap.conf — Single Source of Truth for nfs-klldap-host
# =============================================================================
# This file is the ONLY configuration file that needs editing.
# The container (via bundled Rust generator) auto-derives sssd.conf,
# krb5.conf, and all Ganesha EXPORT fragments from it.
#
# REQUIRED: ldap_uri + [sssd] bind credentials.
# ldap_uri host MUST be a DNS name (A/AAAA + PTR recommended). IP addresses are
# rejected because forward/reverse DNS is required for Kerberos NFS principals.
#
# Kerberos keytab (best practice with --uts=host):
#   Include nfs/<short-hostname>@REALM and nfs/<fqdn>@REALM when they differ.
#   The hostname is confirmed by `hostname` matching /proc/sys/kernel/hostname.
#
# After first edit: the container NEVER overwrites this file.
# =============================================================================

ldap_uri = "ldaps://klldap.example.com:6360"
# Port must appear in ldap_uri. [sssd] port is derived for display only (636/389).

[storage]
container_root = "/export"   # Match docker -v ...:/export

[server]
# hostname = "myhost.example.com"   # Optional override for keytab only.
# Recommended: docker run --uts=host (container sees the real host hostname).

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "CHANGE_THIS_TO_A_STRONG_SECRET"
# ldap_user_search_base = "ou=people,dc=example,dc=com"
# ldap_group_search_base = "ou=groups,dc=example,dc=com"

kllldap_ignored_attributes = true   #improves lookup time, prevents attribute spam

# [kerberos]
# realm = "KRB.EXAMPLE.COM"   # Required if auto-derivation from ldap_uri fails

[ganesha]
default_security = "krb5p"   # krb5p (recommended) | krb5i | krb5

[management]
# webui_admin_group = "lldap_admin"   # LLDAP group for WebUI admins (default)

# =============================================================================
# Optional Shares — add [[shares]] sections (via the WebUI System Settings page
# or by editing this file). After adding/editing shares use the "Restart and apply"
# button (or let the config watcher + supervisor bounce the services) so both
# Ganesha and the WebUI permission tree see the new exports/roots.
#   host_path = absolute path on the Docker HOST (WebUI chown/chmod allow-list).
#   Bind-mount so data appears at container_root/name (default /export/<name>).
# =============================================================================

# [[shares]]
# name = "movies"
# host_path = "/home/user/nfs-data/movies"
# # export_path = "/movies"   # optional; if absent, generator derives "/" + name
# # security = "krb5p"        # optional per-share override (krb5p|krb5i|krb5); default from [ganesha]
# rw = true                 # default RW; set false for RO (or use UI dropdown)
# # squash omitted means no_root_squash; UI has "root_squash" checkbox to set "root_squash"
# # sync omitted means true (safer synchronous writes); set false to disable
# # pref_read omitted = Ganesha default (64 MiB PrefRead). For read-ahead / streaming/large files:
# #   "Min" (gaming ISOs, random-ish, low latency): 1048576 or 2097152 (1-2 MiB)
# #   "Max" (4K streaming, huge seq files on HDD): 16777216 (16 MiB) or 67108864 (64 MiB)
# #   Value is bytes; must be 512..64M. Raw TOML or UI structured shares editor.
"#
    .to_string()
}

/// Write the default template only if the file does not exist.
pub fn write_default_config_if_missing(path: &Path) -> Result<bool, ConfigError> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmpl = generate_default_template();
    fs::write(path, tmpl.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(true)
}
