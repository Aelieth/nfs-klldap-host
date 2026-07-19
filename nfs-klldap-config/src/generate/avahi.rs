//! Avahi static-service XML for Navahi-advertised shares.

use std::fs;
use std::path::Path;

use crate::{ConfigError, NfsKlldapConfig};

use super::directives::sanitize_name;

const NAVAHI_PREFIX: &str = "nfs-klldap-";

/// Matches the generated NFS_Port; there is no config field for it.
const NFS_PORT: u16 = 2049;

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// One `<service-group>` file per effective share (avahi allows only one
/// group per file). The prune is prefix-scoped so foreign service files in
/// the directory survive. While the toggle is off the directory is never
/// created (keeps dev-machine generates from touching /etc/avahi), but an
/// existing directory is still swept so a flip to off withdraws every advert.
pub fn write_avahi_services(cfg: &NfsKlldapConfig, dir: &Path) -> Result<(), ConfigError> {
    if !cfg.navahi_discovery && !dir.exists() {
        return Ok(());
    }
    fs::create_dir_all(dir)?;

    // SRV target: a qualified hostname resolves on clients via unicast DNS
    // (krb5 deployments already require it) and survives avahi's short-label
    // .local identity and conflict renames. Unqualified names stay omitted so
    // the advert falls back to avahi's own <short>.local record.
    let host = cfg.effective_hostname();
    let host_line = if host.contains('.') {
        format!("    <host-name>{}</host-name>\n", xml_escape(&host))
    } else {
        String::new()
    };

    let mut staged: Vec<(String, String)> = Vec::new();
    for share in &cfg.shares {
        if !crate::share_navahi_effective(cfg, share) {
            continue;
        }
        let pseudo = crate::derive_share_pseudo(share);
        let xml = format!(
            r#"<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<!-- Generated from nfs-klldap.conf share "{name_esc}"; edits are overwritten. -->
<service-group>
  <name replace-wildcards="yes">{name_esc} on %h</name>
  <service>
    <type>_nfs._tcp</type>
{host_line}    <port>{port}</port>
    <txt-record>path={path_esc}</txt-record>
  </service>
</service-group>
"#,
            name_esc = xml_escape(&share.name),
            host_line = host_line,
            port = NFS_PORT,
            path_esc = xml_escape(&pseudo),
        );
        staged.push((
            format!("{NAVAHI_PREFIX}{}.service", sanitize_name(&share.name)),
            xml,
        ));
    }

    let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (filename, xml) in staged {
        let path = dir.join(&filename);
        crate::atomic_write(&path, xml.as_bytes())?;
        // avahi-daemon drops privileges; the files must be world-readable
        // regardless of the caller's umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        }
        written.insert(filename);
    }

    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if written.contains(name) {
                continue;
            }
            if name.starts_with(NAVAHI_PREFIX) && name.ends_with(".service") {
                let _ = fs::remove_file(&p);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::xml_escape;

    #[test]
    fn xml_escape_covers_the_five_reserved_chars() {
        assert_eq!(
            xml_escape(r#"a&b<c>d"e'f"#),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
        assert_eq!(xml_escape("plain-name_1"), "plain-name_1");
    }
}
