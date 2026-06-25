//! Docker bridge networking detection helpers.

use std::net::Ipv4Addr;
use std::process::Command;

/// Returns true when addr is an IPv4 address in Docker's default bridge.
/// Range is 172.17.0.0/16.
pub fn is_docker_bridge_ipv4(addr: &str) -> bool {
    let trimmed = addr.trim();
    let ip: Ipv4Addr = match trimmed.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let octets = ip.octets();
    octets[0] == 172 && octets[1] == 17
}

/// Extract `server_addr = <ip>` from a Ganesha CLIENT ID log line.
pub fn extract_server_addr_from_ganesha_line(line: &str) -> Option<String> {
    let marker = "server_addr";
    let lower = line.to_ascii_lowercase();
    let idx = lower.find(marker)?;
    let rest = &line[idx + marker.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '}' || c == ')')
        .unwrap_or(rest.len());
    let ip = rest[..end].trim();
    if ip.is_empty() {
        None
    } else {
        Some(ip.to_string())
    }
}

/// Best-effort primary container IPv4 (typically eth0) via `ip -4 -o addr`.
pub fn container_primary_ipv4() -> Option<String> {
    let output = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        // e.g.
        // "2: eth0    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0"
        if let Some(inet_pos) = line.find("inet ") {
            let after = &line[inet_pos + 5..];
            let ip = after.split_whitespace().next()?.split('/').next()?;
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_docker_bridge_ipv4_detects_default_bridge() {
        assert!(is_docker_bridge_ipv4("172.17.0.2"));
        assert!(is_docker_bridge_ipv4("172.17.255.254"));
    }

    #[test]
    fn is_docker_bridge_ipv4_rejects_other_ranges() {
        assert!(!is_docker_bridge_ipv4("10.0.0.1"));
        assert!(!is_docker_bridge_ipv4("172.18.0.1"));
        assert!(!is_docker_bridge_ipv4("not-an-ip"));
    }

    #[test]
    fn extract_server_addr_from_ganesha_line_parses_fixture() {
        let line = r#"key_locate :CLIENT ID :F_DBG :{{ name=(21:Linux NFSv4.2 blue-lt) server_addr = 172.17.0.2 pnfs_flags 0x10000}}"#;
        assert_eq!(
            extract_server_addr_from_ganesha_line(line).as_deref(),
            Some("172.17.0.2")
        );
    }
}
