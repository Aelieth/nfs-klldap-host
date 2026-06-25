// ! Strict parsers for getent passwd/group output.

/// Parse `getent passwd` line: name:passwd:uid:gid:gecos:home:shell
pub fn parse_getent_passwd(line: &str) -> Option<(u32, u32)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.splitn(7, ':').collect();
    if parts.len() < 4 {
        return None;
    }
    let uid = parts[2].trim().parse::<u32>().ok()?;
    let gid = parts[3].trim().parse::<u32>().ok()?;
    Some((uid, gid))
}

/// Parse `getent group` line: name:passwd:gid:memberlist...
pub fn parse_getent_group(line: &str) -> Option<u32> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.splitn(4, ':').collect();
    if parts.len() < 3 {
        return None;
    }
    parts[2].trim().parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_passwd_exact_and_gecos_safe() {
        assert_eq!(
            parse_getent_passwd("alice:x:1001:1001:Alice Foo:/home/alice:/bin/bash"),
            Some((1001, 1001))
        );
        assert_eq!(
            parse_getent_passwd("bob:x:1005:1005:Bob:Bar:/home/bob:/bin/sh"),
            Some((1005, 1005))
        );
        assert_eq!(
            parse_getent_passwd("  root:x:0:0:root:/root:/bin/bash  "),
            Some((0, 0))
        );
        assert!(parse_getent_passwd("# comment").is_none());
        assert!(parse_getent_passwd("badline").is_none());
    }

    #[test]
    fn parse_group_works() {
        assert_eq!(parse_getent_group("staff:x:100::"), Some(100));
        assert_eq!(parse_getent_group("users:x:200:alice,bob"), Some(200));
    }
}