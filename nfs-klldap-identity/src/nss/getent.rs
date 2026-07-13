//! Strict parsers for getent passwd/group output.

/// One passwd row: login name plus numeric uid/gid.
#[derive(Debug, Clone)]
pub struct PasswdRow {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

/// One group row: name, gid, and member logins.
#[derive(Debug, Clone)]
pub struct GroupRow {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// Parse a passwd row keeping the login name (same rules as parse_getent_passwd).
pub fn parse_passwd_row(line: &str) -> Option<PasswdRow> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.splitn(7, ':').collect();
    if parts.len() < 4 {
        return None;
    }
    Some(PasswdRow {
        name: parts[0].trim().to_string(),
        uid: parts[2].trim().parse().ok()?,
        gid: parts[3].trim().parse().ok()?,
    })
}

/// Parse a group row keeping name and members (same rules as parse_getent_group).
pub fn parse_group_row(line: &str) -> Option<GroupRow> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.splitn(4, ':').collect();
    if parts.len() < 3 {
        return None;
    }
    Some(GroupRow {
        name: parts[0].trim().to_string(),
        gid: parts[2].trim().parse().ok()?,
        members: parts
            .get(3)
            .map(|m| m.trim())
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    })
}

/// Parse `getent passwd` line is name:passwd:uid:gid:gecos:home:shell.
pub fn parse_getent_passwd(line: &str) -> Option<(u32, u32)> {
    parse_passwd_row(line).map(|r| (r.uid, r.gid))
}

/// Parse `getent group` line: name:passwd:gid:memberlist.
pub fn parse_getent_group(line: &str) -> Option<u32> {
    parse_group_row(line).map(|r| r.gid)
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

    #[test]
    fn parse_rows_keep_names_and_members() {
        let r = parse_passwd_row("alice:x:1001:1002:Alice:/home/alice:/bin/bash").unwrap();
        assert_eq!((r.name.as_str(), r.uid, r.gid), ("alice", 1001, 1002));
        let g = parse_group_row("devs:x:3005:alice, bob").unwrap();
        assert_eq!(g.name, "devs");
        assert_eq!(g.gid, 3005);
        assert_eq!(g.members, vec!["alice", "bob"]);
        assert!(parse_group_row("root:x:0:").unwrap().members.is_empty());
        assert!(parse_group_row("root:x:0").unwrap().members.is_empty());
        assert!(parse_passwd_row("# comment").is_none());
        assert!(parse_passwd_row("badline").is_none());
    }
}
