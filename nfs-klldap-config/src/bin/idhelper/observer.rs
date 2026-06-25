//! Tails ganesha.log and triggers idhelper resolve on hybrid principal hints.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use nfs_klldap_config::MACHINE_PRINCIPAL_PREFIXES;

use crate::common::{manage_gids_expected, principal_local_part, IdCache};
use crate::dlog;
use crate::resolve::resolve_principal;

/// Best-effort: tail ganesha.log for early principal hints (feeds resolve).
pub(crate) fn start_ganesha_observer(
    realm: String,
    variants: Vec<String>,
    cache: Arc<Mutex<IdCache>>,
) {
    let log_path = std::env::var("GANESHA_LOG_PATH")
        .unwrap_or_else(|_| "/var/log/ganesha.log".to_string());
    thread::spawn(move || {
        observe_ganesha_log(&log_path, &realm, &variants, cache);
    });
}

fn observe_ganesha_log(path: &str, realm: &str, variants: &[String], cache: Arc<Mutex<IdCache>>) {
    // Per-candidate rate limit: avoid resolve spam on repeated log lines per
    // client.
    let mut recently: std::collections::HashMap<String, std::time::Instant> = std::collections::HashMap::new();
    let mut bridge_warned: std::collections::HashMap<String, std::time::Instant> =
        std::collections::HashMap::new();
    let dedup_window = Duration::from_secs(30);

    loop {
        match File::open(path) {
            Ok(mut f) => {
                // Only watch new data from now on
                let _ = f.seek(SeekFrom::End(0));
                let mut reader = BufReader::new(f);
                let mut buf = String::new();
                loop {
                    buf.clear();
                    match reader.read_line(&mut buf) {
                        Ok(0) => {
                            // No new data yet (regular file at EOF).
                            // Sleep briefly and retry
                            // on the same fd -- appends by Ganesha will become
                            // visible.
                            thread::sleep(Duration::from_millis(250));
                            continue;
                        }
                        Ok(_) => {
                            let line = buf.trim();
                            let _ = maybe_log_managed_gids_noise(line);
                            maybe_warn_bridge_server_addr(
                                line,
                                &mut bridge_warned,
                                dedup_window,
                            );
                            if let Some(candidate) = extract_candidate_principal(line, realm) {
                                let now = std::time::Instant::now();
                                let is_fresh = recently
                                    .get(&candidate)
                                    .map(|last| now.duration_since(*last) >= dedup_window)
                                    .unwrap_or(true);

                                if is_fresh {
                                    recently.insert(candidate.clone(), now);
                                    // Opportunistic prune
                                    if recently.len() > 2048 {
                                        recently.retain(|_, t| now.duration_since(*t) < dedup_window);
                                    }

                                    eprintln!("[idhelper] observed from ganesha log: {}", candidate);
                                    {
                                        let mut guard = cache.lock().unwrap();
                                        // Resolve the candidate.
                                        // If KLLDAP_IDHELPER_DEBUG
                                        // is set, full details (normalize,
                                        // cache hit/miss, getent etc.)
                                        // will be logged by the existing debug
                                        // instrumentation.
                                        let _ = resolve_principal(&candidate, realm, variants, &mut guard);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(300));
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                // Log file may not exist yet at early startup
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// True for real client hostnames from Linux NFSv4.x log lines;
/// rejects noise tokens.
pub(crate) fn looks_like_client_hostname(t: &str) -> bool {
    let s = t.trim();
    if s.len() < 2 || s.len() > 253 {
        return false;
    }
    // Ganesha epoch / pointer tokens: 0x6a375213, 0x7f0c3082f530, 0x10000
    if s.len() >= 3 && s.starts_with("0x") {
        let hex = &s[2..];
        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    if !s.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    let lower = s.to_ascii_lowercase();

    // Strong early rejection of known log noise tokens that frequently appear
    // near client records (prevents host/nil, host/clientid, host/Unique,
    // host/ffff etc.)
    if is_noise_hostname(s) {
        return false;
    }

    // Reject common log noise and formatting tokens (case-insensitive)
    // Source the common noise list .
    // Keep local name for readability;
    // values centralized for idhelper + future.
    const NOISE: &[&str] = nfs_klldap_config::LOG_NOISE_TOKENS;
    if NOISE.contains(&lower.as_str()) {
        return false;
    }

    // Hostname chars only
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return false;
    }

    // Real client hostnames from these logs are almost always lowercase and/or
    // contain dot/hyphen
    if !s.chars().any(|c| c.is_ascii_lowercase()) && !s.contains('.') {
        return false;
    }

    true
}

/// Extra hostname rejection beyond LOG_NOISE_TOKENS (0x…, nfsv4.x,
/// version-like tokens).
fn is_noise_hostname(t: &str) -> bool {
    let s = t.trim().to_ascii_lowercase();
    if s.starts_with("0x") {
        return true;
    }
    if matches!(
        s.as_str(),
        "nil" | "null" | "clientid" | "unique" | "counter" | "created" | "client" |
        "id" | "name" | "addr" | "refcount" | "cr" | "conf" | "unconf" | "debug" |
        "info" | "warning" | "error" | "ffff" | "linux" | "nfsv4"
    ) {
        return true;
    }
    // Also reject version-like tokens (NFSv4.2,
    // 2.3 etc) and obvious non-host words that
    // appear after : or - splits in client name blobs.
    if s.starts_with("nfsv") || s.starts_with("nfs") || (s.chars().any(|c| c.is_ascii_digit()) && s.contains('.')) {
        return true;
    }
    false
}

/// Log verbosity for Ganesha managed_gids / uid2grp noise lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedGidsLogLevel {
    Verbose,
    DebugOnly,
}

/// Decide whether a ganesha log line should be eprintln or debug-only.
pub(crate) fn managed_gids_log_level(line: &str, manage_gids_on: bool) -> Option<ManagedGidsLogLevel> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains("managed_gids") && !lower.contains("uid2grp_allocate") {
        return None;
    }
    if manage_gids_on {
        Some(ManagedGidsLogLevel::Verbose)
    } else {
        Some(ManagedGidsLogLevel::DebugOnly)
    }
}

fn maybe_log_managed_gids_noise(line: &str) -> Option<ManagedGidsLogLevel> {
    let level = managed_gids_log_level(line, manage_gids_expected())?;
    match level {
        ManagedGidsLogLevel::Verbose => {
            eprintln!("[idhelper] observed ganesha idmapper: {}", line);
        }
        ManagedGidsLogLevel::DebugOnly => {
            dlog!("ganesha idmapper (manage_gids=false, debug only): {}", line);
        }
    }
    Some(level)
}

fn maybe_warn_bridge_server_addr(
    line: &str,
    bridge_warned: &mut std::collections::HashMap<String, std::time::Instant>,
    dedup_window: Duration,
) {
    let Some(addr) = nfs_klldap_config::extract_server_addr_from_ganesha_line(line) else {
        return;
    };
    if !nfs_klldap_config::is_docker_bridge_ipv4(&addr) {
        return;
    }
    if extract_linux_nfs_hostname(line).is_none() {
        return;
    }
    let now = std::time::Instant::now();
    let is_fresh = bridge_warned
        .get(&addr)
        .map(|last| now.duration_since(*last) >= dedup_window)
        .unwrap_or(true);
    if !is_fresh {
        return;
    }
    bridge_warned.insert(addr.clone(), now);
    eprintln!(
        "[idhelper] WARN: Ganesha CLIENT record server_addr={} is a Docker bridge address; \
         clients may fail to reconnect. Use --network=host (or network_mode: host).",
        addr
    );
}

/// Extract hostname from "Linux NFSv4.x <host>" groups;
/// skip nil/clientid noise.
fn extract_linux_nfs_hostname(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let marker = "nfsv4";
    if let Some(m) = lower.find(marker) {
        let suffix = &line[m + marker.len()..];

        // Prefer the group that contains the Linux NFS client string.
        // Scan all groups after the marker and pick the last plausible host
        // only from a group that contains "linux" or looks like "(21:Linux..."
        // or "-(21:Linux...".
        let mut best: Option<String> = None;
        let mut search = suffix;
        while let Some(p) = search.find('(') {
            let rest = &search[p + 1..];
            if let Some(end) = rest.find(')') {
                let inside = &rest[..end];
                let group_lower = inside.to_ascii_lowercase();
                let looks_like_client_group = group_lower.contains("linux") || group_lower.contains("nfsv4") || inside.contains("Linux NFS");
                if looks_like_client_group {
                    for token in inside.split_whitespace().rev() {
                        let t = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
                        if looks_like_client_hostname(t)
                            && !t.eq_ignore_ascii_case("linux")
                            && !is_noise_hostname(t)
                        {
                            best = Some(t.to_string());
                            break;
                        }
                    }
                }
                search = &rest[end + 1..];
            } else {
                break;
            }
        }
        if best.is_some() {
            return best;
        }

        // Conservative fallback: skip internal debug blobs (clientid=,
        // cr_refcount, etc.).
        let lower_line = line.to_ascii_lowercase();
        let is_internal_blob = lower_line.contains("conf = (nil)") || lower_line.contains("clientid=") || lower_line.contains("unique=") || lower_line.contains("counter=") || lower_line.contains("cr_refcount");
        if is_internal_blob {
            return None;
        }

        let mut iter = suffix.split(|c: char| {
            c.is_whitespace() || c == '(' || c == ')' || c == '[' || c == ']' || c == ':' || c == '.'
        });
        let _ = iter.next(); // skip version
        for w in iter {
            let t = w.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
            if t.is_empty() { continue; }
            let tl = t.to_ascii_lowercase();
            if ["linux", "nfsv4", "created", "client", "name", "nil", "null", "conf", "unconf", "clientid", "unique", "counter", "stuff", "token", "other", "value", "key", "loc", "ref", "addr", "server"].contains(&tl.as_str()) || is_noise_hostname(t) {
                continue;
            }
            if looks_like_client_hostname(t) {
                return Some(t.to_string());
            }
        }
    }
    None
}

pub(crate) fn extract_candidate_principal(line: &str, realm: &str) -> Option<String> {
    let realm_lower = realm.to_ascii_lowercase();

    // "Get uid for user@REALM using nfsidmap" — resolve user principals
    // immediately.
    if let Some(start) = line.find("Get uid for ") {
        let rest = &line[start + "Get uid for ".len()..];
        if let Some(end) = rest.find(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_') {
            let cand = &rest[..end].trim();
            if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
                // Only treat non-machine service forms as user candidates
                // here.
                if !MACHINE_PRINCIPAL_PREFIXES.iter().any(|p| cand.to_ascii_lowercase().starts_with(p)) {
                    return Some(cand.to_string());
                }
            }
        }
    }

    // 0b. Special high-signal case for our own mapping failures.
    // When Ganesha logs "Could not map principal ...", extract immediately.
    if let Some(start) = line.find("Could not map principal ") {
        let rest = &line[start + "Could not map principal ".len()..];
        if let Some(end) = rest.find(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_') {
            let cand = &rest[..end];
            if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
                return Some(cand.to_string());
            }
        }
        if let Some(at_pos) = rest.find('@') {
            let cand = &rest[..at_pos+1 + rest[at_pos+1..].find(|c: char| !c.is_alphanumeric() && c != '.' && c != '-').unwrap_or(rest.len()-at_pos-1)];
            let cand = cand.split_whitespace().next().unwrap_or(cand);
            if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
                return Some(cand.to_string());
            }
        }
    }

    // Explicit Kerberos principals containing the realm .
    if let Some(at_pos) = line.find('@') {
        let before = &line[..at_pos];
        let start = before
            .rfind(|c: char| !c.is_alphanumeric() && c != '/' && c != '.' && c != '-' && c != '_' && c != ':')
            .map_or(0, |p| p + 1);
        let after = &line[at_pos..];
        let end_rel = after
            .find(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_' && c != ':')
            .unwrap_or(after.len());
        let cand = &line[start..at_pos + end_rel];
        if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
            // For host/ style we will normalize later;
            // accept explicit @REALM as high-signal.
            return Some(cand.to_string());
        }
    }

    // "Linux NFSv4.x <hostname>" pattern in client record log lines.
    if let Some(host) = extract_linux_nfs_hostname(line) {
        if !host.eq_ignore_ascii_case("linux") && !host.eq_ignore_ascii_case("nfs") && !is_noise_hostname(&host) && looks_like_client_hostname(&host) {
            // Emit the classic host/ form.
            // Materialization will also create the bare alias.
            return Some(format!("host/{}@{}", host, realm));
        }
    }

    // 3.
    // Legacy direct name= support
    if let Some(pos) = line.find("name=(") {
        let rest = &line[pos + 6..];
        if let Some(endp) = rest.find(')') {
            let inside = &rest[..endp];
            if let Some(last) = inside.split_whitespace().last() {
                let token = last.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
                if looks_like_client_hostname(token) && !is_noise_hostname(token) {
                    return Some(format!("host/{}@{}", token, realm));
                }
            }
        }
    }

    // 4.
    // Limited additional markers.
    // We deliberately avoid "clientid=" and "cr_refcount" because they contain
    // counters ("Unique=...", numbers), not hostnames.
    for marker in &["fs_create_clid_name", "client addr="] {
        if let Some(pos) = line.find(marker) {
            let tail = &line[pos + marker.len()..];
            for w in tail.split(|c: char| c.is_whitespace() || c == '=' || c == '(' || c == ')' || c == ':' || c == ',' || c == '[' || c == ']') {
                let t = w.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
                if looks_like_client_hostname(t) && !is_noise_hostname(t) {
                    return Some(format!("host/{}@{}", t, realm));
                }
            }
        }
    }

    // 5. Fallback: explicit @REALM anywhere (already partially handled above).
    // Only return if the local part looks reasonable.
    if line.to_ascii_lowercase().contains(&realm_lower) {
        for word in line.split(|c: char| {
            c.is_whitespace() || c == '=' || c == '(' || c == ')' || c == ':' || c == ',' || c == '[' || c == ']' || c == '"'
        }) {
            let w = word.trim();
            if w.contains('@') && w.to_ascii_lowercase().contains(&realm_lower) {
                // Accept explicit principals .
                // Guard: do not emit things like "nil@REALM" or
                // "clientid@REALM" from noise.
                let local = principal_local_part(w);
                if is_noise_hostname(local) || !looks_like_client_hostname(local) {
                    continue;
                }
                return Some(w.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod managed_gids_log_tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn write_limited_fs_config(dir: &std::path::Path) -> std::path::PathBuf {
        let mountinfo = dir.join("mountinfo");
        fs::write(
            &mountinfo,
            r#"
36 35 0:59 / /export rw,relatime - btrfs /dev/sda1 rw,noacl
"#,
        )
        .unwrap();
        std::env::set_var("NFS_KLLDAP_MOUNTINFO_PATH", &mountinfo);
        let conf = dir.join("nfs-klldap.conf");
        fs::write(
            &conf,
            r#"
ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "data"
host_path = "/media/data"
"#,
        )
        .unwrap();
        std::env::set_var("NFS_CONFIG", &conf);
        conf
    }

    #[test]
    fn maybe_log_managed_gids_noise_downgrades_via_manage_gids_expected() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_limited_fs_config(tmp.path());
        assert!(
            !manage_gids_expected(),
            "limited-fs fixture must yield manage_gids_expected() == false"
        );
        let line = "managed_gids failed for uid 1001";
        assert_eq!(
            maybe_log_managed_gids_noise(line),
            Some(ManagedGidsLogLevel::DebugOnly)
        );
    }

    #[test]
    fn maybe_log_managed_gids_noise_verbose_when_manage_gids_on() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let conf = tmp.path().join("nfs-klldap.conf");
        fs::write(
            &conf,
            r#"
ldap_uri = "ldaps://kllap.test:6360"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=test,dc=com"
ldap_default_authtok = "sekret"
[[shares]]
name = "data"
host_path = "/media/data"
manage_gids = true
"#,
        )
        .unwrap();
        std::env::set_var("NFS_CONFIG", &conf);
        assert!(manage_gids_expected());
        assert_eq!(
            maybe_log_managed_gids_noise("managed_gids stale cache"),
            Some(ManagedGidsLogLevel::Verbose)
        );
    }

    #[test]
    fn maybe_log_managed_gids_noise_ignores_unrelated_lines() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_limited_fs_config(tmp.path());
        assert_eq!(maybe_log_managed_gids_noise("nfs4_op succeeded"), None);
    }
}
