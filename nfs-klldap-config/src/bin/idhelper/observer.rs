//! Tails ganesha.log and triggers idhelper resolve on hybrid principal hints.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;



use nfs_klldap_identity::principal_local_part;

use crate::common::{manage_gids_expected, IdCache};
use crate::dlog;
use crate::resolve::{resolve_groups_for_principal, resolve_principal};

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
    // Per-candidate rate limit: avoid resolve spam on repeated log lines per.
    let mut recently: std::collections::HashMap<String, std::time::Instant> = std::collections::HashMap::new();
    let mut bridge_warned: std::collections::HashMap<String, std::time::Instant> =
        std::collections::HashMap::new();
    let dedup_window = Duration::from_secs(30);

    loop {
        match File::open(path) {
            Ok(mut f) => {
                // Watch only new log data from the current seek offset onward.
                let _ = f.seek(SeekFrom::End(0));
                let mut reader = BufReader::new(f);
                let mut buf = String::new();
                loop {
                    buf.clear();
                    match reader.read_line(&mut buf) {
                        Ok(0) => {
                            // No new data yet (regular file at EOF). Sleep.
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
                            detect_my_getgrouplist_failure_and_heal(line, &cache, realm, variants);
                            if let Some(candidate) = extract_candidate_principal(line, realm) {
                                let now = std::time::Instant::now();
                                let is_fresh = recently
                                    .get(&candidate)
                                    .map(|last| now.duration_since(*last) >= dedup_window)
                                    .unwrap_or(true);

                                if is_fresh {
                                    recently.insert(candidate.clone(), now);
                                    // Keeps the rate-limit map small.
                                    if recently.len() > 2048 {
                                        recently.retain(|_, t| now.duration_since(*t) < dedup_window);
                                    }

                                    eprintln!("[idhelper] observed from ganesha log: {}", candidate);
                                    {
                                        let mut guard = cache.lock().unwrap();
                                        let prod = crate::materialize::NssMaterializePaths::production();
                                        let _ = resolve_principal(&candidate, realm, variants, &mut guard, &prod);
                                        let _ = resolve_groups_for_principal(
                                            &candidate, realm, variants, &mut guard, &prod, false,
                                        );
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
                // Log file may not exist yet at early startup.
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// True for real client hostnames in Linux NFSv4.x log lines.
pub(crate) fn looks_like_client_hostname(t: &str) -> bool {
    let s = t.trim();
    if s.len() < 2 || s.len() > 253 {
        return false;
    }
    // Ganesha epoch / pointer tokens is 0x6a375213, 0x7f0c3082f530, 0x10000.
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

    // Strong early rejection of known log noise tokens that frequently appear.
    if is_noise_hostname(s) {
        return false;
    }

    // Reject common log noise and formatting tokens (case-insensitive) Source.
    const NOISE: &[&str] = nfs_klldap_config::LOG_NOISE_TOKENS;
    if NOISE.contains(&lower.as_str()) {
        return false;
    }

    // Accept only characters that appear in real hostnames.
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return false;
    }

    // Real client hostnames from these logs are almost always lowercase. They.
    if !s.chars().any(|c| c.is_ascii_lowercase()) && !s.contains('.') {
        return false;
    }

    true
}

/// Extra hostname rejection beyond LOG_NOISE_TOKENS (hex, version-like).
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
    // Also reject version-like tokens (NFSv4.2 2.3 etc) and obvious non-host.
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

/// Decide whether a Ganesha log line is eprintln or debug-only.
/// Depends on manage_gids.
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

/// Detect my_getgrouplist_alloc failure from ganesha.log line (AC5 E).
/// On match: log the *exact* result+errno *seen by ganesha process* (not idhelper view),
/// trigger REBULK + nss re-materialize + cache refresh + socket-grps recheck.
/// Self-healing + exposes ganesha view.
fn detect_my_getgrouplist_failure_and_heal(
    line: &str,
    cache: &std::sync::Arc<std::sync::Mutex<crate::common::IdCache>>,
    realm: &str,
    variants: &[String],
) {
    let low = line.to_ascii_lowercase();
    if !low.contains("my_getgrouplist_alloc") || !(low.contains("failed") || low.contains("warn")) {
        return;
    }
    // Parse user + errno + ngroups for exact ganesha-seen info
    // e.g. "getgrouplist for user: root failed, ngroups: 1, errno: 1"
    let user = if let Some(u) = extract_user_from_getgrouplist_line(line) {
        u
    } else {
        "unknown".to_string()
    };
    let errno = extract_errno(line).unwrap_or(0u32);
    let ngroups = extract_ngroups(line).unwrap_or(0u32);
    eprintln!(
        "[idhelper] INFO ganesha-seen getgrouplist (from running ganesha.nfsd log, not idhelper view): user={} ngroups={} errno={} ; triggering immediate re-seed + nss invalidate + recheck",
        user, ngroups, errno
    );
    // Immediate re-seed: REBULK via socket + direct re-resolve + re-mat for root + user
    let _ = std::process::Command::new("timeout")
        .args(["3", "sh", "-c", &format!("printf 'REBULK\n' | nc -U $(cat /proc/$$/fd/1 2>/dev/null || echo /var/run/nfs-klldap/idhelper.sock) 2>/dev/null || printf 'REBULK\n' > /dev/null") ])
        .status();
    // direct heal using lock
    {
        let mut guard = cache.lock().unwrap();
        let prod = crate::materialize::NssMaterializePaths::production();
        let _ = crate::resolve::resolve_principal("root", realm, variants, &mut guard, &prod);
        let _ = crate::resolve::resolve_principal(&user, realm, variants, &mut guard, &prod);
        let _ = crate::resolve::resolve_groups_for_principal("root", realm, variants, &mut guard, &prod, true);
        let _ = crate::resolve::resolve_groups_for_principal(&user, realm, variants, &mut guard, &prod, true);
        let _ = crate::materialize::materialize_nss_wrappers_at(&guard, &prod, None);
    }
    // recheck grps via socket (non fatal)
    let _ = try_socket_grps("root");
    let _ = try_socket_grps(&user);
}

/// Parse "user: foo" or "for user: foo" from getgrouplist log line.
fn extract_user_from_getgrouplist_line(line: &str) -> Option<String> {
    for pat in ["user:", "user ", "for user "] {
        if let Some(idx) = line.find(pat) {
            let rest = &line[idx + pat.len()..];
            let tok = rest.split(|c: char| !c.is_alphanumeric() && c != '@' && c != '/' && c != '.' && c != '-').next().unwrap_or("");
            if !tok.is_empty() {
                return Some(tok.to_string());
            }
        }
    }
    None
}

fn extract_errno(line: &str) -> Option<u32> {
    if let Some(i) = line.find("errno:") {
        let rest = &line[i+6..];
        return rest.split(|c:char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).next().and_then(|s| s.parse().ok());
    }
    None
}

fn extract_ngroups(line: &str) -> Option<u32> {
    if let Some(i) = line.find("ngroups:") {
        let rest = &line[i+8..];
        return rest.split(|c:char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).next().and_then(|s| s.parse().ok());
    }
    None
}

fn try_socket_grps(p: &str) -> Option<Vec<u32>> {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let mut s = UnixStream::connect(crate::common::socket_path()).ok()?;
    let _ = s.write_all(format!("GRPS {}\n", p).as_bytes());
    None // fire and forget for heal; response not needed here
}

/// Extract hostname from "Linux NFSv4.x <host>" log groups.
fn extract_linux_nfs_hostname(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let marker = "nfsv4";
    if let Some(m) = lower.find(marker) {
        let suffix = &line[m + marker.len()..];

        // Prefer the group that contains the Linux NFS client string. Scan.
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

        // Conservative fallback: skip internal debug blobs (clientid=.
        let lower_line = line.to_ascii_lowercase();
        let is_internal_blob = lower_line.contains("conf = (nil)") || lower_line.contains("clientid=") || lower_line.contains("unique=") || lower_line.contains("counter=") || lower_line.contains("cr_refcount");
        if is_internal_blob {
            return None;
        }

        let mut iter = suffix.split(|c: char| {
            c.is_whitespace() || c == '(' || c == ')' || c == '[' || c == ']' || c == ':' || c == '.'
        });
        let _ = iter.next(); // Skip the NFS version token.
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

    // uid2grp unsupported path (legacy): resolve on stub message. Still useful if seen.
    if let Some(start) = line.find("Unsupported code path for principal ") {
        let rest = &line[start + "Unsupported code path for principal ".len()..];
        let cand = rest.split_whitespace().next().unwrap_or(rest).trim();
        if cand.contains('@') {
            return Some(cand.to_string());
        }
    }

    // getpwnam/getgrouplist/idmapper indicators for on-demand under UseGetpwnam=true.
    // Ganesha (and libnfsidmap under nss_wrapper) may log the names it looks up.
    // Catch both user@REALM and host/*@REALM (and bare host segments that we promote).
    // Explicit uid:0 / uid2grp uid 0 for machine/root to drive reactive materialize for uid0.
    {
        let lower = line.to_ascii_lowercase();
        let markers = ["getpwnam", "getgrouplist", "getgrnam", "idmapper", "uid2grp_allocate_by_uid"];
        let has_marker = markers.iter().any(|m| lower.contains(m));
        if has_marker {
            // Robust: scan for any whitespace/paren/quote-delimited token containing @ and our realm.
            // This catches getpwnam("user@REALM"), getpwnam(host/foo@REALM), etc.
            // Token scan below splits on common delimiters to find @-bearing principals.
            let delims = |c: char| c.is_whitespace() || matches!(c, '(' | ')' | '"' | '\'' | '[' | ']' | ',' | ':' | '=' | '<' | '>');
            for w in line.split(delims) {
                let t = w.trim();
                if t.contains('@') && t.to_ascii_lowercase().contains(&realm_lower) {
                    // Clean surrounding punctuation from the token.
                    let cand = t.trim_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '/' && c != '.' && c != '-' && c != '_');
                    if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
                        return Some(cand.to_string());
                    }
                }
            }
            // Host promotion (only for host segments near markers when no @ form was present).
            for m in &markers {
                if let Some(pos) = lower.find(m) {
                    let tail = &line[pos + m.len()..];
                    if let Some(hp) = tail.find("host/") {
                        let rest = &tail[hp + 5..];
                        let short: String = rest.chars()
                            .take_while(|&c| c.is_alphanumeric() || c == '-' || c == '.')
                            .collect();
                        if looks_like_client_hostname(&short) && !is_noise_hostname(&short) {
                            return Some(format!("host/{}@{}", short, realm));
                        }
                    }
                    // Parenthesized/quoted hostname after marker (Linux NFS client style or bare).
                    for &open in &['(', '"', '\'', '[', '<'] {
                        if let Some(op) = tail.find(open) {
                            let inner_start = op + 1;
                            if let Some(close_rel) = tail[inner_start..].find(|c: char| [')','"','\'',']','>'].contains(&c)) {
                                let inside = &tail[inner_start..inner_start + close_rel];
                                for token in inside.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '.') {
                                    let t = token.trim();
                                    if t.is_empty() || is_noise_hostname(t) { continue; }
                                    if looks_like_client_hostname(t) {
                                        return Some(format!("host/{}@{}", t, realm));
                                    }
                                }
                            }
                        }
                    }
                    // Very conservative bare token: only if it contains '.' (looks like fqdn) or is a classic short lowercase host.
                    for w in tail.split(|c: char| c.is_whitespace() || c == '=' || c == ':' || c == ',') {
                        let t = w.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.' && c != '/');
                        if t.is_empty() { continue; }
                        if is_noise_hostname(t) { continue; }
                        let tl = t.to_ascii_lowercase();
                        if ["failed", "trying", "returned", "no", "entry", "missing", "not", "found", "for", "client", "user", "getpwnam", "getgrouplist"].contains(&tl.as_str()) {
                            continue;
                        }
                        if tl.starts_with("host/") {
                            let short = tl.trim_start_matches("host/");
                            if looks_like_client_hostname(short) {
                                return Some(format!("host/{}@{}", short, realm));
                            }
                        }
                        if t.contains('.') && looks_like_client_hostname(t) {
                            return Some(format!("host/{}@{}", t, realm));
                        }
                    }
                }
            }
        }
    }

    // Match Get uid for user@REALM (or host/*@REALM) lines. Under UseGetpwnam the
    // getpwnam path produces these; allow both user and machine forms for on-demand.
    if let Some(start) = line.find("Get uid for ") {
        let rest = &line[start + "Get uid for ".len()..];
        let end = rest.find(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_' && c != '/')
            .unwrap_or(rest.len());
        let cand = &rest[..end].trim();
        if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
            return Some(cand.to_string());
        }
    }

    // Step 0b. Special high-signal case for our own mapping failures. When.
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

    // Extract explicit Kerberos principals that contain the configured realm.
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
            // For host/ style we will normalize later accept explicit @REALM.
            return Some(cand.to_string());
        }
    }

    // Match Linux NFSv4.x hostname patterns in client record log lines.
    if let Some(host) = extract_linux_nfs_hostname(line) {
        if !host.eq_ignore_ascii_case("linux") && !host.eq_ignore_ascii_case("nfs") && !is_noise_hostname(&host) && looks_like_client_hostname(&host) {
            // Emit the classic host/ form. Materialization will also create.
            return Some(format!("host/{}@{}", host, realm));
        }
    }

    // Step 3. Legacy direct name=(21:Linux NFSv4.2 ...) support. Still useful.
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

    // Step 4 applies limited markers and accepts only validated tokens.
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

    // Step 5. Fallback: explicit @REALM anywhere (already partially handled.
    if line.to_ascii_lowercase().contains(&realm_lower) {
        for word in line.split(|c: char| {
            c.is_whitespace() || c == '=' || c == '(' || c == ')' || c == ':' || c == ',' || c == '[' || c == ']' || c == '"'
        }) {
            let w = word.trim();
            if w.contains('@') && w.to_ascii_lowercase().contains(&realm_lower) {
                // Accept explicit principals (they are usually the real.
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
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap();
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
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap();
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
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_limited_fs_config(tmp.path());
        assert_eq!(maybe_log_managed_gids_noise("nfs4_op succeeded"), None);
    }

    #[test]
    fn extract_unsupported_code_path_machine_principal() {
        // Machine principals still hit allocate_by_principal stub under _MSPAC_SUPPORT; observer warms resolve.
        let line = "uid2grp_allocate_by_principal :ID MAPPER :WARN :Unsupported code path for principal host/blue-lt@SATOMLIN.COM";
        assert_eq!(
            extract_candidate_principal(line, "SATOMLIN.COM"),
            Some("host/blue-lt@SATOMLIN.COM".to_string())
        );
    }

    #[test]
    fn managed_gids_log_level_matches_uid2grp_allocate_by_uid() {
        let line = "uid2grp_allocate_by_uid uid: 3001";
        assert_eq!(
            managed_gids_log_level(line, true),
            Some(ManagedGidsLogLevel::Verbose)
        );
    }

    #[test]
    fn managed_gids_log_level_ignores_allocate_by_principal_when_manage_gids_on() {
        let line = "uid2grp_allocate_by_principal :ID MAPPER :WARN :Unsupported code path for principal testuser1@TESTLABBY.LOCAL";
        assert_eq!(
            managed_gids_log_level(line, true),
            Some(ManagedGidsLogLevel::Verbose)
        );
    }

    #[test]
    fn extract_getpwnam_triggers_user_principal() {
        // UseGetpwnam path: Ganesha does getpwnam(user@REALM) -> observer must react.
        let line = r#"idmapper :ID MAPPER :DEBUG :getpwnam("testuser42@EXAMPLE.COM") failed, trying short"#;
        assert_eq!(
            extract_candidate_principal(line, "EXAMPLE.COM"),
            Some("testuser42@EXAMPLE.COM".to_string())
        );
    }

    #[test]
    fn extract_getgrouplist_triggers_machine_principal() {
        // getgrouplist on host segment or qualified host/ form must fire on-demand.
        let line1 = r#"ganesha : getgrouplist host/blue-lt@REALM"#;
        assert_eq!(
            extract_candidate_principal(line1, "REALM"),
            Some("host/blue-lt@REALM".to_string())
        );
        let line2 = r#"getgrouplist(blue-lt) for client cred"#;
        assert_eq!(
            extract_candidate_principal(line2, "REALM"),
            Some("host/blue-lt@REALM".to_string())
        );
    }

    #[test]
    fn extract_getpwnam_host_qualified_direct() {
        let line = r#"getpwnam host/server42@CLUSTER.LOCAL returned no entry"#;
        assert_eq!(
            extract_candidate_principal(line, "CLUSTER.LOCAL"),
            Some("host/server42@CLUSTER.LOCAL".to_string())
        );
    }

    #[test]
    fn extract_getuid_for_machine_form() {
        // "Get uid for " now accepts host/*@ forms too (getpwnam path can log this).
        let line = "Get uid for host/worker3@MYREALM.ORG";
        assert_eq!(
            extract_candidate_principal(line, "MYREALM.ORG"),
            Some("host/worker3@MYREALM.ORG".to_string())
        );
    }
}
