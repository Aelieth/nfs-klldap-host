//! Background Ganesha log observer for opportunistic principal resolution.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use nfs_klldap_config::MACHINE_PRINCIPAL_PREFIXES;

use crate::common::IdCache;
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
    // Simple per-candidate rate limit to avoid spamming "observed" + full resolve/materialize
    // on every log line that matches the same client name (very common during a mount).
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
                            // No new data yet (regular file at EOF). Sleep briefly and retry
                            // on the same fd -- appends by Ganesha will become visible.
                            thread::sleep(Duration::from_millis(250));
                            continue;
                        }
                        Ok(_) => {
                            let line = buf.trim();
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
                                    // Opportunistic prune (tiny map in practice)
                                    if recently.len() > 2048 {
                                        recently.retain(|_, t| now.duration_since(*t) < dedup_window);
                                    }

                                    eprintln!("[idhelper] observed from ganesha log: {}", candidate);
                                    {
                                        let mut guard = cache.lock().unwrap();
                                        // Resolve (and classify) the candidate. If KLLDAP_IDHELPER_DEBUG
                                        // is set, full details (normalize, cache hit/miss, getent etc.)
                                        // will be logged by the existing debug instrumentation.
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

/// Returns true only for tokens that look like real client hostnames
/// (short name or fqdn) that we expect from "Linux NFSv4.x <host>" strings.
/// Rejects log formatting noise such as "Unique", "CLIENT", "ID", "ffff", "Created", etc.
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

    // Strong early rejection of known log noise tokens that frequently appear near
    // client records (prevents host/nil, host/clientid, host/Unique, host/ffff etc.)
    if is_noise_hostname(s) {
        return false;
    }

    // Reject common log noise and formatting tokens (case-insensitive)
    // Source the common noise list (Ganesha log hygiene for hybrid principal observer).
    // Keep local name for readability; values centralized for idhelper + future.
    const NOISE: &[&str] = nfs_klldap_config::LOG_NOISE_TOKENS;
    if NOISE.contains(&lower.as_str()) {
        return false;
    }

    // Hostname chars only
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return false;
    }

    // Real client hostnames from these logs are almost always lowercase and/or contain dot/hyphen
    if !s.chars().any(|c| c.is_ascii_lowercase()) && !s.contains('.') {
        return false;
    }

    true
}

/// Exact-match noise tokens (case-insensitive) that must never become a client hostname.
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
    // Also reject version-like tokens (NFSv4.2, 2.3 etc) and obvious non-host words that
    // appear after : or - splits in client name blobs.
    if s.starts_with("nfsv") || s.starts_with("nfs") || (s.chars().any(|c| c.is_ascii_digit()) && s.contains('.')) {
        // e.g. "NFSv4.2" or "10.10" style after split
        return true;
    }
    false
}

/// Try to extract a client hostname from a string that contains the common
/// Ganesha/Linux-NFS pattern "Linux NFSv4.<ver> <hostname>".
/// Only return a token if it comes from a group that looks like the client name
/// (contains "Linux" or the version+host pattern), skipping (nil), (NULL), clientid blobs.
fn extract_linux_nfs_hostname(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let marker = "nfsv4";
    if let Some(m) = lower.find(marker) {
        let suffix = &line[m + marker.len()..];

        // Prefer the group that contains the Linux NFS client string.
        // Scan all (...) groups after the marker and pick the last plausible host
        // only from a group that contains "linux" or looks like "(21:Linux..." or "-(21:Linux...".
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

        // Fallback scan is deliberately conservative.
        // If the line smells like an internal client-record debug blob (lots of (nil), clientid=, Unique=, Counter=, cr_refcount), do not trust the loose word fallback.
        // (Good names from "Linux NFSv4..." groups will already have been returned via the best path above.)
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

    // 0. High-signal early sighting: Ganesha is about to / is calling the idmapper for a principal.
    //    "Get uid for testuser1@REALM using nfsidmap" tells us a user principal is needed *now*.
    //    Extract and resolve immediately (observer background) so state may be ready or for retries/other threads.
    if let Some(start) = line.find("Get uid for ") {
        let rest = &line[start + "Get uid for ".len()..];
        if let Some(end) = rest.find(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_') {
            let cand = &rest[..end].trim();
            if cand.contains('@') && cand.to_ascii_lowercase().contains(&realm_lower) {
                // Only treat non-machine service forms as user candidates here.
                if !MACHINE_PRINCIPAL_PREFIXES.iter().any(|p| cand.to_ascii_lowercase().starts_with(p)) {
                    return Some(cand.to_string());
                }
            }
        }
    }

    // 0b. Special high-signal case for our own mapping failures.
    //    When Ganesha logs "Could not map principal ...", extract immediately.
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

    // 1. Look for explicit Kerberos principals containing the realm (user@REALM or host/xxx@REALM).
    //    Keep relatively permissive for real principals, but still validate the local part.
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
            // For host/ style we will normalize later; accept explicit @REALM as high-signal.
            return Some(cand.to_string());
        }
    }

    // 2. Primary reliable source: the "Linux NFSv4.x <hostname>" pattern.
    //    This appears in name=(...), fs_create_clid_name "client name [...]",
    //    and similar client record descriptions. Prefer this over blind word scanning.
    if let Some(host) = extract_linux_nfs_hostname(line) {
        if !host.eq_ignore_ascii_case("linux") && !host.eq_ignore_ascii_case("nfs") && !is_noise_hostname(&host) && looks_like_client_hostname(&host) {
            // Emit the classic host/ form. Materialization will also create the bare alias.
            return Some(format!("host/{}@{}", host, realm));
        }
    }

    // 3. Legacy direct name=(21:Linux NFSv4.2 ...) support (still useful for some log lines)
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

    // 4. Limited additional markers. Only accept tokens that pass the strict hostname check.
    //    We deliberately avoid "clientid=" and "cr_refcount" because they contain counters
    //    ("Unique=...", numbers), not hostnames.
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
    //    Only return if the local part looks reasonable.
    if line.to_ascii_lowercase().contains(&realm_lower) {
        for word in line.split(|c: char| {
            c.is_whitespace() || c == '=' || c == '(' || c == ')' || c == ':' || c == ',' || c == '[' || c == ']' || c == '"'
        }) {
            let w = word.trim();
            if w.contains('@') && w.to_ascii_lowercase().contains(&realm_lower) {
                // Accept explicit principals (they are usually the real thing).
                // Guard: do not emit things like "nil@REALM" or "clientid@REALM" from noise.
                if let Some(local) = w.split('@').next() {
                    if is_noise_hostname(local) || !looks_like_client_hostname(local) {
                        continue;
                    }
                }
                return Some(w.to_string());
            }
        }
    }

    None
}
