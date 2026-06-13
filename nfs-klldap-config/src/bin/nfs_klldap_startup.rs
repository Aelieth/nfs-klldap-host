//! nfs-klldap-startup — Guided first-run TUI + reachability diagnostics (runs as root).
//!
//! 3-step state machine that blocks until:
//!   1. Persistent /config volume
//!   2. ldap_uri (DNS name) reachable
//!   3. Bind credentials work
//!
//! (Shares are optional at startup and may be added later.)
//!
//! Emits the required `nfs/<host>@REALM` principal banner using the two-tier
//! hostname contract. Entry point remains a thin pid-1 supervisor.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::thread;
use std::time::Duration;

use nfs_klldap_config::{
    derive_realm_from_uri, extract_host_from_uri, format_nfs_principal_list,
    get_consistent_hostname, is_persistent_config, nfs_keytab_host_matches,
    resolve_posix_attribute_mapping, ConfigError, NfsKlldapConfig,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    let config_path = PathBuf::from(
        env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string()),
    );

    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("run");

    match cmd {
        "run" | "startup" => {
            if let Err(e) = run_guided_startup(&config_path) {
                eprintln!("FATAL: {}", e);
                exit(2);
            }
        }
        "check" => {
            if let Err(e) = run_one_shot_diagnostics(&config_path) {
                eprintln!("ERROR: {}", e);
                exit(2);
            }
        }
        "help" | "--help" | "-h" => {
            print_help();
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            print_help();
            exit(1);
        }
    }
}

fn print_help() {
    eprintln!(
        "nfs-klldap-startup v{} — guided container bring-up (3-step TUI; entrypoint orchestrates services)

Usage:
  nfs-klldap-startup run      Run the full guided 3-step waiting TUI until ready
  nfs-klldap-startup check    Run diagnostics once and exit

Hostname / keytab:
  Use --uts=host so the container sees the real Docker host hostname.
  The TUI shows nfs/<hostname>@REALM using that name (short + FQDN principals
  when the hostname contains a dot). You may pass --hostname to override.
",
        env!("CARGO_PKG_VERSION")
    );
}

// Hostname: get_consistent_hostname() — `hostname` and /proc must agree.

/// Enhanced persistent volume check + writability test.
/// Gives the user immediate, actionable feedback instead of mysterious later failures.
fn check_persistent_writable_config(path: &Path) -> bool {
    if !is_persistent_config(path) {
        return false;
    }

    // Verify we can actually write to the location (as root during startup)
    let parent = path.parent().unwrap_or(Path::new("/config"));
    let test_file = parent.join(".nfs-klldap-persist-test");

    let can_write = std::fs::File::create(&test_file).is_ok();
    if can_write {
        let _ = std::fs::remove_file(&test_file);
    }
    can_write
}

/// Rich result for LDAP server reachability diagnostics (much better than bool).
#[derive(Debug)]
enum LdapReachability {
    Reachable,
    DnsFailure { detail: String },
    Unreachable { detail: String },
}

/// Performs a thorough reachability check using tools available in the image
/// (getent + nc + timeout) to give the user excellent diagnostic messages.
fn check_ldap_reachability(host: &str, uri: &str) -> LdapReachability {
    let port: u16 = uri
        .split(':')
        .next_back()
        .and_then(|s| {
            s.trim_end_matches(|c: char| !c.is_ascii_digit())
                .parse()
                .ok()
        })
        .unwrap_or(636);

    // DNS resolution test (very important to distinguish from port issues)
    let dns = Command::new("getent").args(["hosts", host]).output();
    if let Ok(out) = dns {
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return LdapReachability::DnsFailure {
                detail: if msg.is_empty() {
                    "Host not found in DNS".to_string()
                } else {
                    msg
                },
            };
        }
    }

    // Port connectivity test using nc (we now guarantee netcat-openbsd (or equivalent) is installed in the image)
    let nc = Command::new("timeout")
        .args(["4", "nc", "-w", "3", "-zv", host, &port.to_string()])
        .output();

    match nc {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .trim()
            .to_string();

            if out.status.success() {
                LdapReachability::Reachable
            } else {
                LdapReachability::Unreachable {
                    detail: if combined.is_empty() {
                        "Connection failed with no specific error from nc".to_string()
                    } else {
                        combined
                    },
                }
            }
        }
        Err(e) => LdapReachability::Unreachable {
            detail: format!("Failed to execute timeout/nc: {}", e),
        },
    }
}

/// Attempts LDAP bind and returns rich error information for the user.
///
/// This now performs a *narrow* search using exactly the same attribute names
/// that will later be used by the WebUI's LLDAP client (and documented in the
/// generated sssd.conf comments). The actual probe now performs a narrow base
/// search on the bind DN using only those mapped attributes. This keeps the
/// early handshake consistent with the rest of the system and avoids feeding
/// LLDAP extra attribute names during the first bind.
fn check_ldap_bind(cfg: &NfsKlldapConfig) -> Result<(), String> {
    let uri = &cfg.ldap_uri;
    let dn = &cfg.sssd.ldap_default_bind_dn;
    let pw = &cfg.sssd.ldap_default_authtok;

    let is_ldaps = uri.starts_with("ldaps://");

    // Resolve the same POSIX attribute mapping that SSSD and the WebUI will use.
    // Even a very early/partial config still produces sensible defaults
    // (uidNumber, gidNumber, homeDirectory, loginShell, etc.).
    let mapping = resolve_posix_attribute_mapping(&cfg.sssd);

    // Build an explicit, narrow attribute list for this probe.
    // We request the core identity attributes for the bind DN itself (a base
    // search on its own entry) plus objectClass. This is deliberately the same
    // set of names the rest of the system will use.
    let mut attrs: Vec<&str> = vec![
        &mapping.user_name,
        &mapping.user_uid_number,
        &mapping.user_gid_number,
        &mapping.user_home_directory,
        &mapping.user_shell,
        "objectClass",
    ];
    if let Some(f) = cfg
        .sssd
        .ldap_user_fullname
        .as_ref()
        .filter(|v| !v.trim().is_empty())
    {
        let f = f.trim();
        if !attrs.iter().any(|a| a.eq_ignore_ascii_case(f)) {
            attrs.push(f);
        }
    }
    // Dedup while preserving order (simple and sufficient here).
    let mut seen = std::collections::HashSet::new();
    let attr_list: Vec<&str> = attrs.into_iter().filter(|a| seen.insert(*a)).collect();

    let mut cmd = Command::new("timeout");
    cmd.args(["10", "ldapsearch"]).args([
        "-H",
        uri,
        "-D",
        dn,
        "-w",
        pw,
        "-s",
        "base",
        "-b",
        dn, // Search the bind DN's own entry (narrow, like future SSSD lookups)
        "-o",
        "nettimeout=5",
    ]);

    // Append the narrow attribute list.
    for a in &attr_list {
        cmd.arg(a);
    }

    // Auto TLS handling based on URI scheme
    if is_ldaps {
        // Pragmatic default for LLDAP / internal self-signed certs.
        // We can make this configurable later via a dedicated config option.
        cmd.env("LDAPTLS_REQCERT", "never");
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => return Err(format!("Could not execute ldapsearch: {}", e)),
    };

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let raw = if !stderr.is_empty() { stderr } else { stdout };

        let friendly = if raw.contains("Invalid credentials") || raw.contains("(49)") {
            format!("BIND FAILED: Invalid credentials (error 49).\n             → Double-check ldap_default_bind_dn and ldap_default_authtok.\n             Raw ldapsearch output: {}", raw)
        } else if raw.contains("Can't contact LDAP server")
            || raw.contains("(-1)")
            || raw.contains("TLS")
            || raw.contains("certificate")
        {
            format!("BIND FAILED: Cannot contact LDAP server or TLS/certificate issue.\n             → Common causes: wrong port, self-signed cert (we set LDAPTLS_REQCERT=never for ldaps), or firewall.\n             Raw: {}", raw)
        } else {
            format!("BIND FAILED:\n             {}", raw)
        };

        Err(friendly)
    }
}

// is_persistent_config (and tolerant load helpers) below are used by both the TUI and the WebUI.

/// Guided first-run loop (3 steps: volume, ldap_uri, bind creds).
///
/// The 3 steps are:
///   1. Persistent volume at $NFS_CONFIG (different device from container root)
///   2. ldap_uri present + TCP reachable (must be DNS name, not IP)
///   3. Bind DN + password present and ldapsearch succeeds
///
/// (A [[shares]] section is no longer required to reach Ready; shares may be
/// added later via the WebUI or config edit.)
///
/// Steps are marked [✓] as soon as they are satisfied (see is_step_complete).
fn run_guided_startup(config_path: &Path) -> Result<(), ConfigError> {
    println!("\x1b[2J\x1b[H"); // Clear screen + home for the TUI

    loop {
        // Small delay to let recent writes to the bind-mounted config file become
        // visible inside the container (some Docker storage drivers / filesystems
        // have slight propagation delay on host -> container updates).
        thread::sleep(Duration::from_millis(250));

        print_header(config_path);
        let step = compute_current_step(config_path);

        print_step_status(&step);

        if step == StartupStep::Ready {
            println!("\n[OK] All startup requirements satisfied. Proceeding to service start...\n");
            print_runtime_diagnostics();
            return Ok(());
        }

        println!(
            "\n[WAITING] Edit the config file — the container will auto-continue when ready.\n"
        );
        thread::sleep(Duration::from_secs(8));
        print!("\x1b[2J\x1b[H"); // Clear for next iteration (simple TUI refresh)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StartupStep {
    WaitForPersistentVolume,
    SetLdapUri,
    AddBindCredentials,
    Ready,
}

fn print_header(config_path: &Path) {
    // Two-tier consistent retrieval (hostname command + /proc confirmation).
    // Both sources must agree. If they don't, we surface a loud, actionable error.
    let (hostname, consistency_note) = match get_consistent_hostname() {
        Ok(c) => (c.hostname, " (confirmed by `hostname` + /proc)".to_string()),
        Err(e) => {
            // Print the full rich diagnostic immediately — this is the moment
            // Hostname mismatch is now visible.
            eprintln!("\n{}", e);
            // Still allow the TUI to continue (operator may need to edit config first),
            // but use a clear placeholder so the rest of the banner is still useful.
            (
                "<INCONSISTENT — see error above>".to_string(),
                String::new(),
            )
        }
    };

    let realm_display = attempt_realm_for_display(config_path)
        .unwrap_or_else(|| "YOUR.REALM (set ldap_uri to auto-derive)".to_string());

    let principal_list = format_nfs_principal_list(&hostname, &realm_display);

    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║  nfs-klldap-host — FIRST RUN SETUP (Step-by-Step)  [Rust guided mode]        ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Container hostname: {:<55} ║", hostname);
    if !consistency_note.is_empty() {
        println!("║  {:<76} ║", consistency_note);
    }
    println!("║  Keytab should include:                                                      ║");
    for line in wrap_banner_lines(&principal_list, 74) {
        println!("║  {:<76} ║", line);
    }
    println!("║  Use --uts=host so the hostname above is your real Docker host name.         ║");
    println!("║  Optional: [server] hostname or --hostname to override.                      ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");
}

fn wrap_banner_lines(text: &str, width: usize) -> Vec<String> {
    if text.len() <= width {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        if rest.len() <= width {
            lines.push(rest.to_string());
            break;
        }
        let split_at = rest[..width].rfind(", ").map(|i| i + 2).unwrap_or(width);
        lines.push(rest[..split_at].trim_end().to_string());
        rest = rest[split_at..].trim_start();
    }
    lines
}

/// Tolerantly extract ldap_uri from the config file (even if incomplete) and
/// derive a realm for display in the startup banner. Does not require full
/// validation or bind credentials.
fn attempt_realm_for_display(config_path: &Path) -> Option<String> {
    if !config_path.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(config_path).ok()?;
    // Very small tolerant parse: look for ldap_uri = "..." or ldap_uri = '...'
    for line in contents.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("ldap_uri") {
            // Accept optional whitespace, =, and optional quotes
            if let Some(eq_pos) = rest.find('=') {
                let val = rest[eq_pos + 1..]
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'');
                if !val.is_empty() && (val.starts_with("ldap://") || val.starts_with("ldaps://")) {
                    if let Some(r) = derive_realm_from_uri(val) {
                        // Never surface the placeholder as a success
                        if !r.eq_ignore_ascii_case("EXAMPLE.COM")
                            && !r.eq_ignore_ascii_case("EXAMPLE")
                        {
                            return Some(r);
                        }
                    }
                }
            }
        }
    }
    None
}

fn print_step_status(current: &StartupStep) {
    let steps = [
        (
            StartupStep::WaitForPersistentVolume,
            "STEP 1/3",
            "Mount a persistent config volume (REQUIRED)",
        ),
        (
            StartupStep::SetLdapUri,
            "STEP 2/3",
            "Set ldap_uri in nfs-klldap.conf (DNS name only)",
        ),
        (
            StartupStep::AddBindCredentials,
            "STEP 3/3",
            "Add LLDAP bind credentials in [sssd] section",
        ),
    ];

    for (step, label, desc) in &steps {
        if *step == *current {
            println!("  [ ] {}  {}", label, desc);
            // Print extra guidance for the current step
            print_current_step_guidance(current);
        } else if is_step_complete(step, current) {
            println!("  [✓] {}  {}", label, desc);
        } else {
            println!("  [ ] {}  {}", label, desc);
        }
    }
}

/// Returns true if `step` has been completed given that we are now at `current`.
/// Ordering: WaitForPersistentVolume < SetLdapUri < AddBindCredentials < Ready
fn is_step_complete(step: &StartupStep, current: &StartupStep) -> bool {
    if *step == *current {
        return false;
    }
    // Ready means everything before it is done
    if *current == StartupStep::Ready {
        return true;
    }
    match (step, current) {
        // Step 1 is complete once we are past it
        (
            StartupStep::WaitForPersistentVolume,
            StartupStep::SetLdapUri | StartupStep::AddBindCredentials,
        ) => true,
        // Step 2 is complete once we are past it
        (StartupStep::SetLdapUri, StartupStep::AddBindCredentials) => true,
        // Step 3 is complete once we reach Ready (handled above)
        _ => false,
    }
}

fn print_current_step_guidance(current: &StartupStep) {
    match current {
        StartupStep::WaitForPersistentVolume => {
            println!("             -v /path/on/your/host:/config");
            println!();
            println!("             [TROUBLESHOOTING]");
            println!("             The config file is currently inside the container's ephemeral overlay.");
            println!("             Any changes will be lost when the container restarts.");
            println!("             You MUST bind-mount a real host directory at /config.");
            println!("             Example:  -v /home/user/nfs-config:/config");
        }

        StartupStep::SetLdapUri => {
            // Always show current value first (if present), then a clearly labeled example
            println!("             Current value in config:");

            let config_path_str = std::env::var("NFS_CONFIG")
                .unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string());
            let mut current_val: Option<String> = None;

            if let Ok(contents) = std::fs::read_to_string(&config_path_str) {
                for line in contents.lines() {
                    let t = line.trim();
                    if t.starts_with("ldap_uri") {
                        if let Some(eq) = t.find('=') {
                            let val = t[eq + 1..].trim().trim_matches(|c| c == '"' || c == '\'');
                            if !val.is_empty()
                                && (val.starts_with("ldap://") || val.starts_with("ldaps://"))
                            {
                                println!("             {}", t);
                                current_val = Some(val.to_string());
                            }
                        }
                        break;
                    }
                }
            }

            if current_val.is_none() {
                println!("             (not yet set)");
            }

            println!();
            println!("             Example (copy-paste ready):");
            println!("             ldap_uri = \"ldaps://lldap.yourdomain.com:6360\"");
            println!("             (must be a real DNS name — IP addresses are rejected)");
            println!();

            // Real reachability diagnostics only when we have a value
            if let Some(val) = current_val {
                let host = extract_host_from_uri(&val);
                let port: u16 = val
                    .split(':')
                    .next_back()
                    .and_then(|s| {
                        s.trim_end_matches(|c: char| !c.is_ascii_digit())
                            .parse()
                            .ok()
                    })
                    .unwrap_or(636);

                println!(
                    "             [TROUBLESHOOTING] Testing reachability of {}:{}",
                    host, port
                );

                match check_ldap_reachability(&host, &val) {
                    LdapReachability::DnsFailure { detail, .. } => {
                        println!("             ❌ DNS FAILURE");
                        println!("                Could not resolve hostname '{}'", host);
                        println!("                Detail: {}", detail);
                        println!("                → Common fixes:");
                        println!(
                            "                  - Check spelling / DNS records on the Docker host"
                        );
                        println!(
                            "                  - Container may need --network=host or --dns=..."
                        );
                        println!("                  - Test from host: getent hosts {}", host);
                    }
                    LdapReachability::Unreachable { detail, .. } => {
                        println!("             ❌ PORT UNREACHABLE (resolved successfully)");
                        println!("                Detail: {}", detail);
                        println!("                → Common fixes:");
                        println!("                  - Is the port correct? (ldaps usually 636, ldap usually 389)");
                        println!(
                            "                  - Firewall / SELinux blocking from Docker host?"
                        );
                        println!(
                            "                  - Try from the Docker host:  nc -zv {} {}",
                            host, port
                        );
                    }
                    LdapReachability::Reachable => {
                        println!("             ✓ Basic TCP reachability OK (DNS + port open)");
                    }
                }
            }
        }

        StartupStep::AddBindCredentials => {
            println!("             Current values from config:");

            let config_path = std::env::var("NFS_CONFIG")
                .unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string());

            if let Ok(cfg) = NfsKlldapConfig::load(Path::new(&config_path)) {
                let dn = if cfg.sssd.ldap_default_bind_dn.trim().is_empty() {
                    "(not set)".to_string()
                } else {
                    cfg.sssd.ldap_default_bind_dn.clone()
                };
                let pw_masked = if cfg.sssd.ldap_default_authtok.trim().is_empty() {
                    "(not set)".to_string()
                } else {
                    "********".to_string()
                };

                println!("             ldap_default_bind_dn  = \"{}\"", dn);
                println!("             ldap_default_authtok = \"{}\"", pw_masked);
            } else {
                println!("             ldap_default_bind_dn  = \"(config not loadable)\"");
                println!("             ldap_default_authtok = \"(config not loadable)\"");
            }

            println!();
            println!("             [TROUBLESHOOTING] Testing LDAP bind...");

            if let Ok(cfg) = NfsKlldapConfig::load(Path::new(&config_path)) {
                match check_ldap_bind(&cfg) {
                    Ok(_) => {
                        println!("             ✓ Bind successful!");
                    }
                    Err(err) => {
                        println!("             {}", err);
                        println!("             → Verify the DN exactly matches what is in your LDAP server.");
                        println!("             → Make sure the password has no extra spaces or newlines.");
                    }
                }
                let mapping = resolve_posix_attribute_mapping(&cfg.sssd);
                println!();
                println!("             [SSSD] After startup, see /etc/sssd/sssd.conf (from this file).");
                println!("             Defaults: ldap_schema=rfc2307bis, enumerate=false, ldap_id_mapping=false");
                println!("             POSIX attrs: uid={}, uidNumber={}, gidNumber={}, member={}",
                    mapping.user_name, mapping.user_uid_number, mapping.user_gid_number, mapping.group_member);
                if cfg.ldap_uri.starts_with("ldaps://") && cfg.sssd.ldap_tls_reqcert.is_none() {
                    println!("             For self-signed LLDAP/KLLDAP certs add to [sssd]:");
                    println!("               ldap_tls_reqcert = \"never\"");
                }
                if cfg.sssd.enumerate == Some(true) {
                    println!("             WARNING: enumerate=true can overload KLLDAP — default is false.");
                }
            }
        }

        StartupStep::Ready => {}
    }
}

/// Compute which step we are currently on by running the various checks.
/// This is the Rust version of the big if-chain that used to live in
/// print_current_step_guidance + the various test_* shell functions.
fn compute_current_step(config_path: &Path) -> StartupStep {
    // Step 1: Persistent volume?
    if !check_persistent_writable_config(config_path) {
        return StartupStep::WaitForPersistentVolume;
    }

    // Try to load the config. If it fails basic parsing we treat it as "not ready yet".
    let cfg = match NfsKlldapConfig::load(config_path) {
        Ok(c) => c,
        Err(_) => {
            // Still missing critical fields or not parseable → we need at least ldap_uri
            // Fall through to step 2 guidance.
            return StartupStep::SetLdapUri;
        }
    };

    // Step 2: ldap_uri present and server reachable?
    if cfg.ldap_uri.trim().is_empty() {
        return StartupStep::SetLdapUri;
    }

    let host = extract_host_from_uri(&cfg.ldap_uri);
    match check_ldap_reachability(&host, &cfg.ldap_uri) {
        LdapReachability::Reachable => {}
        _ => return StartupStep::SetLdapUri,
    }

    // Step 3: Bind credentials present and working?
    if cfg.sssd.ldap_default_bind_dn.trim().is_empty()
        || cfg.sssd.ldap_default_authtok.trim().is_empty()
    {
        return StartupStep::AddBindCredentials;
    }

    if check_ldap_bind(&cfg).is_err() {
        return StartupStep::AddBindCredentials;
    }

    // Ready once bind credentials are present and working.
    // Shares ([[shares]]) are optional for initial startup and may be configured
    // later (via WebUI System Settings or direct edit + container restart).
    StartupStep::Ready
}



/// One-shot diagnostics (useful for `nfs-klldap-startup check` and for the
/// future when we want to expose health info).
fn run_one_shot_diagnostics(config_path: &Path) -> Result<(), ConfigError> {
    println!("=== nfs-klldap-startup diagnostics ===");
    println!("Config: {}", config_path.display());
    println!("Persistent volume: {}", is_persistent_config(config_path));

    match NfsKlldapConfig::load(config_path) {
        Ok(cfg) => {
            println!("ldap_uri : {}", cfg.ldap_uri);
            println!("realm    : {}", cfg.effective_realm());
            println!("shares   : {}", cfg.shares.len());
        }
        Err(e) => {
            println!("Config load error: {}", e);
        }
    }

    println!();
    print_runtime_diagnostics();

    Ok(())
}

/// Port of the shell check_runtime_permissions + check_keytab_hostname_match.
/// Runs as root during startup (advisory diagnostics + remediation instructions).
fn print_runtime_diagnostics() {
    println!("  [RUNTIME PERMISSIONS] Checking keytab readability and runtime dirs...");

    let kt = "/etc/krb5.keytab";
    let kt_path = Path::new(kt);

    if kt_path.exists() {
        // As root we can always read it here, but we still show ls -l for the user
        if let Ok(output) = Command::new("ls").arg("-l").arg(kt).output() {
            let ls = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("             Current: {}", ls);
        }
        println!("             [OK] keytab is readable by current user (root during setup)");
    } else {
        println!(
            "             (no keytab at {} — Kerberos NFS will not work until provided)",
            kt
        );
    }

    // Writable runtime dirs test (same dirs as the old shell logic)
    let runtime_dirs = [
        "/var/log/ganesha",
        "/var/lib/sss",
        "/var/run/ganesha",
        "/var/run/sssd",
        "/etc/ganesha/exports.d",
    ];

    for d in &runtime_dirs {
        let dir = Path::new(d);
        if dir.is_dir() {
            let test_file = dir.join(".write-test-rust-$$");
            if std::fs::File::create(&test_file).is_ok() {
                let _ = std::fs::remove_file(&test_file);
            } else {
                println!(
                    "             [ACTION REQUIRED] {} is not writable by current user",
                    d
                );
                println!("                    Fix on host (or add --user root temporarily for debugging):");
                println!(
                    "                      # Determine the runtime 'nfs' UID inside the image:"
                );
                println!("                      NFS_UID=$(docker run --rm --entrypoint id $d -u nfs 2>/dev/null | tr -cd 0-9)");
                println!("                      sudo chown -R $NFS_UID:$NFS_UID {}   # (use the real container nfs uid)", d);
            }
        }
    }

    // Hostname / keytab principal alignment (non-blocking)
    print_keytab_hostname_alignment();
}

fn print_keytab_hostname_alignment() {
    println!("  [KEYTAB/HOSTNAME] Checking keytab principal alignment...");

    let kt = "/etc/krb5.keytab";
    let kt_path = Path::new(kt);

    if !kt_path.exists() {
        println!("             (no keytab mounted at {} yet — Kerberos NFS will not work until provided)", kt);
        return;
    }

    let klist_out = match Command::new("klist").args(["-k", kt]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            println!("             (klist not available or failed — skipping detailed principal check; keytab file is present)");
            return;
        }
    };

    // Use the same two-tier confirmed value that the TUI banner used.
    // This guarantees the alignment check and the early banner can never disagree.
    let current_host = match get_consistent_hostname() {
        Ok(c) => c.hostname,
        Err(_) => {
            // Fall back to the old direct call only for the (rare) case where we are
            // already in a bad state; the loud warning was already emitted earlier.
            Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        }
    };

    // Parse nfs/ principals from klist output
    let mut kt_hosts: Vec<String> = Vec::new();
    for line in klist_out.lines() {
        if line.contains("nfs/") {
            if let Some(princ) = line.split_whitespace().nth(1) {
                if let Some(after_slash) = princ.split('/').nth(1) {
                    let host = after_slash.split('@').next().unwrap_or("");
                    if !host.is_empty() {
                        kt_hosts.push(host.to_string());
                    }
                }
            }
        }
    }

    kt_hosts.sort();
    kt_hosts.dedup();

    if kt_hosts.is_empty() {
        println!("             WARNING: keytab exists but contains no nfs/* service principals");
        println!("                      (hostname and keytab: no nfs principals found)");
        return;
    }

    let kt_str = kt_hosts.join(" ");

    let realm_hint = std::env::var("NFS_CONFIG")
        .ok()
        .and_then(|p| NfsKlldapConfig::load(Path::new(&p)).ok())
        .map(|c| c.display_realm())
        .unwrap_or_else(|| "YOUR.REALM".to_string());

    let aligned = kt_hosts
        .iter()
        .any(|h| nfs_keytab_host_matches(h, &current_host));

    if aligned {
        println!(
            "             (hostname and keytab: aligned)   hostname={}   keytab={}",
            current_host, kt_str
        );
    } else {
        println!("             WARNING: hostname and keytab nfs/* principals do not match.");
        println!("                      Container hostname : {}", current_host);
        println!(
            "                      Expected (best practice): {}",
            format_nfs_principal_list(&current_host, &realm_hint)
        );
        println!("                      nfs/ principals in keytab : {}", kt_str);
        println!("                      Use --uts=host and recreate keytab with short + FQDN principals.");
        println!("                      Services will continue; see WebUI System Settings for status.");
    }
}
