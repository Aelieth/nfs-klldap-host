//! nfs-klldap-startup — Container startup / guided setup binary (Rust).
//!
//! This binary owns the "bring the container online" experience:
//! - The 4-step guided first-run TUI / state machine (previously in entrypoint.sh)
//! - Reachability tests (LDAP port, bind, DNS, share paths)
//! - Persistent volume detection
//! - Best-effort realm derivation for the banner (from ldap_uri)
//! - Hostname suggestion using the recommended insertion pattern
//!   (host.example.com → host-nfs.example.com, not host.example.com-nfs)
//!
//! It is designed to run as root (as the entrypoint does during setup) so it
//! has full access to the host bind mounts and can write generated configs
//! into /etc/* before we gosu drop to the unprivileged `nfs` user for the
//! actual daemons.
//!
//! Long term this will replace almost all of the fragile grep|cut|tr|sed
//! parsing that used to live in entrypoint.sh.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::thread;
use std::time::Duration;

use nfs_klldap_config::{
    derive_realm_from_uri, extract_host_from_uri, is_persistent_config, load_host_paths_only,
    looks_like_docker_default_hostname, suggested_nfs_hostname, NfsKlldapConfig, ConfigError,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    let config_path = PathBuf::from(
        env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string()),
    );

    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("run");

    match cmd {
        "run" | "startup" => {
            ensure_good_hostname();
            if let Err(e) = run_guided_startup(&config_path) {
                eprintln!("FATAL: {}", e);
                exit(2);
            }
        }
        "check" => {
            ensure_good_hostname();
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
        "nfs-klldap-startup — guided container bring-up (replaces most of entrypoint.sh logic)

Usage:
  nfs-klldap-startup run      Run the full guided 4-step waiting TUI until ready
  nfs-klldap-startup check    Run diagnostics once and exit

Hostname behavior (standard since v0.4):
  - The startup binary retrieves the real Docker *host* machine's hostname
    (not the container ID) so it can derive the correct <short>-nfs.<domain> name.
  - Supported: -e HOST_HOSTNAME=...   or   -v /etc/hostname:/etc/hostname:ro
  - Explicit --hostname on docker run always bypasses the auto logic.
"
    );
}

// -----------------------------------------------------------------------------
// Auto hostname normalization (new standard behavior)
// -----------------------------------------------------------------------------

/// Ensure we are using a good, Kerberos-friendly hostname of the form
/// <shortname>-nfs.<domain> derived from the *Docker host's* hostname.
///
/// This implements the requested standard "auto" behavior:
///
/// - If the user explicitly passed `--hostname` on `docker run`, Docker sets
///   that value and it will contain a dot or otherwise look intentional.
///   We detect this and leave it completely alone (explicit always wins).
///
/// - Otherwise (Docker assigned a default container-ID style hostname such as
///   a 12-char hex string with no dot), we attempt to discover the real
///   hostname of the machine the operator is logged into ("the Docker host")
///   via:
///     1. `HOST_HOSTNAME` environment variable (easiest):
///        docker run -e HOST_HOSTNAME="$(hostname)" ...
///     2. Bind-mounting the host's /etc/hostname (fully automatic discovery):
///        -v /etc/hostname:/etc/hostname:ro
///        The startup binary detects when the file content differs from the
///        live container hostname and uses it as the real host name.
///     3. Other conventional mount points (/host/hostname, etc.).
///
///   We then derive the `-nfs` variant using `suggested_nfs_hostname` and
///   attempt to apply it with the `hostname` command.
///
/// Because the startup binary runs as root, it can also use privileged
/// techniques (reading the host kernel hostname via /proc/1/root or
/// executing the host's `hostname` binary) to discover the real machine
/// name even when the distro has no /etc/hostname file at all.
///
/// Setting the hostname from inside the container requires CAP_SYS_ADMIN
/// (or running the container with `--privileged`). If the set fails we emit
/// precise, copy-pasteable instructions telling the user the exact value
/// they should pass with `--hostname` on the next start.
fn ensure_good_hostname() {
    let current = current_hostname();

    if !looks_like_docker_default_hostname(&current) {
        // Looks like the user (or orchestration) provided an explicit --hostname.
        // Explicit always takes precedence; do nothing.
        return;
    }

    let host_base = discover_host_base_name();
    if host_base.is_empty() {
        // Keep the message short so it doesn't interleave with or pollute the TUI.
        eprintln!("[HOSTNAME] Docker default hostname detected ({current}). No HOST_HOSTNAME or host /etc/hostname provided.");
        eprintln!("           Pass -e HOST_HOSTNAME=\"$(hostname)\" (recommended) or --hostname <good-name> for Kerberos.");
        eprintln!("           Continuing with current name; keytab must match exactly what you see in the banner below.");
        eprintln!();
        return;
    }

    let desired = suggested_nfs_hostname(&host_base);
    if desired == current {
        return;
    }

    println!("\n[HOSTNAME] Container has Docker default hostname ('{current}').");
    println!("           Auto-deriving recommended name from host: {desired}");

    // Attempt the set. This will succeed only with sufficient capability.
    let status = Command::new("hostname").arg(&desired).status();

    match status {
        Ok(s) if s.success() => {
            println!("           [OK] Container hostname set to {desired}.");
            // Keep $HOSTNAME in sync for anything that reads the variable later.
            std::env::set_var("HOSTNAME", &desired);
        }
        _ => {
            eprintln!("           [ACTION REQUIRED] Could not set hostname (no CAP_SYS_ADMIN).");
            eprintln!("           Restart with explicit:  --hostname {desired}");
            eprintln!("           Or the easy one-liner on the host:  --hostname \"$(hostname | sed 's/^\\([^.]*\\)/\\1-nfs/')\"");
            eprintln!("           Continuing with current name '{current}'. Keytab must match it.");
        }
    }
}

/// Return the current hostname, preferring the kernel view then the env var.
fn current_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

// (looks_like_docker_default_hostname is now provided by the library)

/// Discover the *Docker host's* real hostname (the machine running Docker,
/// not this container).
///
/// The goal is for the startup binary to automatically retrieve the real
/// host's hostname so it can derive the recommended <short>-nfs.<domain>
/// name without the user always having to pass --hostname.
///
/// Detection order (first good candidate wins):
/// 1. HOST_HOSTNAME environment variable (easiest explicit signal).
/// 2. The file /etc/hostname when it has been bind-mounted from the host.
/// 3. Common explicit mount points for the host hostname file.
/// 4. Privileged root-based discovery (since we run as root during startup):
///    - Read /proc/1/root/proc/sys/kernel/hostname (works on hosts without
///      any /etc/hostname file at all — the hostname lives only in the kernel).
///    - Execute the host's `hostname` binary via /proc/1/root (the method
///      the user requested: "use root commands such as simply 'hostname'").
///    - Fall back to nsenter if available on the host.
///
/// This tier allows fully automatic operation on privileged or semi-privileged
/// containers without the operator having to pass any extra flags or mounts.
fn discover_host_base_name() -> String {
    // 1. Explicit env var — user is deliberately telling us the host name.
    if let Ok(val) = std::env::var("HOST_HOSTNAME") {
        let t = val.trim();
        if !t.is_empty() && !looks_like_docker_default_hostname(t) {
            return t.to_string();
        }
    }

    // 2. The single most useful passive method:
    //    User did: -v /etc/hostname:/etc/hostname:ro
    //    Inside the container the *file* now contains the Docker host's real
    //    hostname, while the live kernel hostname is still the container ID
    //    (or whatever Docker assigned).
    if let Ok(file_content) = std::fs::read_to_string("/etc/hostname") {
        let t = file_content.trim();
        let live = current_hostname();
        if !t.is_empty()
            && t != live
            && !looks_like_docker_default_hostname(t)
        {
            return t.to_string();
        }
    }

    // 3. Explicitly mounted copies at conventional locations.
    //    Users who don't want to replace the container's /etc/hostname can use
    //    one of these instead.
    let candidates: [&str; 6] = [
        "/host/hostname",
        "/host/etc/hostname",
        "/etc/hostname.host",
        "/run/host/hostname",
        "/mnt/host/hostname",
        "/proc/1/root/etc/hostname", // privileged: view from the real host init ns
    ];

    for path in &candidates {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let t = contents.trim();
            if !t.is_empty() && !looks_like_docker_default_hostname(t) {
                return t.to_string();
            }
        }
    }

    // 4. Privileged discovery using root access (we run as root during startup).
    //    Many distros do not have /etc/hostname at all — the hostname lives
    //    only in the kernel (UTS namespace). Since we are root, we can reach
    //    into the host's namespace via /proc/1/root and run "hostname" or read
    //    the kernel hostname file directly.
    if let Some(hostname) = try_read_host_hostname_via_privileged_root() {
        return hostname;
    }

    String::new()
}

/// When running as root (which the startup binary does), attempt to discover
/// the real Docker host's hostname by reaching into the host's root filesystem
/// via /proc/1/root.
///
/// This is the method of last resort for hosts that have no /etc/hostname file
/// (very common on minimal, systemd-only, or appliance distros). The hostname
/// is only maintained live in the kernel.
///
/// We try:
/// - Reading the host's live kernel hostname directly
/// - Executing the host's `hostname` binary (various common paths)
///
/// These only work when the container has sufficient privileges
/// (typically --privileged or a combination of pid/host + CAP_SYS_ADMIN etc.).
fn try_read_host_hostname_via_privileged_root() -> Option<String> {
    // Method A: Read the host kernel's live hostname.
    // This is the most universal and doesn't depend on any hostname package.
    // On many systems without /etc/hostname, `hostname` command itself reads this.
    if let Ok(contents) = std::fs::read_to_string("/proc/1/root/proc/sys/kernel/hostname") {
        let t = contents.trim();
        if !t.is_empty() && !looks_like_docker_default_hostname(t) {
            return Some(t.to_string());
        }
    }

    // Method B: Execute the host's "hostname" binary directly.
    // We try the most common locations across distros.
    let hostname_binaries: [&str; 4] = [
        "/proc/1/root/bin/hostname",
        "/proc/1/root/usr/bin/hostname",
        "/proc/1/root/usr/local/bin/hostname",
        "/proc/1/root/sbin/hostname",
    ];

    for bin in &hostname_binaries {
        if !std::path::Path::new(bin).exists() {
            continue;
        }
        if let Ok(output) = Command::new(bin).output() {
            if output.status.success() {
                let t = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !t.is_empty() && !looks_like_docker_default_hostname(&t) {
                    return Some(t);
                }
            }
        }
    }

    // Method C (optional extra): Try nsenter if it exists on the host.
    // This can work even without full --privileged in some configurations.
    let nsenter_paths: [&str; 2] = [
        "/proc/1/root/usr/bin/nsenter",
        "/proc/1/root/bin/nsenter",
    ];

    for nsenter in &nsenter_paths {
        if std::path::Path::new(nsenter).exists() {
            // Try to run: nsenter -t 1 -m -u hostname
            if let Ok(output) = Command::new(nsenter)
                .args(["-t", "1", "-m", "-u", "--", "hostname"])
                .output()
            {
                if output.status.success() {
                    let t = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !t.is_empty() && !looks_like_docker_default_hostname(&t) {
                        return Some(t);
                    }
                }
            }
        }
    }

    None
}

/// The main guided startup loop. This is the Rust replacement for the big
/// wait_for_valid_config + print_current_step_guidance dance in entrypoint.sh.
///
/// The 4 steps are:
///   1. Persistent volume at $NFS_CONFIG (different device from container root)
///   2. ldap_uri present + TCP reachable (must be DNS name, not IP)
///   3. Bind DN + password present and ldapsearch succeeds
///   4. At least one [[shares]] with a host_path that exists on the host
///
/// Steps are marked [x] as soon as they are satisfied (see is_step_complete).
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

        println!("\n[WAITING] Edit the config file — the container will auto-continue when ready.\n");
        thread::sleep(Duration::from_secs(8));
        print!("\x1b[2J\x1b[H"); // Clear for next iteration (simple TUI refresh)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StartupStep {
    WaitForPersistentVolume,
    SetLdapUri,
    AddBindCredentials,
    AddShares,
    Ready,
}

fn print_header(config_path: &Path) {
    // Get hostname portably (no dependency on the 'hostname' binary)
    let effective_host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string());

    // Best-effort realm derivation for the banner (works even if other config is missing).
    // We only need ldap_uri to be parseable; we do NOT run full validation here.
    let realm_display = attempt_realm_for_display(config_path)
        .unwrap_or_else(|| "YOUR.REALM (set ldap_uri to auto-derive)".to_string());

    // Build a friendly hostname line for the banner.
    // Never suggest mangling a Docker container-ID (e.g. "3c896c1c2e24-nfs").
    // Only offer the "(recommended: ...)" hint when we have a plausible real host name.
    let host_line = if looks_like_docker_default_hostname(&effective_host) {
        format!("{}   (Docker default — pass -e HOST_HOSTNAME or --hostname)", effective_host)
    } else {
        let suggested = suggested_nfs_hostname(&effective_host);
        if suggested != effective_host {
            format!("{}   (recommended: {})", effective_host, suggested)
        } else {
            effective_host.clone()
        }
    };

    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║  nfs-klldap-host — FIRST RUN SETUP (Step-by-Step)  [Rust guided mode]        ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Container hostname: {:<55} ║", host_line);

    // The keytab line must never advertise a container-ID principal.
    let keytab_line = if looks_like_docker_default_hostname(&effective_host) {
        "nfs/<realhost>-nfs.<domain>@REALM   (pass -e HOST_HOSTNAME or --hostname)".to_string()
    } else {
        format!("{}@{}", effective_host, realm_display)
    };
    println!("║  Keytab must contain: nfs/{:<50} ║", keytab_line);
    println!("║                                                                              ║");
    println!("║  The container is WAITING. It will auto-start services when these steps      ║");
    println!("║  are complete (no manual restart needed).                                    ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");
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
                let val = rest[eq_pos + 1..].trim().trim_matches(|c| c == '"' || c == '\'');
                if !val.is_empty() && (val.starts_with("ldap://") || val.starts_with("ldaps://")) {
                    if let Some(r) = derive_realm_from_uri(val) {
                        // Never surface the placeholder as a success
                        if !r.eq_ignore_ascii_case("EXAMPLE.COM") && !r.eq_ignore_ascii_case("EXAMPLE") {
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
        (StartupStep::WaitForPersistentVolume, "STEP 1/4", "Mount a persistent config volume (REQUIRED)"),
        (StartupStep::SetLdapUri,             "STEP 2/4", "Set ldap_uri in nfs-klldap.conf (DNS name only)"),
        (StartupStep::AddBindCredentials,     "STEP 3/4", "Add LLDAP bind credentials in [sssd] section"),
        (StartupStep::AddShares,              "STEP 4/4", "Add at least one [[shares]] section"),
    ];

    for (step, label, desc) in &steps {
        if *step == *current {
            println!("  [  ] {}  {}", label, desc);
            // Print extra guidance for the current step
            print_current_step_guidance(current);
        } else if is_step_complete(step, current) {
            println!("  [x] {}  {}", label, desc);
        } else {
            println!("  [  ] {}  {}", label, desc);
        }
    }
}

/// Returns true if `step` has been completed given that we are now at `current`.
/// Ordering: WaitForPersistentVolume < SetLdapUri < AddBindCredentials < AddShares < Ready
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
        (StartupStep::WaitForPersistentVolume, StartupStep::SetLdapUri | StartupStep::AddBindCredentials | StartupStep::AddShares) => true,
        // Step 2 is complete once we are past it
        (StartupStep::SetLdapUri, StartupStep::AddBindCredentials | StartupStep::AddShares) => true,
        // Step 3 is complete once we are past it
        (StartupStep::AddBindCredentials, StartupStep::AddShares) => true,
        // Step 4 is only complete when we reach Ready (handled above)
        _ => false,
    }
}

fn print_current_step_guidance(current: &StartupStep) {
    match current {
        StartupStep::WaitForPersistentVolume => {
            println!("             -v /path/on/your/host:/config");
        }
        StartupStep::SetLdapUri => {
            println!("             ldap_uri = \"ldaps://lldap.yourdomain.com:6360\"");
            println!("             (must be a real DNS name — IP addresses are rejected)");
        }
        StartupStep::AddBindCredentials => {
            println!("             ldap_default_bind_dn  = \"uid=admin,ou=people,dc=...\"");
            println!("             ldap_default_authtok = \"your-strong-password\"");
        }
        StartupStep::AddShares => {
            println!("             [[shares]]");
            println!("             name = \"my-share\"");
            println!("             host_path = \"/export/my-share\"   # must exist on the host");
        }
        StartupStep::Ready => {}
    }
}

/// Compute which step we are currently on by running the various checks.
/// This is the Rust version of the big if-chain that used to live in
/// print_current_step_guidance + the various test_* shell functions.
fn compute_current_step(config_path: &Path) -> StartupStep {
    // Step 1: Persistent volume?
    if !is_persistent_config(config_path) {
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

    // Step 2: ldap_uri present and port reachable?
    if cfg.ldap_uri.trim().is_empty() {
        return StartupStep::SetLdapUri;
    }

    // Lightweight port check (mirrors the old `nc -z` test)
    let host = extract_host_from_uri(&cfg.ldap_uri);
    if !tcp_port_reachable(&host, &cfg.ldap_uri) {
        return StartupStep::SetLdapUri;
    }

    // Step 3: Bind credentials present and working?
    if cfg.sssd.ldap_default_bind_dn.trim().is_empty() || cfg.sssd.ldap_default_authtok.trim().is_empty() {
        return StartupStep::AddBindCredentials;
    }

    // Quick bind test (uses ldapsearch like the shell did)
    if !ldap_bind_works(&cfg) {
        return StartupStep::AddBindCredentials;
    }

    // Step 4: At least one share with a valid host_path?
    let host_paths = match load_host_paths_only(config_path) {
        Ok(p) => p,
        Err(_) => vec![],
    };

    if host_paths.is_empty() {
        return StartupStep::AddShares;
    }

    // Check that the first declared host_path actually exists on the host
    if let Some(first) = host_paths.first() {
        if !first.exists() {
            return StartupStep::AddShares;
        }
    }

    StartupStep::Ready
}

// -----------------------------------------------------------------------------
// Rust wrappers for the reachability / diagnostic tests (replacing shell logic)
// -----------------------------------------------------------------------------

fn tcp_port_reachable(host: &str, uri: &str) -> bool {
    // Try to extract port, default 636 for ldaps
    let port: u16 = uri
        .split(':')
        .last()
        .and_then(|s| s.trim_end_matches(|c: char| !c.is_ascii_digit()).parse().ok())
        .unwrap_or(636);

    // Use a simple TCP connect attempt. We prefer this over shelling to `nc`
    // when possible (more portable, no extra tool dependency).
    std::net::TcpStream::connect_timeout(
        &format!("{}:{}", host, port).parse().unwrap_or_else(|_| "127.0.0.1:1".parse().unwrap()),
        Duration::from_secs(3),
    )
    .is_ok()
}

fn ldap_bind_works(cfg: &NfsKlldapConfig) -> bool {
    // Mirror the old `ldapsearch -D ... -w ...` test.
    // We keep using the real ldapsearch tool for now (it understands SASL, TLS, etc.).
    let uri = &cfg.ldap_uri;
    let dn = &cfg.sssd.ldap_default_bind_dn;
    let pw = &cfg.sssd.ldap_default_authtok;

    let status = Command::new("ldapsearch")
        .args([
            "-H", uri,
            "-D", dn,
            "-w", pw,
            "-s", "base",
            "-b", "",
        ])
        .output();

    match status {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
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
        println!("             (no keytab at {} — Kerberos NFS will not work until provided)", kt);
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
                println!("             [ACTION REQUIRED] {} is not writable by current user", d);
                println!("                    Fix on host (or add --user root temporarily for debugging):");
                println!("                      sudo chown -R 1000:1000 {}   # (example UID; use the container's nfs uid)", d);
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

    let current_host = Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

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

    if kt_hosts.iter().any(|h| h == &current_host) {
        println!("             (hostname and keytab: aligned)   hostname={}   keytab={}", current_host, kt_str);
    } else {
        let suggested = suggested_nfs_hostname(&current_host);
        println!("             WARNING: (hostname and keytab: mismatch! change hostname or recreate keytab)");
        println!("                      Container hostname : {}", current_host);
        if suggested != current_host {
            println!("                      Recommended hostname for this host: {}", suggested);
            println!("                      (Use --hostname {} when starting the container)", suggested);
        }
        println!("                      nfs/ principals in keytab : {}", kt_str);
        println!("                      Services will continue to start.");
        println!("                      See the web UI (System Settings page) for current status and remediation steps.");
    }
}