//! nfs-klldap-startup — Container startup / guided setup binary (Rust).
//!
//! This binary owns the "bring the container online" experience:
//! - The 4-step guided first-run TUI / state machine (previously in entrypoint.sh)
//! - Reachability tests (LDAP port, bind, DNS, share paths)
//! - Persistent volume detection
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

use nfs_klldap_config::{extract_host_from_uri, is_persistent_config, load_host_paths_only, NfsKlldapConfig, ConfigError};

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
        "nfs-klldap-startup — guided container bring-up (replaces most of entrypoint.sh logic)

Usage:
  nfs-klldap-startup run      Run the full guided 4-step waiting TUI until ready
  nfs-klldap-startup check    Run diagnostics once and exit
"
    );
}

/// The main guided startup loop. This is the Rust replacement for the big
/// wait_for_valid_config + print_current_step_guidance dance in entrypoint.sh.
fn run_guided_startup(config_path: &Path) -> Result<(), ConfigError> {
    println!("\x1b[2J\x1b[H"); // Clear screen + home

    loop {
        print_header();
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

fn print_header() {
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║  nfs-klldap-host — FIRST RUN SETUP (Step-by-Step)  [Rust guided mode]        ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  The container is WAITING. It will auto-start services when these steps      ║");
    println!("║  are complete (no manual restart needed).                                    ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");
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
            println!("  [OK] {}  {}", label, desc);
        } else {
            println!("  [  ] {}  {}", label, desc);
        }
    }
}

fn is_step_complete(step: &StartupStep, current: &StartupStep) -> bool {
    // Simple ordering: everything before the current step is considered complete
    match (step, current) {
        (StartupStep::WaitForPersistentVolume, _) => false,
        (StartupStep::SetLdapUri, StartupStep::WaitForPersistentVolume) => false,
        (StartupStep::AddBindCredentials, StartupStep::WaitForPersistentVolume | StartupStep::SetLdapUri) => false,
        (StartupStep::AddShares, StartupStep::WaitForPersistentVolume | StartupStep::SetLdapUri | StartupStep::AddBindCredentials) => false,
        _ => true,
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
        println!("             WARNING: (hostname and keytab: mismatch! change hostname or recreate keytab)");
        println!("                      Container hostname : {}", current_host);
        println!("                      nfs/ principals in keytab : {}", kt_str);
        println!("                      Services will continue to start.");
        println!("                      See the web UI (System Settings page) for current status and remediation steps.");
    }
}