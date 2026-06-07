//! nfs-klldap-startup — container bring-up supervisor + non-interactive diagnostics.
//!
//! The blocking terminal TUI is replaced by the WebUI setup wizard; this binary
//! provides `supervise` (pid-1), `check`, and `wait-ready` entry points.

#![deny(unsafe_code, dead_code)]

#[path = "../supervisor.rs"]
mod supervisor;

use std::env;
use std::path::Path;
use std::process::{exit, Command};
use std::thread;
use std::time::Duration;

use nfs_klldap_config::{
    check_persistent_writable, compute_startup_step, default_config_path, effective_startup_step,
    format_nfs_principal_list, get_consistent_hostname, is_persistent_config,
    is_preconfigured_deployment, nfs_keytab_host_matches, parse_klist_nfs_hosts,
    resolve_keytab_path, startup_step_hint, StartupStep, NfsKlldapConfig,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    let config_path = default_config_path();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("supervise");

    match cmd {
        "supervise" | "run" | "startup" => {
            if let Err(e) = supervisor::run_supervisor(&config_path) {
                eprintln!("FATAL: {e}");
                exit(2);
            }
        }
        "supervise-probe" => {
            std::env::set_var("NFS_KLLDAP_SUPERVISE_PROBE", "1");
            if let Err(e) = supervisor::run_supervisor(&config_path) {
                eprintln!("FATAL: {e}");
                exit(2);
            }
        }
        "check" => {
            if let Err(e) = run_one_shot_diagnostics(&config_path) {
                eprintln!("ERROR: {e}");
                exit(2);
            }
        }
        "wait-ready" => {
            if let Err(e) = wait_until_ready(&config_path) {
                eprintln!("ERROR: {e}");
                exit(2);
            }
        }
        "help" | "--help" | "-h" => print_help(),
        _ => {
            eprintln!("Unknown command: {cmd}");
            print_help();
            exit(1);
        }
    }
}

fn print_help() {
    eprintln!(
        "nfs-klldap-startup v{} — container supervisor + diagnostics

Usage:
  nfs-klldap-startup supervise       Run pid-1 supervisor (default; replaces entrypoint logic)
  nfs-klldap-startup supervise-probe One-shot supervise path for CI (probe mode, then exit)
  nfs-klldap-startup check           One-shot diagnostics and exit
  nfs-klldap-startup wait-ready      Poll until setup steps pass (no UI)

First-run setup is handled by the WebUI wizard at https://<host>:9630/setup
",
        env!("CARGO_PKG_VERSION")
    );
}

/// Poll until compute_startup_step returns Ready (used by tests and automation).
fn wait_until_ready(config_path: &Path) -> Result<(), String> {
    loop {
        let step = compute_startup_step(config_path);
        if step == StartupStep::Ready {
            if let Ok(v) = std::env::var("HOST_NFS").or_else(|_| std::env::var("NFS_KLLDAP_HOST_NFS")) {
                let t = v.trim().to_ascii_lowercase();
                if t == "true" || t == "1" || t == "yes" || t == "on" {
                    println!("[HOST_NFS] Mode active — host NFS server (Ganesha at /etc/ganesha) will serve the shares.");
                    println!("           This container manages config, Kerberos material, SSSD identity, and the WebUI permission tools.");
                }
            }
            return Ok(());
        }
        eprintln!(
            "[wait-ready] {} — {}",
            step.label(),
            startup_step_hint(step)
        );
        thread::sleep(Duration::from_secs(2));
    }
}

/// One-shot diagnostics for `nfs-klldap-startup check`.
fn run_one_shot_diagnostics(config_path: &Path) -> Result<(), nfs_klldap_config::ConfigError> {
    println!("=== nfs-klldap-startup diagnostics ===");
    println!("Config: {}", config_path.display());
    println!("Persistent volume: {}", is_persistent_config(config_path));
    println!("Writable persistent: {}", check_persistent_writable(config_path));

    let kt = resolve_keytab_path();
    let probe_step = compute_startup_step(config_path);
    let effective = effective_startup_step(config_path, &kt);
    println!(
        "Startup step (live probes): {} ({})",
        probe_step.label(),
        startup_step_hint(probe_step)
    );
    println!(
        "Effective startup state: {} ({})",
        effective.label(),
        startup_step_hint(effective)
    );
    let preconf = is_preconfigured_deployment(config_path, &kt);
    println!("Pre-configured bypass: {preconf} (keytab + complete conf skips wizard)");

    match NfsKlldapConfig::load(config_path) {
        Ok(cfg) => {
            println!("ldap_uri : {}", cfg.ldap_uri);
            println!("realm    : {}", cfg.effective_realm());
            println!("shares   : {}", cfg.shares.len());
        }
        Err(e) => println!("Config load error: {e}"),
    }

    println!();
    print_network_diagnostics();
    print_runtime_diagnostics(config_path);
    Ok(())
}

fn print_network_diagnostics() {
    if let Some(ip) = nfs_klldap_config::container_primary_ipv4() {
        if nfs_klldap_config::is_docker_bridge_ipv4(&ip) {
            println!("  [NETWORK] WARNING: container primary IPv4 is {ip} (Docker bridge range)");
            println!("             NFSv4 + Kerberos expect host-reachable addresses.");
            println!("             Use --network=host (docker run) or network_mode: host (compose).");
        }
    }
}

fn print_runtime_diagnostics(config_path: &Path) {
    println!("  [RUNTIME] keytab and hostname alignment...");

    let kt = resolve_keytab_path();
    if kt.is_file() {
        if let Ok(output) = Command::new("ls").arg("-l").arg(&kt).output() {
            let ls = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("             keytab ({}): {ls}", kt.display());
        }
    } else {
        println!(
            "             (no keytab at {} — mount /etc/krb5.keytab for Kerberos NFS)",
            kt.display()
        );
    }

    print_keytab_hostname_alignment(config_path, &kt);
}

fn print_keytab_hostname_alignment(config_path: &Path, kt: &Path) {
    if !kt.is_file() {
        return;
    }

    let kt_str = kt.to_string_lossy();
    let klist_out = match Command::new("klist").args(["-k", kt_str.as_ref()]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            println!("             (klist unavailable — keytab file is present)");
            return;
        }
    };

    let current_host = match get_consistent_hostname() {
        Ok(c) => c.hostname,
        Err(_) => Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
    };

    let kt_hosts = parse_klist_nfs_hosts(&klist_out);
    if kt_hosts.is_empty() {
        println!("             WARNING: keytab has no nfs/* principals");
        return;
    }

    let realm_hint = NfsKlldapConfig::load(config_path)
        .map(|c| c.display_realm())
        .unwrap_or_else(|_| "YOUR.REALM".to_string());

    let aligned = kt_hosts
        .iter()
        .any(|h| nfs_keytab_host_matches(h, &current_host));

    if aligned {
        println!(
            "             hostname/keytab aligned: host={current_host} nfs={}",
            kt_hosts.join(" ")
        );
    } else {
        println!("             WARNING: hostname and keytab nfs/* principals differ.");
        println!("                      hostname: {current_host}");
        println!(
            "                      expected: {}",
            format_nfs_principal_list(&current_host, &realm_hint)
        );
        println!("                      keytab: {}", kt_hosts.join(" "));
    }
}

