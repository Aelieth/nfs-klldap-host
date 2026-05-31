//! nfs-klldap-config CLI. Subcommands: init | generate | validate.
//! generate drives the watcher + WebUI save path (root execution required for 0600 files).

use std::env;
use std::path::{Path, PathBuf};
use std::process::exit;

use nfs_klldap_config::{
    generate_all, get_consistent_hostname, write_default_config_if_missing, ConfigError,
    GenerationPaths, NfsKlldapConfig,
};

fn usage() {
    eprintln!(
        "nfs-klldap-config v0.5 — type-safe config tool for nfs-klldap-host

Usage:
  nfs-klldap-config init     --config <path>
  nfs-klldap-config generate --config <path> [--dry-run]
  nfs-klldap-config validate --config <path>

Companion binary:
  nfs-klldap-startup         (guided container startup / orchestration — replaces most of entrypoint.sh logic over time)

The binaries are intended to be called by the container entrypoint and the host UI."
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        exit(1);
    }

    let cmd = &args[1];
    let mut config_path = PathBuf::from("/config/nfs-klldap.conf");
    let mut dry_run = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    config_path = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("--config requires a path");
                    exit(1);
                }
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            _ => {
                eprintln!("Unknown arg: {}", args[i]);
                usage();
                exit(1);
            }
        }
    }

    let result = match cmd.as_str() {
        "init" => handle_init(&config_path),
        "generate" => handle_generate(&config_path, dry_run),
        "validate" => handle_validate(&config_path),
        "help" | "--help" | "-h" => {
            usage();
            Ok(())
        }
        _ => {
            usage();
            exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("ERROR: {}", e);
        exit(2);
    }
}

fn handle_init(path: &Path) -> Result<(), ConfigError> {
    match write_default_config_if_missing(path) {
        Ok(true) => {
            println!("Created default config at {}", path.display());
            println!("Edit it, then restart the container or send SIGHUP.");
            Ok(())
        }
        Ok(false) => {
            println!(
                "Config already exists at {} — not overwriting.",
                path.display()
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn handle_generate(path: &Path, dry_run: bool) -> Result<(), ConfigError> {
    let cfg = NfsKlldapConfig::load(path)?;

    if dry_run {
        println!("=== DRY RUN — would generate from {} ===", path.display());
        println!(
            "hostname (from config or best-effort): {}",
            cfg.effective_hostname()
        );

        // NEW: Show the two-tier confirmed runtime value (primary + secondary must agree).
        // This is the value the TUI and WebUI will actually use for keytab reminders
        // when no [server] hostname override is present. Useful for CI / sanity checks
        // that the same name is seen by nfs-klldap-config, nfs-klldap-startup, and nfs-klldap-ui.
        match get_consistent_hostname() {
            Ok(c) => {
                println!(
                    "hostname (two-tier confirmed):         {}   [primary+secondary agree]",
                    c.hostname
                );
            }
            Err(e) => {
                println!("hostname (two-tier):                   INCONSISTENT");
                eprintln!("{}", e);
            }
        }

        println!("realm:    {}", cfg.effective_realm());
        println!("shares:   {}", cfg.shares.len());
        for s in &cfg.shares {
            println!(
                "  - {} → host:{}  container:{}",
                s.name,
                s.host_path.display(),
                cfg.container_path_for(s)
            );
        }
        return Ok(());
    }

    let paths = GenerationPaths::default();
    generate_all(&cfg, &paths)?;

    println!("Generated configs from {}", path.display());
    println!("  sssd:    {}", paths.sssd_conf.display());
    println!("  krb5:    {}", paths.krb5_conf.display());
    println!("  ganesha: {}", paths.ganesha_conf.display());
    println!(
        "  exports: {} ({} share fragments)",
        paths.exports_dir.display(),
        cfg.shares.len()
    );
    Ok(())
}

fn handle_validate(path: &Path) -> Result<(), ConfigError> {
    let cfg = NfsKlldapConfig::load(path)?;
    println!("OK: {} is valid", path.display());
    println!("  ldap_uri : {}", cfg.ldap_uri);
    println!("  realm    : {}", cfg.effective_realm());
    println!("  shares   : {}", cfg.shares.len());
    for s in &cfg.shares {
        println!("    {} (host: {})", s.name, s.host_path.display());
    }
    Ok(())
}
