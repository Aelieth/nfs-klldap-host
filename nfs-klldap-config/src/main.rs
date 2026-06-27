#![deny(unsafe_code, dead_code)]

//! The nfs-klldap-config CLI provides init, generate, and validate.
//! The generate subcommand drives the config watcher on WebUI save.

use std::env;
use std::path::{Path, PathBuf};
use std::process::exit;

use nfs_klldap_config::{
    compute_effective_flags, generate_all, get_consistent_hostname, limited_fs_warnings_only,
    probe_fs_capabilities, write_default_config_if_missing, ConfigError, FsCapabilities,
    GenerationPaths, NfsKlldapConfig, Share,
};

fn usage() {
    eprintln!(
        "nfs-klldap-config v{} — type-safe config tool for nfs-klldap-host

Usage:
  nfs-klldap-config init     --config <path>
  nfs-klldap-config generate --config <path> [--dry-run]
  nfs-klldap-config validate --config <path>
  nfs-klldap-config fs-warnings --config <path>

Companion binary:
  nfs-klldap-startup         (pid-1 supervise + diagnostics; entrypoint.sh execs it)

The binaries are intended to be called by the container entrypoint and the host UI.",
        env!("CARGO_PKG_VERSION")
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
        "fs-warnings" => handle_fs_warnings(&config_path),
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
            println!("Edit it, then use the WebUI 'Restart and apply' (or send SIGHUP to the running container) so Ganesha/SSSD/WebUI pick it up.");
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

        // Two-tier runtime hostname (setup wizard/UI use this for keytab.
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
        println!("idmap domain (would use /etc/idmapd.conf): {}", cfg.nfsv4_domain());
        println!("shares:   {}", cfg.shares.len());
        for s in &cfg.shares {
            print_share_probe_line(&cfg, s, true);
        }
        return Ok(());
    }

    let paths = GenerationPaths::from_env();
    if !dry_run {
        for p in [
            &paths.sssd_conf,
            &paths.krb5_conf,
            &paths.ganesha_conf,
            &paths.idmap_conf,
        ] {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let _ = std::fs::create_dir_all(&paths.exports_dir);
    }
    generate_all(&cfg, &paths)?;

    println!("Generated configs from {}", path.display());
    println!("  sssd:    {}", paths.sssd_conf.display());
    println!("  krb5:    {}", paths.krb5_conf.display());
    println!("  idmap:   {}", paths.idmap_conf.display());
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
        print_share_probe_line(&cfg, s, false);
    }
    Ok(())
}

fn handle_fs_warnings(path: &Path) -> Result<(), ConfigError> {
    let cfg = NfsKlldapConfig::load(path)?;
    for w in limited_fs_warnings_only(&cfg) {
        println!("{}", w.format_line());
    }
    Ok(())
}

fn print_share_probe_line(cfg: &NfsKlldapConfig, s: &Share, dry_run: bool) {
    let container = cfg.container_path_for(s);
    let serve = cfg.serve_path_for(s);
    let caps = probe_fs_capabilities(Path::new(&serve)).unwrap_or_else(|_| FsCapabilities {
        fstype: "unknown".into(),
        mount_options: vec![],
        acl_capable: true,
    });
    if !caps.acl_capable {
        let eff = compute_effective_flags(s, &caps);
        println!(
            "  - {} → host:{}  container:{}  serve:{}  fs:{} acl_capable=false effective_enable_acl={} effective_manage_gids={}",
            s.name,
            s.host_path.display(),
            container,
            serve,
            caps.fstype,
            eff.enable_acl,
            eff.manage_gids
        );
        return;
    }
    if dry_run {
        println!(
            "  - {} → host:{}  container:{}  serve:{}",
            s.name,
            s.host_path.display(),
            container,
            serve
        );
    } else {
        println!("    {} (host: {})", s.name, s.host_path.display());
    }
}
