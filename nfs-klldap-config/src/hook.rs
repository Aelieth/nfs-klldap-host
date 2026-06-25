//! Post-generate hook: optional operator script after config generation.
//! Runs before Ganesha recycle.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::{ConfigError, NfsKlldapConfig};

/// Hook path from [ganesha] post_generate_hook or.
/// NFS_KLLDAP_POST_GENERATE_HOOK.
pub fn effective_post_generate_hook(cfg: &NfsKlldapConfig) -> Option<String> {
    if let Ok(env) = std::env::var("NFS_KLLDAP_POST_GENERATE_HOOK") {
        let t = env.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    cfg.ganesha
        .post_generate_hook
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn is_executable(path: &Path) -> bool {
    path.is_file() && {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path)
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
}

/// Invoke the configured hook once per share (SHARE_* env vars).
/// Non-zero exit aborts.
pub fn run_post_generate_hooks(cfg: &NfsKlldapConfig) -> Result<(), ConfigError> {
    let Some(hook) = effective_post_generate_hook(cfg) else {
        return Ok(());
    };
    let hook_path = Path::new(&hook);
    if !is_executable(hook_path) {
        return Err(ConfigError::Validation(format!(
            "post_generate_hook is not executable: {}",
            hook_path.display()
        )));
    }

    for share in &cfg.shares {
        run_hook_for_share(hook_path, cfg, share)?;
    }
    Ok(())
}

fn run_hook_for_share(
    hook_path: &Path,
    cfg: &NfsKlldapConfig,
    share: &crate::Share,
) -> Result<(), ConfigError> {
    let container_path = cfg.container_path_for(share);
    let serve_path = cfg.serve_path_for(share);
    let ganesha_path = share
        .ganesha_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(serve_path.as_str());

    eprintln!(
        "INFO [nfs-klldap-config] post_generate_hook: {} (share={})",
        hook_path.display(),
        share.name
    );

    let mut child = Command::new(hook_path)
        .env("SHARE_NAME", &share.name)
        .env("HOST_PATH", share.host_path.display().to_string())
        .env("CONTAINER_PATH", &container_path)
        .env("SERVE_PATH", &serve_path)
        .env("GANESHA_PATH", ganesha_path)
        .env(
            "EXPORT_PATH",
            share.export_path.as_deref().unwrap_or(&format!("/{}", share.name)),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ConfigError::Validation(format!("post_generate_hook spawn failed: {e}")))?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }

    let status = child
        .wait()
        .map_err(|e| ConfigError::Validation(format!("post_generate_hook wait failed: {e}")))?;

    if !stdout.trim().is_empty() {
        eprintln!(
            "INFO [nfs-klldap-config] post_generate_hook stdout (share={}): {}",
            share.name,
            stdout.trim()
        );
    }
    if !stderr.trim().is_empty() {
        eprintln!(
            "INFO [nfs-klldap-config] post_generate_hook stderr (share={}): {}",
            share.name,
            stderr.trim()
        );
    }

    if !status.success() {
        return Err(ConfigError::Validation(format!(
            "post_generate_hook {} failed for share '{}' (exit={:?})",
            hook_path.display(),
            share.name,
            status.code()
        )));
    }
    Ok(())
}
