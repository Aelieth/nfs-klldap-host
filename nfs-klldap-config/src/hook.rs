//! Post-generate hook runs after successful generate.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::{ConfigError, NfsKlldapConfig};

/// Returns the hook path from [ganesha] post_generate_hook or env override.
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

/// Invoke the configured hook once per share (SHARE_* env vars)
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
    // serve_path = container_path (Ganesha EXPORT Path=). source_path defaults to the
    // serve path (no staging); when set distinctly, the hook stages source -> serve.
    let serve_path = cfg.serve_path_for(share);
    let source_path = share
        .source_path
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| serve_path.clone());
    let pseudo = crate::derive_share_pseudo(share);

    eprintln!(
        "INFO [nfs-klldap-config] post_generate_hook: {} (share={})",
        hook_path.display(),
        share.name
    );

    let mut child = Command::new(hook_path)
        .env("SHARE_NAME", &share.name)
        .env("HOST_PATH", share.host_path.display().to_string())
        // SOURCE_PATH = where the real data lives inside the container (staging source).
        .env("SOURCE_PATH", &source_path)
        // SERVE_PATH = Ganesha EXPORT Path= (the ACL-capable serve/staging tree).
        .env("SERVE_PATH", &serve_path)
        // Back-compat: CONTAINER_PATH historically meant the serve path.
        .env("CONTAINER_PATH", &serve_path)
        .env("PSEUDO_PATH", &pseudo)
        .env("EXPORT_PATH", &pseudo)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_share(source_path: Option<&str>) -> NfsKlldapConfig {
        let mut cfg = NfsKlldapConfig {
            ldap_uri: "ldaps://klldap.test:6360".into(),
            sssd: crate::SssdSection {
                ldap_default_bind_dn: "uid=a,ou=people,dc=x,dc=com".into(),
                ldap_default_authtok: "s".into(),
                ..Default::default()
            },
            shares: vec![crate::Share {
                name: "media".into(),
                host_path: "/media/data".into(),
                container_path: "/export/media".into(),
                source_path: source_path.map(str::to_string),
                ..Default::default()
            }],
            ..Default::default()
        };
        cfg.validate_and_derive().expect("valid cfg");
        cfg
    }

    fn write_env_dump_hook(dir: &Path, dump: &Path) -> std::path::PathBuf {
        let hook = dir.join("hook.sh");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\nenv | grep -E '^(SHARE_NAME|HOST_PATH|SOURCE_PATH|SERVE_PATH|CONTAINER_PATH|PSEUDO_PATH|EXPORT_PATH)=' | sort > {}\n",
                dump.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        hook
    }

    #[test]
    fn hook_env_carries_source_serve_split_and_pseudo_back_compat() {
        let _lock = crate::ENV_TEST_LOCK.lock().unwrap();
        std::env::remove_var("NFS_KLLDAP_POST_GENERATE_HOOK");
        let tmp = tempfile::tempdir().unwrap();
        let dump = tmp.path().join("env.dump");
        let hook = write_env_dump_hook(tmp.path(), &dump);

        let mut cfg = cfg_with_share(Some("/export/raid/media"));
        cfg.ganesha.post_generate_hook = Some(hook.display().to_string());
        run_post_generate_hooks(&cfg).expect("hook must run");

        let env = std::fs::read_to_string(&dump).unwrap();
        assert!(env.contains("SHARE_NAME=media"), "{env}");
        assert!(env.contains("HOST_PATH=/media/data"), "{env}");
        assert!(env.contains("SOURCE_PATH=/export/raid/media"), "{env}");
        assert!(env.contains("SERVE_PATH=/export/media"), "{env}");
        // Back-compat names: CONTAINER_PATH mirrors serve, EXPORT_PATH mirrors pseudo.
        assert!(env.contains("CONTAINER_PATH=/export/media"), "{env}");
        assert!(env.contains("PSEUDO_PATH=/media"), "{env}");
        assert!(env.contains("EXPORT_PATH=/media"), "{env}");
    }

    #[test]
    fn hook_source_defaults_to_serve_when_unset() {
        let _lock = crate::ENV_TEST_LOCK.lock().unwrap();
        std::env::remove_var("NFS_KLLDAP_POST_GENERATE_HOOK");
        let tmp = tempfile::tempdir().unwrap();
        let dump = tmp.path().join("env.dump");
        let hook = write_env_dump_hook(tmp.path(), &dump);

        let mut cfg = cfg_with_share(None);
        cfg.ganesha.post_generate_hook = Some(hook.display().to_string());
        run_post_generate_hooks(&cfg).expect("hook must run");

        let env = std::fs::read_to_string(&dump).unwrap();
        assert!(env.contains("SOURCE_PATH=/export/media"), "{env}");
        assert!(env.contains("SERVE_PATH=/export/media"), "{env}");
    }

    #[test]
    fn non_executable_hook_aborts_with_validation_error() {
        let _lock = crate::ENV_TEST_LOCK.lock().unwrap();
        std::env::remove_var("NFS_KLLDAP_POST_GENERATE_HOOK");
        let tmp = tempfile::tempdir().unwrap();
        let hook = tmp.path().join("not-exec.sh");
        std::fs::write(&hook, "#!/bin/sh\ntrue\n").unwrap();

        let mut cfg = cfg_with_share(None);
        cfg.ganesha.post_generate_hook = Some(hook.display().to_string());
        let err = run_post_generate_hooks(&cfg).expect_err("must reject non-executable hook");
        assert!(err.to_string().contains("not executable"), "{err}");
    }
}
