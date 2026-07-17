//! Supervisor env + runtime path helpers (extracted from supervisor/mod.rs for
//! modularization; keeps ACL/NOACL notes none here).

use std::fs;
use std::path::{Path, PathBuf};

const RECYCLE_MARKER_DEFAULT: &str = "/tmp/.nfs-klldap-services-recycled";
const EXTRAUSERS_PASSWD_DEFAULT: &str = "/var/lib/extrausers/passwd";
const EXTRAUSERS_GROUP_DEFAULT: &str = "/var/lib/extrausers/group";

/// libnss-extrausers reads these paths from the process environment.
pub(crate) fn ensure_nss_extrausers_env(passwd: &Path, group: &Path) {
    std::env::set_var("NSS_EXTRAUSERS_PASSWD", passwd);
    std::env::set_var("NSS_EXTRAUSERS_GROUP", group);
}

pub(crate) fn recycle_marker_path() -> PathBuf {
    std::env::var("NFS_KLLDAP_RECYCLE_MARKER")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(RECYCLE_MARKER_DEFAULT))
}

pub(crate) fn loop_probe_ready_path() -> Option<PathBuf> {
    std::env::var("NFS_KLLDAP_LOOP_PROBE_READY")
        .ok()
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

pub(crate) fn touch_loop_probe_ready() {
    if let Some(path) = loop_probe_ready_path() {
        let _ = fs::write(&path, b"ready\n");
    }
}

/// Runtime paths and binaries (override via env for CI).
pub(crate) struct SupervisorEnv {
    pub nfs_config: PathBuf,
    pub sssd_conf: PathBuf,
    pub krb5_conf: PathBuf,
    pub ganesha_conf: PathBuf,
    pub exports_dir: PathBuf,
    pub idmap_conf: PathBuf,
    pub nfs_conf: PathBuf,
    pub config_bin: PathBuf,
    pub ui_bin: PathBuf,
    pub watcher_bin: PathBuf,
    pub idhelper_bin: PathBuf,
    pub healthcheck: PathBuf,
    pub nss_passwd: PathBuf,
    pub nss_group: PathBuf,
    pub extrausers_passwd: PathBuf,
    pub extrausers_group: PathBuf,
    pub nss_wrapper_so: PathBuf,
    pub use_nss_wrapper: bool,
    pub log_format_json: bool,
    /// Runs a CI one-shot that generates configs, logs bring-up, then exits.
    pub supervise_probe: bool,
    /// Runs a bounded CI loop after post-wizard SIGHUP with complete config.
    pub supervise_wizard_probe: bool,
    /// Exercises supervisor_loop with probe stubs until a real SIGHUP arrives.
    pub supervise_loop_probe: bool,
    /// Tests ganesha SIGHUP reload and stop_ganesha against a stub nfsd.
    pub supervise_recycle_probe: bool,
    /// Waits for OS SIGHUP then runs handle_sighup on the hook path.
    pub supervise_sighup_hook_probe: bool,
    /// Verifies identity-only changes recycle SSSD without ganesha SIGHUP.
    pub supervise_identity_recycle_probe: bool,
    /// Enables HOST_NFS sidecar mode that generates fragments and skips nfsd.
    pub host_nfs_mode: bool,
    /// Overrides loop sleep ms; zero enables wizard-probe bounded ticks.
    pub supervisor_tick_ms: u64,
    /// Max loop iterations before exit when supervise_wizard_probe is set.
    pub supervisor_max_ticks: u32,
    /// Copytruncate cap for the runtime logs (NFS_KLLDAP_LOG_ROTATE_MAX_MB,
    /// default 64; 0 disables rotation).
    pub log_rotate_max_bytes: u64,
}

impl SupervisorEnv {
    pub(crate) fn from_env(config_path: &Path) -> Self {
        let env_path = |key: &str, default: &str| -> PathBuf {
            std::env::var(key)
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(default))
        };
        let use_nss = std::env::var("USE_NSS_WRAPPER")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        Self {
            nfs_config: config_path.to_path_buf(),
            sssd_conf: env_path("SSSD_CONF", "/etc/sssd/sssd.conf"),
            krb5_conf: env_path("KRB5_CONF", "/etc/krb5.conf"),
            ganesha_conf: env_path("GANESHA_CONF", "/etc/ganesha/ganesha.conf"),
            exports_dir: env_path("EXPORTS_DIR", "/etc/ganesha/exports.d"),
            idmap_conf: env_path("IDMAP_CONF", "/etc/idmapd.conf"),
            nfs_conf: env_path("NFS_CONF", "/etc/nfs.conf"),
            config_bin: env_path("CONFIG_BIN", "/usr/local/bin/nfs-klldap-config"),
            ui_bin: env_path("UI_BIN", "/usr/local/bin/nfs-klldap-ui"),
            watcher_bin: env_path("WATCHER_BIN", "/usr/local/bin/nfs-klldap-conf-watcher"),
            idhelper_bin: env_path("IDHELPER_BIN", "/usr/local/bin/nfs-klldap-idhelper"),
            healthcheck: env_path("HEALTHCHECK", "/container/healthcheck.sh"),
            nss_passwd: env_path("NSS_PASSWD", "/var/lib/nfs-klldap/nss_passwd"),
            nss_group: env_path("NSS_GROUP", "/var/lib/nfs-klldap/nss_group"),
            extrausers_passwd: env_path("NSS_EXTRAUSERS_PASSWD", EXTRAUSERS_PASSWD_DEFAULT),
            extrausers_group: env_path("NSS_EXTRAUSERS_GROUP", EXTRAUSERS_GROUP_DEFAULT),
            nss_wrapper_so: super::resolve_nss_wrapper_so(),
            use_nss_wrapper: use_nss,
            log_format_json: std::env::var("LOG_FORMAT")
                .map(|v| v == "json")
                .unwrap_or(false),
            supervise_probe: std::env::var("NFS_KLLDAP_SUPERVISE_PROBE")
                .is_ok_and(|v| v == "1"),
            supervise_wizard_probe: std::env::var("NFS_KLLDAP_SUPERVISE_WIZARD_PROBE")
                .is_ok_and(|v| v == "1"),
            supervise_loop_probe: std::env::var("NFS_KLLDAP_SUPERVISE_LOOP_PROBE")
                .is_ok_and(|v| v == "1"),
            supervise_recycle_probe: std::env::var("NFS_KLLDAP_SUPERVISE_RECYCLE_PROBE")
                .is_ok_and(|v| v == "1"),
            supervise_sighup_hook_probe: std::env::var("NFS_KLLDAP_SUPERVISE_SIGHUP_HOOK_PROBE")
                .is_ok_and(|v| v == "1"),
            supervise_identity_recycle_probe: std::env::var(
                "NFS_KLLDAP_SUPERVISE_IDENTITY_RECYCLE_PROBE",
            )
            .is_ok_and(|v| v == "1"),
            host_nfs_mode: nfs_klldap_config::resolve_host_nfs_mode(config_path),
            supervisor_tick_ms: std::env::var("NFS_KLLDAP_SUPERVISOR_TICK_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2000),
            supervisor_max_ticks: std::env::var("NFS_KLLDAP_SUPERVISOR_MAX_TICKS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(12),
            log_rotate_max_bytes: std::env::var("NFS_KLLDAP_LOG_ROTATE_MAX_MB")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(64)
                * 1024
                * 1024,
        }
    }
}