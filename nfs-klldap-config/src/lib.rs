#![deny(unsafe_code, dead_code)]

//! Validate/derive nfs-klldap.conf; generate sssd/krb5/idmapd/nfs/ganesha artifacts.

mod config;
mod constants;
mod error;
mod exports_fingerprint;
mod ganesha_liveness;
pub mod ganesha_readiness;
mod recycle_plan;

mod fs_probe;
pub mod ganesha_log_contract;
pub mod proc_run;
mod fs_warnings;
mod ganesha_identity_pipeline;
mod ganesha_nss_contract;
mod generate;
mod hook;
mod hostname;
mod network;
mod persist;
mod startup;
mod template;
mod validate;

pub use config::{
    derive_share_pseudo, GenerationPaths, NfsKlldapConfig, PosixAttributeMapping, Share,
    ShareFieldWarning, SssdSection, StorageSection,
};
pub use network::{
    command_with_timeout, container_primary_ipv4, extract_server_addr_from_ganesha_line,
    is_docker_bridge_ipv4,
};
pub mod ignored_attributes;
pub use error::ConfigError;
pub use exports_fingerprint::{
    fingerprint_exports_dir, fingerprint_identity_artifacts, fingerprint_shares, FNV1A_SEED,
};
pub use ganesha_liveness::{
    discover_ganesha_daemon_pid, pgrep_running,
    pkill_binary, pkill_process, process_is_live,
};
pub use recycle_plan::{
    plan_from_changes, plan_full_recycle, ganesha_sighup_failed, GaneshaAction,
    ServiceRecyclePlan, WebuiAction,
};
pub use signals::{
    install_signal_handlers, reap_children, request_full_recycle, request_sighup,
    shutdown_requested, signal_process_hup, signal_process_kill, signal_process_term,
    signal_supervisor_full_recycle, signal_supervisor_hup, take_full_recycle_requested,
    take_sighup_requested,
};
pub use fs_probe::{
    acl_probe_verdict, compute_effective_flags, compute_effective_flags_probed,
    compute_read_access_policy_emit, normalize_path, probe_from_mountinfo,
    probe_fs_capabilities, verdict_from_caps,
    AclProbeVerdict, EffectiveShareFlags, MountinfoSnapshot,
    ReadAccessPolicyEmit, FsCapabilities,
};
pub use ganesha_log_contract::{
    classify_notsupp_failure_path, ganesha_96_has_mode_only_access_knob, NotsuppFailurePath,
};
pub use ganesha_identity_pipeline::{
    identity_principals_for_check, probe_client_host, probe_user_principal,
    run_identity_pipeline, warm_principals_for_startup,
    warm_principals_nss_ready,
};
pub use ganesha_nss_contract::{
    evaluate_nss_contract, evaluate_short_name_getgrouplist_contract, find_nss_wrapper_so,
    ld_preload_for_ganesha,
    probe_nss_groups_exact, probe_nss_passwd_exact, probe_nss_passwd_from_file_exact,
    GaneshaNssEnv,
};
pub use ganesha_readiness::{
    build_ganesha_envp, check_ganesha_readiness, filter_proc_environ_keys,
    idhelper_socket_request, proc_environ_map,
    proc_pid_environ, probe_ganesha_process_groups, probe_id_g_under_env, probe_socket_grps,
    probe_socket_grouplist, resolve_nss_sss_so, signal_ganesha_reload_idmap,
    GaneshaReadinessReport, GaneshaSpawnEnv,
};

/// True when LDAP bind DN and password are configured in nfs-klldap.conf.
pub fn ldap_bind_configured(cfg: &NfsKlldapConfig) -> bool {
    !cfg.sssd.ldap_default_bind_dn.trim().is_empty()
        && !cfg.sssd.ldap_default_authtok.trim().is_empty()
}
pub use fs_warnings::{
    any_share_manage_gids_enabled, collect_fs_warnings, limited_fs_warnings_only,
    share_divergent_submount_warning_snapshot, share_fs_acl_limited_with_mountinfo,
    share_fs_warning_message_snapshot,
    share_fs_warning_message_with_mountinfo, FsShareWarning, PosixOnlyPolicy,
};
pub use hook::run_post_generate_hooks;
pub use generate::generate_all;

mod idhelper_check;
pub use idhelper_check::{
    check_idhelper_sample_resolutions, emit_idhelper_check_log, idhelper_socket_path,
};

pub use hostname::{
    format_nfs_principal_list, get_consistent_hostname, host_nfs_active, host_nfs_from_env,
    looks_like_docker_default_hostname, nfs_keytab_host_matches, nfs_keytab_host_variants,
    resolve_host_nfs_mode, runtime_hostname, runtime_realm,
    runtime_realm_from_disk, runtime_server_variants_from_disk,
    webui_tls_disabled,
};
pub use persist::{atomic_write, is_persistent_config};
pub use startup::{
    attempt_realm_from_config, check_ldap_bind, check_ldap_reachability, check_persistent_writable,
    compute_startup_step, compute_wizard_step, config_has_required_startup_fields,
    default_config_path,
    effective_startup_step, format_bind_probe, format_reachability_probe, format_volume_probe,
    is_preconfigured_deployment, is_setup_wizard_complete, resolve_keytab_path,
    is_step_complete, mark_setup_wizard_complete, should_bring_up_services,
    supervisor_loop_tick, startup_step_hint, SupervisorLoopAction,
    setup_wizard_marker_path,
    webui_setup_url, LdapReachability, StartupStep, DEFAULT_KEYTAB_PATH, SETUP_WIZARD_MARKER,
};
pub use template::{generate_default_template, write_default_config_if_missing};
pub use nfs_klldap_identity::{derive_realm_from_uri, extract_host_from_uri, host_is_ip};
pub use nfs_klldap_identity::{get_keytab_info, parse_klist_nfs_hosts, KeytabInfo};

// Structured LDAP resolution (IdLdapResolver) shared with Nfs-klldap-identity.
pub mod idmap;
pub use idmap::{
    classify_principal, from_sssd_section,
    machine_short_name, normalize_principal, parse_getent_passwd,
    parse_group_row, parse_passwd_row,
    principal_local_part, sssd_resolver_inputs,
    IdLdapResolver, IdMapSnapshot, PosixGroupEntry, PosixUserEntry,
};

// Public Ganesha / idmapd / identity constants used by generate and callers.
pub use constants::{
    FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID,
    GANESHA_ALLOWED_SECTYPES, GANESHA_ALLOWED_SQUASH, GANESHA_DEFAULT_SECTYPE,
    GANESHA_DEFAULT_SQUASH, GANESHA_PROTOCOLS, GANESHA_PWNAM_IMPL, GANESHA_ROOT_KRB_PRINCIPALS,
    IDMAPD_GSS_METHODS, IDMAPD_NOBODY_GROUP, IDMAPD_NOBODY_USER,
    IDMAPD_TRANSLATION_METHOD, LOG_NOISE_TOKENS, MACHINE_GID, MACHINE_PRINCIPAL_PREFIXES, MACHINE_UID,
};

// Single TLS policy source of truth lives in nfs-klldap-identity (cacert-aware).
pub use nfs_klldap_identity::{ldap_conn_settings, ldap_tls_policy};

mod signals;

/// Serializes env-mutating tests across modules. Needed because cargo test --worksp
#[cfg(test)]
pub(crate) static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests;
