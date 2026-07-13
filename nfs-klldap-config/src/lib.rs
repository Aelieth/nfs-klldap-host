#![deny(unsafe_code, dead_code)]

//! Validates TOML and generates sssd.conf, krb5.conf, and export fragments.

mod config;
mod constants;
mod error;
mod exports_fingerprint;
mod ganesha_liveness;
pub mod ganesha_readiness;
mod recycle_plan;

mod fs_probe;
pub mod ganesha_log_contract;
mod posix_only_policy;
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
    derive_share_pseudo, resolve_cache_profile, ShareFieldWarning, CACHE_PROFILES,
    GaneshaSection, GenerationPaths, HostSection, KerberosSection, ManagementSection,
    NfsKlldapConfig, PosixAttributeMapping, ServerSection, Share, SssdSection, StorageSection,
    WebuiSection, SHARE_KNOWN_KEYS,
};
pub use network::{
    container_primary_ipv4, extract_server_addr_from_ganesha_line, is_docker_bridge_ipv4,
};
pub use validate::detect_share_unknown_keys;

pub mod ignored_attributes;
pub use error::ConfigError;
pub use exports_fingerprint::{
    fingerprint_exports_dir, fingerprint_identity_artifacts, fingerprint_shares, FNV1A_SEED,
};
pub use ganesha_liveness::{
    discover_ganesha_daemon_pid, ganesha_is_live, pgrep_live_pids, pgrep_pids, process_is_live,
    reconcile_ganesha_pid,
};
pub use recycle_plan::{
    plan_from_changes, ganesha_sighup_failed, GaneshaAction, ServiceRecyclePlan,
};
pub use signals::{
    install_signal_handlers, reap_one_child, request_sighup, shutdown_requested,
    signal_process_hup, signal_process_kill, signal_process_term, signal_supervisor_hup,
    take_sighup_requested,
};
pub use constants::PROC_COMM_NAME_MAX;

pub use fs_probe::{
    acl_probe_verdict, compute_effective_flags, compute_effective_flags_probed,
    compute_read_access_policy_emit, normalize_path, probe_from_mountinfo,
    probe_from_mountinfo_with_root, probe_fs_capabilities, probe_fs_capabilities_with_root,
    serve_path_posix_acl_supported, serve_path_posix_acl_write_probe, verdict_from_caps,
    AclProbeVerdict, EffectiveShareFlags, ReadAccessPolicyEmit, FsCapabilities,
};
pub use ganesha_log_contract::{
    acl_notsupp_diagnosis_signatures, acl_notsupp_fixture_path, classify_notsupp_failure_path,
    ganesha_96_has_mode_only_access_knob, load_acl_notsupp_fixture,
    log_shows_acl_path_getattr_notsupp, log_shows_acl_path_op_access_notsupp,
    log_shows_identity_failure, log_shows_identity_path_notsupp, log_shows_posix_ok_getattr,
    validate_acl_notsupp_fixture, NotsuppFailurePath, GANESHA_96_NO_MODE_ONLY_ACCESS_KNOB,
};
pub use posix_only_policy::PosixOnlyPolicy;
pub use ganesha_identity_pipeline::{
    identity_principals_for_check, probe_client_host, probe_user_principal,
    run_identity_pipeline, warm_principals_for_startup,
    warm_principals_nss_ready, IdentityPrincipals,
};
pub use ganesha_nss_contract::{
    evaluate_nss_contract, evaluate_short_name_getgrouplist_contract, ld_preload_for_ganesha,
    nss_lookup_names, probe_nss_groups, probe_nss_groups_exact, probe_nss_passwd,
    probe_nss_passwd_exact, probe_nss_passwd_from_file_exact, short_pw_name_for_principal,
    GaneshaNssEnv,
};
pub use ganesha_readiness::{
    build_ganesha_envp, check_ganesha_readiness, check_synthetic_krb_log_clean,
    exercise_ganesha_uid2grp, filter_proc_environ_keys, ganesha_log_has_getgrouplist_warn,
    ganesha_log_has_managed_gids_failure,
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
    any_share_manage_gids_enabled, collect_fs_warnings, limited_fs_warning,
    limited_fs_warning_settings_ui, limited_fs_warnings_only, share_fs_acl_limited,
    share_fs_acl_limited_with_mountinfo, share_fs_warning_message,
    share_fs_warning_message_with_mountinfo, FsShareWarning,
};
pub use hook::{effective_post_generate_hook, run_post_generate_hooks};
pub use generate::generate_all;

mod idhelper_check;
pub use idhelper_check::{
    check_idhelper_sample_resolutions, emit_idhelper_check_log, idhelper_socket_path,
};

pub use hostname::{
    format_nfs_principal_list, get_consistent_hostname, host_nfs_active, host_nfs_from_env,
    looks_like_docker_default_hostname, nfs_keytab_host_matches, nfs_keytab_host_variants,
    parse_host_nfs_env_value, resolve_host_nfs_mode, runtime_hostname, runtime_realm,
    runtime_realm_from_disk, runtime_server_variants, runtime_server_variants_from_disk,
    webui_tls_disabled,
    ConsistentHostname, HostnameInconsistency, HostnameObservation, HostnameSource,
};
pub use persist::{is_persistent_config, load_host_paths_only};
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
#[doc(hidden)]
pub use startup::lock_setup_marker_for_tests;
pub use template::{generate_default_template, write_default_config_if_missing};
pub use nfs_klldap_identity::{derive_realm_from_uri, extract_host_from_uri, host_is_ip};
pub use nfs_klldap_identity::{
    get_keytab_info, parse_klist_nfs_hosts, parse_klist_nfs_principals, read_keytab_nfs_principals,
    KeytabInfo,
};

// Structured LDAP resolution (IdLdapResolver) shared with Nfs-klldap-identity.
pub mod idmap;
pub use idmap::{
    classify_principal, escape_ldap_filter, extract_first_attr_value, from_sssd_section,
    machine_short_name, normalize_principal, parse_getent_group, parse_getent_passwd,
    parse_group_row, parse_passwd_row,
    posix_mapping_from_sssd, principal_local_part, sssd_resolver_inputs,
    IdLdapResolver, IdMapSnapshot, PosixGroupEntry, PosixUserEntry,
};

// Centralized constants (Ganesha 9.6 trixie + hybrid Principal + POSIX.
pub use constants::{
    DEFAULT_GROUP_GID_ATTR, DEFAULT_GROUP_NAME_ATTR, DEFAULT_GROUP_OBJECT_CLASS,
    DEFAULT_USER_FULLNAME_ATTR, DEFAULT_USER_GID_ATTR, DEFAULT_USER_HOME_ATTR,
    DEFAULT_USER_NAME_ATTR, DEFAULT_USER_OBJECT_CLASS, DEFAULT_USER_PRINCIPAL_ATTR,
    DEFAULT_USER_SHELL_ATTR, DEFAULT_USER_UID_ATTR, FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID,
    GANESHA_ALLOWED_SECTYPES, GANESHA_ALLOWED_SQUASH, GANESHA_DEFAULT_SECTYPE,
    GANESHA_DEFAULT_SQUASH, GANESHA_PROTOCOLS, GANESHA_PWNAM_IMPL, GANESHA_ROOT_KRB_PRINCIPALS,
    IDMAPD_GSS_METHODS, IDMAPD_NOBODY_GROUP, IDMAPD_NOBODY_USER,
    IDMAPD_TRANSLATION_METHOD, LOG_NOISE_TOKENS, MACHINE_GID, MACHINE_PRINCIPAL_PREFIXES, MACHINE_UID,
    DEFAULT_GROUP_MEMBER_ATTR_KLLDAP, DEFAULT_GROUP_MEMBER_ATTR_LEGACY,
};

// Single TLS policy source of truth lives in nfs-klldap-identity (cacert-aware).
pub use nfs_klldap_identity::{ldap_conn_settings, ldap_tls_policy};

mod signals;

/// Serializes env-mutating tests across modules. Needed because cargo test --worksp
#[cfg(test)]
pub(crate) static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests;
