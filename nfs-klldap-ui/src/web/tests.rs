use super::*;
use axum::body::Body;
use axum::http::{header::COOKIE, Request, StatusCode};
use tower::ServiceExt;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;


fn add_session_cookie(mut req: Request<Body>, token: &str) -> Request<Body> {
    let cookie = format!("session={}", token);
    req.headers_mut().insert(COOKIE, cookie.parse().unwrap());
    req
}

fn test_acl_caps() -> Arc<acl_capability::AclCapabilityCache> {
    Arc::new(acl_capability::AclCapabilityCache::new_from_env())
}

fn test_acl_alert() -> Arc<StdMutex<Option<String>>> {
    Arc::new(StdMutex::new(None))
}

/// The one AppState literal for router tests: scenario config path, setup
/// marker, and mountinfo fixture vary; every other field is fixed.
fn test_app_state(
    cp: &std::path::Path,
    setup_marker: PathBuf,
    mountinfo: Option<PathBuf>,
) -> AppState {
    let cfg_val = nfs_klldap_config::NfsKlldapConfig::load(cp).expect("load test config");
    let cfg = Arc::new(RwLock::new(cfg_val.clone()));
    let fs = Arc::new(RwLock::new(FsManager::new(cfg_val)));
    AppState {
        fs,
        lldap: Arc::new(tokio::sync::RwLock::new(Arc::new(crate::create_test_lldap()))),
        config: cfg,
        auth: Arc::new(AuthManager::new(cp, None, None)),
        config_path: cp.to_path_buf(),
        keytab_hostname: "h".into(),
        keytab_realm: "R".into(),
        keytab_alert: Arc::new(StdMutex::new(None)),
        apply_progress: Arc::new(Mutex::new(None)),
        restart_requested: Arc::new(Mutex::new(None)),
        direct_tls: true,
        webui_bind: "0.0.0.0:9630".into(),
        setup_marker_override: Some(setup_marker),
        setup_test: Arc::new(StdMutex::new(setup::SetupTestState::default())),
        host_nfs_mode: false,
        fs_probe_mountinfo_path: mountinfo,
        acl_caps: test_acl_caps(),
        acl_alert: test_acl_alert(),
    }
}

/// Writes the standard "ok" setup marker and returns its path.
fn write_setup_marker(tmp: &tempfile::TempDir, name: &str) -> PathBuf {
    let sm = tmp.path().join(name);
    std::fs::write(&sm, "ok\n").ok();
    sm
}

/// Mountinfo fixture marking `root` as an ACL-capable ext4 mount: tests stay
/// hermetic from the host mount table while the real write probe still runs
/// against the temp directory.
fn write_capable_mountinfo(
    tmp: &tempfile::TempDir,
    name: &str,
    root: &std::path::Path,
) -> PathBuf {
    let mi = tmp.path().join(name);
    std::fs::write(
        &mi,
        format!(
            "36 35 0:59 / {} rw,relatime - ext4 /dev/sda1 rw\n",
            root.display()
        ),
    )
    .unwrap();
    mi
}

fn make_test_state_with_limited_fs_mountinfo() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let mp = tmp.path().join("m");
    std::fs::write(&mp, "24 1 8:1 / /data rw - ext4 /dev/sda1 rw,noacl\n").ok();
    let cp = tmp.path().join("c");
    let sm = write_setup_marker(&tmp, ".s");
    let min = r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "/"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "data"
host_path = "/foo/data"
container_path = "/data"
"#;
    std::fs::write(&cp, min).ok();
    let st = test_app_state(&cp, sm, Some(mp));
    (st, tmp)
}

// Settings + Ganesha roundtrip (save-shares with root_squash/enable_acl/ganesha override, generate_all). ACL mutation covered by dedicated test below.
#[tokio::test]
async fn settings_ganesha_roundtrip_cases() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    // Exercise acl_limited and fs warning badge paths with limited mountinfo fixture (noacl) via shipped config funcs used by renders.
    let mp_path = state.fs_probe_mountinfo_path.as_ref().expect("mp set in helper").clone();
    {
        let cfg = state.config.read().expect("config lock");
        let s0 = &cfg.shares[0];
        let is_limited =
            nfs_klldap_config::share_fs_acl_limited_with_mountinfo(&cfg, s0, Some(&mp_path));
        assert!(
            is_limited,
            "noacl mountinfo fixture must make acl_limited true via shipped func"
        );
        let wmsg =
            nfs_klldap_config::share_fs_warning_message_with_mountinfo(&cfg, s0, Some(&mp_path));
        assert!(
            wmsg.is_some() && wmsg.unwrap().contains("limited"),
            "limited mountinfo must yield fs warning via shipped func"
        );
    }
    let cp = state.config_path.clone();
    let auth = state.auth.clone();
    let token = auth.create_privileged_session("testadmin");
    let app = router(state);

    // Drive shipped settings_page render with limited mountinfo to exercise fs_warning badge in HTML (covers the pruned settings_and_index_render_fs_warning... case)
    let gr = Request::builder().uri("/settings").body(Body::empty()).unwrap();
    let gr = add_session_cookie(gr, &token);
    let grs = app.clone().oneshot(gr).await.unwrap();
    let gbody = axum::body::to_bytes(grs.into_body(), 1024*1024).await.unwrap();
    let ghtml = String::from_utf8_lossy(&gbody);
    assert!(ghtml.contains("alert alert-warning") && (ghtml.contains("limited") || ghtml.contains("fs_warning") || ghtml.contains("NOACL")), "settings render must include limited fs warning badge via shipped template + mountinfo probe");
    // enable_acl unset (auto) must show Non-ACL status-dot — same as Share Permissions / Disable_ACL export.
    // (Legend also has bare share-dot.acl / .noacl keys; assert titled card dots only.)
    assert!(
        ghtml.contains(r#"share-dot noacl" title="Non-ACL limited""#)
            || ghtml.contains("share-dot noacl") && ghtml.contains(r#"title="Non-ACL limited""#),
        "settings share with enable_acl=auto must render Non-ACL limited status-dot"
    );
    assert!(
        !ghtml.contains(r#"share-dot acl" title="ACL supported""#),
        "settings share with enable_acl=auto must not render an ACL-supported status-dot"
    );
    assert!(
        ghtml.contains("data-acl-chip") && ghtml.contains("acl auto (off)"),
        "auto share on a noacl fs must show the probed 'auto (off)' chip"
    );
    assert!(
        ghtml.contains(r#"data-acl-probed="incapable""#),
        "noacl mount must expose data-acl-probed=incapable for the status JS"
    );
    assert!(
        ghtml.contains("auto (detect)") && !ghtml.contains("auto (NOACL)"),
        "the enable_acl dropdown must use the new 'auto (detect)' label"
    );

    let body_noacl = "share_name_0=data&share_host_0=%2Fmedia%2Fdata&share_pseudo_0=&share_rw_0=true&share_cache_profile_0=Default&share_enable_acl_0=false&share_manage_gids_0=false&share_read_access_policy_0=pre&share_container_path_0=%2Fexport%2Fstaging%2Fdata&share_root_squash_0=on";
    let req = Request::builder().method("POST").uri("/settings/save-shares").header("content-type","application/x-www-form-urlencoded").body(Body::from(body_noacl)).unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let written = std::fs::read_to_string(&cp).unwrap();
    assert!(written.contains("enable_acl = false"));
    assert!(written.contains("container_path = \"/export/staging/data\""));
    // root_squash from checkbox presence now roundtrips via collect
    assert!(written.contains("squash = \"root_squash\"") || written.contains("squash = 'root_squash'") || written.contains("root_squash"));

    let body_acl = "share_name_0=acldata&share_host_0=%2Fmedia%2Facldata&share_pseudo_0=&share_rw_0=true&share_cache_profile_0=Default&share_enable_acl_0=true&share_manage_gids_0=true&share_read_access_policy_0=auto&share_manage_gids_expiration_0=900&share_container_path_0=%2Fexport%2Facldata";
    let req2 = Request::builder().method("POST").uri("/settings/save-shares").header("content-type","application/x-www-form-urlencoded").body(Body::from(body_acl)).unwrap();
    let req2 = add_session_cookie(req2, &token);
    let _ = app.clone().oneshot(req2).await.unwrap();
    let w2 = std::fs::read_to_string(&cp).unwrap();
    assert!(w2.contains("enable_acl = true"));
    assert!(w2.contains("manage_gids_expiration = 900"));

    // generate (after body with MGE)
    let gen_dir = std::env::temp_dir().join("grok-verif-gen");
    let _ = std::fs::remove_dir_all(&gen_dir);
    std::fs::create_dir_all(&gen_dir).ok();
    let exd = gen_dir.join("exports.d"); std::fs::create_dir_all(&exd).ok();
    let cfg_for_gen = nfs_klldap_config::NfsKlldapConfig::load(&cp).expect("load");
    let paths = nfs_klldap_config::GenerationPaths { sssd_conf: gen_dir.join("s.conf"), krb5_conf: gen_dir.join("k.conf"), ganesha_conf: gen_dir.join("g.conf"), exports_dir: exd.clone(), idmap_conf: gen_dir.join("i.conf"), nfs_conf: gen_dir.join("n.conf") };
    nfs_klldap_config::generate_all(&cfg_for_gen, &paths).ok();
    let frag = std::fs::read_dir(&exd).ok().and_then(|it| it.filter_map(|e| e.ok()).find(|e| e.path().extension().is_some_and(|x| x == "conf")).and_then(|e| std::fs::read_to_string(e.path()).ok())).unwrap_or_default();
    // The group-trust window is global: the deprecated share value seeds
    // DS Idmapped_*_Time_Validity in the main conf (9.13 routing — the
    // old core param is no longer emitted anywhere) and must never land
    // in the EXPORT fragment.
    assert!(!frag.contains("Manage_Gids_Expiration"), "MGE must not be in fragment: {frag}");
    let gmain = std::fs::read_to_string(gen_dir.join("g.conf")).unwrap_or_default();
    assert!(gmain.contains("Idmapped_Group_Time_Validity = 900;"), "share MGE seeds global idmapped validity: {gmain}");
    assert!(!gmain.contains("Manage_Gids_Expiration"), "old core param must not be emitted: {gmain}");

    // drive shipped structured save for default_security (POST exercises the /settings/save handler, Form binding for ganesha_default_security/override, and apply path)
    let body_defsec = "ganesha_default_security=nfs&override_ganesha_default_security=on";
    let reqsec = Request::builder().method("POST").uri("/settings/save").header("content-type","application/x-www-form-urlencoded").body(Body::from(body_defsec)).unwrap();
    let reqsec = add_session_cookie(reqsec, &token);
    let rsec_save = app.clone().oneshot(reqsec).await.unwrap();
    // The browser submits checkboxes as "on"; this must bind and save (the
    // old typed Option<bool> form silently 422ed here).
    assert_eq!(
        rsec_save.status(),
        StatusCode::OK,
        "structured default_security save must succeed"
    );

    // Ensure the value is on disk for render (drive raw save path too); then GET to exercise default_security + override flag in rendered form
    let cur = std::fs::read_to_string(&cp).unwrap_or_default();
    let with_g = if cur.contains("[ganesha]") { cur } else { format!("{}\n[ganesha]\ndefault_security = \"nfs\"\n", cur) };
    let rawb = format!("raw_content={}", urlencoding::encode(&with_g));
    let rraw = Request::builder().method("POST").uri("/settings/save-raw").header("content-type","application/x-www-form-urlencoded").body(Body::from(rawb)).unwrap();
    let rraw = add_session_cookie(rraw, &token);
    let _ = app.clone().oneshot(rraw).await.unwrap();
    let gsec = Request::builder().uri("/settings").body(Body::empty()).unwrap();
    let gsec = add_session_cookie(gsec, &token);
    let rsec = app.clone().oneshot(gsec).await.unwrap();
    let bsec = axum::body::to_bytes(rsec.into_body(), 1024*1024).await.unwrap();
    let hsec = String::from_utf8_lossy(&bsec);
    assert!(hsec.contains("ganesha_default_security") && (hsec.contains("nfs") || hsec.contains("value=\"nfs\"") || hsec.contains("selected")), "settings render must show the overridden default_security value");

    let body_off = "share_name_0=data&share_host_0=%2Fmedia%2Fdata&share_pseudo_0=&share_rw_0=true&share_cache_profile_0=Default&share_enable_acl_0=false&share_manage_gids_0=true&share_read_access_policy_0=pre&share_manage_gids_expiration_0=900&share_container_path_0=%2Fexport%2Fdata";
    let reqoff = Request::builder().method("POST").uri("/settings/save-shares").header("content-type","application/x-www-form-urlencoded").body(Body::from(body_off)).unwrap();
    let reqoff = add_session_cookie(reqoff, &token);
    let _ = app.clone().oneshot(reqoff).await.unwrap();
    let woff = std::fs::read_to_string(&cp).unwrap();
    assert!(woff.contains("container_path = \"/export/data\""));

    let grd = Request::builder().uri("/settings").body(Body::empty()).unwrap();
    let grd = add_session_cookie(grd, &token);
    let grds = app.clone().oneshot(grd).await.unwrap();
    let gbd = axum::body::to_bytes(grds.into_body(), 1024*1024).await.unwrap();
    let ghd = String::from_utf8_lossy(&gbd);
    assert!(ghd.contains("share_container_path_0") && ghd.contains("/export/data"), "settings render must show container_path input");
}

// Settings must reflect the LIVE probe: an auto share whose serve path
// proves ACL-capable renders "auto (on)" + an ACL status dot, matching what
// generate emits (previously it always showed NOACL via the static path).
#[tokio::test]
async fn settings_auto_share_on_capable_fs_renders_acl_on() {
    let tmp = tempfile::TempDir::new().unwrap();
    // aclroot exists and is on a real ACL-capable fs (tmpfs/ext4), the
    // scaffold's mountinfo marks it capable, and the share is auto (unset).
    let (_fs, _prog, token, app) = acl_test_scaffold(&tmp).await;
    let req = Request::builder().uri("/settings").body(Body::empty()).unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains(r#"data-acl-probed="capable""#),
        "capable serve path must expose data-acl-probed=capable"
    );
    assert!(
        html.contains("acl auto (on)"),
        "auto + proven-capable must render the 'auto (on)' chip"
    );
    assert!(
        html.contains(r#"title="ACL supported""#),
        "auto + capable must render the ACL-supported status dot (title attr)"
    );
}

// The NFS-client status panel must surface bind count + pool state so the
// operator can watch LDAP-login pressure while tuning.
#[tokio::test]
async fn lldap_status_reports_bind_count_and_pool_state() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let token = state.auth.create_privileged_session("statuser");
    let app = router(state);
    let html = get_html(&app, &token, "/settings/lldap-status").await;
    assert!(html.contains("LDAP binds since start"), "status line must show bind count");
    assert!(html.contains("pool cold"), "offline client must report a cold pool");
}

// The restart latch must release once the supervisor completes the recycle
// (marker touched), so a follow-up save can schedule again — a no-op HUP
// must not wedge the latch permanently.
#[tokio::test]
async fn recycle_latch_releases_after_marker_and_reschedules() {
    use std::time::Duration;
    let (state, tmp) = make_test_state_with_limited_fs_mountinfo();
    let marker = tmp.path().join("recycle-marker");
    std::env::set_var("NFS_KLLDAP_SUPERVISOR_PID", "0"); // skip a real HUP
    std::env::set_var("NFS_KLLDAP_RECYCLE_DELAY_MS", "1");
    std::env::set_var("NFS_KLLDAP_RECYCLE_MARKER", &marker);

    // First schedule latches; an immediate second is refused.
    assert!(
        super::settings::try_schedule_service_recycle(
            &state,
            super::RecycleKind::SharesApply,
            "t1"
        )
        .await
    );
    assert!(
        !super::settings::try_schedule_service_recycle(
            &state,
            super::RecycleKind::SharesApply,
            "t2"
        )
        .await,
        "a second recycle must be refused while one is in flight"
    );

    // Simulate the supervisor finishing the recycle and wait for the latch
    // to clear. Re-touch each poll so a parallel test that shares the global
    // marker env cannot remove it out from under us.
    let released = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            std::fs::write(&marker, "recycled\n").ok();
            if state.restart_requested.lock().await.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(released.is_ok(), "latch must clear after the marker is touched");
    assert!(
        super::settings::try_schedule_service_recycle(
            &state,
            super::RecycleKind::SharesApply,
            "t3"
        )
        .await,
        "a later recycle must schedule once the latch cleared"
    );

    std::env::remove_var("NFS_KLLDAP_SUPERVISOR_PID");
    std::env::remove_var("NFS_KLLDAP_RECYCLE_DELAY_MS");
    std::env::remove_var("NFS_KLLDAP_RECYCLE_MARKER");
}

// A "Restart and apply" arriving while a graceful shares apply is in flight
// must never be silently dropped: the latch upgrades to FullRestart and the
// call reports success; anything else arriving while latched is deduped.
#[tokio::test]
async fn full_restart_escalates_over_inflight_shares_apply() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    std::env::set_var("NFS_KLLDAP_SUPERVISOR_PID", "0"); // skip a real signal
    std::env::set_var("NFS_KLLDAP_RECYCLE_DELAY_MS", "1");

    assert!(
        super::settings::try_schedule_service_recycle(
            &state,
            super::RecycleKind::SharesApply,
            "esc1"
        )
        .await
    );
    assert!(
        super::settings::try_schedule_service_recycle(
            &state,
            super::RecycleKind::FullRestart,
            "esc2"
        )
        .await,
        "a full restart must escalate over an in-flight shares apply"
    );
    assert_eq!(
        *state.restart_requested.lock().await,
        Some(super::RecycleKind::FullRestart),
        "the latch must upgrade to the full restart"
    );
    assert!(
        !super::settings::try_schedule_service_recycle(
            &state,
            super::RecycleKind::FullRestart,
            "esc3"
        )
        .await,
        "a second full restart must dedupe while one is pending"
    );
    assert!(
        !super::settings::try_schedule_service_recycle(
            &state,
            super::RecycleKind::SharesApply,
            "esc4"
        )
        .await,
        "a shares apply must dedupe under a pending full restart"
    );

    std::env::remove_var("NFS_KLLDAP_SUPERVISOR_PID");
    std::env::remove_var("NFS_KLLDAP_RECYCLE_DELAY_MS");
}

// Deterministic core of the supervisor-driven SIGHUP reload: a share appended
// to the conf becomes visible in the in-memory config without any restart.
#[test]
fn reload_config_and_fs_picks_up_share_edits() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (state, _mi) = acl_watch_state(&tmp, "", true);
    assert_eq!(state.config.read().unwrap().shares.len(), 1);

    let extra = tmp.path().join("serve2");
    std::fs::create_dir_all(&extra).unwrap();
    let mut conf = std::fs::read_to_string(&state.config_path).unwrap();
    conf.push_str(&format!(
        "\n[[shares]]\nname = \"s2\"\nhost_path = \"/s2\"\ncontainer_path = \"{}\"\n",
        extra.display()
    ));
    std::fs::write(&state.config_path, conf).unwrap();

    state
        .reload_config_and_fs()
        .expect("in-process reload must succeed");
    let cfg = state.config.read().unwrap();
    assert_eq!(cfg.shares.len(), 2, "reload must surface the appended share");
    assert_eq!(cfg.shares[1].name, "s2");
}

fn write_watch_mountinfo(path: &std::path::Path, mount: &std::path::Path, capable: bool) {
    let fstype = if capable { "btrfs" } else { "vfat" };
    std::fs::write(
        path,
        format!("36 35 0:59 / {} rw,relatime - {} /dev/sda1 rw\n", mount.display(), fstype),
    )
    .unwrap();
}

// Single-share state with a controllable mountinfo fixture + real serve dir,
// so the ACL watcher's verdict can be flipped deterministically in tests.
fn acl_watch_state(
    tmp: &tempfile::TempDir,
    enable_acl_line: &str,
    capable: bool,
) -> (AppState, std::path::PathBuf) {
    let serve = tmp.path().join("serve");
    std::fs::create_dir_all(&serve).unwrap();
    let mi = tmp.path().join("mi");
    write_watch_mountinfo(&mi, tmp.path(), capable);
    let cp = tmp.path().join("c");
    let cfg_txt = format!(
        r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{root}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "s1"
host_path = "/s1"
container_path = "{serve}"
{acl}
"#,
        root = tmp.path().display(),
        serve = serve.display(),
        acl = enable_acl_line
    );
    std::fs::write(&cp, cfg_txt).unwrap();
    let sm = write_setup_marker(tmp, ".s");
    let st = test_app_state(&cp, sm, Some(mi.clone()));
    (st, mi)
}

// An auto share whose mount loses ACL support (stable over two ticks) must
// schedule the service recycle so generate can flip it to NOACL.
#[tokio::test]
async fn acl_watch_auto_flip_schedules_recycle() {
    std::env::set_var("NFS_KLLDAP_SUPERVISOR_PID", "0");
    std::env::set_var("NFS_KLLDAP_RECYCLE_DELAY_MS", "1");
    let tmp = tempfile::TempDir::new().unwrap();
    let (state, mi) = acl_watch_state(&tmp, "", true);
    let mut tr = super::acl_watch::FlipTracker::default();
    let o0 = super::acl_watch::acl_reprobe_tick(&state, &mut tr).await;
    assert!(!o0.hup_scheduled, "capable baseline must not fire");
    write_watch_mountinfo(&mi, tmp.path(), false);
    let o1 = super::acl_watch::acl_reprobe_tick(&state, &mut tr).await;
    assert!(!o1.hup_scheduled, "one divergent tick must not fire (hysteresis)");
    let o2 = super::acl_watch::acl_reprobe_tick(&state, &mut tr).await;
    assert!(o2.hup_scheduled, "a stable flip over two ticks must schedule a recycle");
    assert_eq!(
        *state.restart_requested.lock().await,
        Some(super::RecycleKind::SharesApply),
        "recycle latch must hold the graceful apply kind"
    );
    std::env::remove_var("NFS_KLLDAP_SUPERVISOR_PID");
    std::env::remove_var("NFS_KLLDAP_RECYCLE_DELAY_MS");
}

// An explicit enable_acl=true share that loses ACL support must NEVER
// recycle (generate would refuse all exports); it raises a banner that
// clears once capability returns.
#[tokio::test]
async fn acl_watch_explicit_on_incapable_raises_and_clears_banner() {
    std::env::set_var("NFS_KLLDAP_SUPERVISOR_PID", "0");
    std::env::set_var("NFS_KLLDAP_RECYCLE_DELAY_MS", "1");
    let tmp = tempfile::TempDir::new().unwrap();
    let (state, mi) = acl_watch_state(&tmp, "enable_acl = true", false);
    let mut tr = super::acl_watch::FlipTracker::default();
    let o1 = super::acl_watch::acl_reprobe_tick(&state, &mut tr).await;
    assert!(o1.alert.is_none(), "one incapable tick is below the streak threshold");
    let o2 = super::acl_watch::acl_reprobe_tick(&state, &mut tr).await;
    assert!(!o2.hup_scheduled, "explicit-on must never auto-recycle");
    let msg = o2.alert.expect("two incapable ticks must raise the banner");
    assert!(msg.contains("refuse to generate"), "banner explains the reload refusal: {msg}");
    assert!(state.acl_alert.lock().unwrap().is_some());
    // Heal: capability returns.
    write_watch_mountinfo(&mi, tmp.path(), true);
    let o3 = super::acl_watch::acl_reprobe_tick(&state, &mut tr).await;
    assert!(o3.alert.is_none(), "banner clears once capability returns");
    assert!(state.acl_alert.lock().unwrap().is_none());
    std::env::remove_var("NFS_KLLDAP_SUPERVISOR_PID");
    std::env::remove_var("NFS_KLLDAP_RECYCLE_DELAY_MS");
}

// The acl_alert banner must render on both Share Permissions and Settings.
#[tokio::test]
async fn acl_alert_banner_renders_on_index_and_settings() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    *state.acl_alert.lock().unwrap() = Some("ACL banner probe text".into());
    let token = state.auth.create_privileged_session("acltester");
    let app = router(state);
    for uri in ["/", "/settings"] {
        let html = get_html(&app, &token, uri).await;
        assert!(
            html.contains("ACL banner probe text"),
            "{uri} must render the acl_alert banner"
        );
    }
}

// Tab-row nav replaces the page headings: each page marks its own tab active (bold via
// .active) with aria-current, no <h2>/rail label renders, the legend rides the tab row,
// and pages that don't override the tabrow block (login/setup) get no tabs at all.
#[tokio::test]
async fn nav_tabs_replace_headings_and_mark_active_page() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let token = state.auth.create_privileged_session("tabtester");
    let app = router(state);

    let index = get_html(&app, &token, "/").await;
    assert!(
        index.contains(r#"<a href="/" class="page-tab active" aria-current="page">Share Permissions</a>"#),
        "index must mark the Share Permissions tab active"
    );
    assert!(index.contains(r#"<a href="/settings" class="page-tab">System Settings</a>"#));
    assert!(!index.contains("<h2"), "the Share Permissions heading must be gone");
    let tabs = index.find("page-tabs").unwrap();
    let legend = index.find("perm-legend").unwrap();
    let layout = index.find("perm-layout").unwrap();
    assert!(tabs < legend && legend < layout, "legend must ride the tab row above the layout");

    let settings = get_html(&app, &token, "/settings").await;
    assert!(
        settings.contains(r#"<a href="/settings" class="page-tab active" aria-current="page">System Settings</a>"#),
        "settings must mark the System Settings tab active"
    );
    assert!(settings.contains(r#"<a href="/" class="page-tab">Share Permissions</a>"#));
    assert!(!settings.contains("<h2"), "the System Settings heading must be gone");
    assert!(!settings.contains("rl-hd"), "the SETTINGS rail label must be gone");
    assert!(
        settings.contains("pane-note"),
        "the share load/apply lifecycle note must live in the Shares pane now"
    );

    let req = Request::builder().uri("/login").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert!(
        !String::from_utf8_lossy(&body).contains("page-tabs"),
        "unauthenticated pages must not render the tab row"
    );
}

// Dedicated integration test for ACL apply path: POST /acl-apply, wait on shipped ApplyProgress, hard assert via shipped fs.get_acl_table only.
#[tokio::test]
async fn web_acl_apply_post_waits_then_get_dir_acl() {
    use std::time::Duration;
    use tokio::time::timeout;

    // Real TempDir as container root + logical share path (modeled on fs::make_test_acl_config_for).
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("aclroot");
    std::fs::create_dir_all(&real_root).unwrap();
    let logical = std::path::Path::new("/acldata");

    // Hermetic capable-FS fixture: the /acl-apply gate probes the node's
    // mount, and parallel tests decoy the env-global mountinfo path.
    let mi = tmp.path().join("mi");
    std::fs::write(
        &mi,
        format!("36 35 0:59 / {} rw,relatime - btrfs /dev/sda1 rw\n", tmp.path().display()),
    )
    .unwrap();
    // Build minimal NfsKlldapConfig so the logical path is allowed and maps to our real dir for setfacl/getfacl.
    let cp = tmp.path().join("c");
    let min_cfg = format!(
        r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "acldata"
host_path = "{}"
container_path = "{}"
"#,
        real_root.display(),
        logical.display(),
        real_root.display()
    );
    std::fs::write(&cp, min_cfg).unwrap();
    let sm = write_setup_marker(&tmp, ".s");
    let st = test_app_state(&cp, sm, Some(mi));
    let fs_for_assert = st.fs.clone();
    // Keep handle to progress slot before moving state into router so we can wait on it.
    let progress_slot = st.apply_progress.clone();
    let token = st.auth.create_privileged_session("acltest");
    let app = router(st);

    // POST the apply (shipped handler; it will spawn and set the progress slot).
    let p = urlencoding::encode(logical.to_str().unwrap());
    let body = format!("path={}&op=set&typ=user&id=4242&perms=r-x", p);
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Wait on the handler's progress gate (shipped ApplyProgress) before asserting effect.
    let wait_res = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(prog) = progress_slot.lock().await.as_ref() {
                if prog.finished.load(std::sync::atomic::Ordering::Relaxed) {
                    let txt = prog.final_result_text.lock().expect("poison").clone().unwrap_or_default();
                    if txt.contains("OK") || txt.contains("ACL") {
                        return true;
                    }
                    // even on error path we will still check get_dir_acl below; break to avoid infinite
                    return true;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await;

    assert!(wait_res.is_ok(), "should have observed progress finish");

    // Hard assert ONLY via the shipped fs wrapper on the exact logical path the POST targeted.
    let table = fs_for_assert
        .read()
        .expect("fs lock")
        .get_acl_table(logical)
        .expect("path must be allowed under share");
    let has = table.access.iter().any(|l| {
        l.tag == crate::privileged::AclTag::NamedUser(4242) && l.perms.to_str() == "r-x"
    });
    assert!(has, "after POST /acl-apply + wait, shipped fs.get_acl_table on logical path must show the entry");
}

// Shared scaffold for the ACL layer tests: TempDir-backed share (logical
// /acldata -> real tempdir), privileged session, router, progress handle.
async fn acl_test_scaffold(
    tmp: &tempfile::TempDir,
) -> (
    Arc<RwLock<FsManager>>,
    Arc<Mutex<Option<Arc<crate::fs::ApplyProgress>>>>,
    String,
    axum::Router,
) {
    let real_root = tmp.path().join("aclroot");
    std::fs::create_dir_all(&real_root).unwrap();
    // Hermetic mountinfo fixture marking the tempdir capable, so the auto
    // probe never reads the env-global mountinfo path other tests decoy.
    let mi = tmp.path().join("mi");
    std::fs::write(
        &mi,
        format!("36 35 0:59 / {} rw,relatime - btrfs /dev/sda1 rw\n", tmp.path().display()),
    )
    .unwrap();
    let cp = tmp.path().join("c");
    let min_cfg = format!(
        r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "acldata"
host_path = "/acldata"
container_path = "{}"
"#,
        real_root.display(),
        real_root.display()
    );
    std::fs::write(&cp, min_cfg).unwrap();
    let sm = write_setup_marker(tmp, ".s");
    let st = test_app_state(&cp, sm, Some(mi));
    let fs_for_assert = st.fs.clone();
    let progress_slot = st.apply_progress.clone();
    let token = st.auth.create_privileged_session("acltest");
    (fs_for_assert, progress_slot, token, router(st))
}

async fn wait_acl_progress(
    progress_slot: &Arc<Mutex<Option<Arc<crate::fs::ApplyProgress>>>>,
) {
    use std::time::Duration;
    use tokio::time::timeout;
    let ok = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(prog) = progress_slot.lock().await.as_ref() {
                if prog.finished.load(std::sync::atomic::Ordering::Relaxed) {
                    return true;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(ok.is_ok(), "acl apply progress must finish");
}

// Default (inheritance) layer: op targets the default ACL only; the
// access layer stays untouched.
#[tokio::test]
async fn web_acl_apply_default_layer_writes_default_acl_only() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let body = "path=%2Facldata&op=add&typ=user&id=5151&perms=rwx&layer=default";
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    wait_acl_progress(&progress).await;
    let table = fs
        .read()
        .expect("fs lock")
        .get_acl_table(std::path::Path::new("/acldata"))
        .expect("allowed");
    assert!(
        table.default.iter().any(|l| l.tag == crate::privileged::AclTag::NamedUser(5151)),
        "default layer must carry the new entry"
    );
    assert!(
        !table.access.iter().any(|l| matches!(l.tag, crate::privileged::AclTag::NamedUser(_))),
        "access layer must stay untouched by a default-layer add"
    );
}

// POSIX has no default ACL for files: the handler refuses with 422 before
// any setfacl runs (raw tool errors never reach the panel).
#[tokio::test]
async fn web_acl_apply_default_layer_on_file_rejected_422() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (_fs, _progress, token, app) = acl_test_scaffold(&tmp).await;
    std::fs::write(tmp.path().join("aclroot").join("f.txt"), b"x").unwrap();
    let body = "path=%2Facldata%2Ff.txt&op=add&typ=user&id=5151&perms=rwx&layer=default";
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(text.contains("directories only"), "422 body names the rule: {text}");
}

// Scaffold with a divergent submount: capable share root (btrfs fixture over
// the tempdir) plus a vfat child mount at <real_root>/sub. Per-share model:
// the panel must stay editable there while /acl-apply refuses the write.
async fn acl_submount_scaffold(tmp: &tempfile::TempDir) -> (String, axum::Router) {
    let real_root = tmp.path().join("aclroot");
    let sub = real_root.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let mi = tmp.path().join("mi");
    std::fs::write(
        &mi,
        format!(
            "36 35 0:59 / {} rw,relatime - btrfs /dev/sda1 rw\n\
             37 36 0:60 / {} rw,relatime - vfat /dev/sdb1 rw\n",
            tmp.path().display(),
            sub.display()
        ),
    )
    .unwrap();
    let cp = tmp.path().join("c");
    let min_cfg = format!(
        r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "acldata"
host_path = "/acldata"
container_path = "{}"
"#,
        real_root.display(),
        real_root.display()
    );
    std::fs::write(&cp, min_cfg).unwrap();
    let sm = write_setup_marker(tmp, ".s");
    let st = test_app_state(&cp, sm, Some(mi));
    let token = st.auth.create_privileged_session("acltest");
    (token, router(st))
}

// Per-share model: the panel classifies at the share serve root, so a node on
// an incapable submount still renders an editable ACL section (auto pill).
#[tokio::test]
async fn dir_perms_editable_on_capable_share_regardless_of_submount() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (token, app) = acl_submount_scaffold(&tmp).await;
    let req = Request::builder()
        .uri("/dir-perms?path=%2Facldata%2Fsub")
        .body(Body::empty())
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        !html.contains("acl-sec disabled"),
        "share-level gate must keep the ACL section editable on a submount node"
    );
    assert!(
        html.contains(r#"<span class="pill on">auto</span>"#),
        "pill must show the share-level auto state"
    );
}

// The /acl-apply backstop still checks the write target's own mount: an ACL
// write aimed at the vfat submount must 422 even though the panel is live.
#[tokio::test]
async fn acl_apply_422_backstop_on_incapable_submount() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (token, app) = acl_submount_scaffold(&tmp).await;
    let body = "path=%2Facldata%2Fsub&op=add&typ=user&id=5151&perms=rwx&layer=access";
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(text.contains("submount"), "422 body names the submount rule: {text}");
}

// The manifest is the client's only way to learn a share's ACL class (probing
// over NFSv4 is structurally impossible), so it must serve without a session
// and carry only bootstrap fields — never server-internal paths.
#[tokio::test]
async fn client_manifest_is_public_and_minimal() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let app = router(state);
    let req = Request::builder()
        .uri("/client-manifest.json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "no session cookie may be required");
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.contains("json"), "manifest must be JSON, got {ct}");
    let cc = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(cc.contains("no-store"), "live-computed classes must not be cached: {cc}");
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();
    assert!(body.contains(r#""manifest_version":1"#), "{body}");
    assert!(body.contains(r#""pseudo":"/data""#), "{body}");
    assert!(body.contains(r#""security":"krb5p""#), "unset security falls to the default: {body}");
    assert!(body.contains(r#""acl":"noacl""#), "noacl fixture share must classify noacl: {body}");
    assert!(body.contains(r#""acl_state":"auto (off)""#), "{body}");
    // Field-name assertions: the fixture's pseudo (/data) textually equals its
    // container_path, so exclude the internal-path KEYS, not the value.
    assert!(!body.contains("host_path"), "internal paths must not leak: {body}");
    assert!(!body.contains("container_path"), "internal paths must not leak: {body}");
}

// The same auto share the UI promotes to ACL must publish "acl" to clients —
// one classification for every surface.
#[tokio::test]
async fn client_manifest_acl_share_reports_acl() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (_fs, _progress, _token, app) = acl_test_scaffold(&tmp).await;
    let req = Request::builder()
        .uri("/client-manifest.json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();
    assert!(body.contains(r#""pseudo":"/acldata""#), "{body}");
    assert!(body.contains(r#""acl":"acl""#), "capable auto share must publish acl: {body}");
    assert!(body.contains(r#""acl_state":"auto (on)""#), "{body}");
}

// Pre-setup the manifest must answer JSON (the empty/default share set), not
// redirect a machine client into the HTML wizard.
#[tokio::test]
async fn client_manifest_bypasses_setup_gate() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let marker = state.setup_marker_override.clone();
    let app = router(state);
    if let Some(m) = &marker {
        std::fs::remove_file(m).ok();
    }
    let req = Request::builder()
        .uri("/client-manifest.json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "machine endpoint must bypass the wizard redirect"
    );
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.contains("json"), "pre-setup response must still be JSON, got {ct}");
}

// op=mask needs no principal; it rewrites the layer's group-class cap.
#[tokio::test]
async fn web_acl_apply_mask_op_caps_named_entries() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    // Seed a named entry directly on disk so a mask exists to rewrite.
    let real = tmp.path().join("aclroot");
    crate::privileged::apply_acl(
        &real,
        crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::User(6161),
            perms: crate::privileged::AclPerms::from_str("rwx"),
            default: false,
        },
    )
    .expect("seed");
    // The target is a directory, so the x-less submitted mask fuses r→x (the
    // POSIX dir rule); write still gets capped off the rwx entry.
    let body = "path=%2Facldata&op=mask&perms=r--&layer=access";
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    wait_acl_progress(&progress).await;
    let table = fs
        .read()
        .expect("fs lock")
        .get_acl_table(std::path::Path::new("/acldata"))
        .expect("allowed");
    let mask = table.mask_of(false).expect("mask present");
    assert!(
        mask.r && !mask.w && mask.x,
        "dir mask must fuse to r-x after op=mask r--"
    );
    let entry = table
        .access
        .iter()
        .find(|l| l.tag == crate::privileged::AclTag::NamedUser(6161))
        .expect("named entry kept");
    let eff = table.effective_perms(entry, false);
    assert!(eff.r && !eff.w && eff.x, "named entry effective perms capped to r-x");
}

// Directory ACL applies fuse r→x exactly like the POSIX dir matrix: the dir
// editor hides Exec and submits x-less perms; execute is the traversal bit,
// so a Read grant that can't traverse would be useless over NFS.
#[tokio::test]
async fn web_acl_apply_dir_add_fuses_execute_from_read() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let body = "path=%2Facldata&op=add&typ=user&id=5252&perms=r--&layer=access";
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    wait_acl_progress(&progress).await;
    let table = fs
        .read()
        .expect("fs lock")
        .get_acl_table(std::path::Path::new("/acldata"))
        .expect("allowed");
    let entry = table
        .access
        .iter()
        .find(|l| l.tag == crate::privileged::AclTag::NamedUser(5252))
        .expect("entry added");
    assert_eq!(entry.perms.to_str(), "r-x", "dir add must fuse execute from read");
}

// Files keep the literal triad — r without x is normal for a file, so the
// fuse never runs on file targets.
#[tokio::test]
async fn web_acl_apply_file_add_keeps_literal_perms() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    std::fs::write(tmp.path().join("aclroot").join("f.txt"), b"x").unwrap();
    let body = "path=%2Facldata%2Ff.txt&op=add&typ=user&id=5353&perms=rw-&layer=access";
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    wait_acl_progress(&progress).await;
    let table = fs
        .read()
        .expect("fs lock")
        .get_acl_table(std::path::Path::new("/acldata/f.txt"))
        .expect("allowed");
    let entry = table
        .access
        .iter()
        .find(|l| l.tag == crate::privileged::AclTag::NamedUser(5353))
        .expect("entry added");
    assert_eq!(entry.perms.to_str(), "rw-", "file add must keep the literal perms");
}

// The ACL grid shows the stored triad truthfully on BOTH node kinds: Exec is
// a real checked-from-disk bit on directory panels too (the server fuses r→x
// for dirs at apply time; the old scope-gated file-execute knob is retired).
#[tokio::test]
async fn dir_perms_acl_grid_execute_column_matches_node_kind() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (_fs, _progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    // Seed a named entry (creates the mask too) so entry + mask rows render.
    crate::privileged::apply_acl(
        &real,
        crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::User(6161),
            perms: crate::privileged::AclPerms::from_str("rwx"),
            default: false,
        },
    )
    .expect("seed");
    std::fs::write(real.join("f.txt"), b"x").unwrap();

    let req = Request::builder()
        .uri("/dir-perms?path=%2Facldata")
        .body(Body::empty())
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let dir_html = String::from_utf8_lossy(&bytes).to_string();
    assert!(dir_html.contains(r#"data-kind="dir""#), "dir panel carries its kind for the JS contract");
    // Dir panes render the full R/W/Exec grid with Exec checked from the
    // stored bit: the seeded rwx entry surfaces its x as a checked box.
    assert!(
        dir_html.contains(r#"class="abit" data-ch="x" aria-label="execute" checked disabled"#),
        "dir entry rows show the stored execute bit checked"
    );
    // The seeded mask is rwx (setfacl recalc from the rwx entry).
    assert!(
        dir_html.contains(r#"class="mbit" data-ch="x" aria-label="mask execute" checked disabled"#),
        "dir mask row shows the stored mask execute bit checked"
    );
    // Both add rows carry a plain Exec box (Inherit's included — the server
    // fuses r→x for the directory layer at apply time).
    assert_eq!(
        dir_html.matches(r#"class="ebit" data-ch="x""#).count(),
        2,
        "both dir add rows render an Exec box"
    );
    // Staged-batch plumbing: rows carry the principal name; the form carries
    // the hidden acl_ops field; the retired per-form scope radios are gone.
    assert!(dir_html.contains(r#"data-name=""#), "rows carry data-name for the staged batch");
    assert!(dir_html.contains(r#"class="acl-ops-field""#), "form carries the acl_ops field");
    assert!(!dir_html.contains("acl-rec-scope"), "the add form has no scope radios of its own");
    assert!(!dir_html.contains("acl-add-hd"), "the add form has no private header labels");
    assert!(!dir_html.contains("file-mode-readout"), "the Files NNN readout is retired");
    // The scope-gated knob labels are gone everywhere.
    assert!(!dir_html.contains("recursive reach)"), "the file-execute knob labels are retired");
    assert!(!dir_html.contains("derived on inherit)"), "the inherit-derived Exec label is retired");

    let req = Request::builder()
        .uri("/dir-perms?path=%2Facldata%2Ff.txt")
        .body(Body::empty())
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let file_html = String::from_utf8_lossy(&bytes).to_string();
    assert!(file_html.contains(r#"data-kind="file""#), "file panel keeps the 3-col grid");
    assert!(
        file_html.contains(r#"class="ebit" data-ch="x""#),
        "file add form keeps the Exec checkbox"
    );
}

// The /acl-apply endpoint itself refuses paths whose mount cannot store
// POSIX ACLs — a stale panel or hand-built POST never lands on disk.
#[tokio::test]
async fn web_acl_apply_refused_on_incapable_mount_422() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (_fs, _progress, token, app) = acl_test_scaffold(&tmp).await;
    // Flip the scaffold's mountinfo fixture to a denylisted filesystem:
    // the per-path capability gate must now refuse the mutation.
    std::fs::write(
        tmp.path().join("mi"),
        format!("36 35 0:59 / {} rw,relatime - vfat /dev/sdd1 rw\n", tmp.path().display()),
    )
    .unwrap();
    let body = "path=%2Facldata&op=add&typ=user&id=5151&perms=rwx&layer=access";
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(text.contains("not available"), "422 names the refusal: {text}");
}

// Scoped ACL applies ride the walker: scope=all sweeps the subtree with
// capital-X semantics (plain files never gain execute from the grant).
#[tokio::test]
async fn web_acl_apply_scope_all_sweeps_subtree() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    std::fs::create_dir_all(real.join("sub")).unwrap();
    std::fs::write(real.join("sub").join("f.txt"), b"x").unwrap();
    let body = "path=%2Facldata&op=add&typ=user&id=8181&perms=rwx&layer=access&scope=all";
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    wait_acl_progress(&progress).await;
    let table = fs
        .read()
        .expect("fs lock")
        .get_acl_table(std::path::Path::new("/acldata/sub/f.txt"))
        .expect("allowed");
    let entry = table
        .access
        .iter()
        .find(|l| l.tag == crate::privileged::AclTag::NamedUser(8181))
        .expect("nested file must carry the swept entry");
    assert!(entry.perms.r && entry.perms.w && entry.perms.x,
        "submitted x is the explicit Exec grant — files in scope take it literally");
    let sub = fs
        .read()
        .expect("fs lock")
        .get_acl_table(std::path::Path::new("/acldata/sub"))
        .expect("allowed");
    assert!(sub
        .access
        .iter()
        .any(|l| l.tag == crate::privileged::AclTag::NamedUser(8181) && l.perms.x),
        "directories in scope gain x");
}

// The flagship flow: Read-only grant with a recursive reach and Exec left
// unchecked — every directory in scope takes the fused r-x (traversal),
// every file takes exactly r-- (no execute unless the Exec box grants it).
#[tokio::test]
async fn web_acl_apply_recursive_exec_unchecked_files_stay_xless() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    std::fs::create_dir_all(real.join("sub")).unwrap();
    std::fs::write(real.join("sub").join("f.txt"), b"x").unwrap();
    let body = "path=%2Facldata&op=add&typ=user&id=9191&perms=r--&layer=access&scope=all";
    let req = Request::builder()
        .method("POST")
        .uri("/acl-apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    wait_acl_progress(&progress).await;
    let perms_of = |p: &str| {
        fs.read()
            .expect("fs lock")
            .get_acl_table(std::path::Path::new(p))
            .expect("allowed")
            .access
            .iter()
            .find(|l| l.tag == crate::privileged::AclTag::NamedUser(9191))
            .map(|l| l.perms.to_str())
            .expect("entry present")
    };
    assert_eq!(perms_of("/acldata"), "r-x", "target dir takes the fused grant");
    assert_eq!(perms_of("/acldata/sub"), "r-x", "dirs in scope take the fused grant");
    assert_eq!(perms_of("/acldata/sub/f.txt"), "r--", "files take the literal x-less grant");
}

// One Apply commits POSIX and the staged ACL batch in order: chown/chmod
// first, then each setfacl op, with an explicit mask op landing last so it
// wins over the recalculation the entry ops trigger.
#[tokio::test]
async fn web_apply_acl_ops_batch_runs_after_posix() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    let ops = r#"[{"op":"set","typ":"user","id":"7777","name":"","perms":"rw-","layer":"access"},{"op":"mask","perms":"r--","layer":"access"}]"#;
    let body = format!(
        "path=%2Facldata&owner_user=&owner_group=&mode=770&recursive_scope=none&acl_ops={}",
        urlencoding::encode(ops)
    );
    let req = Request::builder()
        .method("POST")
        .uri("/apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(text.contains("data-applying"), "batch apply runs as the normal async job: {text}");
    let cmd = wait_apply_finished(&progress).await;
    assert!(cmd.contains("chmod"), "log names the POSIX pass: {cmd}");
    assert!(cmd.contains("setfacl -m u:7777:rwx"), "log names the fused entry op: {cmd}");
    assert!(cmd.contains("setfacl -m m::r-x"), "log names the fused mask op: {cmd}");
    use std::os::unix::fs::PermissionsExt;
    // Owner/other bits prove the chmod landed; the group class of an
    // extended-ACL inode IS the mask, so the explicit r-x mask op landing
    // LAST leaves group bits 5 — had it run before the entry op, the -m
    // recalculation would have bumped them back to 7.
    let mode = std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o750, "chmod first, explicit mask op last");
    let table = fs
        .read()
        .expect("fs lock")
        .get_acl_table(std::path::Path::new("/acldata"))
        .expect("allowed");
    let entry = table
        .access
        .iter()
        .find(|l| l.tag == crate::privileged::AclTag::NamedUser(7777))
        .expect("staged entry landed");
    assert_eq!(entry.perms.to_str(), "rwx", "dir entry takes the fused grant");
    let mask = table
        .access
        .iter()
        .find(|l| l.tag == crate::privileged::AclTag::Mask)
        .expect("mask present");
    assert_eq!(
        mask.perms.to_str(),
        "r-x",
        "the explicit (fused) mask op lands last and wins over the -m recalculation"
    );
}

// The capability backstop from /acl-apply guards the batched path too: an
// incapable mount refuses the whole apply before anything mutates.
#[tokio::test]
async fn web_apply_acl_ops_gate_rejected_no_mutation() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (_fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o750)).unwrap();
    std::fs::write(
        tmp.path().join("mi"),
        format!("36 35 0:59 / {} rw,relatime - vfat /dev/sdd1 rw\n", tmp.path().display()),
    )
    .unwrap();
    let ops = r#"[{"op":"set","typ":"user","id":"7878","perms":"rw-","layer":"access"}]"#;
    let body = format!(
        "path=%2Facldata&owner_user=&owner_group=&mode=770&recursive_scope=none&acl_ops={}",
        urlencoding::encode(ops)
    );
    let req = Request::builder()
        .method("POST")
        .uri("/apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(text.contains("ACL editing is not available"), "alert names the refusal: {text}");
    assert!(!text.contains("data-applying"), "no apply job may start: {text}");
    assert!(progress.lock().await.is_none(), "no progress slot may be claimed");
    let mode = std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o750, "the POSIX half must not land either");
}

// An unresolvable principal rejects the whole batch before any mutation —
// the chown/chmod half must not land without its staged ACL edits.
#[tokio::test]
async fn web_apply_acl_ops_unresolved_principal_rejected_before_mutation() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (_fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o750)).unwrap();
    let ops = r#"[{"op":"set","typ":"user","id":"","name":"no-such-user-xyz","perms":"rw-","layer":"access"}]"#;
    let body = format!(
        "path=%2Facldata&owner_user=&owner_group=&mode=770&recursive_scope=none&acl_ops={}",
        urlencoding::encode(ops)
    );
    let req = Request::builder()
        .method("POST")
        .uri("/apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(
        text.contains("Could not resolve ACL principal"),
        "alert names the unresolved principal: {text}"
    );
    assert!(progress.lock().await.is_none(), "no progress slot may be claimed");
    let mode = std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o750, "nothing mutates on a rejected batch");
}

// The single Apply scope fans every batched op out with the split specs:
// dirs take the fused grant, files take the literal triad — execute lands
// on files exactly where the staged Exec knob granted it.
#[tokio::test]
async fn web_apply_acl_ops_scope_all_dir_fused_file_literal() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    std::fs::create_dir_all(real.join("sub")).unwrap();
    std::fs::write(real.join("sub").join("f.txt"), b"x").unwrap();
    let ops = r#"[{"op":"set","typ":"user","id":"6001","perms":"rw-","layer":"access"},{"op":"set","typ":"user","id":"6002","perms":"rwx","layer":"access"}]"#;
    let body = format!(
        "path=%2Facldata&owner_user=&owner_group=&mode=770&recursive_scope=all&file_mode=660&acl_ops={}",
        urlencoding::encode(ops)
    );
    let req = Request::builder()
        .method("POST")
        .uri("/apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    wait_apply_finished(&progress).await;
    let perms_of = |p: &str, uid: u32| {
        fs.read()
            .expect("fs lock")
            .get_acl_table(std::path::Path::new(p))
            .expect("allowed")
            .access
            .iter()
            .find(|l| l.tag == crate::privileged::AclTag::NamedUser(uid))
            .map(|l| l.perms.to_str())
            .expect("entry present")
    };
    assert_eq!(perms_of("/acldata/sub", 6001), "rwx", "dirs fuse execute from read");
    assert_eq!(perms_of("/acldata/sub/f.txt", 6001), "rw-", "x-less op leaves files x-less");
    assert_eq!(perms_of("/acldata/sub/f.txt", 6002), "rwx", "the Exec knob grants file execute literally");
}

// A staged removal commits as setfacl -x for that principal.
#[tokio::test]
async fn web_apply_acl_ops_remove_by_id() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    crate::privileged::apply_acl(
        &real,
        crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::User(5252),
            perms: crate::privileged::AclPerms::from_str("rwx"),
            default: false,
        },
    )
    .expect("seed");
    let ops = r#"[{"op":"delete","typ":"user","id":"5252","layer":"access"}]"#;
    let body = format!(
        "path=%2Facldata&owner_user=&owner_group=&mode=770&recursive_scope=none&acl_ops={}",
        urlencoding::encode(ops)
    );
    let req = Request::builder()
        .method("POST")
        .uri("/apply")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    wait_apply_finished(&progress).await;
    let table = fs
        .read()
        .expect("fs lock")
        .get_acl_table(std::path::Path::new("/acldata"))
        .expect("allowed");
    assert!(
        !table
            .access
            .iter()
            .any(|l| l.tag == crate::privileged::AclTag::NamedUser(5252)),
        "staged removal deletes the entry"
    );
}

// Tree rows on ACL-active shares carry the "+" marker exactly where the
// ACL is extended (one batched getfacl per fragment).
#[tokio::test]
async fn tree_fragment_marks_extended_acl_rows() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (_fs, _progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    std::fs::create_dir_all(real.join("plain")).unwrap();
    std::fs::create_dir_all(real.join("marked")).unwrap();
    crate::privileged::apply_acl(
        &real.join("marked"),
        crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::User(9191),
            perms: crate::privileged::AclPerms::from_str("r-x"),
            default: false,
        },
    )
    .expect("seed");
    let req = Request::builder()
        .method("GET")
        .uri("/tree?path=%2Facldata")
        .body(Body::empty())
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 512 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&bytes).to_string();
    assert!(html.contains("marked<span class=\"acl-plus\""),
        "ACL'd row label carries the + marker: {html}");
    assert!(!html.contains("plain<span class=\"acl-plus\""),
        "plain row must not carry the marker: {html}");
}

// The panel surfaces the full model: mask row, default section, effective
// badge on capped rows, and the Group-row mask hint once extended.
#[tokio::test]
async fn dir_perms_renders_mask_default_and_effective_sections() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (_fs, _progress, token, app) = acl_test_scaffold(&tmp).await;
    let real = tmp.path().join("aclroot");
    for m in [
        crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::User(6161),
            perms: crate::privileged::AclPerms::from_str("rwx"),
            default: false,
        },
        crate::privileged::AclModification::SetMask {
            perms: crate::privileged::AclPerms::from_str("r--"),
            default: false,
        },
        crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::Group(7171),
            perms: crate::privileged::AclPerms::from_str("r-x"),
            default: true,
        },
    ] {
        crate::privileged::apply_acl(&real, m).expect("seed acl");
    }
    let req = Request::builder()
        .method("GET")
        .uri("/dir-perms?path=%2Facldata")
        .body(Body::empty())
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 512 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&bytes).to_string();
    assert!(html.contains("acl-mask-row"), "mask row rendered");
    assert!(html.contains(r#"data-layer="default""#), "Inherit pane rendered");
    assert!(html.contains("acl-tab"), "layer tabs rendered");
    assert!(html.contains(">Inherit</button>"), "Inherit tab labeled");
    assert!(html.contains("acl-cell capped"), "mask-capped bit renders dimmed");
    assert!(html.contains("Mask caps this entry"), "capped row carries the effective tooltip");
    assert!(html.contains("mask-star"), "Group row carries the mask hint when extended");
    assert!(html.contains("acl-act"), "unified Add/Remove/Modify actions rendered");
}

// POSIX apply owner resolution: uid/gid 0 is a first-class owner (root on
// disk = the nobody identity clients see under root-squash). The old code
// used 0 as an "unset" sentinel and silently rewrote 0:0 — and any
// untouched form — to a hardcoded 1000:1000.
#[tokio::test]
async fn web_apply_permissions_zero_owner_and_keep_current() {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tokio::time::timeout;

    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("permroot");
    std::fs::create_dir_all(&real_root).unwrap();
    let logical = std::path::Path::new("/permsdata");

    let cp = tmp.path().join("c");
    let min_cfg = format!(
        r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "permsdata"
host_path = "{}"
container_path = "{}"
"#,
        real_root.display(),
        logical.display(),
        real_root.display()
    );
    std::fs::write(&cp, min_cfg).unwrap();
    let sm = write_setup_marker(&tmp, ".s");
    let mi = write_capable_mountinfo(&tmp, "perms-mountinfo", &real_root);
    let st = test_app_state(&cp, sm, Some(mi));
    let progress_slot = st.apply_progress.clone();
    let token = st.auth.create_privileged_session("permtest");
    let app = router(st);

    let post_and_get_cmd = |body: String| {
        let app = app.clone();
        let token = token.clone();
        let progress_slot = progress_slot.clone();
        async move {
            let req = Request::builder()
                .method("POST")
                .uri("/apply")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap();
            let req = add_session_cookie(req, &token);
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            // cmd is recorded synchronously before the spawn; wait for
            // finish so successive posts don't race the walker.
            timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(prog) = progress_slot.lock().await.as_ref() {
                        if prog.finished.load(std::sync::atomic::Ordering::Relaxed) {
                            return prog.cmd.lock().expect("poison").clone().unwrap_or_default();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("apply must finish")
        }
    };

    let p = urlencoding::encode(logical.to_str().unwrap());

    // 1) Hidden numeric ids carry 0 (panel round-trip of a 0:0 directory).
    let cmd = post_and_get_cmd(format!(
        "path={p}&owner_user=nobody+(0)&owner_group=nobody+(0)&mode=0755&owner_user_uid=0&owner_group_gid=0"
    ))
    .await;
    assert!(cmd.contains("chown 0:0"), "hidden 0 ids must chown 0:0, got: {cmd}");

    // 2) Hand-typed names: nobody/root resolve to 0 without LDAP.
    let cmd = post_and_get_cmd(format!(
        "path={p}&owner_user=nobody&owner_group=root&mode=0755&owner_user_uid=&owner_group_gid="
    ))
    .await;
    assert!(cmd.contains("chown 0:0"), "typed nobody/root must chown 0:0, got: {cmd}");

    // 3) Untouched owner fields keep the directory's current ownership
    //    (never a hardcoded default).
    let md = std::fs::metadata(&real_root).unwrap();
    let (cur_uid, cur_gid) = (md.uid(), md.gid());
    let cmd = post_and_get_cmd(format!(
        "path={p}&owner_user=&owner_group=&mode=0770&owner_user_uid=&owner_group_gid="
    ))
    .await;
    assert!(
        cmd.contains(&format!("chown {cur_uid}:{cur_gid}")),
        "blank owner fields must keep current {cur_uid}:{cur_gid}, got: {cmd}"
    );

    // 4) Directory modes normalize r-implies-x (an r-without-x dir lists
    //    as empty over NFS — round-4 users share at 0776): 0776 applies
    //    as 0777 to directories (files keep 0776), noted in the log.
    let cmd = post_and_get_cmd(format!(
        "path={p}&owner_user=&owner_group=&mode=0776&owner_user_uid=&owner_group_gid="
    ))
    .await;
    assert!(
        cmd.contains("read implies execute") && cmd.contains("777"),
        "0776 on a dir must note the r-implies-x normalization: {cmd}"
    );
    let disk_mode = std::fs::metadata(&real_root).unwrap().permissions().mode() & 0o7777;
    assert_eq!(disk_mode, 0o777, "the directory itself must be normalized on disk");

    // The owner/group live search must offer the synthetic nobody (0)
    // row — including while LLDAP is unavailable (nobody is not an LDAP
    // entity), which is what this test's lldap stub simulates.
    for (uri, marker) in [
        ("/users/search?owner_user=nobody", r#"data-uid="0""#),
        ("/users/search?owner_user=0", r#"data-uid="0""#),
        ("/groups/search?owner_group=nobody", r#"data-gid="0""#),
    ] {
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains(marker) && html.contains("nobody"),
            "{uri} must offer the synthetic nobody(0) row: {html}"
        );
    }
}

// GET /settings/share-card must render a blank card with the field tooltips the JS copy had lost.
#[tokio::test]
async fn share_card_fragment_renders_blank_card_with_tooltips() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let token = state.auth.create_privileged_session("cardtest");
    let app = router(state);
    let req = Request::builder().uri("/settings/share-card?idx=3").body(Body::empty()).unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"name="share_name_3""#), "blank card must carry the requested idx");
    assert!(
        html.contains("share-dot noacl") && html.contains(r#"title="Non-ACL limited""#),
        "blank card defaults to the NOACL dot"
    );
    assert!(html.contains("Path on the host that backs this share."), "field tooltips must be present on new cards");
    assert!(!html.contains("share-card-ed open"), "server sends the card closed; the JS opens it after insert");
    // New shares default to root_squash ON (0.9.81 hardening) — the box ships checked.
    let sq = html.find("share_root_squash_3").expect("root_squash checkbox present");
    assert!(html[sq..sq + 80].contains("checked"), "blank card must default root_squash checked");
}

// GET / must carry the single-sourced Apply Log shell the poller's oob swaps replace.
#[tokio::test]
async fn index_renders_apply_log_shell() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let token = state.auth.create_privileged_session("logtest");
    let app = router(state);
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("apply-status-content apply-log-content"), "shell must keep the JS contract classes");
    // Exact shell open tag: no hx-swap-oob and no data-apply-finished on the initial render.
    assert!(
        html.contains(r#"<div id="apply-status" class="apply-status">"#),
        "index must render the initial Apply Log shell without oob/finished attrs"
    );
}

// Share-card chips are non-conformity signals: only options that deviate
// from the default/auto values render (RW, root_squash, cache default, and
// the [ganesha] default security stay implicit; ACL state rides the dot).
#[tokio::test]
async fn index_share_cards_render_standout_chips_only() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("shares");
    for sub in ["alpha", "beta", "gamma"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    let mi = tmp.path().join("mi");
    std::fs::write(
        &mi,
        format!("36 35 0:59 / {} rw,relatime - btrfs /dev/sda1 rw\n", tmp.path().display()),
    )
    .unwrap();
    let cp = tmp.path().join("c");
    // alpha = all defaults; beta = deviates on every chip-worthy option;
    // gamma = explicit values that EQUAL the defaults (must stay chipless).
    let cfg = format!(
        r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{root}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "alpha"
host_path = "/alpha"
container_path = "{root}/alpha"
[[shares]]
name = "beta"
host_path = "/beta"
container_path = "{root}/beta"
rw = false
squash = "no_root_squash"
cache_profile = "Read - Heavy"
security = "krb5i"
[[shares]]
name = "gamma"
host_path = "/gamma"
container_path = "{root}/gamma"
rw = true
squash = "root_squash"
security = "krb5p"
"#,
        root = root.display()
    );
    std::fs::write(&cp, cfg).unwrap();
    let sm = write_setup_marker(&tmp, ".chips");
    let state = test_app_state(&cp, sm, Some(mi));
    let token = state.auth.create_privileged_session("chipstest");
    let app = router(state);
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&body).to_string();
    // Deviations render, each exactly once (beta only).
    assert_eq!(html.matches(r#"class="share-chip ro""#).count(), 1, "one RO chip: {html}");
    assert_eq!(html.matches(">no_root_squash<").count(), 1, "one squash warn chip");
    assert_eq!(html.matches(">cache: read - heavy<").count(), 1, "one cache chip");
    assert_eq!(html.matches(">krb5i<").count(), 1, "one security chip");
    // Defaults stay implicit — explicitly-configured defaults included.
    assert!(!html.contains(">RW<"), "rw is the default access — no chip");
    assert!(!html.contains(">root_squash<"), "root_squash is the default — no chip");
    assert!(!html.contains(">cache: default<"), "the default cache profile carries no chip");
    assert!(!html.contains(">krb5p<"), "the default security carries no chip");
    // ACL state stays out of the chips: the dot + panel ACL section carry it.
    assert!(!html.contains(">acl "), "no acl chip on the share cards");
}

// The security chip's comparison target is the CONFIGURED [ganesha]
// default_security, not a hardcoded krb5p: whichever flavor is the default
// stays chipless while the other two chip.
#[tokio::test]
async fn index_security_chips_follow_configured_default() {
    async fn chips_html(default_security: &str, shares: &[(&str, Option<&str>)]) -> String {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("shares");
        let mut shares_toml = String::new();
        for (name, sec) in shares {
            std::fs::create_dir_all(root.join(name)).unwrap();
            shares_toml.push_str(&format!(
                "[[shares]]\nname = \"{name}\"\nhost_path = \"/{name}\"\ncontainer_path = \"{}/{name}\"\n",
                root.display()
            ));
            if let Some(sec) = sec {
                shares_toml.push_str(&format!("security = \"{sec}\"\n"));
            }
        }
        let mi = tmp.path().join("mi");
        std::fs::write(
            &mi,
            format!("36 35 0:59 / {} rw,relatime - btrfs /dev/sda1 rw\n", tmp.path().display()),
        )
        .unwrap();
        let cp = tmp.path().join("c");
        std::fs::write(
            &cp,
            format!(
                r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{root}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[ganesha]
default_security = "{default_security}"
{shares_toml}"#,
                root = root.display()
            ),
        )
        .unwrap();
        let sm = write_setup_marker(&tmp, ".secchips");
        let state = test_app_state(&cp, sm, Some(mi));
        let token = state.auth.create_privileged_session("secchips");
        let app = router(state);
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        String::from_utf8_lossy(&body).to_string()
    }

    // krb5i default: inherit and explicit-krb5i stay chipless; krb5p + krb5 chip.
    let html = chips_html(
        "krb5i",
        &[("delta", None), ("eps", Some("krb5i")), ("zeta", Some("krb5p")), ("eta", Some("krb5"))],
    )
    .await;
    assert_eq!(html.matches(">krb5p<").count(), 1, "krb5p deviates from krb5i: {html}");
    assert_eq!(html.matches(">krb5<").count(), 1, "krb5 deviates from krb5i");
    assert!(!html.contains(">krb5i<"), "the configured default never chips");

    // krb5 default: same rule rotated (the krb5p default is covered above).
    let html = chips_html(
        "krb5",
        &[("delta", Some("krb5")), ("eps", Some("krb5i")), ("zeta", Some("krb5p"))],
    )
    .await;
    assert_eq!(html.matches(">krb5p<").count(), 1, "krb5p deviates from krb5");
    assert_eq!(html.matches(">krb5i<").count(), 1, "krb5i deviates from krb5");
    assert!(!html.contains(">krb5<"), "the configured default never chips");
}

// The share select's blank option means "default from [ganesha]": a shares
// save must keep it unset (the old path materialized security = "krb5p",
// silently mis-exporting every share under a non-krb5p default), and the
// settings card chips only an explicit security that deviates.
#[tokio::test]
async fn settings_save_shares_blank_security_stays_inherited() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("shares");
    std::fs::create_dir_all(root.join("data")).unwrap();
    let mi = tmp.path().join("mi");
    std::fs::write(
        &mi,
        format!("36 35 0:59 / {} rw,relatime - btrfs /dev/sda1 rw\n", tmp.path().display()),
    )
    .unwrap();
    let cp = tmp.path().join("c");
    std::fs::write(
        &cp,
        format!(
            r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{root}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[ganesha]
default_security = "krb5i"
[[shares]]
name = "data"
host_path = "/media/data"
container_path = "{root}/data"
"#,
            root = root.display()
        ),
    )
    .unwrap();
    let sm = write_setup_marker(&tmp, ".secsave");
    let state = test_app_state(&cp, sm, Some(mi));
    let token = state.auth.create_privileged_session("secsave");
    let app = router(state);

    // container_path must stay under storage.container_root or validation
    // rejects the whole save (and every assertion below would be vacuous).
    let base = format!(
        "share_name_0=data&share_host_0=%2Fmedia%2Fdata&share_pseudo_0=&share_rw_0=true&share_cache_profile_0=Default&share_enable_acl_0=false&share_container_path_0={}&share_root_squash_0=on",
        urlencoding::encode(&format!("{}/data", root.display()))
    );
    let save = |security: &str| {
        let body = format!("{base}&share_security_0={security}");
        let req = Request::builder()
            .method("POST")
            .uri("/settings/save-shares")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        add_session_cookie(req, &token)
    };

    // Blank select → no security key on disk, no chip anywhere.
    let resp = app.clone().oneshot(save("")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Shares saved"), "save must not be rejected: {html}");
    let written = std::fs::read_to_string(&cp).unwrap();
    assert!(
        !written.contains("\nsecurity ="),
        "blank security must stay unset (inherit), not materialize: {written}"
    );
    assert!(!html.contains(r#"<span class="sc-chip">krb5"#), "inheriting share carries no chip");

    // Explicit deviation → key written, chip on the settings card.
    let resp = app.clone().oneshot(save("krb5p")).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    let written = std::fs::read_to_string(&cp).unwrap();
    assert!(written.contains("security = \"krb5p\""), "explicit override persists: {written}");
    assert!(
        html.contains(r#"<span class="sc-chip">krb5p</span>"#),
        "krb5p deviates from the krb5i default — settings card chips it"
    );

    // Explicit but EQUAL to the default → key persists, chip stays off.
    let resp = app.clone().oneshot(save("krb5i")).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    let written = std::fs::read_to_string(&cp).unwrap();
    assert!(written.contains("security = \"krb5i\""), "explicit-but-equal stays explicit");
    assert!(
        !html.contains(r#"<span class="sc-chip">krb5i</span>"#),
        "a security matching the default is conformant — no chip"
    );

    // Back to blank → the stale key is removed, not left pinned.
    let resp = app.clone().oneshot(save("")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let written = std::fs::read_to_string(&cp).unwrap();
    assert!(
        !written.contains("\nsecurity ="),
        "reverting to default must drop the security key: {written}"
    );
}

// The vendored htmx asset must bypass the setup gate, and served pages must reference it (no CDN).
#[tokio::test]
async fn htmx_asset_served_pre_setup_and_referenced_locally() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let marker = state.setup_marker_override.clone();
    let app = router(state);

    // Marker present: /login renders normally and must reference the local asset only.
    let lreq = Request::builder().uri("/login").body(Body::empty()).unwrap();
    let lresp = app.clone().oneshot(lreq).await.unwrap();
    assert_eq!(lresp.status(), StatusCode::OK);
    let lbody = axum::body::to_bytes(lresp.into_body(), 1024 * 1024).await.unwrap();
    let lhtml = String::from_utf8_lossy(&lbody);
    assert!(lhtml.contains("/assets/htmx-"), "pages must load the vendored htmx");
    assert!(lhtml.contains("/assets/permissions.js"), "pages must load the app script asset");
    assert!(!lhtml.contains("unpkg.com"), "no CDN reference may remain in served HTML");

    // Marker removed (first-run state): the assets must still bypass the setup gate.
    if let Some(m) = &marker {
        std::fs::remove_file(m).ok();
    }
    for asset in ["/assets/htmx-1.9.12.min.js", "/assets/permissions.js"] {
        let req = Request::builder().uri(asset).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{asset} must be served while the setup wizard gate is active");
        let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        assert!(ct.contains("javascript"), "{asset} must carry a JS content-type, got {ct}");
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        assert!(!body.is_empty(), "{asset} body must not be empty");
    }
}

// GET /dir-perms renders the POSIX matrix + hidden numeric uid/gid fields (for name translation)
// and marks the ACL section non-ACL when the share did not opt into enable_acl (default).
#[tokio::test]
async fn dir_perms_get_renders_posix_matrix_and_noacl_section() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("permroot");
    std::fs::create_dir_all(&real_root).unwrap();
    let logical = std::path::Path::new("/permdata");
    // Hermetic capable-FS fixture (see acl_test_scaffold for rationale).
    let mi = tmp.path().join("mi");
    std::fs::write(
        &mi,
        format!("36 35 0:59 / {} rw,relatime - btrfs /dev/sda1 rw\n", tmp.path().display()),
    )
    .unwrap();

    let cp = tmp.path().join("c");
    let min_cfg = format!(
        r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "permdata"
host_path = "{}"
container_path = "{}"
"#,
        real_root.display(), logical.display(), real_root.display()
    );
    std::fs::write(&cp, min_cfg).unwrap();
    let sm = write_setup_marker(&tmp, ".s");
    let st = test_app_state(&cp, sm, Some(mi));
    let token = st.auth.create_privileged_session("permtest");
    let app = router(st);

    let uri = format!("/dir-perms?path={}", urlencoding::encode(logical.to_str().unwrap()));
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("perm-matrix"), "must render the POSIX rwx matrix");
    assert!(html.contains(r#"name="owner_user_uid""#), "must render hidden uid field for name translation");
    assert!(html.contains(r#"name="mode""#), "must render the mode field /apply expects");
    assert!(html.contains("class=\"octal\""), "must render the octal readout");
    // enable_acl unset on an ACL-proven serve path (tempdir) => AUTO turns
    // ACL on: the section is active and the pill says so (0.9.90).
    assert!(!html.contains("acl-sec disabled"), "auto + proven probe must not grey the ACL section");
    assert!(html.contains(">auto</span>"), "auto promotion must show the auto pill");
}

// /apply-progress must answer HTTP 286 (htmx "stop polling") once the apply is finished —
// and when no apply exists at all — while an in-flight apply keeps polling on 200.
// A plain 200 after finish left the hidden poller running forever, which yanked the panel
// out of edit mode every 350ms (the "Edit untoggles after the first Apply" bug).
#[tokio::test]
async fn apply_progress_polling_terminates() {
    use std::sync::atomic::Ordering;

    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let progress_slot = state.apply_progress.clone();
    let token = state.auth.create_privileged_session("testadmin");
    let app = router(state);

    async fn poll(app: &axum::Router, token: &str) -> (u16, String) {
        let req = Request::builder().uri("/apply-progress").body(Body::empty()).unwrap();
        let req = add_session_cookie(req, token);
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    // 1. No apply ever ran: a poller hitting this is stray and must be told to stop.
    let (status, body) = poll(&app, &token).await;
    assert_eq!(status, 286, "no-progress poll must return 286 to cancel stray pollers");
    assert!(!body.contains(r#"data-apply-finished="true""#), "no-progress shell must not carry the finished marker");

    // 2. Apply in flight: keep polling (200), live shell with an active Cancel button.
    let prog = Arc::new(crate::fs::ApplyProgress::default());
    *prog.cmd.lock().unwrap() = Some("chmod 770 /data".into());
    *progress_slot.lock().await = Some(prog.clone());
    let (status, body) = poll(&app, &token).await;
    assert_eq!(status, 200, "unfinished apply must keep the poller running");
    assert!(!body.contains(r#"data-apply-finished="true""#), "unfinished apply must not carry the finished marker");
    assert!(body.contains("cancelCurrentApply"), "live apply must render an active Cancel button");

    // 3. Apply finished: 286 stops the poll loop, and the oob shell still carries the
    //    finished marker + result text for the client's finish handler.
    prog.finished.store(true, Ordering::Relaxed);
    *prog.final_result_text.lock().unwrap() = Some("Result: 3 changed, 0 skipped, 0 errors".into());
    let (status, body) = poll(&app, &token).await;
    assert_eq!(status, 286, "finished apply must cancel htmx polling");
    assert!(body.contains(r#"data-apply-finished="true""#), "finished shell must carry the finished marker");
    assert!(body.contains("3 changed"), "finished shell must carry the final result text");
}

// The autocomplete endpoints must distinguish "LDAP unavailable" from "no match".
// The test LLDAP client has no service credentials, so list_users/list_groups
// short-circuit to None before any network I/O — deterministic and fast.
#[tokio::test]
async fn users_and_groups_search_routes_render_fallback_without_ldap() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let token = state.auth.create_privileged_session("searchtest");
    let app = router(state);

    for uri in ["/users/search?owner_user=test", "/groups/search?owner_group=300"] {
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let req = add_session_cookie(req, &token);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{uri} must render a fragment");
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("LLDAP search unavailable"), "{uri} without LDAP creds must say unavailable, got: {html}");
        assert!(html.contains(r#"class="suggestion"#), "{uri} note must reuse the suggestion styling");
    }

    // No session: the endpoint must not leak the suggestion machinery.
    let req = Request::builder().uri("/users/search?owner_user=test").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Unauthorized"));
}

// ===== 0.9.85: files in the tree + per-kind permission editors =====

// Share-backed state over a real tempdir, for tree / dir-perms / apply
// tests that need actual filesystem entries behind the share.
fn make_share_backed_state(
    real_root: &std::path::Path,
    logical: &str,
    tmp: &tempfile::TempDir,
) -> AppState {
    let cp = tmp.path().join("share-cfg");
    let min_cfg = format!(
        r#"ldap_uri = "ldaps://klldap.test:6360"
[storage]
container_root = "{}"
[sssd]
ldap_default_bind_dn = "uid=admin"
ldap_default_authtok = "s"
[[shares]]
name = "share"
host_path = "{}"
container_path = "{}"
"#,
        real_root.display(),
        logical,
        real_root.display()
    );
    std::fs::write(&cp, min_cfg).unwrap();
    let sm = write_setup_marker(tmp, ".share-s");
    let mi = write_capable_mountinfo(tmp, "share-mountinfo", real_root);
    test_app_state(&cp, sm, Some(mi))
}

async fn get_html(app: &axum::Router, token: &str, uri: &str) -> String {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let req = add_session_cookie(req, token);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{uri} must render");
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    String::from_utf8_lossy(&body).into_owned()
}

async fn post_form(app: &axum::Router, token: &str, uri: &str, body: String) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, token);
    app.clone().oneshot(req).await.unwrap().status()
}

// Waits for the async scan+apply task to finish and returns the recorded cmd.
async fn wait_apply_finished(
    progress_slot: &Arc<Mutex<Option<Arc<crate::fs::ApplyProgress>>>>,
) -> String {
    use std::time::Duration;
    use tokio::time::timeout;
    timeout(Duration::from_secs(2), async {
        loop {
            if let Some(prog) = progress_slot.lock().await.as_ref() {
                if prog.finished.load(std::sync::atomic::Ordering::Relaxed) {
                    return prog.cmd.lock().expect("poison").clone().unwrap_or_default();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("apply must finish")
}

// Like wait_apply_finished, but returns the final result text — the Apply
// Log body carrying per-op outcomes and the traversal-fusion notices.
async fn wait_apply_result_text(
    progress_slot: &Arc<Mutex<Option<Arc<crate::fs::ApplyProgress>>>>,
) -> String {
    use std::time::Duration;
    use tokio::time::timeout;
    timeout(Duration::from_secs(2), async {
        loop {
            if let Some(prog) = progress_slot.lock().await.as_ref() {
                if prog.finished.load(std::sync::atomic::Ordering::Relaxed) {
                    return prog
                        .final_result_text
                        .lock()
                        .expect("poison")
                        .clone()
                        .unwrap_or_default();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("apply must finish")
}

#[tokio::test]
async fn tree_lists_files_after_dirs_with_icons_and_mtime() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("treeroot");
    std::fs::create_dir_all(real_root.join("beta")).unwrap();
    std::fs::create_dir_all(real_root.join("Alpha")).unwrap();
    std::fs::write(real_root.join("zeta.txt"), b"z").unwrap();
    std::fs::write(real_root.join("Movie.MKV"), b"m").unwrap();
    std::fs::write(real_root.join(".hidden"), b"h").unwrap();
    std::fs::write(real_root.join("script.sh"), b"#!/bin/sh").unwrap();
    std::fs::write(real_root.join("game.exe"), b"MZ").unwrap();
    let st = make_share_backed_state(&real_root, "/treedata", &tmp);
    let token = st.auth.create_privileged_session("treetest");
    let app = router(st);

    let html = get_html(&app, &token, "/tree?path=%2Ftreedata&root=true").await;
    assert!(html.contains(r#"class="dir root-dir""#), "root row present");
    assert!(html.contains("📁"), "dir rows carry the folder emoji");
    assert!(html.contains("🎬"), ".MKV categorizes case-insensitively as movie");
    assert!(html.contains("❔"), "extension-less .hidden is unknown");
    assert!(html.contains("📜"), ".sh categorizes as script/code");
    assert!(html.contains(r#"title="script / code""#), "row icons carry hover labels");
    assert!(html.contains("🪟"), ".exe categorizes as Windows/WINE");
    assert!(html.contains(r#"data-path="/treedata/Alpha""#), "logical child paths");
    // Files carry a right-aligned modified stamp (format proven by the
    // format_mtime_utc unit test; here just its presence + this century).
    assert!(html.contains(r#"title="modified (UTC)">2"#), "file rows show mtime: {html}");
    // Ordering: dirs first (case-insensitive), then files (case-insensitive).
    let pos = |needle: &str| html.find(needle).unwrap_or_else(|| panic!("missing {needle}"));
    assert!(pos("Alpha</button>") < pos("beta</button>"), "dirs sort case-insensitively");
    assert!(pos("beta</button>") < pos(">.hidden</button>"), "dirs list before files");
    assert!(pos(">.hidden</button>") < pos("Movie.MKV</button>"));
    assert!(pos("Movie.MKV</button>") < pos("zeta.txt</button>"));
    // File rows are select-only: no caret button inside .file spans.
    assert!(html.contains(r#"class="file""#) && html.contains("file-label"));
}

#[tokio::test]
async fn tree_child_fragment_renders_empty_row_for_empty_dir() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("treeroot");
    std::fs::create_dir_all(real_root.join("empty")).unwrap();
    let st = make_share_backed_state(&real_root, "/treedata", &tmp);
    let token = st.auth.create_privileged_session("treetest");
    let app = router(st);

    let html = get_html(&app, &token, "/tree?path=%2Ftreedata%2Fempty").await;
    assert!(html.contains("tree-empty") && html.contains("(empty)"), "{html}");
    assert!(!html.contains(r#"class="dir""#) && !html.contains(r#"class="file""#));
}

#[tokio::test]
async fn dir_perms_dir_renders_matrix_with_specials_and_real_exec_bits() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("permroot");
    std::fs::create_dir_all(real_root.join("Alpha")).unwrap();
    // 0711: owner rwx, group/other execute-only. Every stored bit — x
    // included — must render truthfully now that Exec is a real column.
    std::fs::set_permissions(
        real_root.join("Alpha"),
        std::fs::Permissions::from_mode(0o711),
    )
    .unwrap();
    let st = make_share_backed_state(&real_root, "/permsdata", &tmp);
    let token = st.auth.create_privileged_session("permtest");
    let app = router(st);

    let html = get_html(&app, &token, "/dir-perms?path=%2Fpermsdata%2FAlpha").await;
    assert!(html.contains(r#"data-kind="dir""#), "dir panels are marked for the JS");
    assert!(html.contains("perm-matrix-dir"), "dir matrix renders for dirs");
    // The stored 0711 renders as-is: owner x checked, group x checked with
    // group read unchecked (traverse-only is now expressible, not warned).
    assert!(
        html.contains(r#"aria-label="Owner execute" checked"#),
        "dir matrix shows the stored owner execute bit: {html}"
    );
    assert!(
        html.contains(r#"aria-label="Group execute" checked"#),
        "dir matrix shows the stored group execute bit"
    );
    assert!(
        !html.contains(r#"aria-label="Group read" checked"#),
        "group read stays unchecked for 0711"
    );
    assert!(html.contains(r#"class="sbit""#), "setgid/sticky stay available on dirs");
    // Compaction contract: helper prose lives in title hovers, not body text.
    assert!(
        html.contains(r#"title="Read includes browse"#),
        "fuse hint lives in the Read column's hover title"
    );
    assert!(
        !html.contains("cleared on Apply"),
        "the traverse-only warning is retired — x is a real editable bit"
    );
    assert!(
        !html.contains("(inherit group)") && !html.contains("(restrict delete)")
            && !html.contains("(this directory only)") && !html.contains(">Permission bits<"),
        "parenthetical subtitles and the redundant matrix heading are gone"
    );
    // Apply-scope radios stay; the scope-gated fbit knob column is retired —
    // Exec is a real pbit on all three audiences (9 pbits total).
    assert_eq!(
        html.matches(r#"name="recursive_scope""#).count(),
        3,
        "three scope radios (none/single/all)"
    );
    assert!(html.contains(r#"value="single""#) && html.contains(r#"value="all""#));
    assert!(
        !html.contains("file-opts"),
        "the separate file-bits matrix is gone — Exec lives in the main matrix"
    );
    assert!(!html.contains("fbit"), "the scope-gated file-execute knob class is retired");
    assert_eq!(
        html.matches(r#"class="pbit""#).count(),
        9,
        "full R/W/X triad per audience"
    );
    assert!(html.contains(r#"name="file_mode""#), "hidden file_mode field survives");
}

#[tokio::test]
async fn dir_perms_file_renders_full_matrix_without_specials() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("permroot");
    std::fs::create_dir_all(&real_root).unwrap();
    std::fs::write(real_root.join("zeta.txt"), b"z").unwrap();
    let st = make_share_backed_state(&real_root, "/permsdata", &tmp);
    let token = st.auth.create_privileged_session("permtest");
    let app = router(st);

    let html = get_html(&app, &token, "/dir-perms?path=%2Fpermsdata%2Fzeta.txt").await;
    assert!(html.contains(r#"data-kind="file""#), "file panels are marked for the JS");
    assert!(
        html.contains(r#"aria-label="Owner execute""#),
        "files keep the full independent triad"
    );
    assert!(!html.contains(r#"class="sbit""#), "no special bits for files");
    assert!(!html.contains("perm-matrix-dir"), "no condensed matrix for files");
    assert!(!html.contains("Read includes browse"), "no fuse hint for files");
    assert!(!html.contains(r#"name="recursive_scope""#), "no scope radios on file panels");
    assert!(!html.contains(r#"class="fbit""#), "no file-bits editor on file panels");
    assert!(
        html.contains(r#"name="owner_user_uid""#) && html.contains(r#"name="mode""#),
        "owner + mode plumbing unchanged for files"
    );
}

// HTTP-layer extension of fs::apply_normalizes_directory_mode_but_not_files:
// an x-less mode POST (the editor submits the triad as checked — here all
// Exec boxes unchecked) fuses r→x on every directory the server walks while
// files receive exactly the explicit file_mode bits (x-less: no execute).
#[tokio::test]
async fn web_recursive_apply_xless_mode_fuses_dirs_not_files() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("xlessroot");
    std::fs::create_dir_all(real_root.join("sub")).unwrap();
    std::fs::write(real_root.join("f.txt"), b"data").unwrap();
    let st = make_share_backed_state(&real_root, "/xlessdata", &tmp);
    let slot = st.apply_progress.clone();
    let token = st.auth.create_privileged_session("xlesstest");
    let app = router(st);

    // Blank owners keep the current uid/gid so unprivileged chown succeeds.
    let status = post_form(
        &app,
        &token,
        "/apply",
        "path=%2Fxlessdata&owner_user=&owner_group=&mode=0660&recursive_scope=all&file_mode=0660&owner_user_uid=&owner_group_gid="
            .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cmd = wait_apply_finished(&slot).await;
    assert!(
        cmd.contains("read implies execute"),
        "dir applies surface the fuse note: {cmd}"
    );
    assert!(cmd.contains("files=660"), "cmd names the explicit file mode: {cmd}");
    let mode_of = |p: &std::path::Path| {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    };
    assert_eq!(mode_of(&real_root), 0o770, "share root fused r→x");
    assert_eq!(mode_of(&real_root.join("sub")), 0o770, "subdir fused r→x");
    assert_eq!(
        mode_of(&real_root.join("f.txt")),
        0o660,
        "file gets the x-less file bits — no implicit execute"
    );
}

// Requirement 3/4 of the truthful-Exec redesign: a Read-only recursive apply
// fuses every directory to r-x and the Apply Log NAMES each fused directory,
// so the refreshed panel (disk truth: r-x, not the r-- the user set) is
// explained. Files stay literal r--.
#[tokio::test]
async fn web_apply_r_only_recursive_logs_traversal_notice() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("noticeroot");
    std::fs::create_dir_all(real_root.join("sub")).unwrap();
    std::fs::write(real_root.join("f.txt"), b"data").unwrap();
    let st = make_share_backed_state(&real_root, "/noticedata", &tmp);
    let slot = st.apply_progress.clone();
    let token = st.auth.create_privileged_session("noticetest");
    let app = router(st);

    let status = post_form(
        &app,
        &token,
        "/apply",
        "path=%2Fnoticedata&owner_user=&owner_group=&mode=0444&recursive_scope=all&file_mode=0444&owner_user_uid=&owner_group_gid="
            .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rtext = wait_apply_result_text(&slot).await;
    assert!(
        rtext.contains("set with 555 to allow traversal"),
        "the log names the fused directory mode: {rtext}"
    );
    assert!(
        rtext.matches("to allow traversal").count() == 2,
        "one notice per fused directory (root + sub): {rtext}"
    );
    assert!(
        !rtext.contains("more directories"),
        "no overflow line for a 2-dir tree: {rtext}"
    );
    let mode_of = |p: &std::path::Path| {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    };
    assert_eq!(mode_of(&real_root), 0o555, "share root fused r→x");
    assert_eq!(mode_of(&real_root.join("sub")), 0o555, "subdir fused r→x");
    assert_eq!(mode_of(&real_root.join("f.txt")), 0o444, "files stay literal r--");

    // Scope None: the target dir alone is walked — exactly one notice.
    let status = post_form(
        &app,
        &token,
        "/apply",
        "path=%2Fnoticedata&owner_user=&owner_group=&mode=0400&recursive_scope=none&owner_user_uid=&owner_group_gid="
            .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rtext = wait_apply_result_text(&slot).await;
    assert!(
        rtext.contains("set with 500 to allow traversal"),
        "DirOnly scope still explains the fused target dir: {rtext}"
    );
    assert_eq!(rtext.matches("to allow traversal").count(), 1, "{rtext}");
    assert_eq!(mode_of(&real_root), 0o500, "target dir fused r→x at scope none");
}

// The staged-batch twin: an Exec-unchecked (r--) ACL set on a directory
// lands fused r-x on disk, the op's OK line carries the fusion note, and the
// refreshed panel shows the stored x checked — truthful display end to end.
#[tokio::test]
async fn web_apply_acl_x_uncheck_round_trip_logs_fusion() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (fs, progress, token, app) = acl_test_scaffold(&tmp).await;
    let ops = r#"[{"op":"set","typ":"user","id":"6262","name":"","perms":"r--","layer":"access"}]"#;
    let body = format!(
        "path=%2Facldata&owner_user=&owner_group=&mode=750&recursive_scope=none&acl_ops={}",
        urlencoding::encode(ops)
    );
    let status = post_form(&app, &token, "/apply", body).await;
    assert_eq!(status, StatusCode::OK);
    let rtext = wait_apply_result_text(&progress).await;
    assert!(
        rtext.contains("ACL set (1/1) OK:") && rtext.contains("directories fused to r-x for traversal"),
        "the op's OK line explains the dir fusion: {rtext}"
    );
    let table = fs
        .read()
        .expect("fs lock")
        .get_acl_table(std::path::Path::new("/acldata"))
        .expect("allowed");
    let entry = table
        .access
        .iter()
        .find(|l| l.tag == crate::privileged::AclTag::NamedUser(6262))
        .expect("entry present");
    assert_eq!(entry.perms.to_str(), "r-x", "dir entry landed fused");
    // The panel re-reads getfacl and must show the stored x as checked.
    let html = get_html(&app, &token, "/dir-perms?path=%2Facldata").await;
    assert!(
        html.contains(r#"class="abit" data-ch="x" aria-label="execute" checked disabled"#),
        "refreshed dir panel shows the fused execute bit checked: {html}"
    );
}

#[tokio::test]
async fn web_apply_on_file_target_is_single_node_and_unfused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("filetgt");
    std::fs::create_dir_all(real_root.join("sub")).unwrap();
    std::fs::write(real_root.join("f1.txt"), b"1").unwrap();
    std::fs::write(real_root.join("sub/f2.txt"), b"2").unwrap();
    std::fs::set_permissions(
        real_root.join("sub/f2.txt"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let st = make_share_backed_state(&real_root, "/filedata", &tmp);
    let slot = st.apply_progress.clone();
    let token = st.auth.create_privileged_session("filetest");
    let app = router(st);

    // recursive_scope=all on purpose: the server must brace file targets
    // to the node itself no matter what scope a hand-crafted POST claims.
    let status = post_form(
        &app,
        &token,
        "/apply",
        format!(
            "path={}&owner_user=&owner_group=&mode=0640&recursive_scope=all&file_mode=0777&owner_user_uid=&owner_group_gid=",
            urlencoding::encode("/filedata/f1.txt")
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cmd = wait_apply_finished(&slot).await;
    assert!(
        !cmd.contains("-R") && !cmd.contains("read implies execute")
            && !cmd.contains("dirs=") && !cmd.contains("directly inside"),
        "file target renders a plain single-node cmd: {cmd}"
    );
    let mode_of = |p: &std::path::Path| {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    };
    assert_eq!(mode_of(&real_root.join("f1.txt")), 0o640, "exact raw mode, no fuse");
    assert_eq!(
        mode_of(&real_root.join("sub/f2.txt")),
        0o600,
        "a claimed recursive scope on a file must not walk anywhere else"
    );
}

async fn post_form_html(app: &axum::Router, token: &str, uri: &str, body: String) -> String {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, token);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    String::from_utf8_lossy(&b).into_owned()
}

// Seeds root 0755 { f1.txt 0600, sub/ 0755, sub/f2.txt 0600 } under the tempdir.
fn seed_scope_tree(real_root: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(real_root.join("sub")).unwrap();
    std::fs::set_permissions(real_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(real_root.join("f1.txt"), b"1").unwrap();
    std::fs::write(real_root.join("sub/f2.txt"), b"2").unwrap();
    std::fs::set_permissions(real_root.join("f1.txt"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(real_root.join("sub"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(real_root.join("sub/f2.txt"), std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn disk_mode(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

#[tokio::test]
async fn web_apply_scope_none_touches_directory_inode_only() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("scopenone");
    seed_scope_tree(&real_root);
    let st = make_share_backed_state(&real_root, "/scopedata", &tmp);
    let slot = st.apply_progress.clone();
    let token = st.auth.create_privileged_session("scopetest");
    let app = router(st);

    let status = post_form(
        &app, &token, "/apply",
        "path=%2Fscopedata&owner_user=&owner_group=&mode=0660&recursive_scope=none&owner_user_uid=&owner_group_gid="
            .to_string(),
    ).await;
    assert_eq!(status, StatusCode::OK);
    let cmd = wait_apply_finished(&slot).await;
    assert!(cmd.contains("(directory only)"), "None scope is labeled in the log: {cmd}");
    assert_eq!(disk_mode(&real_root), 0o770, "the directory inode fuses");
    assert_eq!(disk_mode(&real_root.join("f1.txt")), 0o600, "immediate files untouched at None");
    assert_eq!(disk_mode(&real_root.join("sub")), 0o755);
    assert_eq!(disk_mode(&real_root.join("sub/f2.txt")), 0o600);
}

#[tokio::test]
async fn web_apply_scope_single_spares_subdirectories() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("scopesingle");
    seed_scope_tree(&real_root);
    let st = make_share_backed_state(&real_root, "/scopedata", &tmp);
    let slot = st.apply_progress.clone();
    let token = st.auth.create_privileged_session("scopetest");
    let app = router(st);

    let status = post_form(
        &app, &token, "/apply",
        "path=%2Fscopedata&owner_user=&owner_group=&mode=0660&recursive_scope=single&file_mode=0640&owner_user_uid=&owner_group_gid="
            .to_string(),
    ).await;
    assert_eq!(status, StatusCode::OK);
    let cmd = wait_apply_finished(&slot).await;
    assert!(
        cmd.contains("single directory") && cmd.contains("files=640"),
        "single scope + file mode named in the log: {cmd}"
    );
    assert_eq!(disk_mode(&real_root), 0o770, "dir fused");
    assert_eq!(disk_mode(&real_root.join("f1.txt")), 0o640, "direct file gets the file bits");
    assert_eq!(disk_mode(&real_root.join("sub")), 0o755, "subdir spared");
    assert_eq!(disk_mode(&real_root.join("sub/f2.txt")), 0o600, "nested file spared");
}

#[tokio::test]
async fn web_apply_scope_all_grants_file_execute_only_when_chosen() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("scopeall");
    seed_scope_tree(&real_root);
    let st = make_share_backed_state(&real_root, "/scopedata", &tmp);
    let slot = st.apply_progress.clone();
    let token = st.auth.create_privileged_session("scopetest");
    let app = router(st);

    let status = post_form(
        &app, &token, "/apply",
        "path=%2Fscopedata&owner_user=&owner_group=&mode=0660&recursive_scope=all&file_mode=0754&owner_user_uid=&owner_group_gid="
            .to_string(),
    ).await;
    assert_eq!(status, StatusCode::OK);
    let cmd = wait_apply_finished(&slot).await;
    assert!(cmd.contains("files=754"), "explicit file mode in the log: {cmd}");
    assert_eq!(disk_mode(&real_root), 0o770);
    assert_eq!(disk_mode(&real_root.join("sub")), 0o770, "all dirs fused");
    assert_eq!(
        disk_mode(&real_root.join("f1.txt")),
        0o754,
        "file execute lands only because it was explicitly chosen"
    );
    assert_eq!(disk_mode(&real_root.join("sub/f2.txt")), 0o754);
}

#[tokio::test]
async fn web_apply_rejects_special_bits_in_file_mode() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real_root = tmp.path().join("scopebad");
    seed_scope_tree(&real_root);
    let st = make_share_backed_state(&real_root, "/scopedata", &tmp);
    let token = st.auth.create_privileged_session("scopetest");
    let app = router(st);

    let html = post_form_html(
        &app, &token, "/apply",
        "path=%2Fscopedata&owner_user=&owner_group=&mode=0660&recursive_scope=all&file_mode=2660&owner_user_uid=&owner_group_gid="
            .to_string(),
    ).await;
    assert!(
        html.contains("special bits") && html.contains("nothing was changed"),
        "setgid in file_mode must be rejected up front: {html}"
    );
    assert_eq!(disk_mode(&real_root), 0o755, "rejection happens before any chmod");
    assert_eq!(disk_mode(&real_root.join("f1.txt")), 0o600);
}

#[tokio::test]
async fn html_pages_are_no_store_but_assets_keep_their_cache_policy() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let app = router(state);

    let login = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(
        login
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "auth-sensitive HTML must never be replayed from browser cache"
    );

    let css = app
        .oneshot(
            Request::builder()
                .uri("/assets/style.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        css.headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("public, max-age=3600"),
        "an explicit asset cache policy wins over the HTML no-store default"
    );
}

// ---------------------------------------------------------------------------
// Admin pane: change-password authorization matrix, maintenance endpoints,
// pane render contract, and the session-timeout FieldSpec round-trip.
// ---------------------------------------------------------------------------

fn change_pw_body(current: Option<&str>, new: &str, confirm: &str) -> String {
    let mut b = format!("new_password={new}&confirm_password={confirm}");
    if let Some(c) = current {
        b.push_str(&format!("&current_password={c}"));
    }
    b
}

async fn post_change_password(
    app: &axum::Router,
    token: &str,
    body: String,
) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/settings/change-password")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let req = add_session_cookie(req, token);
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn settings_change_password_localhost_matrix() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    state.auth.set_simple_password("oldpassword").unwrap();
    let auth = state.auth.clone();
    let acting = auth.create_privileged_session("localhost");
    let other_local = auth.create_privileged_session("localhost");
    let ldap_admin = auth.create_privileged_session("someadmin");
    let app = router(state);

    // Wrong current password: 200 error page, nothing rotated.
    let (st, html) =
        post_change_password(&app, &acting, change_pw_body(Some("wrong"), "newpassword1", "newpassword1")).await;
    assert_eq!(st, StatusCode::OK);
    assert!(html.contains("alert-danger") && html.contains("Password not changed"), "{html}");
    assert!(auth.validate_simple_password("localhost", "oldpassword").is_ok());

    // Confirmation mismatch and a too-short password both refuse.
    let (_, html) =
        post_change_password(&app, &acting, change_pw_body(Some("oldpassword"), "newpassword1", "different1")).await;
    assert!(html.contains("do not match"), "{html}");
    let (_, html) =
        post_change_password(&app, &acting, change_pw_body(Some("oldpassword"), "short1", "short1")).await;
    assert!(html.contains("at least 8"), "{html}");
    assert!(auth.validate_simple_password("localhost", "oldpassword").is_ok());

    // Correct current password rotates and signs out the other localhost session.
    let (st, html) =
        post_change_password(&app, &acting, change_pw_body(Some("oldpassword"), "newpassword1", "newpassword1")).await;
    assert_eq!(st, StatusCode::OK);
    assert!(html.contains("alert-success") && html.contains("Signed out 1 other localhost session"), "{html}");
    assert!(auth.validate_simple_password("localhost", "newpassword1").is_ok());
    assert!(auth.validate_simple_password("localhost", "oldpassword").is_err());
    assert_eq!(auth.validate(&acting).as_deref(), Some("localhost"), "acting session survives");
    assert!(auth.validate(&other_local).is_none(), "other localhost session dropped");
    assert_eq!(auth.validate(&ldap_admin).as_deref(), Some("someadmin"), "LDAP session untouched");
}

#[tokio::test]
async fn settings_change_password_ldap_admin_paths() {
    // One test drives all three live-check outcomes so the TEST_LIVE_ADMIN_CHECK
    // env hook is never observed half-set by a parallel test.
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    state.auth.set_simple_password("oldpassword").unwrap();
    let auth = state.auth.clone();
    let admin = auth.create_privileged_session("someadmin");
    let stale_local = auth.create_privileged_session("localhost");
    let app = router(state);

    // Env unset: the offline test client has no service creds -> fail closed.
    let (st, html) =
        post_change_password(&app, &admin, change_pw_body(None, "newpassword1", "newpassword1")).await;
    assert_eq!(st, StatusCode::OK);
    assert!(html.contains("alert-danger") && html.contains("failing closed"), "{html}");
    assert!(auth.validate_simple_password("localhost", "oldpassword").is_ok());

    // Live member: rotates without the current password (recovery path) and
    // signs out localhost sessions while keeping the acting LDAP session.
    std::env::set_var("TEST_LIVE_ADMIN_CHECK", "member");
    let (_, html) =
        post_change_password(&app, &admin, change_pw_body(None, "newpassword1", "newpassword1")).await;
    std::env::set_var("TEST_LIVE_ADMIN_CHECK", "not-member");
    assert!(html.contains("alert-success"), "{html}");
    assert!(auth.validate_simple_password("localhost", "newpassword1").is_ok());
    assert!(auth.validate(&stale_local).is_none(), "localhost sessions dropped");
    assert_eq!(auth.validate(&admin).as_deref(), Some("someadmin"), "acting admin kept");

    // Live non-member: denied.
    let (_, html) =
        post_change_password(&app, &admin, change_pw_body(None, "anotherpw123", "anotherpw123")).await;
    std::env::remove_var("TEST_LIVE_ADMIN_CHECK");
    assert!(html.contains("alert-danger") && html.contains("not a member"), "{html}");
    assert!(auth.validate_simple_password("localhost", "newpassword1").is_ok());
}

#[tokio::test]
async fn settings_admin_pane_renders_for_both_principals() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let auth = state.auth.clone();
    let local = auth.create_privileged_session("localhost");
    let admin = auth.create_privileged_session("someadmin");
    let app = router(state);

    let get = |token: String| {
        let app = app.clone();
        async move {
            let req = Request::builder().uri("/settings").body(Body::empty()).unwrap();
            let req = add_session_cookie(req, &token);
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
            String::from_utf8_lossy(&body).into_owned()
        }
    };

    let html = get(local.clone()).await;
    // Pane renamed: admin rail item + section, no stale apply names.
    assert!(html.contains(r#"data-pane="admin""#) && html.contains(">Admin<"), "{html}");
    assert!(!html.contains(r#"data-pane="apply""#) && !html.contains(r#"data-pane-content="apply""#));
    // Restart block intact, new blocks present.
    assert!(html.contains(r#"action="/settings/restart""#));
    assert!(html.contains(r#"action="/settings/change-password""#));
    // FS probe lives in Overview; the identity-refresh button is gone (endpoint stays).
    assert!(html.contains("reprobe-fs-btn") && !html.contains("refresh-identity-btn"));
    assert!(html.contains(r#"name="webui_session_timeout_minutes""#) && html.contains(r#"form="settings-form""#));
    // Overview rows: version + bind URL (test harness always binds 0.0.0.0:9630, TLS on).
    assert!(html.contains(env!("CARGO_PKG_VERSION")));
    assert!(html.contains("https://0.0.0.0:9630"));
    // localhost sees the current-password field.
    assert!(html.contains(r#"name="current_password""#));

    // An LDAP admin sees the live-recheck note instead of a current-password field.
    let html = get(admin.clone()).await;
    assert!(!html.contains(r#"name="current_password""#));
    assert!(html.contains("membership check authorizes this change"), "{html}");
}

#[tokio::test]
async fn settings_maintenance_endpoints_gate_and_report() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let auth = state.auth.clone();
    let token = auth.create_privileged_session("localhost");
    let app = router(state);

    for uri in ["/settings/reprobe-filesystems", "/settings/refresh-identity"] {
        let req = Request::builder().method("POST").uri(uri).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert!(resp.status().is_redirection(), "{uri} must gate on auth");
    }

    // Re-probe classifies the fixture share: noacl ext4 -> auto (off)/incapable.
    let req = Request::builder()
        .method("POST")
        .uri("/settings/reprobe-filesystems")
        .body(Body::empty())
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json = String::from_utf8_lossy(&body);
    assert!(json.contains(r#""ok":true"#), "{json}");
    assert!(json.contains("share 'data'") && json.contains("incapable"), "{json}");

    // Identity refresh fails honestly on the creds-less offline test client.
    let req = Request::builder()
        .method("POST")
        .uri("/settings/refresh-identity")
        .body(Body::empty())
        .unwrap();
    let req = add_session_cookie(req, &token);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json = String::from_utf8_lossy(&body);
    assert!(json.contains(r#""ok":false"#) && json.contains("service credentials"), "{json}");
}

#[tokio::test]
async fn settings_save_roundtrips_session_timeout() {
    let (state, _tmp) = make_test_state_with_limited_fs_mountinfo();
    let cp = state.config_path.clone();
    let auth = state.auth.clone();
    let token = auth.create_privileged_session("localhost");
    let app = router(state);

    let save = |body: &'static str| {
        let app = app.clone();
        let token = token.clone();
        async move {
            let req = Request::builder()
                .method("POST")
                .uri("/settings/save")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap();
            let req = add_session_cookie(req, &token);
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let b = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
            String::from_utf8_lossy(&b).into_owned()
        }
    };

    let html = save("webui_session_timeout_minutes=45").await;
    assert!(html.contains(r#"value="45""#), "render reflects the saved value: {html}");
    let written = std::fs::read_to_string(&cp).unwrap();
    assert!(written.contains("[webui]") && written.contains("session_timeout_minutes = 45"), "{written}");

    // Below the floor: validation refuses at 200 with an error box, no write.
    let html = save("webui_session_timeout_minutes=3").await;
    assert!(html.contains("Validation error") && html.contains("alert-danger"), "{html}");
    let written = std::fs::read_to_string(&cp).unwrap();
    assert!(written.contains("session_timeout_minutes = 45"), "failed save must not touch the file");

    // Blank clears back to the default (key removed).
    let _ = save("webui_session_timeout_minutes=").await;
    let written = std::fs::read_to_string(&cp).unwrap();
    assert!(!written.contains("session_timeout_minutes"), "{written}");
}
