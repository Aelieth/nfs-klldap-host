//! Navahi avahi-daemon lifecycle under the real supervisor loop: gated on the
//! conf flag, applied by full recycle, HUP'd (not bounced) on SharesApply,
//! respawned on crash.

mod common;

use common::{Supervised, TestDirs, COMPLETE_TOML};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// One supervisor at a time: cleanup pkills by the avahi-daemon comm name,
/// which would reach a sibling test's stub.
static SERIAL: Mutex<()> = Mutex::new(());

fn navahi_on_toml() -> String {
    format!(
        "{}navahi_insecure = true\n",
        COMPLETE_TOML.replacen("[sssd]", "navahi_discovery = true\n[sssd]", 1)
    )
}

fn stub_avahi(dirs: &TestDirs) -> PathBuf {
    let log = dirs.out.join("avahi-stub.log");
    let body = format!(
        "#!/bin/bash\nLOG=\"{}\"\necho START >> \"$LOG\"\ntrap 'echo HUP >> \"$LOG\"' HUP\ntrap 'echo TERM >> \"$LOG\"; exit 0' TERM\nwhile :; do sleep 0.1; done\n",
        log.display()
    );
    dirs.stub_script("avahi-daemon", &body);
    log
}

fn spawn_supervisor(dirs: &TestDirs) -> Supervised {
    let keytab = dirs.keytab();
    let recycle_marker = dirs.recycle_marker();
    dirs.stub_ganesha_trap_log();
    dirs.stub_sssd_pipe();
    dirs.stub_idhelper_fixture();
    dirs.stub_webui_trap_log();
    dirs.stub_sleeper("nfs-klldap-conf-watcher");
    dirs.stub_exit0("healthcheck.sh");
    dirs.stub_sleeper("inotifywait");
    let mut cmd = dirs.base_cmd("supervise");
    dirs.service_bins_env(&mut cmd);
    dirs.nss_env(&mut cmd);
    cmd.env("AVAHI_BIN", dirs.stubs.join("avahi-daemon"))
        .env("NFS_KLLDAP_SUPERVISOR_TICK_MS", "100")
        .env("NFS_KLLDAP_STOP_GANESHA_TERM_SECS", "2")
        .env("NFS_KLLDAP_KEYTAB_PATH", &keytab)
        .env("NFS_KLLDAP_WEBUI_LOG", dirs.out.join("webui.log"))
        .env("NFS_KLLDAP_RECYCLE_MARKER", &recycle_marker);
    Supervised::spawn(&mut cmd)
}

fn count_lines(log: &Path, word: &str) -> usize {
    fs::read_to_string(log)
        .map(|s| s.lines().filter(|l| *l == word).count())
        .unwrap_or(0)
}

#[test]
fn avahi_starts_only_with_flag_and_full_recycle_applies_flips() {
    let _s = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    // Phase 1: flag off — bring-up must not start avahi.
    {
        let dirs = TestDirs::new(COMPLETE_TOML);
        let avahi_log = stub_avahi(&dirs);
        let sup = spawn_supervisor(&dirs);
        sup.wait_for(Duration::from_secs(35), "bring-up did not complete", |c| {
            c.contains("Container is ready (pre-configured path)")
        });
        assert_eq!(count_lines(&avahi_log, "START"), 0, "flag off must not start avahi");
        let combined = sup.stop_and_log();
        assert!(!combined.contains("Started avahi-daemon"), "log={combined:?}");
    }
    // Phase 2: flag on — starts at bring-up; flip off + SIGUSR1 stops it.
    let dirs = TestDirs::new(&navahi_on_toml());
    let avahi_log = stub_avahi(&dirs);
    let sup = spawn_supervisor(&dirs);
    let l = avahi_log.clone();
    sup.wait_for(Duration::from_secs(35), "avahi did not start at bring-up", move |c| {
        c.contains("Started avahi-daemon") && count_lines(&l, "START") >= 1
    });
    dirs.edit_conf("navahi_discovery = true", "navahi_discovery = false");
    sup.sigusr1();
    let l = avahi_log.clone();
    sup.wait_for(Duration::from_secs(35), "flip-off recycle must stop avahi", move |c| {
        c.contains("Stopped avahi-daemon") && count_lines(&l, "TERM") >= 1
    });
    // A stopped-by-flag avahi must not be revived by the steady-state loop.
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(count_lines(&avahi_log, "START"), 1, "no restart after flag-off");
    // Flip back on: the next full recycle is the application path.
    dirs.edit_conf("navahi_discovery = false", "navahi_discovery = true");
    sup.sigusr1();
    let l = avahi_log.clone();
    sup.wait_for(Duration::from_secs(35), "flip-on recycle must start avahi", move |_c| {
        count_lines(&l, "START") >= 2
    });
    let _ = sup.stop_and_log();
}

#[test]
fn shares_apply_hups_avahi_and_ganesha_without_bounce() {
    let _s = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dirs = TestDirs::new(&navahi_on_toml());
    let avahi_log = stub_avahi(&dirs);
    let sup = spawn_supervisor(&dirs);
    let l = avahi_log.clone();
    sup.wait_for(Duration::from_secs(35), "avahi did not start at bring-up", move |c| {
        c.contains("Started avahi-daemon") && count_lines(&l, "START") >= 1
    });
    // Un-flag the share: the fragment loses sys/3,4 (exports delta → ganesha
    // reread) and the advert XML is pruned (avahi delta → HUP, no bounce).
    dirs.edit_conf("navahi_insecure = true", "navahi_insecure = false");
    sup.sighup();
    let l = avahi_log.clone();
    sup.wait_for(
        Duration::from_secs(25),
        "SharesApply must HUP avahi for the advert change",
        move |c| {
            c.contains("Navahi advert XMLs changed")
                && c.contains("Sent SIGHUP to avahi-daemon")
                && count_lines(&l, "HUP") >= 1
        },
    );
    assert_eq!(count_lines(&avahi_log, "TERM"), 0, "SharesApply must not bounce avahi");
    assert_eq!(count_lines(&avahi_log, "START"), 1);
    let combined = sup.stop_and_log();
    assert!(
        combined.contains("Sent SIGHUP to ganesha.nfsd") || combined.contains("ganesha=Sighup"),
        "export delta must ride the graceful reread; log={combined:?}"
    );
}

#[test]
fn crashed_avahi_respawns_within_budget() {
    let _s = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dirs = TestDirs::new(&navahi_on_toml());
    let avahi_log = stub_avahi(&dirs);
    let sup = spawn_supervisor(&dirs);
    let l = avahi_log.clone();
    sup.wait_for(Duration::from_secs(35), "avahi did not start at bring-up", move |c| {
        c.contains("Started avahi-daemon") && count_lines(&l, "START") >= 1
    });
    let stub = dirs.stubs.join("avahi-daemon");
    let killed = std::process::Command::new("pkill")
        .args(["-KILL", "-f", "--"])
        .arg(stub.to_string_lossy().as_ref())
        .status()
        .expect("pkill stub avahi");
    assert!(killed.success(), "stub avahi must have been running");
    let l = avahi_log.clone();
    sup.wait_for(Duration::from_secs(25), "dead avahi must respawn", move |c| {
        c.contains("avahi is down — respawning") && count_lines(&l, "START") >= 2
    });
    let _ = sup.stop_and_log();
}
