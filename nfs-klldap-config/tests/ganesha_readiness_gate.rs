//! Integration: drives shipped check_ganesha_readiness + mock idhelper socket.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use nfs_klldap_config::{
    build_ganesha_envp, check_ganesha_readiness, filter_proc_environ_keys, GaneshaSpawnEnv,
};

fn mock_socket_server(sock: PathBuf, stop: Arc<AtomicBool>) {
    let _ = fs::remove_file(&sock);
    if let Some(p) = sock.parent() {
        let _ = fs::create_dir_all(p);
    }
    let listener = UnixListener::bind(&sock).expect("bind mock idhelper socket");
    listener.set_nonblocking(true).ok();
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    let resp = if line.starts_with("GRPS root") || line.starts_with("GROUPLIST root") {
                        "OK 0\n"
                    } else if line.starts_with("GRPS testuser1") || line.starts_with("GROUPLIST testuser1")
                    {
                        "OK 3002|3007|3005\n"
                    } else {
                        "ERR unknown\n"
                    };
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    let _ = fs::remove_file(&sock);
}

#[test]
fn check_ganesha_readiness_succeeds_with_mock_socket_and_nss_fixture() {
    let td = tempfile::tempdir().unwrap();
    let nss = td.path().join("nss");
    fs::create_dir_all(&nss).unwrap();
    let pw = nss.join("nss_passwd");
    let gr = nss.join("nss_group");
    fs::write(
        &pw,
        "root:x:0:0:root:/root:/bin/sh\n\
         testuser1:x:3788:3002:testuser1:/nonexistent:/usr/sbin/nologin\n",
    )
    .unwrap();
    fs::write(
        &gr,
        "root:x:0:root\nstaff:x:3002:testuser1\naux:x:3007:testuser1\n",
    )
    .unwrap();
    let sock = td.path().join("idhelper.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let sock_t = sock.clone();
    let server = thread::spawn(move || mock_socket_server(sock_t, stop_t));

    let wrapper = nfs_klldap_config::GaneshaNssEnv::from_runtime_defaults();
    let Some(nss_wrapper_so) = wrapper.ld_preload else {
        eprintln!("skip: libnss_wrapper.so not on host");
        return;
    };
    let cfg = GaneshaSpawnEnv {
        nss_passwd: pw.clone(),
        nss_group: gr.clone(),
        extrausers_passwd: nss.join("extrausers/passwd"),
        extrausers_group: nss.join("extrausers/group"),
        idhelper_bin: PathBuf::from("/usr/local/bin/nfs-klldap-idhelper"),
        idhelper_socket: sock.to_string_lossy().to_string(),
        nss_wrapper_so,
        use_nss_wrapper: true,
    };
    let envp = build_ganesha_envp(&cfg);
    let glog = td.path().join("ganesha.log");
    fs::write(&glog, "nfs_start :NFS STARTUP :EVENT :ok\n").unwrap();

    // Wait for mock socket
    for _ in 0..50 {
        if UnixStream::connect(&sock).is_ok() {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(20));
    }

    let report = check_ganesha_readiness(
        None,
        &envp,
        Some("testuser1"),
        glog.to_str().unwrap(),
        sock.to_str().unwrap(),
    );
    stop.store(true, Ordering::Relaxed);
    let _ = server.join();

    assert!(report.root_ok, "root id -G must succeed");
    assert!(report.sample_ok, "sample must have supplemental gids");
    assert!(report.socket_ok, "mock socket GRPS+GROUPLIST must succeed");
    assert!(report.synthetic_clean);
    // ganesha_process_ok false without live pid is expected in unit context
}

#[test]
fn filter_proc_environ_fixture_matches_supervisor_diagnostic() {
    let raw = b"LD_PRELOAD=/lib/libnss_wrapper.so\0NSS_WRAPPER_PASSWD=/var/lib/nfs-klldap/nss_passwd\0";
    let keys = filter_proc_environ_keys(raw);
    assert!(keys.iter().any(|k| k.contains("LD_PRELOAD")));
    assert!(keys.iter().any(|k| k.contains("NSS_WRAPPER_PASSWD")));
}