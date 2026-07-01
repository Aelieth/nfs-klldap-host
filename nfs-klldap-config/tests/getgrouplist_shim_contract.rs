//! Contract: Ganesha 9.6 getgrouplist shim returns ret==0 and authoritative gids via idhelper socket.

use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use nfs_klldap_config::{
    normalize_linux_getgrouplist_ret, query_idhelper_socket_gids,
};

fn mock_grouplist_server(sock_path: PathBuf, stop: Arc<AtomicBool>) {
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).expect("bind mock socket");
    listener.set_nonblocking(true).ok();
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    let resp = if line.starts_with("GROUPLIST root") {
                        "OK 0|3005\n"
                    } else if line.starts_with("GROUPLIST testuser1") {
                        "OK 3002|3005|3007\n"
                    } else {
                        "ERR\n"
                    };
                    let mut w = stream;
                    let _ = w.write_all(resp.as_bytes());
                    let _ = w.shutdown(Shutdown::Both);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
}

fn shim_so_path() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws_root = manifest_dir.parent()?;
    let arch = std::env::consts::ARCH;
    let candidates = [
        ws_root.join(format!(
            "target/debug/libnfs_klldap_getgrouplist_shim.so"
        )),
        ws_root.join(format!(
            "target/{arch}-unknown-linux-gnu/debug/libnfs_klldap_getgrouplist_shim.so"
        )),
        ws_root.join(format!(
            "target/release/libnfs_klldap_getgrouplist_shim.so"
        )),
        PathBuf::from("/usr/lib/x86_64-linux-gnu/libnfs_klldap_getgrouplist_shim.so"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

#[test]
fn linux_positive_getgrouplist_ret_normalizes_to_zero_for_ganesha() {
    assert_eq!(normalize_linux_getgrouplist_ret(1), 0, "root ngroups=1 case from logs.txt");
    assert_eq!(normalize_linux_getgrouplist_ret(3), 0, "testuser1 ngroups=3 case from logs.txt");
}

#[test]
fn idhelper_socket_grouplist_returns_authoritative_gids() {
    let td = tempfile::tempdir().unwrap();
    let sock = td.path().join("idhelper.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let sock_t = sock.clone();
    let server = thread::spawn(move || mock_grouplist_server(sock_t, stop_t));
    for _ in 0..100 {
        if UnixStream::connect(&sock).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let root = query_idhelper_socket_gids(sock.to_str().unwrap(), "GROUPLIST", "root")
        .expect("GROUPLIST root");
    assert_eq!(root, vec![0, 3005]);
    let user = query_idhelper_socket_gids(sock.to_str().unwrap(), "GROUPLIST", "testuser1")
        .expect("GROUPLIST testuser1");
    assert_eq!(user, vec![3002, 3005, 3007]);
    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
}

#[test]
fn shipped_cdylib_getgrouplist_returns_zero_under_ld_preload() {
    let Some(shim) = shim_so_path() else {
        eprintln!("skip: libnfs_klldap_getgrouplist_shim.so not built (run cargo build -p nfs-klldap-getgrouplist-shim)");
        return;
    };
    let td = tempfile::tempdir().unwrap();
    let sock = td.path().join("idhelper.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let sock_t = sock.clone();
    let server = thread::spawn(move || mock_grouplist_server(sock_t, stop_t));
    for _ in 0..100 {
        if UnixStream::connect(&sock).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let script = r#"
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
getgrouplist = libc.getgrouplist
getgrouplist.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_int)]
getgrouplist.restype = ctypes.c_int
ng = ctypes.c_int(16)
groups = (ctypes.c_uint * 16)()
user = sys.argv[1].encode()
gid = int(sys.argv[2])
ret = getgrouplist(user, gid, groups, ctypes.byref(ng))
print(f"ret={ret} ngroups={ng.value} gids=" + ",".join(str(groups[i]) for i in range(ng.value)))
sys.exit(0 if ret == 0 else 1)
"#;
    let script_path = td.path().join("probe.py");
    std::fs::write(&script_path, script).unwrap();

    for (user, gid, want_gids) in [
        ("root", "0", "0,3005"),
        ("testuser1", "3002", "3002,3005,3007"),
    ] {
        let out = Command::new("python3")
            .arg(&script_path)
            .arg(user)
            .arg(gid)
            .env("LD_PRELOAD", &shim)
            .env("NFS_KLLDAP_IDHELPER_SOCKET", sock.to_str().unwrap())
            .env(
                "NFS_KLLDAP_IDHELPER_PRERESOLVE",
                "host/zima-nas@REALM,testuser1@REALM",
            )
            .output()
            .expect("python probe");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "shim getgrouplist({user}) must return ret==0: stdout={stdout} stderr={stderr}"
        );
        assert!(stdout.contains("ret=0"), "ganesha-compat ret==0: {stdout}");
        assert!(
            stdout.contains(want_gids),
            "authoritative gids for {user}: {stdout} want {want_gids}"
        );
    }

    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
}