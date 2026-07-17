//! Wall-clock-bounded subprocess execution.
//!
//! Every external command on a request or reload path must carry a ceiling:
//! `getfacl`/`setfacl` against a stalled mount, or a `generate` stuck in a
//! write probe, otherwise parks its caller (a bounded blocking thread, or the
//! supervisor loop itself) forever. Timeout kills the child and surfaces as
//! `ErrorKind::TimedOut` naming the program.

use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Poll cadence: fast first (typical getfacl finishes in ~1-2ms — keep the
/// panel path snappy), then coarse while waiting out a slow child.
const FAST_POLLS: u32 = 20;
const FAST_POLL: Duration = Duration::from_millis(1);
const SLOW_POLL: Duration = Duration::from_millis(15);

/// Run to completion with captured stdout/stderr, killing at `timeout`.
/// Stdout/stderr are drained on reader threads — a child that fills a pipe
/// while the parent only polls `try_wait` would otherwise deadlock until the
/// timeout fires even on a healthy run.
pub fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> io::Result<Output> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut out_pipe = child.stdout.take().expect("stdout piped above");
    let mut err_pipe = child.stderr.take().expect("stderr piped above");
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });
    let status = wait_or_kill(&mut child, timeout, &program);
    // Readers reach EOF once the child (or its killed remains) closes the
    // pipes; join AFTER the wait so a timeout can't leave them stranded.
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    Ok(Output {
        status: status?,
        stdout,
        stderr,
    })
}

/// Run with the parent's stdio (output streams live — used where operators
/// watch the log in real time, e.g. the supervisor's `generate`), killing at
/// `timeout`.
pub fn status_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> io::Result<std::process::ExitStatus> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd.spawn()?;
    wait_or_kill(&mut child, timeout, &program)
}

fn wait_or_kill(
    child: &mut std::process::Child,
    timeout: Duration,
    program: &str,
) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    let mut polls: u32 = 0;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{program} exceeded its {}s ceiling and was killed",
                    timeout.as_secs()
                ),
            ));
        }
        polls += 1;
        std::thread::sleep(if polls <= FAST_POLLS { FAST_POLL } else { SLOW_POLL });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_command_completes_with_output() {
        let out = run_with_timeout(
            Command::new("sh").args(["-c", "echo ok; echo err >&2"]),
            Duration::from_secs(5),
        )
        .expect("sh runs");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "err");
    }

    #[test]
    fn hung_command_is_killed_and_names_program() {
        let start = Instant::now();
        let err = run_with_timeout(
            Command::new("sleep").arg("30"),
            Duration::from_millis(200),
        )
        .expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("sleep"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(5), "killed promptly");
    }

    #[test]
    fn pipe_filling_child_does_not_deadlock() {
        // 1 MiB of output far exceeds the ~64KB pipe buffer; the reader
        // threads must drain it while the parent polls.
        let out = run_with_timeout(
            Command::new("sh").args(["-c", "head -c 1048576 /dev/zero"]),
            Duration::from_secs(10),
        )
        .expect("completes");
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 1_048_576);
    }

    #[test]
    fn status_with_timeout_kills_hung_child() {
        let err = status_with_timeout(
            Command::new("sleep").arg("30"),
            Duration::from_millis(200),
        )
        .expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
