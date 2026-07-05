//! shared runner for external analyzer and plugin subprocesses.
//!
//! centralizes the spawn + pipe-drain + optional-timeout logic so the built-in
//! analyzers and the plugin system share a single, tested implementation
//! instead of duplicating the delicate deadlock-avoidance dance.

use std::io::{self, Read as _};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

/// captured result of a subprocess that ran to completion.
pub(crate) struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// outcome of [`run_process`].
///
/// a timeout is not an [`io::Error`]: it is an expected control-flow result
/// that each caller renders into its own analyzer/plugin error, so it gets its
/// own variant rather than being smuggled through the `Err` channel.
pub(crate) enum Run {
    /// the child exited on its own; carries its status and captured streams.
    Completed(Output),
    /// the child outlived `timeout` and was killed.
    TimedOut,
}

/// run `cmd`, capturing stdout and stderr.
///
/// with `timeout` `None` the call blocks until the child exits (the original,
/// unbounded behaviour). with `Some(_)` the child is killed and [`Run::TimedOut`]
/// returned if it outlives the deadline.
///
/// stdout and stderr are always piped and drained on background threads so a
/// child that fills an OS pipe buffer cannot deadlock.
pub(crate) fn run_process(cmd: &mut Command, timeout: Option<Duration>) -> io::Result<Run> {
    match timeout {
        None => run_blocking(cmd),
        Some(timeout) => run_with_timeout(cmd, timeout),
    }
}

/// run to completion with no timeout. `Command::output` drains both pipes for
/// us, so no manual drain threads are needed on this path.
fn run_blocking(cmd: &mut Command) -> io::Result<Run> {
    let output = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;
    Ok(Run::Completed(Output {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }))
}

/// run with a timeout, killing the child if it exceeds the deadline.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> io::Result<Run> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    // drain stdout and stderr on background threads so a child that produces
    // lots of output cannot deadlock by filling the OS pipe buffer while we
    // block in wait_timeout.
    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stdout_pipe.read_to_end(&mut buf).ok();
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stderr_pipe.read_to_end(&mut buf).ok();
        buf
    });

    match child.wait_timeout(timeout)? {
        Some(status) => {
            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();
            Ok(Run::Completed(Output {
                status,
                stdout,
                stderr,
            }))
        }
        None => {
            // timed out — kill the child so the pipes close, then join the
            // drain threads before returning.
            child.kill().ok();
            child.wait().ok();
            stdout_thread.join().ok();
            stderr_thread.join().ok();
            Ok(Run::TimedOut)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_timeout_runs_to_completion() {
        let mut cmd = Command::new("/bin/echo");
        cmd.arg("hello");
        match run_process(&mut cmd, None).unwrap() {
            Run::Completed(out) => {
                assert!(out.status.success());
                assert_eq!(out.stdout, b"hello\n");
            }
            Run::TimedOut => panic!("must not time out when no timeout is set"),
        }
    }

    #[test]
    fn completes_within_timeout() {
        // invoke the binary directly (no shell) to avoid ETXTBSY under
        // cargo-llvm-cov and orphaned children holding the pipes open.
        let mut cmd = Command::new("/bin/echo");
        cmd.arg("ok");
        match run_process(&mut cmd, Some(Duration::from_secs(10))).unwrap() {
            Run::Completed(out) => {
                assert!(out.status.success());
                assert_eq!(out.stdout, b"ok\n");
            }
            Run::TimedOut => panic!("a fast process should complete before the deadline"),
        }
    }

    #[test]
    fn timeout_kills_slow_process() {
        // invoke `sleep` directly rather than via `/bin/sh -c`: a shell may fork
        // sleep as a child, and killing only the shell would orphan sleep
        // holding the pipes open, hanging the drain threads.
        let mut cmd = Command::new("sleep");
        cmd.arg("60");
        match run_process(&mut cmd, Some(Duration::from_secs(1))).unwrap() {
            Run::TimedOut => {}
            Run::Completed(_) => panic!("a slow process should have timed out"),
        }
    }
}
