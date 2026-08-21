//! shared runner for external analyzer and plugin subprocesses.
//!
//! centralizes the spawn + pipe-drain + optional-timeout logic for the
//! built-in analyzers and the plugin system.

use std::io;
use std::process::{Child, Command, ExitStatus, Stdio};
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

/// run with a timeout, killing the child (and, on Unix, its whole subprocess
/// tree) if it exceeds the deadline.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> io::Result<Run> {
    // put the child in its own process group so, on timeout, we can signal the
    // entire subprocess tree at once. killing only the direct child would leave
    // grandchildren that inherited the stdio pipes (a `cargo`/`rustc` under
    // `cargo geiger`, a `go build` under `go-geiger`) holding the write ends
    // open, and the drain-thread joins below would then block until that
    // orphaned tree finished on its own, so the deadline would not be a real
    // wall-clock cap.
    set_own_process_group(cmd);

    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    let stdout_pipe = child.stdout.take().expect("stdout piped");
    let stderr_pipe = child.stderr.take().expect("stderr piped");

    wait_and_drain(&mut child, stdout_pipe, stderr_pipe, timeout)
}

/// wait for `child` up to `timeout` while both streams drain on background
/// threads, so a child that fills an OS pipe buffer cannot deadlock the wait.
///
/// generic over the readers so tests can drive either arm with a failing one.
fn wait_and_drain<O, E>(
    child: &mut Child,
    stdout_pipe: O,
    stderr_pipe: E,
    timeout: Duration,
) -> io::Result<Run>
where
    O: io::Read + Send + 'static,
    E: io::Read + Send + 'static,
{
    let stdout_thread = std::thread::spawn(move || drain(stdout_pipe));
    let stderr_thread = std::thread::spawn(move || drain(stderr_pipe));

    match child.wait_timeout(timeout)? {
        Some(status) => {
            // join both before propagating, so one failed stream still reaps the
            // other drain thread.
            let stdout = finish_drain(stdout_thread.join(), "stdout");
            let stderr = finish_drain(stderr_thread.join(), "stderr");
            Ok(Run::Completed(Output {
                status,
                stdout: stdout?,
                stderr: stderr?,
            }))
        }
        None => {
            // timed out: kill the whole tree so every inherited pipe write end
            // closes, then join the now-unblocked drain threads before returning.
            // the kill cuts those reads short by design, so their errors are
            // discarded along with the buffers.
            kill_child_tree(child);
            stdout_thread.join().ok();
            stderr_thread.join().ok();
            Ok(Run::TimedOut)
        }
    }
}

/// read one of the child's pipes to end, yielding a read that fails partway as
/// an error rather than as the bytes collected so far.
fn drain<R: io::Read>(mut pipe: R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    pipe.read_to_end(&mut buf)?;
    Ok(buf)
}

/// turn a joined drain thread into its buffer, naming `stream` in either failure.
fn finish_drain(
    joined: std::thread::Result<io::Result<Vec<u8>>>,
    stream: &str,
) -> io::Result<Vec<u8>> {
    match joined {
        Ok(Ok(buf)) => Ok(buf),
        Ok(Err(e)) => Err(io::Error::new(
            e.kind(),
            format!("failed to read child {stream}: {e}"),
        )),
        Err(_) => Err(io::Error::other(format!(
            "the {stream} drain thread panicked"
        ))),
    }
}

/// on Unix, place the child in a new process group that it leads, so its whole
/// subprocess tree can be signalled at once on timeout. a no-op elsewhere.
#[cfg(unix)]
fn set_own_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    cmd.process_group(0);
}

#[cfg(not(unix))]
fn set_own_process_group(_cmd: &mut Command) {}

/// kill a timed-out child and reap it.
///
/// on Unix the child leads its own process group (see [`set_own_process_group`]),
/// so we `SIGKILL` the entire group: this closes the stdio pipes held by any
/// grandchildren the direct child spawned, which is what lets the drain-thread
/// joins return promptly instead of waiting on an orphaned subprocess tree.
#[cfg(unix)]
fn kill_child_tree(child: &mut Child) {
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;

    // process_group(0) made the child the leader of a group whose pgid equals
    // its pid; the child has not been reaped yet, so the pid is still valid.
    let pgid = Pid::from_raw(child.id() as i32);
    // nix's killpg is a safe wrapper (no `unsafe` at the call site, so this
    // stays out of the workspace unsafe budget). best-effort: an already-dead
    // group yields ESRCH, which we ignore.
    let _ = killpg(pgid, Signal::SIGKILL);
    child.wait().ok();
}

/// non-Unix fallback: kill only the direct child. a hang inside a spawned
/// grandchild may not be interrupted.
#[cfg(not(unix))]
fn kill_child_tree(child: &mut Child) {
    child.kill().ok();
    child.wait().ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::test_spawn_guard;

    /// yields `head`, then fails instead of reporting EOF.
    struct FailingReader {
        head: io::Cursor<Vec<u8>>,
    }

    impl FailingReader {
        fn new(head: &[u8]) -> Self {
            Self {
                head: io::Cursor::new(head.to_vec()),
            }
        }
    }

    impl io::Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match io::Read::read(&mut self.head, buf)? {
                0 => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "pipe died mid-stream",
                )),
                n => Ok(n),
            }
        }
    }

    #[test]
    fn failing_reader_yields_its_bytes_before_erroring() {
        let mut reader = FailingReader::new(b"partial output");
        let mut buf = Vec::new();
        io::Read::read_to_end(&mut reader, &mut buf).ok();
        assert_eq!(buf, b"partial output");
    }

    #[test]
    fn drain_returns_the_whole_stream() {
        assert_eq!(drain(&b"complete output"[..]).unwrap(), b"complete output");
    }

    #[test]
    fn drain_errors_on_a_read_that_fails_partway() {
        let err = drain(FailingReader::new(b"partial output")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn finish_drain_names_the_stream_and_keeps_the_error_kind() {
        let failed: std::thread::Result<io::Result<Vec<u8>>> = Ok(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "pipe died mid-stream",
        )));
        let err = finish_drain(failed, "stdout").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(err.to_string().contains("stdout"), "{err}");
    }

    #[test]
    fn finish_drain_turns_a_panicked_thread_into_an_error() {
        let panicked: std::thread::Result<io::Result<Vec<u8>>> = Err(Box::new("boom"));
        let err = finish_drain(panicked, "stderr").unwrap_err();
        assert!(err.to_string().contains("stderr"), "{err}");
    }

    /// a child that has already exited, so [`wait_and_drain`] takes its completed arm.
    fn spawn_immediate_child() -> Child {
        Command::new("/bin/echo")
            .arg("ok")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn /bin/echo")
    }

    #[test]
    fn completed_arm_propagates_a_failed_stdout_drain() {
        let _lock = test_spawn_guard();
        let mut child = spawn_immediate_child();
        let Err(err) = wait_and_drain(
            &mut child,
            FailingReader::new(b"partial output"),
            io::empty(),
            Duration::from_secs(10),
        ) else {
            panic!("a failed stdout drain must not be reported as a completed run");
        };
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(err.to_string().contains("stdout"), "{err}");
    }

    #[test]
    fn completed_arm_propagates_a_failed_stderr_drain() {
        let _lock = test_spawn_guard();
        let mut child = spawn_immediate_child();
        let Err(err) = wait_and_drain(
            &mut child,
            io::empty(),
            FailingReader::new(b"partial output"),
            Duration::from_secs(10),
        ) else {
            panic!("a failed stderr drain must not be reported as a completed run");
        };
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(err.to_string().contains("stderr"), "{err}");
    }

    #[test]
    fn completed_arm_returns_each_stream_in_its_own_field() {
        let _lock = test_spawn_guard();
        let mut child = spawn_immediate_child();
        let run = wait_and_drain(
            &mut child,
            &b"the output"[..],
            &b"the diagnostics"[..],
            Duration::from_secs(10),
        )
        .unwrap();
        match run {
            Run::Completed(out) => {
                assert!(out.status.success());
                assert_eq!(out.stdout, b"the output");
                assert_eq!(out.stderr, b"the diagnostics");
            }
            Run::TimedOut => panic!("a child that already exited must not time out"),
        }
    }

    #[test]
    fn timed_out_arm_discards_a_failed_drain() {
        let _lock = test_spawn_guard();
        let mut cmd = Command::new("sleep");
        cmd.arg("60").stdout(Stdio::null()).stderr(Stdio::null());
        // the kill below signals the whole group, so the child must lead one.
        set_own_process_group(&mut cmd);
        let mut child = cmd.spawn().expect("spawn sleep");
        let run = wait_and_drain(
            &mut child,
            FailingReader::new(b"partial output"),
            io::empty(),
            Duration::from_secs(1),
        )
        .unwrap();
        match run {
            Run::TimedOut => {}
            Run::Completed(_) => panic!("a slow process should have timed out"),
        }
    }

    #[test]
    fn no_timeout_runs_to_completion() {
        // shared spawn lock: keep this subprocess's fork from overlapping a
        // concurrent script write in another test module (ETXTBSY).
        let _lock = test_spawn_guard();
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
        let _lock = test_spawn_guard();
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
        let _lock = test_spawn_guard();
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

    // the analyzers this runner protects (cargo geiger, go-geiger) do their real
    // work in grandchildren that inherit the stdio pipes, so the timeout must
    // reap the whole process tree, not just the direct child.
    #[cfg(unix)]
    #[test]
    fn timeout_kills_whole_process_tree_promptly() {
        use std::time::Instant;

        let _lock = test_spawn_guard();
        // `sleep 30 | cat` runs sleep and cat as grandchildren of the shell,
        // both holding our inherited stdout pipe. killing only the shell would
        // orphan them and the drain-thread joins would block for the full 30s;
        // the process-group kill must tear the tree down well before then.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("sleep 30 | cat");

        let start = Instant::now();
        match run_process(&mut cmd, Some(Duration::from_secs(1))).unwrap() {
            Run::TimedOut => {}
            Run::Completed(_) => panic!("a slow process tree should have timed out"),
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout must fire promptly, not wait for orphaned grandchildren; took {elapsed:?}"
        );
    }
}
