//! Run the child process and mask its echo.

use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};

use crate::error::{Error, Result};
use crate::inject::mask::Masker;

use super::Injection;

/// Spawn the child process and pass its exit code through.
///
/// With `mask = true` stdout/stderr go through pipes and are masked; with `false` all three fds
/// are inherited (keeping the TTY, which interactive child processes need).
pub fn execute(command: &[String], injection: &Injection, mask: bool) -> Result<i32> {
    if !mask {
        // Without masking, inherit directly: that keeps TTY semantics and saves a pipe copy (including the empty-injection case).
        return spawn_child(command, injection, ChildIo::Inherit);
    }
    spawn_child(
        command,
        injection,
        ChildIo::Piped {
            mask: true,
            out: Box::new(std::io::stdout()),
            err: Box::new(std::io::stderr()),
        },
    )
}

/// The child process's IO policy.
pub(super) enum ChildIo {
    /// All three fds are inherited. This keeps TTY semantics (which interactive child processes
    /// need) at the cost of being unable to mask — which is exactly why it is used only for `--no-masking`.
    Inherit,
    /// stdout/stderr go through pipes. With `mask` true, secrets are swapped for placeholders as
    /// they are read; with `false` the bytes pass through untouched (`execute` never uses this
    /// combination — it leaves tests an observable "unmasked" path).
    Piped {
        mask: bool,
        out: Box<dyn Write + Send>,
        err: Box<dyn Write + Send>,
    },
}

/// Spawn the child: environment = the current process environment + injected variables (overriding same-named ones), exit code passed through verbatim.
pub(super) fn spawn_child(command: &[String], injection: &Injection, io: ChildIo) -> Result<i32> {
    let (program, args) = command.split_first().ok_or_else(|| {
        Error::usage(crate::msg!(
            "no command to run; expected `akey run … -- <command>`",
            "没有要运行的命令；应为 `akey run … -- <command>`"
        ))
    })?;
    let mut child = Command::new(program);
    child.args(args);
    for (name, value) in &injection.vars {
        child.env(name, value.as_str());
    }

    match io {
        ChildIo::Inherit => Ok(exit_code(child.status()?)),
        ChildIo::Piped { mask, out, err } => {
            child
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut running = child.spawn()?;
            let stdout = running.stdout.take().ok_or_else(missing_pipe)?;
            let stderr = running.stderr.take().ok_or_else(missing_pipe)?;

            // Both streams must be read in parallel: while one stream is read on a single thread,
            // the other pipe fills up and deadlocks both the child and the reader. stdin stays
            // inherited, so interactive input is unaffected.
            let out_thread = std::thread::spawn({
                let secrets = injection.secrets();
                move || relay(stdout, out, secrets, mask)
            });
            let err_thread = std::thread::spawn({
                let secrets = injection.secrets();
                move || relay(stderr, err, secrets, mask)
            });

            let status = running.wait()?;
            join_relay(out_thread)?;
            join_relay(err_thread)?;
            Ok(exit_code(status))
        }
    }
}

/// After `Stdio::piped()` the `take()` cannot fail; failing to get a pipe can only be an internal error.
fn missing_pipe() -> Error {
    Error::Io(std::io::Error::other(crate::msg!(
        "child output pipe was not created",
        "未创建子进程的输出管道"
    )))
}

/// Reap a reader thread. A panicking thread or a failed write must be reported; the only
/// non-error is a downstream that closed first (`| head`) — then the child's exit code is the
/// answer the caller wants.
fn join_relay(handle: std::thread::JoinHandle<std::io::Result<()>>) -> Result<()> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Ok(Err(e)) => Err(Error::Io(e)),
        Err(_) => Err(Error::Io(std::io::Error::other(crate::msg!(
            "output relay thread panicked",
            "输出中继线程发生 panic"
        )))),
    }
}

/// Pump one child output stream into `sink`. With `mask` true, [`Masker`] masks chunk by chunk;
/// otherwise [`Masker`] stays disabled and passes everything through.
pub(super) fn relay(
    mut reader: impl Read,
    mut sink: Box<dyn Write + Send>,
    secrets: Vec<String>,
    mask: bool,
) -> std::io::Result<()> {
    let mut masker = if mask {
        Masker::with_secrets(secrets)
    } else {
        Masker::new()
    };
    let mut buf = [0u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let chunk = masker.push(&buf[..read]);
        if !chunk.is_empty() {
            sink.write_all(&chunk)?;
            sink.flush()?;
        }
    }
    let tail = masker.finish();
    if !tail.is_empty() {
        sink.write_all(&tail)?;
    }
    sink.flush()
}

/// Exit code pass-through. `run` is a transparent wrapper: an agent that would have seen
/// exit code 7 must still see exit code 7, or its error handling silently misfires.
fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    abnormal_exit(status)
}

/// Unix: killed by a signal → `128 + signal` (the shell convention).
#[cfg(unix)]
fn abnormal_exit(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map_or(1, |signal| 128 + signal)
}

/// Windows: there is no signal number. An abnormal termination surfaces as `NTSTATUS` in
/// `code()`, which is already reported above; reaching here means neither was available, and
/// there is no better answer than a generic failure.
#[cfg(windows)]
fn abnormal_exit(_status: ExitStatus) -> i32 {
    1
}
