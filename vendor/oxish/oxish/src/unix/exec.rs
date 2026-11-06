use core::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use std::{
    collections::VecDeque,
    io,
    process::{ExitStatus, Stdio},
};

use rustix::process::{Pid, Signal, kill_process_group};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::timeout,
    sync::OwnedSemaphorePermit,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
};
use tracing::debug;

use crate::GitCommand;

/// A validated Git command running with piped stdio and no terminal
///
/// Everything here is non-blocking: inbound channel data is queued (the caller bounds the queue
/// with the SSH window) and written to the child when its pipe accepts it, and the output pipes
/// are read only when the caller has window to send. The child runs in its own process group so
/// that it and anything it spawned can be killed together.
pub(crate) struct GitProcess {
    child: Option<Child>,
    group: Option<Pid>,
    stdin: Option<ChildStdin>,
    queue: VecDeque<u8>,
    stdin_closing: bool,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    status: Option<ExitStatus>,
    permit: Option<OwnedSemaphorePermit>,
}

/// Which child output pipe to read
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Output {
    Stdout,
    Stderr,
}

impl GitProcess {
    /// Spawn a validated command; `protocol` is an already validated `GIT_PROTOCOL` value
    ///
    /// The permit stays held until the child has been reaped, including while it is being stopped.
    pub(crate) fn spawn(
        command: &GitCommand,
        protocol: Option<&str>,
        permit: OwnedSemaphorePermit,
    ) -> io::Result<Self> {
        let mut cmd = Command::new(&command.program);
        cmd.args(&command.args)
            .env_clear()
            .envs(command.env.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true);
        if let Some(protocol) = protocol {
            cmd.env("GIT_PROTOCOL", protocol);
        }

        debug!(program = ?command.program, args = ?command.args, "spawning git");
        let mut child = cmd.spawn()?;
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw);
        let missing = |name| io::Error::other(format!("spawned git has no {name}"));
        Ok(Self {
            stdin: Some(child.stdin.take().ok_or_else(|| missing("stdin"))?),
            stdout: Some(child.stdout.take().ok_or_else(|| missing("stdout"))?),
            stderr: Some(child.stderr.take().ok_or_else(|| missing("stderr"))?),
            child: Some(child),
            group,
            queue: VecDeque::new(),
            stdin_closing: false,
            status: None,
            permit: Some(permit),
        })
    }

    /// Queue channel data for the child's stdin
    ///
    /// Returns false when the child no longer reads its stdin and the data was dropped.
    pub(crate) fn queue_stdin(&mut self, data: &[u8]) -> bool {
        if self.stdin.is_none() {
            return false;
        }
        self.queue.extend(data);
        true
    }

    /// Close the child's stdin once everything queued has been written
    pub(crate) fn close_stdin(&mut self) {
        self.stdin_closing = true;
    }

    /// Write queued data to the child
    ///
    /// Returns the number of queued bytes that left the queue (written, or discarded because
    /// the child closed its stdin) once there is any, so the caller can return that much window
    /// to the client. Pending means nothing moved.
    pub(crate) fn poll_stdin(&mut self, cx: &mut Context<'_>) -> Poll<usize> {
        let mut moved = 0;
        while let Some(stdin) = self.stdin.as_mut() {
            if self.queue.is_empty() {
                if self.stdin_closing {
                    self.stdin = None;
                }
                break;
            }

            let (front, _) = self.queue.as_slices();
            match Pin::new(stdin).poll_write(cx, front) {
                Poll::Ready(Ok(written)) => {
                    self.queue.drain(..written);
                    moved += written;
                }
                Poll::Ready(Err(error)) => {
                    debug!(%error, "git closed its stdin; discarding queued data");
                    moved += self.queue.len();
                    self.queue.clear();
                    self.stdin = None;
                }
                Poll::Pending => break,
            }
        }

        match moved {
            0 => Poll::Pending,
            moved => Poll::Ready(moved),
        }
    }

    /// Whether nothing is waiting to be written to the child
    pub(crate) fn stdin_drained(&self) -> bool {
        self.queue.is_empty()
    }

    /// Read from stdout or stderr
    ///
    /// `Ready(Ok(0))` means end of file; the pipe is then closed and never read again.
    pub(crate) fn poll_output(
        &mut self,
        output: Output,
        buf: &mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let mut read_buf = ReadBuf::new(buf);
        let result = match output {
            Output::Stdout => match self.stdout.as_mut() {
                Some(pipe) => Pin::new(pipe).poll_read(cx, &mut read_buf),
                None => return Poll::Ready(Ok(0)),
            },
            Output::Stderr => match self.stderr.as_mut() {
                Some(pipe) => Pin::new(pipe).poll_read(cx, &mut read_buf),
                None => return Poll::Ready(Ok(0)),
            },
        };

        match result {
            Poll::Ready(Ok(())) => {
                let read = read_buf.filled().len();
                if read == 0 {
                    self.close_output(output);
                }
                Poll::Ready(Ok(read))
            }
            Poll::Ready(Err(error)) => {
                self.close_output(output);
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Stop reading an output pipe
    pub(crate) fn close_output(&mut self, output: Output) {
        match output {
            Output::Stdout => self.stdout = None,
            Output::Stderr => self.stderr = None,
        }
    }

    /// Whether both output pipes have reached end of file
    pub(crate) fn outputs_closed(&self) -> bool {
        self.stdout.is_none() && self.stderr.is_none()
    }

    /// Whether the given output pipe is still open
    pub(crate) fn output_open(&self, output: Output) -> bool {
        match output {
            Output::Stdout => self.stdout.is_some(),
            Output::Stderr => self.stderr.is_some(),
        }
    }

    /// Wait for the child to exit, reaping it; the status is remembered
    pub(crate) fn poll_exit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ExitStatus>> {
        if let Some(status) = self.status {
            return Poll::Ready(Ok(status));
        }

        let Some(child) = self.child.as_mut() else {
            return Poll::Ready(Err(io::Error::other("git process already released")));
        };

        let mut wait = core::pin::pin!(child.wait());
        match wait.as_mut().poll(cx) {
            Poll::Ready(Ok(status)) => {
                self.status = Some(status);
                Poll::Ready(Ok(status))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Stop the child in the background: end its stdin, then signal it if it lingers
    ///
    /// Closing stdin first lets Git leave through its own fatal path, which removes the
    /// quarantine directory of an interrupted push; Git does not remove it when a signal stops
    /// `index-pack`. Output is discarded meanwhile so a write cannot kill it with `SIGPIPE`. The
    /// reaper task owns the child and the permit, so a `SIGKILL` can never hit a recycled
    /// process ID and the command counts against the budget until it was reaped.
    pub(crate) fn terminate(&mut self) {
        self.stdin = None;
        self.queue.clear();
        if self.status.is_some() {
            return;
        }

        let Some(mut child) = self.child.take() else {
            return;
        };
        let group = self.group;
        let (stdout, stderr) = (self.stdout.take(), self.stderr.take());
        let permit = self.permit.take();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            signal_group(group, Signal::KILL);
            let _ = child.start_kill();
            return;
        };
        runtime.spawn(async move {
            stop(&mut child, group, stdout, stderr).await;
            drop(permit);
        });
    }
}

/// How long a command may take to exit after its stdin ended before it is sent `SIGTERM`
const STDIN_EOF_GRACE: Duration = Duration::from_secs(1);
/// How long a command may take to exit after `SIGTERM` before it is killed
const TERMINATE_GRACE: Duration = Duration::from_secs(3);
/// The longest a stopping command keeps its permit, short of a process that survives `SIGKILL`
pub(crate) const STOP_LIMIT: Duration = STDIN_EOF_GRACE.saturating_add(TERMINATE_GRACE);

async fn stop(
    child: &mut Child,
    group: Option<Pid>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
) {
    let drain = async move {
        tokio::join!(discard(stdout), discard(stderr));
        core::future::pending::<()>().await
    };
    let escalate = async {
        if timeout(STDIN_EOF_GRACE, child.wait()).await.is_ok() {
            return;
        }
        signal_group(group, Signal::TERM);
        if timeout(TERMINATE_GRACE, child.wait()).await.is_ok() {
            return;
        }
        signal_group(group, Signal::KILL);
        let _ = child.kill().await;
    };
    tokio::select! {
        () = escalate => {}
        () = drain => {}
    }
}

async fn discard<R: AsyncRead + Unpin>(pipe: Option<R>) {
    if let Some(mut pipe) = pipe {
        let _ = tokio::io::copy(&mut pipe, &mut tokio::io::sink()).await;
    }
}

fn signal_group(group: Option<Pid>, signal: Signal) {
    if let Some(group) = group {
        if let Err(error) = kill_process_group(group, signal) {
            debug!(%error, ?signal, "error signaling git process group");
        }
    }
}

impl Drop for GitProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}
