use core::{
    pin::Pin,
    task::{Context, Poll},
};
use std::{
    collections::VecDeque,
    io,
    process::{ExitStatus, Stdio},
};

use rustix::process::{Pid, Signal, kill_process_group};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
};
use tracing::{debug, warn};

use crate::GitCommand;

/// A validated Git command running with piped stdio and no terminal
///
/// Everything here is non-blocking: inbound channel data is queued (the caller bounds the queue
/// with the SSH window) and written to the child when its pipe accepts it, and the output pipes
/// are read only when the caller has window to send. The child runs in its own process group so
/// that it and anything it spawned can be killed together.
pub(crate) struct GitProcess {
    child: Child,
    group: Option<Pid>,
    stdin: Option<ChildStdin>,
    queue: VecDeque<u8>,
    stdin_closing: bool,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    status: Option<ExitStatus>,
}

/// Which child output pipe to read
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Output {
    Stdout,
    Stderr,
}

impl GitProcess {
    /// Spawn a validated command; `protocol` is an already validated `GIT_PROTOCOL` value
    pub(crate) fn spawn(command: &GitCommand, protocol: Option<&str>) -> io::Result<Self> {
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
            child,
            group,
            queue: VecDeque::new(),
            stdin_closing: false,
            status: None,
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

        let mut wait = core::pin::pin!(self.child.wait());
        match wait.as_mut().poll(cx) {
            Poll::Ready(Ok(status)) => {
                self.status = Some(status);
                Poll::Ready(Ok(status))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Kill the child and everything in its process group
    pub(crate) fn kill(&mut self) {
        if self.status.is_some() {
            return;
        }

        if let Some(group) = self.group {
            if let Err(error) = kill_process_group(group, Signal::KILL) {
                warn!(%error, "error killing git process group");
            }
        }

        if let Err(error) = self.child.start_kill() {
            debug!(%error, "error killing git process");
        }
    }
}

impl Drop for GitProcess {
    fn drop(&mut self) {
        self.kill();
    }
}
