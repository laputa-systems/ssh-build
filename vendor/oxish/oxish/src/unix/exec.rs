use core::{
    pin::Pin,
    task::{Context, Poll},
};
use std::{env, io, pin::pin, process::Stdio};

use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
};
use tracing::{debug, warn};

/// A child process spawned for an `exec` channel request, with piped stdio.
///
/// Unlike [`Terminal`](super::Terminal), no pty is allocated: stdin, stdout and
/// stderr are pipes so Git pack data crosses the channel byte-clean. Stderr is
/// drained and discarded (the protocol has no stderr message wired up); stdout
/// is forwarded as channel data and the exit status is reported back.
pub(crate) struct ExecProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: ChildStderr,
    pub(crate) stdout_eof: bool,
    pub(crate) stderr_eof: bool,
    pub(crate) eof_sent: bool,
}

impl ExecProcess {
    /// Spawn a forced command (from an authorized-key `command=` option) via the user's shell.
    pub(crate) fn spawn_shell(command: &str, env_vars: &[(String, String)]) -> io::Result<Self> {
        let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
        let mut cmd = Command::new(&shell);
        cmd.arg("-c").arg(command);
        configure(&mut cmd, env_vars);
        debug!(shell, command, "spawning exec via shell");
        Self::spawn(cmd)
    }

    /// Spawn an allow-listed Git command directly, without a shell.
    pub(crate) fn spawn_git(
        program: &str,
        args: &[String],
        env_vars: &[(String, String)],
    ) -> io::Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        configure(&mut cmd, env_vars);
        debug!(program, ?args, "spawning git exec");
        Self::spawn(cmd)
    }

    fn spawn(mut cmd: Command) -> io::Result<Self> {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("spawned exec has no stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("spawned exec has no stderr"))?;
        Ok(Self {
            child,
            stdin,
            stdout,
            stderr,
            stdout_eof: false,
            stderr_eof: false,
            eof_sent: false,
        })
    }

    /// Write channel data to the child's stdin.
    pub(crate) async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match self.stdin.as_mut() {
            Some(stdin) => stdin.write_all(data).await,
            None => Ok(()),
        }
    }

    /// Close the child's stdin so it observes EOF.
    pub(crate) fn shutdown_stdin(&mut self) {
        drop(self.stdin.take());
    }

    /// Read output from the child's stdout.
    pub(crate) fn poll_read_stdout(
        &mut self,
        buf: &mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.stdout).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Drain any pending stderr output, discarding it.
    ///
    /// Always resolves immediately: pending output is consumed until the pipe
    /// would block, so the child can never wedge on a full stderr buffer.
    pub(crate) fn drain_stderr(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.stderr_eof {
            return Ok(());
        }

        let mut buf = [0u8; 4096];
        loop {
            let mut read_buf = ReadBuf::new(&mut buf);
            match Pin::new(&mut self.stderr).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    self.stderr_eof = true;
                    return Ok(());
                }
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Pending => return Ok(()),
            }
        }
    }

    /// Wait for the child process to exit and reap it.
    pub(crate) fn poll_wait(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<std::process::ExitStatus>> {
        let future = self.child.wait();
        let pinned = pin!(future);
        pinned.poll(cx)
    }

    /// Send `SIGKILL` to the child process.
    ///
    /// Use [`Self::poll_wait()`] after calling this to reap the zombie process.
    pub(crate) fn start_kill(&mut self) {
        if let Err(error) = self.child.start_kill() {
            warn!(%error, "error killing exec process");
        }
    }
}

fn configure(cmd: &mut Command, env_vars: &[(String, String)]) {
    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    // The session process runs with a minimal PATH; widen the child's lookup so
    // Git binaries resolve outside the base system directories too.
    const EXTRA_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin"];
    let current = env::var("PATH").unwrap_or_default();
    let mut path = String::new();
    for dir in EXTRA_DIRS {
        if !current.split(':').any(|entry| entry == *dir) {
            path.push_str(dir);
            path.push(':');
        }
    }
    path.push_str(&current);
    if path.ends_with(':') {
        path.pop();
    }
    if !path.is_empty() {
        cmd.env("PATH", path);
    }
}

/// Split an `exec` command string into program plus arguments when it names an
/// allow-listed Git command, applying shell word-splitting (single/double
/// quotes, backslash escapes) so quoted repository paths parse correctly.
///
/// Anything else yields `None`: the caller must reject the request. Arguments
/// are passed as `argv` with no shell involved, so metacharacters in them are
/// inert.
pub(crate) fn parse_git_command(command: &str) -> Option<(String, Vec<String>)> {
    let words = split_words(command)?;
    let (program, args) = words.split_first()?;
    let base = program.rsplit('/').next()?;
    match ALLOWED_COMMANDS.contains(&base) {
        true => Some((program.clone(), args.to_vec())),
        false => None,
    }
}

fn split_words(command: &str) -> Option<Vec<String>> {
    #[derive(PartialEq)]
    enum Quote {
        Single,
        Double,
    }

    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut quote: Option<Quote> = None;
    let mut chars = command.chars();

    while let Some(c) = chars.next() {
        match &quote {
            Some(Quote::Single) => match c {
                '\'' => quote = None,
                _ => current.push(c),
            },
            Some(Quote::Double) => match c {
                '"' => quote = None,
                '\\' => current.push(chars.next()?),
                _ => current.push(c),
            },
            None => match c {
                '\'' => {
                    quote = Some(Quote::Single);
                    in_word = true;
                }
                '"' => {
                    quote = Some(Quote::Double);
                    in_word = true;
                }
                '\\' => {
                    current.push(chars.next()?);
                    in_word = true;
                }
                _ if c.is_whitespace() => {
                    if in_word {
                        words.push(core::mem::take(&mut current));
                        in_word = false;
                    }
                }
                _ => {
                    current.push(c);
                    in_word = true;
                }
            },
        }
    }

    match quote {
        Some(_) => None,
        None => {
            if in_word {
                words.push(current);
            }
            Some(words)
        }
    }
}

const ALLOWED_COMMANDS: &[&str] = &[
    "git-upload-pack",
    "git-receive-pack",
    "git-upload-archive",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_listed_git_commands() {
        let (program, args) = parse_git_command("git-upload-pack '/srv/repos/a.git'").unwrap();
        assert_eq!(program, "git-upload-pack");
        assert_eq!(args, ["'/srv/repos/a.git'".replace('\'', "")]);
        assert!(parse_git_command("git-receive-pack '/x'").is_some());
        assert!(parse_git_command("git-upload-archive '/x'").is_some());
        assert!(parse_git_command("/usr/bin/git-upload-pack '/x'").is_some());
    }

    #[test]
    fn rejects_non_git_commands() {
        for command in [
            "rm -rf /",
            "sh",
            "sh -c 'git-upload-pack /x'",
            "git-upload-pack; rm -rf /",
            "git-upload-packx '/x'",
            "git '/x'",
            "",
            "   ",
            "git-upload-pack '/unterminated",
            "git-upload-pack \\",
        ] {
            assert!(
                parse_git_command(command).is_none(),
                "unexpectedly allowed {command:?}"
            );
        }
    }

    #[test]
    fn shell_word_splitting() {
        let (program, args) = parse_git_command("git-upload-pack '/a b/c.git'").unwrap();
        assert_eq!(program, "git-upload-pack");
        assert_eq!(args, ["/a b/c.git"]);
        let (_, args) = parse_git_command("git-upload-pack \"/a b\"").unwrap();
        assert_eq!(args, ["/a b"]);
        let (_, args) = parse_git_command("git-upload-pack /a\\ b").unwrap();
        assert_eq!(args, ["/a b"]);
        let (_, args) = parse_git_command("git-upload-pack '/a'\\''b'").unwrap();
        assert_eq!(args, ["/a'b"]);
    }
}
