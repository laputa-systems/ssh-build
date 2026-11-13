use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

use crate::client::Connection;
use crate::error::Error;
use crate::stream::{self, InputSource, OutputSink, StreamOptions};
use crate::wire::Interrupt;

/// Bounded output capture limit for a single exec.
pub const DEFAULT_MAX_OUTPUT: usize = 16 * 1024 * 1024;

fn without_blocking_open(options: &mut OpenOptions, path: &std::path::Path) -> std::io::Result<File> {
    let file = options
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)?;
    let flags = rustix::fs::fcntl_getfl(&file)?;
    rustix::fs::fcntl_setfl(&file, flags - rustix::fs::OFlags::NONBLOCK)?;
    Ok(file)
}

/// Open a file for `ExecOptions::stdin_file`. A FIFO opens at once whether or not a writer
/// exists, and reads wait for data through the client's descriptor polling.
pub fn open_stdin_file(path: &std::path::Path) -> std::io::Result<File> {
    without_blocking_open(OpenOptions::new().read(true), path)
}

/// Create or truncate a file for `ExecOptions::stdout_file` or `stderr_file`. A FIFO with no
/// reader fails at once instead of waiting for one.
pub fn create_output_file(path: &std::path::Path) -> std::io::Result<File> {
    without_blocking_open(
        OpenOptions::new().write(true).create(true).truncate(true),
        path,
    )
}

/// Options for one exec request.
pub struct ExecOptions {
    /// Bytes to send on stdin before EOF.
    pub stdin: Option<Vec<u8>>,
    /// A file whose contents follow `stdin` before EOF.
    pub stdin_file: Option<File>,
    /// A file that receives standard output instead of the bounded capture.
    pub stdout_file: Option<File>,
    /// A file that receives standard error instead of the bounded capture.
    pub stderr_file: Option<File>,
    /// The whole-command deadline.
    pub timeout: Option<Duration>,
    /// Maximum bytes captured from each output stream that does not go to a file.
    pub max_output: usize,
    /// Reports that the caller wants the command abandoned.
    pub interrupt: Option<Interrupt>,
    /// Variables to ask the server to set, by SSH `env` request.
    pub env: Vec<(String, String)>,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            stdin: None,
            stdin_file: None,
            stdout_file: None,
            stderr_file: None,
            timeout: None,
            max_output: DEFAULT_MAX_OUTPUT,
            interrupt: None,
            env: Vec::new(),
        }
    }
}

impl std::fmt::Debug for ExecOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecOptions")
            .field("stdin_len", &self.stdin.as_ref().map(Vec::len))
            .field("timeout", &self.timeout)
            .field("max_output", &self.max_output)
            .field("env_names", &self.env.iter().map(|(name, _)| name).collect::<Vec<_>>())
            .finish()
    }
}

/// The remote process outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecStatus {
    /// The process exited with this status.
    Exited(u32),
    /// The process was terminated by this signal name.
    Signaled(String),
    /// The channel closed without an exit status or signal.
    Missing,
}

/// Captured output and the remote outcome.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// The remote process outcome.
    pub status: ExecStatus,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
}

impl std::fmt::Debug for ExecResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecResult")
            .field("status", &self.status)
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .finish()
    }
}

struct Capture {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for Capture {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() + data.len() > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "capture limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Stdin<'a> {
    head: &'a [u8],
    tail: Option<&'a File>,
}

impl Read for Stdin<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.head.is_empty() {
            return self.head.read(buffer);
        }
        match self.tail.as_mut() {
            Some(tail) => tail.read(buffer),
            None => Ok(0),
        }
    }
}

impl InputSource for Stdin<'_> {
    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        if self.head.is_empty() {
            self.tail.and_then(InputSource::descriptor)
        } else {
            None
        }
    }
}

impl OutputSink for Capture {
    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        None
    }
}

struct FileOutput<'a> {
    file: &'a File,
    polled: bool,
}

impl<'a> FileOutput<'a> {
    fn new(file: &'a File) -> Self {
        let polled = file
            .metadata()
            .map_or(true, |metadata| !metadata.file_type().is_file());
        Self { file, polled }
    }
}

impl Write for FileOutput<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.file.write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl OutputSink for FileOutput<'_> {
    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        self.polled.then(|| self.file.as_fd())
    }
}

enum Output<'a> {
    Capture(Capture),
    File(FileOutput<'a>),
}

impl<'a> Output<'a> {
    fn new(file: Option<&'a File>, limit: usize) -> Self {
        match file {
            Some(file) => Self::File(FileOutput::new(file)),
            None => Self::Capture(Capture {
                bytes: Vec::new(),
                limit,
            }),
        }
    }

    fn sink(&mut self) -> &mut dyn OutputSink {
        match self {
            Self::Capture(capture) => capture,
            Self::File(file) => file,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Capture(capture) => capture.bytes,
            Self::File(_) => Vec::new(),
        }
    }
}

pub(crate) fn exec(
    connection: &mut Connection,
    command: &str,
    options: &ExecOptions,
) -> Result<ExecResult, Error> {
    let mut stdout = Output::new(options.stdout_file.as_ref(), options.max_output);
    let mut stderr = Output::new(options.stderr_file.as_ref(), options.max_output);
    let mut stdin = Stdin {
        head: options.stdin.as_deref().unwrap_or_default(),
        tail: options.stdin_file.as_ref(),
    };
    let mut result = stream::exec_stream(
        connection,
        command,
        &StreamOptions {
            timeout: options.timeout,
            interrupt: options.interrupt.clone(),
            env: options.env.clone(),
        },
        Some(&mut stdin),
        stdout.sink(),
        stderr.sink(),
    )?;
    result.stdout = stdout.into_bytes();
    result.stderr = stderr.into_bytes();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_refuses_bytes_past_its_limit() {
        let mut capture = Capture {
            bytes: Vec::new(),
            limit: 4,
        };
        capture.write_all(b"1234").expect("within limit");
        assert!(capture.write_all(b"5").is_err());
        assert_eq!(capture.bytes, b"1234");
    }
}
