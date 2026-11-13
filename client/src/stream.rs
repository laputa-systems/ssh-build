use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::time::{Duration, Instant};

use oxish_proto::{Encode, MessageType};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::time::Timespec;
use zeroize::{Zeroize, Zeroizing};

use crate::channel::{Channel, LOCAL_MAX_PACKET, LOCAL_WINDOW, validate_environment};
use crate::client::Connection;
use crate::error::{Certainty, Error};
use crate::exec::{ExecResult, ExecStatus};
use crate::session::{PtyRequest, SessionEvents, SessionRequest};
use crate::wire::{Interrupt, Packet, SshReader, plain_text};

const OUTPUT_HIGH_WATER: usize = 256 * 1024;
const STDERR_EXTENDED_DATA: u32 = 1;

/// Options for one streamed exec.
#[derive(Clone, Default)]
pub struct StreamOptions {
    /// The whole-command deadline; without one only the interrupt ends a silent command.
    pub timeout: Option<Duration>,
    /// Reports that the caller wants the command abandoned.
    pub interrupt: Option<Interrupt>,
    /// Variables to ask the server to set, by SSH `env` request.
    pub env: Vec<(String, String)>,
}

impl std::fmt::Debug for StreamOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamOptions")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// A source of command input. The client waits on its descriptor, so a source that can block
/// without one would stall the connection, its deadline and its cancellation.
pub trait InputSource: Read {
    /// A descriptor that polls readable when the next read will not block, or `None` for a
    /// source whose reads never block.
    fn descriptor(&self) -> Option<BorrowedFd<'_>>;
}

impl InputSource for File {
    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        Some(self.as_fd())
    }
}

/// A destination for command output. While a sink with a descriptor is not writable the client
/// holds its bytes and keeps serving the connection; a sink without one is written at once.
pub trait OutputSink: Write {
    /// A descriptor that polls writable when a write of up to `PIPE_BUF` bytes will not block, or
    /// `None` for a sink whose writes never block.
    fn descriptor(&self) -> Option<BorrowedFd<'_>>;
}

/// An output sink backed by a file or descriptor the caller owns, such as a pipe or terminal.
pub struct FileSink(File);

impl FileSink {
    /// Write to `file`, holding output back while it does not poll writable.
    pub fn new(file: File) -> Self {
        Self(file)
    }
}

impl Write for FileSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl OutputSink for FileSink {
    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        Some(self.0.as_fd())
    }
}

fn pipe() -> Result<(File, File), Error> {
    let failed = |error| Error::NotSubmitted { detail: format!("cannot create a pipe: {error}") };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(failed)?;
    // macOS has no pipe2, so close-on-exec is set right after the pipe is created.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let (reader, writer) = {
        let (reader, writer) = rustix::pipe::pipe().map_err(failed)?;
        for end in [&reader, &writer] {
            rustix::io::fcntl_setfd(end, rustix::io::FdFlags::CLOEXEC).map_err(failed)?;
        }
        (reader, writer)
    };
    Ok((File::from(reader), File::from(writer)))
}

fn nonblocking(file: &File) -> Result<(), Error> {
    let flags = rustix::fs::fcntl_getfl(file).map_err(|error| Error::NotSubmitted {
        detail: format!("cannot read a pipe's flags: {error}"),
    })?;
    rustix::fs::fcntl_setfl(file, flags | rustix::fs::OFlags::NONBLOCK).map_err(|error| {
        Error::NotSubmitted {
            detail: format!("cannot make a pipe nonblocking: {error}"),
        }
    })
}

const COPY_BUFFER: usize = 16 * 1024;
const INPUT_BUFFER: usize = 64 * 1024;
const INPUT_IDLE_POLL: Duration = Duration::from_millis(10);

/// The calling thread's side of a streamed exec: it feeds stdin into a bounded pipe and drains
/// the output pipes into the caller's writers, so a writer that blocks stops neither the
/// connection thread nor its service of the server.
struct CallerIo<'i, 'o, 'e> {
    stdin: Option<&'i mut dyn InputSource>,
    input: Option<File>,
    out_pipe: File,
    err_pipe: File,
    out: &'o mut dyn Write,
    err: &'e mut dyn Write,
    input_buffer: Zeroizing<Vec<u8>>,
    copy_buffer: Zeroizing<Vec<u8>>,
    pending: std::ops::Range<usize>,
    input_idle: bool,
    input_eof: bool,
    out_done: bool,
    err_done: bool,
}

impl CallerIo<'_, '_, '_> {
    fn run(&mut self) -> Result<(), Error> {
        if self.stdin.is_none() {
            self.end_input();
        }
        loop {
            if self.out_done && self.err_done {
                self.end_input();
                return Ok(());
            }
            let polled = self.poll_once()?;
            if !self.out_done && reports(polled[0]) {
                self.out_done = read_output(
                    &mut self.out_pipe,
                    &mut self.copy_buffer,
                    &mut *self.out,
                    "stdout",
                )?;
            }
            if !self.err_done && reports(polled[1]) {
                self.err_done = read_output(
                    &mut self.err_pipe,
                    &mut self.copy_buffer,
                    &mut *self.err,
                    "stderr",
                )?;
            }
            if self.stdin.is_some()
                && self.input.is_some()
                && self.pending.is_empty()
                && !self.input_eof
            {
                let has_descriptor = self
                    .stdin
                    .as_ref()
                    .is_some_and(|stdin| stdin.descriptor().is_some());
                if !has_descriptor || reports(polled[2]) {
                    self.fill_input()?;
                }
            }
            if !self.pending.is_empty() {
                if polled[3].intersects(PollFlags::ERR | PollFlags::NVAL) {
                    self.end_input();
                } else if polled[3].contains(PollFlags::OUT) {
                    self.flush_input()?;
                }
            }
        }
    }

    fn poll_once(&mut self) -> Result<[PollFlags; 4], Error> {
        let stdin_fd = if self.input.is_some() && self.pending.is_empty() && !self.input_eof {
            self.stdin.as_ref().and_then(|stdin| stdin.descriptor())
        } else {
            None
        };
        let input_fd = if self.pending.is_empty() {
            None
        } else {
            self.input.as_ref().map(AsFd::as_fd)
        };
        let dummy = if self.out_done { &self.err_pipe } else { &self.out_pipe };
        let mut polled = [
            if self.out_done {
                PollFd::new(dummy, PollFlags::empty())
            } else {
                PollFd::new(&self.out_pipe, PollFlags::IN)
            },
            if self.err_done {
                PollFd::new(dummy, PollFlags::empty())
            } else {
                PollFd::new(&self.err_pipe, PollFlags::IN)
            },
            stdin_fd.map_or_else(
                || PollFd::new(dummy, PollFlags::empty()),
                |fd| PollFd::from_borrowed_fd(fd, PollFlags::IN),
            ),
            input_fd.map_or_else(
                || PollFd::new(dummy, PollFlags::empty()),
                |fd| PollFd::from_borrowed_fd(fd, PollFlags::OUT),
            ),
        ];
        let immediate = stdin_fd.is_none()
            && self.input.is_some()
            && self.pending.is_empty()
            && !self.input_eof
            && self
                .stdin
                .as_ref()
                .is_some_and(|stdin| stdin.descriptor().is_none());
        let timeout = if immediate {
            let wait = if self.input_idle {
                INPUT_IDLE_POLL
            } else {
                Duration::ZERO
            };
            Some(Timespec {
                tv_sec: wait.as_secs() as _,
                tv_nsec: wait.subsec_nanos() as _,
            })
        } else {
            None
        };
        match poll(&mut polled, timeout.as_ref()) {
            Ok(0) => Ok([PollFlags::empty(); 4]),
            Ok(_) => Ok([
                polled[0].revents(),
                polled[1].revents(),
                polled[2].revents(),
                polled[3].revents(),
            ]),
            Err(error) if error == rustix::io::Errno::INTR => Ok([PollFlags::empty(); 4]),
            Err(error) => Err(Error::Submitted {
                detail: format!("polling a pipe failed: {error}"),
            }),
        }
    }

    fn fill_input(&mut self) -> Result<(), Error> {
        if self.input.is_none() || self.input_eof {
            return Ok(());
        }
        let Some(stdin) = self.stdin.as_mut() else {
            self.end_input();
            return Ok(());
        };
        match stdin.read(&mut self.input_buffer) {
            Ok(0) => {
                self.input_eof = true;
                self.end_input();
                Ok(())
            }
            Ok(read) => {
                self.input_idle = false;
                self.pending = 0..read;
                self.flush_input()
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                self.input_idle = true;
                Ok(())
            }
            Err(error) => Err(Error::Submitted {
                detail: format!("stdin read failed: {error}"),
            }),
        }
    }

    fn flush_input(&mut self) -> Result<(), Error> {
        let mut broken = false;
        while !self.pending.is_empty() {
            let Some(input) = self.input.as_mut() else {
                break;
            };
            match input.write(&self.input_buffer[self.pending.clone()]) {
                Ok(0) => {
                    return Err(Error::Submitted {
                        detail: "the input pipe accepted no bytes".to_owned(),
                    });
                }
                Ok(written) => self.pending.start += written,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                    broken = true;
                    break;
                }
                Err(error) => {
                    return Err(Error::Submitted {
                        detail: format!("stdin copy failed: {error}"),
                    });
                }
            }
        }
        self.pending = 0..0;
        if broken {
            self.end_input();
        }
        Ok(())
    }

    fn end_input(&mut self) {
        self.input = None;
        self.pending = 0..0;
    }
}

fn read_output(
    pipe: &mut File,
    buffer: &mut [u8],
    sink: &mut dyn Write,
    stream: &'static str,
) -> Result<bool, Error> {
    match pipe.read(buffer) {
        Ok(0) => Ok(true),
        Ok(read) => {
            sink.write_all(&buffer[..read])
                .map_err(|error| sink_error(error, stream))?;
            Ok(false)
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(Error::Submitted {
            detail: format!("{stream} pipe read failed: {error}"),
        }),
    }
}

fn reports(events: PollFlags) -> bool {
    events.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
}

const PIPE_ATOMIC_WRITE: usize = 4096;
const COMPACT_AFTER: usize = 64 * 1024;
const HOLD_CAPACITY: usize = LOCAL_WINDOW as usize + COMPACT_AFTER + LOCAL_MAX_PACKET as usize;
const DRAIN_POLL: Duration = Duration::from_millis(50);

fn ready(descriptor: BorrowedFd<'_>, events: PollFlags, wait: Duration) -> Result<bool, Error> {
    let mut polled = [PollFd::from_borrowed_fd(descriptor, events)];
    let timespec = Timespec {
        tv_sec: wait.as_secs() as _,
        tv_nsec: wait.subsec_nanos() as _,
    };
    match poll(&mut polled, Some(&timespec)) {
        Ok(0) => Ok(false),
        Ok(_) => Ok(true),
        Err(error) if error == rustix::io::Errno::INTR => Ok(false),
        Err(error) => Err(Error::Submitted {
            detail: format!("polling an output file failed: {error}"),
        }),
    }
}

/// One output stream: bytes the sink has not taken yet stay here, and their window stays with
/// the client, so at most the receive window is ever held. The hold is allocated whole the first
/// time it is needed, so it never moves while it holds output.
struct Drain<'a> {
    sink: &'a mut dyn OutputSink,
    stream: &'static str,
    held: Zeroizing<Vec<u8>>,
    taken: usize,
}

impl<'a> Drain<'a> {
    fn new(sink: &'a mut dyn OutputSink, stream: &'static str) -> Self {
        Self {
            sink,
            stream,
            held: Zeroizing::new(Vec::new()),
            taken: 0,
        }
    }

    fn waiting(&self) -> bool {
        self.taken < self.held.len()
    }

    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        if self.waiting() {
            self.sink.descriptor()
        } else {
            None
        }
    }

    /// Hand `data` to the sink and return how many of the received bytes left the client.
    fn accept(&mut self, data: &[u8]) -> Result<usize, Error> {
        if self.sink.descriptor().is_none() {
            sink(self.sink, data, self.stream)?;
            return Ok(data.len());
        }
        if self.waiting() {
            self.held.extend_from_slice(data);
            return self.pump();
        }
        let written = write_ready(self.sink, data, self.stream)?;
        if written < data.len() {
            if self.held.capacity() < HOLD_CAPACITY {
                self.held.reserve_exact(HOLD_CAPACITY);
            }
            self.held.extend_from_slice(&data[written..]);
        }
        Ok(written)
    }

    /// Write held bytes while the sink is writable and return how many left the client.
    fn pump(&mut self) -> Result<usize, Error> {
        let written = write_ready(self.sink, &self.held[self.taken..], self.stream)?;
        self.taken += written;
        if !self.waiting() || self.taken >= COMPACT_AFTER {
            let kept = self.held.len() - self.taken;
            self.held.copy_within(self.taken.., 0);
            self.held[kept..].zeroize();
            self.held.truncate(kept);
            self.taken = 0;
        }
        Ok(written)
    }
}

/// Write `bytes` while `sink` polls writable, at most `PIPE_BUF` at a time, and return how many
/// it took.
fn write_ready(sink: &mut dyn OutputSink, bytes: &[u8], stream: &'static str) -> Result<usize, Error> {
    let mut written = 0;
    while written < bytes.len() {
        let Some(descriptor) = sink.descriptor() else {
            break;
        };
        if !ready(descriptor, PollFlags::OUT, Duration::ZERO)? {
            break;
        }
        let end = bytes.len().min(written + PIPE_ATOMIC_WRITE);
        match sink.write(&bytes[written..end]) {
            Ok(0) => {
                return Err(Error::Submitted {
                    detail: format!("{stream} write accepted no bytes"),
                });
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(sink_error(error, stream)),
        }
    }
    Ok(written)
}

/// Write what the outputs still hold after the connection ended, bounded by the operation's
/// deadline and interrupt.
fn drain_after_disconnect(connection: &mut Connection, outputs: &mut [Drain<'_>; 2]) -> Result<(), Error> {
    let deadline = connection.transport().deadline();
    let interrupt = connection.transport().interrupt();
    loop {
        for output in outputs.iter_mut() {
            output.pump()?;
        }
        let Some(descriptor) = outputs.iter().find_map(Drain::descriptor) else {
            return Ok(());
        };
        if interrupt.as_ref().is_some_and(|interrupt| interrupt()) {
            return Err(Error::Cancelled {
                certainty: Certainty::Submitted,
            });
        }
        let mut slice = DRAIN_POLL;
        if let Some(deadline) = deadline {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout {
                    certainty: Certainty::Submitted,
                });
            }
            slice = slice.min(deadline - now);
        }
        ready(descriptor, PollFlags::OUT, slice)?;
    }
}

struct Input<'a> {
    reader: Option<&'a mut dyn InputSource>,
    buffer: Zeroizing<Vec<u8>>,
    position: usize,
    length: usize,
    eof: bool,
}

impl<'a> Input<'a> {
    fn new(reader: Option<&'a mut dyn InputSource>) -> Self {
        let eof = reader.is_none();
        Self {
            reader,
            buffer: Zeroizing::new(vec![0; 64 * 1024]),
            position: 0,
            length: 0,
            eof,
        }
    }

    fn drained(&self) -> bool {
        self.position == self.length
    }

    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        self.reader.as_ref().and_then(|reader| reader.descriptor())
    }

    fn readable(&self) -> bool {
        let Some(descriptor) = self.descriptor() else {
            return true;
        };
        let mut polled = [PollFd::from_borrowed_fd(descriptor, PollFlags::IN)];
        let immediately = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        !matches!(poll(&mut polled, Some(&immediately)), Ok(0) | Err(_))
    }

    fn refill(&mut self) -> Result<(), Error> {
        let Some(reader) = self.reader.as_mut() else {
            self.eof = true;
            return Ok(());
        };
        loop {
            match reader.read(&mut self.buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(read) => {
                    self.length = read;
                    self.position = 0;
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.length = 0;
                    self.position = 0;
                    return Ok(());
                }
                Err(error) => {
                    return Err(Error::Submitted {
                        detail: format!("stdin read failed: {error}"),
                    });
                }
            }
        }
    }
}

#[derive(Default)]
struct Completion {
    exit_status: Option<u32>,
    exit_signal: Option<String>,
}

impl Completion {
    fn is_reported(&self) -> bool {
        self.exit_status.is_some() || self.exit_signal.is_some()
    }

    fn status(&self) -> ExecStatus {
        match (self.exit_status, &self.exit_signal) {
            (Some(status), _) => ExecStatus::Exited(status),
            (None, Some(signal)) => ExecStatus::Signaled(signal.clone()),
            (None, None) => ExecStatus::Missing,
        }
    }
}

pub(crate) fn exec_stream(
    connection: &mut Connection,
    command: &str,
    options: &StreamOptions,
    stdin: Option<&mut dyn InputSource>,
    stdout: &mut dyn OutputSink,
    stderr: &mut dyn OutputSink,
) -> Result<ExecResult, Error> {
    let request = SessionRequest {
        command: Some(command.to_owned()),
        pty: None,
        env: options.env.clone(),
        timeout: options.timeout,
        interrupt: options.interrupt.clone(),
        keepalive: None,
    };
    session(connection, &request, stdin, stdout, stderr, None)
}

pub(crate) fn session(
    connection: &mut Connection,
    request: &SessionRequest,
    stdin: Option<&mut dyn InputSource>,
    stdout: &mut dyn OutputSink,
    stderr: &mut dyn OutputSink,
    events: Option<&mut dyn SessionEvents>,
) -> Result<ExecResult, Error> {
    connection.require_usable()?;
    validate_environment(&request.env)?;
    connection
        .transport()
        .begin_operation(request.timeout, request.interrupt.clone());
    connection.transport().set_keepalive(request.keepalive);
    let result = run(
        connection,
        request.command.as_deref(),
        request.pty.as_ref(),
        &request.env,
        stdin,
        stdout,
        stderr,
        events,
    );
    connection.transport().end_operation();
    result.map_err(|error| {
        let error = if connection.transport().certainty() == Certainty::Submitted {
            error.after_submission()
        } else {
            error
        };
        connection.mark_unusable();
        error
    })
}

/// Run a command for a Rust caller. The connection runs on a scoped thread with bounded pipes
/// for stdin and both outputs; the calling thread, which owns the non-`Send` writers and input
/// source, feeds and drains those pipes. A writer that blocks then stalls only the caller's
/// thread, while the connection keeps answering the server.
pub(crate) fn exec_stream_to_writers(
    connection: &mut Connection,
    command: &str,
    options: &StreamOptions,
    stdin: Option<&mut dyn InputSource>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExecResult, Error> {
    let (out_pipe, out_writer) = pipe()?;
    let (err_pipe, err_writer) = pipe()?;
    let (mut input_pipe, input_writer) = pipe()?;
    let (abort_reader, abort_writer) = pipe()?;
    nonblocking(&out_writer)?;
    nonblocking(&err_writer)?;
    nonblocking(&input_writer)?;

    let has_stdin = stdin.is_some();
    let mut out_sink = FileSink(out_writer);
    let mut err_sink = FileSink(err_writer);
    connection.transport().set_abort(abort_reader.into());

    type Joined = std::thread::Result<Result<ExecResult, Error>>;
    let outcome: Result<(Result<(), Error>, Joined), Error> = std::thread::scope(|scope| {
        let connection = &mut *connection;
        let worker = std::thread::Builder::new()
            .spawn_scoped(scope, move || {
                let input: Option<&mut dyn InputSource> = if has_stdin {
                    Some(&mut input_pipe)
                } else {
                    None
                };
                exec_stream(
                    connection,
                    command,
                    options,
                    input,
                    &mut out_sink,
                    &mut err_sink,
                )
            })
            .map_err(|error| Error::NotSubmitted {
                detail: format!("cannot start the connection thread: {error}"),
            })?;
        let pumped = CallerIo {
            stdin,
            input: Some(input_writer),
            out_pipe,
            err_pipe,
            out: stdout,
            err: stderr,
            input_buffer: Zeroizing::new(vec![0; INPUT_BUFFER]),
            copy_buffer: Zeroizing::new(vec![0; COPY_BUFFER]),
            pending: 0..0,
            input_idle: false,
            input_eof: false,
            out_done: false,
            err_done: false,
        }
        .run();
        drop(abort_writer);
        let joined = worker.join();
        Ok((pumped, joined))
    });
    connection.transport().clear_abort();
    let (pumped, joined) = outcome?;

    match joined {
        Err(payload) => std::panic::resume_unwind(payload),
        Ok(result) => match pumped {
            Ok(()) => result,
            Err(error) => {
                connection.mark_unusable();
                Err(error)
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    connection: &mut Connection,
    command: Option<&str>,
    pty: Option<&PtyRequest>,
    env: &[(String, String)],
    stdin: Option<&mut dyn InputSource>,
    stdout: &mut dyn OutputSink,
    stderr: &mut dyn OutputSink,
    mut events: Option<&mut dyn SessionEvents>,
) -> Result<ExecResult, Error> {
    let mut channel = Channel::open(connection)?;
    for (name, value) in env {
        channel.set_environment(connection, name, value)?;
    }
    if let Some(pty) = pty {
        channel.request_pty(connection, pty)?;
    }
    match command {
        Some(command) => channel.exec(connection, command.as_bytes())?,
        None => channel.shell(connection)?,
    }
    connection.transport().await_command();
    if let Some(events) = events.as_deref_mut() {
        events.started().map_err(|error| Error::Submitted {
            detail: format!("cannot start the terminal session: {error}"),
        })?;
    }

    let mut input = Input::new(stdin);
    let mut completion = Completion::default();
    let mut outputs = [Drain::new(stdout, "stdout"), Drain::new(stderr, "stderr")];
    let driven = drive(
        connection,
        &mut channel,
        &mut completion,
        &mut input,
        &mut outputs,
        &mut events,
    );
    match driven {
        Ok(()) => {}
        Err(_) if connection.transport().peer_closed() && completion.is_reported() => {
            connection.mark_unusable();
            drain_after_disconnect(connection, &mut outputs)?;
        }
        Err(error) => return Err(error),
    }
    Ok(ExecResult {
        status: completion.status(),
        stdout: Vec::new(),
        stderr: Vec::new(),
    })
}

fn drive(
    connection: &mut Connection,
    channel: &mut Channel,
    completion: &mut Completion,
    input: &mut Input<'_>,
    outputs: &mut [Drain<'_>; 2],
    events: &mut Option<&mut dyn SessionEvents>,
) -> Result<(), Error> {
    loop {
        connection.transport().check()?;
        if connection.transport().keepalive_due() {
            connection.transport().send_keepalive()?;
        }
        while let Some(packet) = connection.try_next_packet()? {
            on_packet(connection, channel, completion, packet, outputs)?;
        }
        if let Some(events) = events.as_deref_mut()
            && let Some(size) = events.window_change()
            && !channel.eof_received
            && !channel.close_received
        {
            channel.send_window_change(connection.transport(), size)?;
        }
        for output in outputs.iter_mut() {
            let written = output.pump()?;
            channel.release(written);
        }
        channel.replenish(connection.transport())?;
        let feeding = feed(connection, channel, input)?;
        if channel.close_received {
            channel.send_close(connection.transport())?;
        }
        let flushed = connection.transport().flush_nonblocking()?;
        let holding = outputs.iter().any(Drain::waiting);
        if channel.is_closed() && flushed && !holding {
            break;
        }
        if connection.rekey_due() {
            connection.rekey(None)?;
            continue;
        }
        if flushed && feeding == Feed::OutputFull {
            continue;
        }
        let waiting_for = if feeding == Feed::WaitingForInput {
            input.descriptor()
        } else {
            None
        };
        let [stdout, stderr] = &*outputs;
        let wake = events.as_deref().and_then(|events| events.descriptor());
        let events = connection.transport().wait_with_files(
            !flushed,
            waiting_for,
            [stdout.descriptor(), stderr.descriptor()],
            wake,
        )?;
        if events.contains(PollFlags::IN) || events.contains(PollFlags::HUP) {
            connection.transport().fill_nonblocking()?;
        }
    }

    Ok(())
}

#[derive(PartialEq, Eq)]
enum Feed {
    Done,
    WaitingForWindow,
    WaitingForInput,
    OutputFull,
}

fn feed(
    connection: &mut Connection,
    channel: &mut Channel,
    input: &mut Input<'_>,
) -> Result<Feed, Error> {
    if channel.eof_sent || channel.close_received {
        return Ok(Feed::Done);
    }
    loop {
        if connection.transport().pending_output() >= OUTPUT_HIGH_WATER {
            return Ok(Feed::OutputFull);
        }
        if input.drained() {
            if input.eof {
                break;
            }
            if channel.remote_window == 0 {
                return Ok(Feed::WaitingForWindow);
            }
            if !input.readable() {
                return Ok(Feed::WaitingForInput);
            }
            input.refill()?;
            if input.drained() && !input.eof {
                return Ok(Feed::WaitingForInput);
            }
            continue;
        }
        if channel.remote_window == 0 {
            return Ok(Feed::WaitingForWindow);
        }
        let sent = channel.send_data(
            connection.transport(),
            &input.buffer[input.position..input.length],
        )?;
        input.position += sent;
    }
    channel.send_eof(connection.transport())?;
    Ok(Feed::Done)
}

fn on_packet(
    connection: &mut Connection,
    channel: &mut Channel,
    completion: &mut Completion,
    packet: Packet,
    outputs: &mut [Drain<'_>; 2],
) -> Result<(), Error> {
    let [stdout, stderr] = outputs;
    match packet.message_type {
        MessageType::ChannelData => {
            let mut reader = SshReader::new(&packet.payload);
            let recipient = reader.u32()?;
            let data = reader.string()?;
            reader.finish()?;
            channel.expect_recipient(recipient)?;
            check_open_for_data(channel)?;
            channel.receive(data.len())?;
            let delivered = stdout.accept(data)?;
            channel.release(delivered);
        }
        MessageType::ChannelExtendedData => {
            let mut reader = SshReader::new(&packet.payload);
            let recipient = reader.u32()?;
            let data_type = reader.u32()?;
            let data = reader.string()?;
            reader.finish()?;
            channel.expect_recipient(recipient)?;
            check_open_for_data(channel)?;
            channel.receive(data.len())?;
            let delivered = if data_type == STDERR_EXTENDED_DATA {
                stderr.accept(data)?
            } else {
                data.len()
            };
            channel.release(delivered);
        }
        MessageType::ChannelWindowAdjust => channel.window_adjust(&packet.payload)?,
        MessageType::ChannelRequest => {
            let mut reader = SshReader::new(&packet.payload);
            let recipient = reader.u32()?;
            channel.expect_recipient(recipient)?;
            let request = reader.text()?.to_owned();
            let want_reply = reader.u8()? != 0;
            match request.as_str() {
                "exit-status" => {
                    let status = reader.u32()?;
                    reader.finish()?;
                    record_completion(completion, Some(status), None)?;
                }
                "exit-signal" => {
                    let signal = plain_text(reader.text()?);
                    let _core_dumped = reader.u8()?;
                    let _message = reader.string()?;
                    let _language = reader.string()?;
                    reader.finish()?;
                    record_completion(completion, None, Some(signal))?;
                }
                _ => {}
            }
            if want_reply {
                let mut reply = Vec::new();
                MessageType::ChannelFailure.encode(&mut reply);
                reply.extend_from_slice(&channel.remote_id.to_be_bytes());
                connection.transport().reply(&reply)?;
            }
        }
        MessageType::ChannelEof => {
            expect_recipient_only(channel, &packet.payload)?;
            channel.eof_received = true;
        }
        MessageType::ChannelClose => {
            expect_recipient_only(channel, &packet.payload)?;
            channel.close_received = true;
        }
        MessageType::RequestSuccess | MessageType::RequestFailure => {
            if !connection.transport().keepalive_answered() {
                return Err(Error::Protocol {
                    detail: "unrequested global request reply".to_owned(),
                });
            }
        }
        other => {
            return Err(Error::Protocol {
                detail: format!("unexpected channel message {other:?}"),
            });
        }
    }
    Ok(())
}

fn record_completion(
    completion: &mut Completion,
    status: Option<u32>,
    signal: Option<String>,
) -> Result<(), Error> {
    if completion.exit_status.is_some() || completion.exit_signal.is_some() {
        return Err(Error::Protocol {
            detail: "server reported the command's completion twice".to_owned(),
        });
    }
    completion.exit_status = status;
    completion.exit_signal = signal;
    Ok(())
}

fn expect_recipient_only(channel: &Channel, payload: &[u8]) -> Result<(), Error> {
    let mut reader = SshReader::new(payload);
    let recipient = reader.u32()?;
    reader.finish()?;
    channel.expect_recipient(recipient)
}

fn check_open_for_data(channel: &Channel) -> Result<(), Error> {
    if channel.eof_received || channel.close_received {
        return Err(Error::Protocol {
            detail: "data after the peer ended its output".to_owned(),
        });
    }
    Ok(())
}

fn sink_error(error: std::io::Error, stream: &'static str) -> Error {
    if error.kind() == std::io::ErrorKind::OutOfMemory {
        Error::OutputLimit { stream }
    } else {
        Error::Submitted {
            detail: format!("{stream} write failed: {error}"),
        }
    }
}

fn sink(output: &mut dyn Write, data: &[u8], stream: &'static str) -> Result<(), Error> {
    output.write_all(data).map_err(|error| sink_error(error, stream))
}
