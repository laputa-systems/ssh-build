use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use std::{collections::BTreeMap, os::unix::process::ExitStatusExt as _};

use proto::{
    IncomingPacket, MAX_PACKET_LEN, MessageType, ProtoError, WriteState,
    auth::KeyOptions,
    channels::{
        ChannelClose, ChannelData, ChannelEof, ChannelExtendedData, ChannelOpen,
        ChannelOpenConfirmation, ChannelOpenFailure, ChannelRequest, ChannelRequestFailure,
        ChannelRequestSuccess, ChannelRequestType, ChannelWindowAdjust, EXTENDED_DATA_STDERR,
        ExitSignal,
    },
    named::ChannelType,
};
use tokio::time::{Instant, Sleep, sleep};
use tracing::{debug, info, warn};

use crate::{
    Error, GitPolicy, PolicyError, validate_protocol,
    platform::{GitProcess, Output},
};

/// Open session channels of one connection
#[derive(Default)]
pub(crate) struct Channels {
    next_id: u32,
    channels: BTreeMap<u32, Channel>,
    /// Channel to poll first, so one busy channel cannot starve the others
    cursor: u32,
}

/// What the connection allows the current channel request to do
pub(crate) struct Grant<'a> {
    pub(crate) policy: &'a GitPolicy,
    pub(crate) options: &'a KeyOptions,
}

impl Channels {
    /// Whether any channel has a running Git process
    pub(crate) fn busy(&self) -> bool {
        self.channels
            .values()
            .any(|channel| matches!(channel.run, Run::Active(_)))
    }

    pub(crate) fn open(
        &mut self,
        open: ChannelOpen<'_>,
        write: &mut WriteState,
    ) -> Result<(), Error> {
        if open.r#type != ChannelType::Session {
            write.encode(&ChannelOpenFailure::unknown_type(open.sender_channel))?;
            return Ok(());
        }

        if self.channels.len() >= MAX_CHANNELS {
            write.encode(&ChannelOpenFailure::resource_shortage(open.sender_channel))?;
            return Ok(());
        }

        let local_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.channels.contains_key(&local_id) {
            write.encode(&ChannelOpenFailure::duplicate_id(open.sender_channel))?;
            return Ok(());
        }

        let channel = Channel {
            remote_id: open.sender_channel,
            send_window: open.initial_window_size,
            receive_window: INITIAL_WINDOW_SIZE,
            credit: 0,
            maximum_packet_size: open.maximum_packet_size.max(MIN_PACKET_SIZE),
            protocol: None,
            run: Run::Idle,
            close_sent: false,
        };

        write.encode(&ChannelOpenConfirmation {
            recipient_channel: channel.remote_id,
            sender_channel: local_id,
            initial_window_size: INITIAL_WINDOW_SIZE,
            maximum_packet_size: MAX_PACKET_LEN - 64, // Leave some room for packet overhead
        })?;
        self.channels.insert(local_id, channel);
        Ok(())
    }

    pub(crate) fn request(
        &mut self,
        request: ChannelRequest<'_>,
        write: &mut WriteState,
        grant: &Grant<'_>,
    ) -> Result<(), Error> {
        let running = self.busy_count();
        let Some(channel) = self.channels.get_mut(&request.recipient_channel) else {
            return Err(ProtoError::InvalidPacket("channel request for unknown channel ID").into());
        };

        let accepted = match request.r#type {
            ChannelRequestType::Env(env) => match (env.name, &channel.run) {
                ("GIT_PROTOCOL", Run::Idle) => match validate_protocol(env.value) {
                    Some(protocol) => {
                        channel.protocol = Some(protocol);
                        true
                    }
                    None => {
                        debug!(value = env.value, "rejecting GIT_PROTOCOL value");
                        false
                    }
                },
                _ => {
                    debug!(name = env.name, "rejecting environment variable request");
                    false
                }
            },
            ChannelRequestType::Exec(exec) => {
                if !matches!(channel.run, Run::Idle) {
                    warn!("rejecting second exec request on a channel");
                    false
                } else if running >= MAX_PROCESSES {
                    warn!("rejecting exec request: too many running commands");
                    false
                } else {
                    match grant.policy.authorize(exec.command, grant.options.git_access) {
                        Ok(command) => match GitProcess::spawn(&command, channel.protocol) {
                            Ok(process) => {
                                info!(service = ?command.service, "running git command");
                                channel.run = Run::Active(Box::new(Active::new(Some(process))));
                                true
                            }
                            Err(error) => {
                                warn!(%error, "failed to spawn git");
                                false
                            }
                        },
                        Err(error @ (PolicyError::NotFound | PolicyError::Denied)) => {
                            info!(%error, "refusing git command");
                            let mut active = Active::new(None);
                            active.stderr_backlog.extend_from_slice(DENIED_MESSAGE);
                            active.outcome = Some(Outcome::Exited(1));
                            channel.run = Run::Active(Box::new(active));
                            true
                        }
                        Err(error) => {
                            warn!(%error, "rejecting exec request");
                            false
                        }
                    }
                }
            }
            other => {
                warn!(request_type = ?other, "rejecting unsupported channel request");
                false
            }
        };

        if request.want_reply {
            match accepted {
                true => write.encode(&ChannelRequestSuccess {
                    recipient_channel: channel.remote_id,
                })?,
                false => write.encode(&ChannelRequestFailure {
                    recipient_channel: channel.remote_id,
                })?,
            }
        }
        Ok(())
    }

    pub(crate) fn adjust_window(&mut self, adjust: &ChannelWindowAdjust) -> Result<(), ProtoError> {
        let Some(channel) = self.channels.get_mut(&adjust.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel window adjust for unknown channel ID",
            ));
        };

        channel.send_window = channel.send_window.saturating_add(adjust.bytes_to_add);
        Ok(())
    }

    /// Queue inbound channel data for the child's stdin
    pub(crate) fn data(&mut self, data: &ChannelData<'_>) -> Result<(), ProtoError> {
        let Some(channel) = self.channels.get_mut(&data.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel data for unknown channel ID",
            ));
        };

        let len = u32::try_from(data.data.len())
            .map_err(|_| ProtoError::InvalidPacket("channel data too large"))?;
        match channel.receive_window.checked_sub(len) {
            Some(window) => channel.receive_window = window,
            None => {
                return Err(ProtoError::InvalidPacket(
                    "channel data exceeds receive window",
                ));
            }
        }

        match &mut channel.run {
            Run::Active(active) => {
                let queued = active
                    .process
                    .as_mut()
                    .is_some_and(|process| process.queue_stdin(&data.data));
                if !queued {
                    channel.credit = channel.credit.saturating_add(len);
                }
            }
            Run::Idle | Run::Finished => channel.credit = channel.credit.saturating_add(len),
        }
        Ok(())
    }

    pub(crate) fn eof(&mut self, eof: &ChannelEof) -> Result<(), ProtoError> {
        let Some(channel) = self.channels.get_mut(&eof.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel eof for unknown channel ID",
            ));
        };

        if let Run::Active(active) = &mut channel.run {
            if let Some(process) = active.process.as_mut() {
                process.close_stdin();
            }
        }

        debug!(channel_id = %eof.recipient_channel, "received channel eof from client");
        Ok(())
    }

    pub(crate) fn close(
        &mut self,
        close: &ChannelClose,
        write: &mut WriteState,
    ) -> Result<(), Error> {
        let Some(channel) = self.channels.get_mut(&close.recipient_channel) else {
            warn!(channel_id = %close.recipient_channel, "channel close for unknown channel ID");
            return Ok(());
        };

        if !channel.close_sent {
            channel.close_sent = true;
            write.encode(&ChannelClose {
                recipient_channel: channel.remote_id,
            })?;
        }

        // The client is no longer listening: kill the command; dropping it reaps it.
        debug!(channel_id = %close.recipient_channel, "received channel close from client; removing");
        self.channels.remove(&close.recipient_channel);
        Ok(())
    }

    /// Drive every channel: feed stdin, forward output, report the exit
    ///
    /// Resolves once at least one message was written, after writing at most a bounded batch.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>, write: &mut WriteState) -> Poll<Result<(), Error>> {
        let ids: Vec<u32> = self
            .channels
            .range(self.cursor..)
            .chain(self.channels.range(..self.cursor))
            .map(|(&id, _)| id)
            .collect();

        let mut wrote = false;
        for id in ids {
            let Some(channel) = self.channels.get_mut(&id) else {
                continue;
            };

            match channel.poll(cx, write) {
                Ok(true) => wrote = true,
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            self.cursor = id.wrapping_add(1);
        }

        match wrote {
            true => Poll::Ready(Ok(())),
            false => Poll::Pending,
        }
    }

    /// Stop every running command: ask politely, then kill whatever is left after the grace period
    pub(crate) async fn shutdown(&mut self) {
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        let mut processes = Vec::new();
        for channel in self.channels.values_mut() {
            if let Run::Active(active) = &mut channel.run {
                if let Some(mut process) = active.process.take() {
                    process.request_stop();
                    processes.push(process);
                }
            }
        }

        for process in &mut processes {
            process.finish_stopping(deadline).await;
        }
    }

    fn busy_count(&self) -> usize {
        self.channels
            .values()
            .filter(|channel| matches!(channel.run, Run::Active(_)))
            .count()
    }
}

struct Channel {
    remote_id: u32,
    /// Bytes we may still send to the client
    send_window: u32,
    /// Bytes the client may still send to us
    receive_window: u32,
    /// Bytes the child has consumed that the client has not yet been told about
    credit: u32,
    maximum_packet_size: u32,
    protocol: Option<&'static str>,
    run: Run,
    close_sent: bool,
}

enum Run {
    /// No command requested yet
    Idle,
    Active(Box<Active>),
    /// The exit was reported and the channel close sent
    Finished,
}

struct Active {
    process: Option<GitProcess>,
    /// Diagnostics owed to the client on stderr before anything else
    stderr_backlog: Vec<u8>,
    outcome: Option<Outcome>,
    next_output: Output,
    eof_sent: bool,
    /// Bounds how long output may linger after the child exited
    drain: Option<Pin<Box<Sleep>>>,
    buf: Box<[u8; READ_CHUNK]>,
}

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Exited(u32),
    Signaled(&'static str),
}

impl Active {
    fn new(process: Option<GitProcess>) -> Self {
        Self {
            process,
            stderr_backlog: Vec::new(),
            outcome: None,
            next_output: Output::Stdout,
            eof_sent: false,
            drain: None,
            buf: Box::new([0; READ_CHUNK]),
        }
    }
}

impl Channel {
    /// Make progress; returns whether any message was written
    fn poll(&mut self, cx: &mut Context<'_>, write: &mut WriteState) -> Result<bool, Error> {
        let Run::Active(active) = &mut self.run else {
            return self.return_credit(write);
        };

        let mut wrote = false;
        if let Some(process) = active.process.as_mut() {
            while let Poll::Ready(moved) = process.poll_stdin(cx) {
                self.credit = self.credit.saturating_add(moved as u32);
            }
        }
        wrote |= self.return_credit(write)?;

        let Run::Active(active) = &mut self.run else {
            return Ok(wrote);
        };

        // Output: alternate stdout and stderr so neither starves the other, bounded per call.
        for _ in 0..MAX_PACKETS_PER_POLL {
            if self.send_window == 0 {
                break;
            }
            let limit = (self.send_window as usize)
                .min(self.maximum_packet_size as usize)
                .min(READ_CHUNK);

            if !active.stderr_backlog.is_empty() {
                let n = active.stderr_backlog.len().min(limit);
                write.encode(&ChannelExtendedData {
                    recipient_channel: self.remote_id,
                    data_type_code: EXTENDED_DATA_STDERR,
                    data: &active.stderr_backlog[..n],
                })?;
                active.stderr_backlog.drain(..n);
                self.send_window -= n as u32;
                wrote = true;
                continue;
            }

            let Some(process) = active.process.as_mut() else {
                break;
            };

            let mut sent = false;
            for output in [active.next_output, other(active.next_output)] {
                if !process.output_open(output) {
                    continue;
                }

                match process.poll_output(output, &mut active.buf[..limit], cx) {
                    Poll::Ready(Ok(0)) => {}
                    Poll::Ready(Ok(n)) => {
                        let data = &active.buf[..n];
                        match output {
                            Output::Stdout => write.encode(&ChannelData {
                                recipient_channel: self.remote_id,
                                data: data.into(),
                            })?,
                            Output::Stderr => write.encode(&ChannelExtendedData {
                                recipient_channel: self.remote_id,
                                data_type_code: EXTENDED_DATA_STDERR,
                                data,
                            })?,
                        }
                        self.send_window -= n as u32;
                        active.next_output = other(output);
                        if let Some(timer) = active.drain.as_mut() {
                            timer.as_mut().reset(Instant::now() + DRAIN_AFTER_EXIT);
                        }
                        sent = true;
                        break;
                    }
                    Poll::Ready(Err(error)) => {
                        warn!(%error, ?output, "error reading git output");
                    }
                    Poll::Pending => {}
                }
            }

            if !sent {
                break;
            }
            wrote = true;
        }

        // Learn of the exit without waiting for the pipes: a grandchild can hold them open.
        if active.outcome.is_none() {
            if let Some(process) = active.process.as_mut() {
                match process.poll_exit(cx) {
                    Poll::Ready(Ok(status)) => {
                        active.outcome = Some(match status.code() {
                            Some(code) => Outcome::Exited(code as u32),
                            None => Outcome::Signaled(signal_name(status.signal())),
                        });
                        process.close_stdin();
                        active.drain = Some(Box::pin(sleep(DRAIN_AFTER_EXIT)));
                    }
                    Poll::Ready(Err(error)) => {
                        warn!(%error, "error waiting for git to exit");
                        active.outcome = Some(Outcome::Exited(255));
                    }
                    Poll::Pending => {}
                }
            }
        }

        if let (Some(timer), Some(process)) = (active.drain.as_mut(), active.process.as_mut()) {
            if self.send_window > 0 && !process.outputs_closed() && timer.as_mut().poll(cx).is_ready() {
                warn!("git exited but its output pipes stayed open; closing them");
                process.close_output(Output::Stdout);
                process.close_output(Output::Stderr);
            }
        }

        let outputs_done = active.stderr_backlog.is_empty()
            && active.process.as_ref().is_none_or(GitProcess::outputs_closed);

        // EOF only after both pipes hit end of file and everything was forwarded.
        if outputs_done && !active.eof_sent && active.outcome.is_some() {
            write.encode(&ChannelEof {
                recipient_channel: self.remote_id,
            })?;
            active.eof_sent = true;
            wrote = true;
        }

        if active.eof_sent {
            if let Some(outcome) = active.outcome {
                match outcome {
                    Outcome::Exited(status) => write.encode(&ChannelRequest {
                        recipient_channel: self.remote_id,
                        r#type: ChannelRequestType::ExitStatus(status),
                        want_reply: false,
                    })?,
                    Outcome::Signaled(name) => write.encode(&ChannelRequest {
                        recipient_channel: self.remote_id,
                        r#type: ChannelRequestType::ExitSignal(ExitSignal { name }),
                        want_reply: false,
                    })?,
                }

                if !self.close_sent {
                    self.close_sent = true;
                    write.encode(&ChannelClose {
                        recipient_channel: self.remote_id,
                    })?;
                }
                self.run = Run::Finished;
                wrote = true;
            }
        }

        Ok(wrote)
    }

    /// Tell the client how much of its window the child has consumed
    fn return_credit(&mut self, write: &mut WriteState) -> Result<bool, Error> {
        let drained = match &self.run {
            Run::Active(active) => active.process.as_ref().is_none_or(GitProcess::stdin_drained),
            _ => true,
        };

        if self.close_sent || self.credit == 0 || (self.credit < INITIAL_WINDOW_SIZE / 4 && !drained) {
            return Ok(false);
        }

        write.encode(&ChannelWindowAdjust {
            recipient_channel: self.remote_id,
            bytes_to_add: self.credit,
        })?;
        self.receive_window = self.receive_window.saturating_add(self.credit);
        self.credit = 0;
        Ok(true)
    }
}

fn other(output: Output) -> Output {
    match output {
        Output::Stdout => Output::Stderr,
        Output::Stderr => Output::Stdout,
    }
}

fn signal_name(signal: Option<i32>) -> &'static str {
    match signal {
        Some(libc::SIGHUP) => "HUP",
        Some(libc::SIGINT) => "INT",
        Some(libc::SIGQUIT) => "QUIT",
        Some(libc::SIGABRT) => "ABRT",
        Some(libc::SIGKILL) => "KILL",
        Some(libc::SIGSEGV) => "SEGV",
        Some(libc::SIGPIPE) => "PIPE",
        Some(libc::SIGALRM) => "ALRM",
        Some(libc::SIGTERM) => "TERM",
        _ => "KILL",
    }
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("remote_id", &self.remote_id)
            .field("send_window", &self.send_window)
            .field("receive_window", &self.receive_window)
            .finish_non_exhaustive()
    }
}

/// Resolves when [`Channels::poll`] has written something
pub(crate) struct ChannelsFuture<'a> {
    channels: &'a mut Channels,
    write: &'a mut WriteState,
}

impl<'a> ChannelsFuture<'a> {
    pub(crate) fn new(channels: &'a mut Channels, write: &'a mut WriteState) -> Self {
        Self { channels, write }
    }
}

impl Future for ChannelsFuture<'_> {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self { channels, write } = &mut *self;
        channels.poll(cx, write)
    }
}

#[derive(Debug)]
pub(crate) enum IncomingChannelMessage<'a> {
    Open(ChannelOpen<'a>),
    Request(ChannelRequest<'a>),
    Data(ChannelData<'a>),
    WindowAdjust(ChannelWindowAdjust),
    Eof(ChannelEof),
    Close(ChannelClose),
}

impl<'a> TryFrom<IncomingPacket<'a>> for IncomingChannelMessage<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        match packet.message_type {
            MessageType::ChannelOpen => {
                Ok(IncomingChannelMessage::Open(ChannelOpen::try_from(packet)?))
            }
            MessageType::ChannelRequest => Ok(IncomingChannelMessage::Request(
                ChannelRequest::try_from(packet)?,
            )),
            MessageType::ChannelData => {
                Ok(IncomingChannelMessage::Data(ChannelData::try_from(packet)?))
            }
            MessageType::ChannelWindowAdjust => Ok(IncomingChannelMessage::WindowAdjust(
                ChannelWindowAdjust::try_from(packet)?,
            )),
            MessageType::ChannelEof => {
                Ok(IncomingChannelMessage::Eof(ChannelEof::try_from(packet)?))
            }
            MessageType::ChannelClose => Ok(IncomingChannelMessage::Close(ChannelClose::try_from(
                packet,
            )?)),
            _ => Err(ProtoError::UnexpectedMessage(
                packet.message_type,
                &[
                    MessageType::ChannelOpen,
                    MessageType::ChannelRequest,
                    MessageType::ChannelData,
                    MessageType::ChannelWindowAdjust,
                    MessageType::ChannelEof,
                    MessageType::ChannelClose,
                ],
            )),
        }
    }
}

const DENIED_MESSAGE: &[u8] = b"oxish: repository not found or access denied\n";
const INITIAL_WINDOW_SIZE: u32 = 16 * MAX_PACKET_LEN;
/// Smallest packet size honored for a client that advertises something absurdly small
const MIN_PACKET_SIZE: u32 = 512;
const READ_CHUNK: usize = 32 * 1024;
const MAX_PACKETS_PER_POLL: usize = 16;
/// Session channels one connection may hold open at once
const MAX_CHANNELS: usize = 8;
/// Git commands one connection may run at once
const MAX_PROCESSES: usize = 4;
/// How long commands get to exit after a stop request when the connection ends
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// How long output pipes may stay open after Git itself exited
const DRAIN_AFTER_EXIT: Duration = Duration::from_secs(5);
