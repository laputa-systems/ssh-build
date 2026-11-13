use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::time::Timespec;
use zeroize::Zeroizing;

use oxish_proto::crypto::{CryptoProvider, HandshakeBuffer, KeySourceSide};
use oxish_proto::key_exchange::NewKeys;
use oxish_proto::named::EncryptionAlgorithm;
use oxish_proto::{
    Completion, Encode, IncomingPacket, MessageType, ProtoError, ReadState, WriteState,
};

use crate::error::{Certainty, Error};

/// Append an SSH `string`.
pub(crate) fn put_string(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buffer.extend_from_slice(value);
}

/// One decrypted SSH packet.
pub struct Packet {
    /// The SSH message type.
    pub message_type: MessageType,
    /// The message body after the type byte.
    pub payload: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Packet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Packet")
            .field("message_type", &self.message_type)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Packet {
    /// The full payload, including the message-type byte.
    pub fn encoded_payload(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.payload.len() + 1);
        encoded.push(u8::from(self.message_type));
        encoded.extend_from_slice(&self.payload);
        encoded
    }
}

/// A bounded reader for SSH wire-format values.
#[derive(Debug, Clone, Copy)]
pub struct SshReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> SshReader<'a> {
    /// Wrap a packet body.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8, Error> {
        let Some(&value) = self.data.get(self.position) else {
            return Err(self.short());
        };
        self.position += 1;
        Ok(value)
    }

    /// Read a big-endian 32-bit integer.
    pub fn u32(&mut self) -> Result<u32, Error> {
        let Some(bytes) = self.data.get(self.position..self.position + 4) else {
            return Err(self.short());
        };
        let mut value = [0u8; 4];
        value.copy_from_slice(bytes);
        self.position += 4;
        Ok(u32::from_be_bytes(value))
    }

    /// Read an SSH `string`.
    pub fn string(&mut self) -> Result<&'a [u8], Error> {
        let length = self.u32()? as usize;
        let Some(bytes) = self.data.get(self.position..self.position + length) else {
            return Err(self.short());
        };
        self.position += length;
        Ok(bytes)
    }

    /// Read an SSH `string` as UTF-8.
    pub fn text(&mut self) -> Result<&'a str, Error> {
        std::str::from_utf8(self.string()?).map_err(|_| Error::Protocol {
            detail: "invalid UTF-8 in string".to_owned(),
        })
    }

    /// Read a comma-separated SSH name-list.
    pub fn name_list(&mut self) -> Result<Vec<String>, Error> {
        let value = self.text()?;
        if value.is_empty() {
            return Ok(Vec::new());
        }
        Ok(value.split(',').map(str::to_owned).collect())
    }

    /// Require that the body has been consumed.
    pub fn finish(&self) -> Result<(), Error> {
        if self.position == self.data.len() {
            Ok(())
        } else {
            Err(Error::Protocol {
                detail: "trailing bytes in SSH message".to_owned(),
            })
        }
    }

    /// The number of bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    fn short(&self) -> Error {
        Error::Protocol {
            detail: "truncated SSH message".to_owned(),
        }
    }
}

struct RawPayload<'a>(&'a [u8]);

impl Encode for RawPayload<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.0);
    }
}

impl fmt::Debug for RawPayload<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawPayload")
            .field("len", &self.0.len())
            .finish()
    }
}

/// A caller-supplied check that reports whether the current operation must stop.
pub type Interrupt = Arc<dyn Fn() -> bool + Send + Sync>;

const INTERRUPT_POLL: Duration = Duration::from_millis(50);
const READ_BUFFER_LIMIT: usize = 256 * 1024;
const REPLY_HIGH_WATER: usize = 64 * 1024;
const MAX_TEXT: usize = 512;
const MAX_IDENTIFICATION_LINE: usize = 255;
const PACKET_FRAMING: usize = 4 + 1 + 255 + 16;

/// Server-supplied text made safe to show: control and bidirectional-override characters are
/// dropped and the length is bounded.
pub(crate) fn plain_text(text: &str) -> String {
    let mut plain: String = text
        .chars()
        .filter(|character| {
            !character.is_control()
                && !matches!(character, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(MAX_TEXT)
        .collect();
    if text.chars().nth(MAX_TEXT).is_some() {
        plain.push_str("...");
    }
    plain
}

/// How packets in the receive direction must align (RFC 4253 section 6, RFC 5647 section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiveFraming {
    /// Before keys: the whole packet, length field included, fills 8-byte blocks.
    Plain,
    /// AEAD: the length travels as associated data, so the rest alone fills cipher blocks.
    Aead { block: u32 },
}

impl ReceiveFraming {
    fn for_cipher(algorithm: &EncryptionAlgorithm<'_>) -> Result<Self, Error> {
        match algorithm {
            EncryptionAlgorithm::Aes128Gcm => Ok(Self::Aead { block: 16 }),
            EncryptionAlgorithm::Chacha20Poly1305 => Ok(Self::Aead { block: 8 }),
            EncryptionAlgorithm::Unknown(name) => Err(Error::UnsupportedAlgorithm {
                category: "encryption",
                name: name.to_string(),
            }),
        }
    }

    fn admits(self, packet_length: u32) -> bool {
        match self {
            Self::Plain => (packet_length + 4).is_multiple_of(8),
            Self::Aead { block } => packet_length.is_multiple_of(block),
        }
    }
}

/// An SSH transport, nonblocking at the socket and bounded by deadlines.
pub struct Transport {
    stream: TcpStream,
    read: ReadState,
    framing: ReceiveFraming,
    write: WriteState,
    client_identification: Vec<u8>,
    server_identification: Vec<u8>,
    certainty: Certainty,
    idle: Duration,
    deadline: Option<Instant>,
    interrupt: Option<Interrupt>,
    last_progress: Instant,
    write_progress: Instant,
    since_kex: KexUsage,
    awaiting_command: bool,
    peer_closed: bool,
    abort: Option<OwnedFd>,
}

#[derive(Debug, Clone, Copy)]
struct KexUsage {
    bytes: u64,
    packets: u64,
    started: Instant,
}

impl KexUsage {
    fn new() -> Self {
        Self {
            bytes: 0,
            packets: 0,
            started: Instant::now(),
        }
    }
}

impl Transport {
    /// Resolve and connect a TCP stream, bounded by `deadline` and `interrupt`, and prepare
    /// SSH packet state. The operation bounds stay in force for the following exchanges.
    pub fn connect(
        host: &str,
        port: u16,
        idle: Duration,
        deadline: Duration,
        interrupt: Option<Interrupt>,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, Error> {
        let limit = Instant::now() + deadline;
        let stream = connect_stream(host, port, idle, limit, interrupt.as_ref())?;
        stream.set_nodelay(true)?;
        stream.set_nonblocking(true)?;
        let now = Instant::now();
        Ok(Self {
            stream,
            read: ReadState::default(),
            framing: ReceiveFraming::Plain,
            write: WriteState::new(provider.secure_random()),
            client_identification: Vec::new(),
            server_identification: Vec::new(),
            certainty: Certainty::NotSubmitted,
            idle,
            deadline: Some(limit),
            interrupt,
            last_progress: now,
            write_progress: now,
            peer_closed: false,
            since_kex: KexUsage::new(),
            awaiting_command: false,
            abort: None,
        })
    }

    pub(crate) fn set_abort(&mut self, descriptor: OwnedFd) {
        self.abort = Some(descriptor);
    }

    pub(crate) fn clear_abort(&mut self) {
        self.abort = None;
    }

    /// Record that a mutation request has been submitted.
    pub fn mark_submitted(&mut self) {
        self.certainty = Certainty::Submitted;
    }

    /// Whether a request may have reached the server on this connection.
    pub fn certainty(&self) -> Certainty {
        self.certainty
    }

    /// Bound the following operation by a whole-operation deadline and an interrupt check.
    pub fn begin_operation(&mut self, timeout: Option<Duration>, interrupt: Option<Interrupt>) {
        self.deadline = timeout.map(|timeout| Instant::now() + timeout);
        self.interrupt = interrupt;
        self.last_progress = Instant::now();
        self.write_progress = Instant::now();
        self.certainty = Certainty::NotSubmitted;
        self.awaiting_command = false;
    }

    /// Tighten the deadline to at most `limit` from now and return the one to restore.
    pub fn bound_phase(&mut self, limit: Duration) -> Option<Instant> {
        let previous = self.deadline;
        let phase = Instant::now() + limit;
        self.deadline = Some(previous.map_or(phase, |deadline| deadline.min(phase)));
        previous
    }

    /// Restore the deadline returned by [`Self::bound_phase`].
    pub fn restore_deadline(&mut self, previous: Option<Instant>) {
        self.deadline = previous;
    }

    /// End the operation bounds set by [`Self::begin_operation`].
    pub fn end_operation(&mut self) {
        self.deadline = None;
        self.interrupt = None;
        self.awaiting_command = false;
    }

    /// Stop timing peer silence while a submitted command runs; only the deadline and
    /// interrupt bound the wait, except when the peer stops draining our output.
    pub fn await_command(&mut self) {
        self.awaiting_command = true;
    }

    /// Fail now if the operation was interrupted or its deadline passed.
    pub fn check(&self) -> Result<(), Error> {
        match self.limit_error() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// The deadline of the current operation, if it has one.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The caller's cancellation check for the current operation, if any.
    pub fn interrupt(&self) -> Option<Interrupt> {
        self.interrupt.clone()
    }

    /// The most the peer may stay silent while the transport waits on it.
    pub fn idle_timeout(&self) -> Duration {
        self.idle
    }

    fn idle_bound(&self) -> bool {
        !self.awaiting_command || self.has_pending_output()
    }

    fn limit_error(&self) -> Option<Error> {
        if self.interrupt.as_ref().is_some_and(|interrupt| interrupt()) {
            return Some(Error::Cancelled {
                certainty: self.certainty,
            });
        }
        let now = Instant::now();
        let idle_bound = self.idle_bound();
        let write_stalled =
            self.has_pending_output() && now.duration_since(self.write_progress) >= self.idle;
        if self.deadline.is_some_and(|deadline| now >= deadline)
            || write_stalled
            || (idle_bound && now.duration_since(self.last_progress) >= self.idle)
        {
            return Some(Error::Timeout {
                certainty: self.certainty,
            });
        }
        None
    }

    /// Wait for read readiness, and write readiness when `write` is set.
    pub fn wait(&mut self, write: bool) -> Result<PollFlags, Error> {
        self.wait_for(true, write, None, [None, None])
    }

    /// Like [`Self::wait`], and also return once `input` can be read or one of `outputs` can be
    /// written. The flags describe the transport only.
    pub fn wait_with_files(
        &mut self,
        write: bool,
        input: Option<BorrowedFd<'_>>,
        outputs: [Option<BorrowedFd<'_>>; 2],
    ) -> Result<PollFlags, Error> {
        self.wait_for(true, write, input, outputs)
    }

    fn wait_for(
        &mut self,
        read: bool,
        write: bool,
        input: Option<BorrowedFd<'_>>,
        outputs: [Option<BorrowedFd<'_>>; 2],
    ) -> Result<PollFlags, Error> {
        loop {
            if let Some(error) = self.limit_error() {
                return Err(error);
            }
            let now = Instant::now();
            let mut remaining = if self.interrupt.is_some() {
                INTERRUPT_POLL
            } else {
                Duration::from_secs(1)
            };
            if let Some(deadline) = self.deadline {
                remaining = remaining.min(deadline.saturating_duration_since(now));
            }
            if self.idle_bound() {
                remaining = remaining.min((self.last_progress + self.idle).saturating_duration_since(now));
            }
            if self.has_pending_output() {
                remaining = remaining.min((self.write_progress + self.idle).saturating_duration_since(now));
            }
            let mut events = PollFlags::empty();
            if read {
                events |= PollFlags::IN;
            }
            if write {
                events |= PollFlags::OUT;
            }
            let abort = self.abort.as_ref().map(AsFd::as_fd);
            let mut descriptors = [
                PollFd::new(&self.stream, events),
                file_entry(&self.stream, input, PollFlags::IN),
                file_entry(&self.stream, outputs[0], PollFlags::OUT),
                file_entry(&self.stream, outputs[1], PollFlags::OUT),
                match abort {
                    Some(descriptor) => PollFd::from_borrowed_fd(descriptor, PollFlags::IN),
                    None => PollFd::new(&self.stream, PollFlags::empty()),
                },
            ];
            let timespec = Timespec {
                tv_sec: remaining.as_secs() as _,
                tv_nsec: remaining.subsec_nanos() as _,
            };
            match poll(&mut descriptors, Some(&timespec)) {
                Ok(0) => continue,
                Ok(_) => {
                    if abort.is_some() && !descriptors[4].revents().is_empty() {
                        return Err(Error::Cancelled {
                            certainty: self.certainty,
                        });
                    }
                    let events = descriptors[0].revents();
                    if reports_socket_failure(events) {
                        let detail = self
                            .stream
                            .take_error()
                            .ok()
                            .flatten()
                            .map_or_else(|| "socket error".to_owned(), |error| error.to_string());
                        return Err(self.attribute(Error::NotSubmitted { detail }));
                    }
                    return Ok(events);
                }
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(error) => {
                    return Err(self.attribute(Error::NotSubmitted {
                        detail: error.to_string(),
                    }));
                }
            }
        }
    }

    fn attribute(&self, error: Error) -> Error {
        match (self.certainty, error) {
            (Certainty::Submitted, Error::NotSubmitted { detail }) => Error::Submitted { detail },
            (_, error) => error,
        }
    }

    /// Read available bytes into the packet buffer.
    pub fn fill_nonblocking(&mut self) -> Result<bool, Error> {
        let mut buffer = [0u8; 16_384];
        match self.stream.read(&mut buffer) {
            Ok(0) => {
                self.peer_closed = true;
                Err(self.attribute(Error::NotSubmitted {
                    detail: "connection closed".to_owned(),
                }))
            }
            Ok(read) => {
                self.read.buf.extend_from_slice(&buffer[..read]);
                self.last_progress = Instant::now();
                self.since_kex.bytes += read as u64;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(false),
            Err(error) => Err(self.transport_error(error)),
        }
    }

    /// Whether the peer ended the connection cleanly before this side did.
    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Decode one complete buffered packet, if any.
    pub fn try_recv(&mut self) -> Result<Option<Packet>, Error> {
        let polled = match self.read.poll_packet() {
            Ok(completion) => completion,
            Err(ProtoError::Incomplete(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        match polled {
            Completion::Incomplete(_) => Ok(None),
            Completion::Complete((sequence, length)) => {
                if !self.framing.admits(u32::from(length)) {
                    return Err(Error::Protocol {
                        detail: format!(
                            "packet length {} is not a whole number of cipher blocks",
                            u32::from(length)
                        ),
                    });
                }
                let packet: IncomingPacket<'_> = self.read.decode_packet(sequence, length)?;
                let message_type = packet.message_type;
                let payload = Zeroizing::new(packet.payload().to_vec());
                self.since_kex.packets += 1;
                Ok(Some(Packet {
                    message_type,
                    payload,
                }))
            }
        }
    }

    fn note_enqueue(&mut self) {
        if !self.has_pending_output() {
            self.write_progress = Instant::now();
        }
    }

    /// Encode a payload without flushing it.
    pub fn encode_raw(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.note_enqueue();
        self.write.reserve(PACKET_FRAMING + payload.len());
        self.write.encode(&RawPayload(payload))?;
        self.since_kex.packets += 1;
        Ok(())
    }

    /// Flush as much buffered output as the transport accepts.
    pub fn flush_nonblocking(&mut self) -> Result<bool, Error> {
        loop {
            let buffered = self.write.buffered();
            if buffered.is_empty() {
                return Ok(true);
            }
            match self.stream.write(buffered) {
                Ok(0) => {
                    return Err(self.attribute(Error::NotSubmitted {
                        detail: "write returned zero".to_owned(),
                    }));
                }
                Ok(written) => {
                    self.last_progress = Instant::now();
                    self.write_progress = self.last_progress;
                    self.since_kex.bytes += written as u64;
                    self.write
                        .written(Ok(written))
                        .map_err(|error| self.transport_error(error))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(false);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(self.transport_error(error)),
            }
        }
    }

    /// Whether an encoded packet is still waiting to be written.
    pub fn has_pending_output(&self) -> bool {
        !self.write.buffered().is_empty()
    }

    /// The number of encoded bytes waiting to be written.
    pub fn pending_output(&self) -> usize {
        self.write.buffered().len()
    }

    /// Close both directions of the transport.
    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    /// Bytes, packets and time spent under the current keys.
    pub fn kex_usage(&self) -> (u64, u64, Duration) {
        (
            self.since_kex.bytes,
            self.since_kex.packets,
            self.since_kex.started.elapsed(),
        )
    }

    fn reset_kex_usage(&mut self) {
        self.since_kex = KexUsage::new();
    }

    fn read_byte(&mut self) -> Result<u8, Error> {
        loop {
            let mut byte = [0u8; 1];
            match self.stream.read(&mut byte) {
                Ok(0) => {
                    return Err(self.attribute(Error::NotSubmitted {
                        detail: "connection closed".to_owned(),
                    }));
                }
                Ok(_) => {
                    self.last_progress = Instant::now();
                    return Ok(byte[0]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    self.wait(false)?;
                }
                Err(error) => return Err(self.transport_error(error)),
            }
        }
    }

    /// Exchange and validate the SSH identification lines.
    pub fn exchange_identifications(&mut self, software: &str) -> Result<(), Error> {
        let client = format!("SSH-2.0-{software}");
        self.note_enqueue();
        self.write.encoded(&RawPayload(client.as_bytes()));
        self.write.encoded(&RawPayload(b"\r\n"));
        self.flush()?;
        self.client_identification = client.into_bytes();

        let mut line = Vec::with_capacity(128);
        while !line.ends_with(b"\r\n") {
            line.push(self.read_byte()?);
            if line.len() > MAX_IDENTIFICATION_LINE {
                return Err(Error::Protocol {
                    detail: "identification line too long".to_owned(),
                });
            }
        }
        line.truncate(line.len() - 2);
        let text = std::str::from_utf8(&line).map_err(|_| Error::Protocol {
            detail: "identification is not UTF-8".to_owned(),
        })?;
        if !text.starts_with("SSH-2.0-") {
            return Err(Error::Protocol {
                detail: format!("unsupported SSH identification {text:?}"),
            });
        }
        self.server_identification = line;
        Ok(())
    }

    /// The client identification without its CRLF.
    pub fn client_identification(&self) -> &[u8] {
        &self.client_identification
    }

    /// The server identification without its CRLF.
    pub fn server_identification(&self) -> &[u8] {
        &self.server_identification
    }

    /// Start the exchange-hash buffer with both identification strings.
    pub fn handshake_buffer(&self) -> HandshakeBuffer {
        let mut buffer = HandshakeBuffer::default();
        buffer.prefixed(&self.client_identification);
        buffer.prefixed(&self.server_identification);
        buffer
    }

    /// Send one already-framed message payload.
    pub fn send_raw(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.encode_raw(payload)?;
        self.flush()
    }

    /// Send one typed message.
    pub fn send(&mut self, payload: &(impl Encode + fmt::Debug)) -> Result<(), Error> {
        self.note_enqueue();
        self.write.encode(payload)?;
        self.since_kex.packets += 1;
        self.flush()
    }

    /// Receive one message.
    pub fn recv(&mut self) -> Result<Packet, Error> {
        loop {
            if let Some(packet) = self.try_recv()? {
                return Ok(packet);
            }
            let flushed = self.flush_nonblocking()?;
            self.wait(!flushed)?;
            self.fill_nonblocking()?;
        }
    }

    /// Send `SSH_MSG_NEWKEYS` and reset the send sequence for strict key exchange.
    pub fn send_newkeys(&mut self, strict: bool) -> Result<(), Error> {
        self.send(&NewKeys)?;
        if strict {
            self.write.sequence_number = 0;
        }
        Ok(())
    }

    /// Reset the receive sequence for strict key exchange after `SSH_MSG_NEWKEYS` arrived.
    pub fn accept_newkeys(&mut self, strict: bool) {
        if strict {
            self.read.sequence_number = 0;
        }
    }

    /// Install the client-to-server sealing key.
    pub fn install_sealer(
        &mut self,
        keys: &KeySourceSide,
        provider: &dyn CryptoProvider,
    ) -> Result<(), Error> {
        self.write.sealer = Some(provider.sealing_key(0, keys)?);
        Ok(())
    }

    /// Install the server-to-client opening key.
    pub fn install_opener(
        &mut self,
        keys: &KeySourceSide,
        provider: &dyn CryptoProvider,
    ) -> Result<(), Error> {
        let framing = ReceiveFraming::for_cipher(&keys.algorithm)?;
        self.read.opener = Some(provider.opening_key(0, keys)?);
        self.framing = framing;
        self.reset_kex_usage();
        Ok(())
    }

    /// Flush buffered packets. Reads continue meanwhile, up to a fixed buffer, so a peer that is
    /// also writing cannot stall both; beyond it the peer's bytes wait in the socket.
    pub fn flush(&mut self) -> Result<(), Error> {
        while !self.flush_nonblocking()? {
            let reading = self.read.buf.len() < READ_BUFFER_LIMIT;
            let events = self.wait_for(reading, true, None, [None, None])?;
            if reading && events.contains(PollFlags::IN) {
                self.fill_nonblocking()?;
            }
        }
        Ok(())
    }

    /// Flush buffered packets without reading anything.
    pub fn drain(&mut self) -> Result<(), Error> {
        while !self.flush_nonblocking()? {
            self.wait_for(false, true, None, [None, None])?;
        }
        Ok(())
    }

    /// Queue a reply to a peer request. Past a fixed amount of unsent output the transport stops
    /// reading until the peer has taken it, so a peer that sends requests and never reads the
    /// answers cannot make the replies pile up.
    pub fn reply(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.encode_raw(payload)?;
        if self.pending_output() >= REPLY_HIGH_WATER {
            self.drain()?;
        }
        Ok(())
    }

    fn transport_error(&self, error: std::io::Error) -> Error {
        match error.kind() {
            std::io::ErrorKind::TimedOut => Error::Timeout {
                certainty: self.certainty,
            },
            _ => self.attribute(Error::NotSubmitted {
                detail: error.to_string(),
            }),
        }
    }
}

fn file_entry<'a>(
    stream: &'a TcpStream,
    descriptor: Option<BorrowedFd<'a>>,
    events: PollFlags,
) -> PollFd<'a> {
    match descriptor {
        Some(descriptor) => PollFd::from_borrowed_fd(descriptor, events),
        None => PollFd::new(stream, PollFlags::empty()),
    }
}

fn reports_socket_failure(events: PollFlags) -> bool {
    events.intersects(PollFlags::ERR | PollFlags::NVAL)
}

fn connect_stream(
    host: &str,
    port: u16,
    idle: Duration,
    limit: Instant,
    interrupt: Option<&Interrupt>,
) -> Result<TcpStream, Error> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let target = host.to_owned();
    std::thread::spawn(move || {
        let _ = sender.send(connect_addresses(&target, port, idle));
    });
    loop {
        if interrupt.is_some_and(|interrupt| interrupt()) {
            return Err(Error::Cancelled {
                certainty: Certainty::NotSubmitted,
            });
        }
        let now = Instant::now();
        if now >= limit {
            return Err(Error::Timeout {
                certainty: Certainty::NotSubmitted,
            });
        }
        match receiver.recv_timeout(INTERRUPT_POLL.min(limit - now)) {
            Ok(outcome) => return outcome,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(Error::NotSubmitted {
                    detail: format!("resolving {host}:{port} failed"),
                });
            }
        }
    }
}

fn connect_addresses(host: &str, port: u16, idle: Duration) -> Result<TcpStream, Error> {
    let mut last_error = None;
    for address in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, idle) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(match last_error {
        Some(error) if error.kind() == std::io::ErrorKind::TimedOut => Error::Timeout {
            certainty: Certainty::NotSubmitted,
        },
        Some(error) => Error::NotSubmitted {
            detail: error.to_string(),
        },
        None => Error::NotSubmitted {
            detail: format!("no address resolved for {host}:{port}"),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_or_invalid_descriptor_wakeup_is_a_connection_failure() {
        assert!(reports_socket_failure(PollFlags::ERR));
        assert!(reports_socket_failure(PollFlags::NVAL));
        assert!(reports_socket_failure(PollFlags::IN | PollFlags::ERR));
    }

    #[test]
    fn plaintext_packets_fill_eight_byte_blocks_including_the_length_field() {
        assert!(ReceiveFraming::Plain.admits(12));
        assert!(!ReceiveFraming::Plain.admits(16));
    }

    #[test]
    fn readable_closed_and_writable_wakeups_are_not_failures() {
        assert!(!reports_socket_failure(PollFlags::IN));
        assert!(!reports_socket_failure(PollFlags::HUP));
        assert!(!reports_socket_failure(PollFlags::IN | PollFlags::HUP | PollFlags::OUT));
    }
}
