use std::time::{Duration, Instant};

use oxish_proto::{Encode, MessageType};

use crate::channel::Channel;
use crate::client::Connection;
use crate::error::Error;
use crate::session::Keepalive;
use crate::wire::{Interrupt, Packet, SshReader};

const OUTPUT_HIGH_WATER: usize = 256 * 1024;
const COMPACT_AFTER: usize = 256 * 1024;
const CLOSE_WAIT: Duration = Duration::from_secs(5);
const KEEPALIVE: Keepalive = Keepalive {
    interval: Duration::from_secs(15),
    dead_after: Duration::from_secs(60),
};
const STALE_AFTER: Duration = Duration::from_secs(1);

/// A byte pipe to the peer of a request-driven protocol, with blocking sends and receives.
pub trait Link {
    /// Queue `data` for the peer, waiting while the peer's window or the transport is full.
    fn send(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Wait until at least `length` bytes are buffered.
    fn fill_at_least(&mut self, length: usize) -> Result<(), Error>;

    /// The bytes received and not yet consumed.
    fn buffered(&self) -> &[u8];

    /// Drop `length` buffered bytes and return their window to the peer.
    fn consume(&mut self, length: usize) -> Result<(), Error>;

    /// End the stream politely. Errors are not reported; the caller is done with the link.
    fn close(&mut self);
}

/// A session channel running a subsystem such as `sftp`.
///
/// The calling thread drives the connection itself: sends and receives keep the transport
/// flushed, answer rekeys and window adjustments, and fail on the operation's idle bound.
pub struct Subsystem {
    connection: Connection,
    channel: Channel,
    inbound: Vec<u8>,
    start: usize,
    interrupt: Option<Interrupt>,
    touched: Instant,
    broken: bool,
}

impl Subsystem {
    /// Open a session channel on `connection` and start the named subsystem.
    pub fn open(
        mut connection: Connection,
        name: &str,
        interrupt: Option<Interrupt>,
    ) -> Result<Self, Error> {
        connection.require_usable()?;
        connection.transport().begin_operation(None, interrupt.clone());
        let started = Channel::open(&mut connection).and_then(|mut channel| {
            channel.subsystem(&mut connection, name)?;
            Ok(channel)
        });
        let channel = match started {
            Ok(channel) => channel,
            Err(error) => {
                connection.mark_unusable();
                return Err(error);
            }
        };
        let mut subsystem = Self {
            connection,
            channel,
            inbound: Vec::new(),
            start: 0,
            interrupt,
            touched: Instant::now(),
            broken: false,
        };
        subsystem.restart();
        Ok(subsystem)
    }

    /// The connection underneath, for its identity and trust facts.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    fn restart(&mut self) {
        let transport = self.connection.transport();
        transport.begin_operation(None, self.interrupt.clone());
        transport.await_command();
        transport.set_keepalive(Some(KEEPALIVE));
        self.touched = Instant::now();
    }

    fn run<T>(&mut self, work: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        if self.broken {
            return Err(Error::Unusable);
        }
        if self.touched.elapsed() >= STALE_AFTER {
            self.restart();
        }
        let result = work(self);
        self.touched = Instant::now();
        if result.is_err() {
            self.broken = true;
            self.connection.mark_unusable();
        }
        result
    }

    fn service(&mut self) -> Result<bool, Error> {
        self.connection.transport().check()?;
        if self.connection.transport().keepalive_due() {
            self.connection.transport().send_keepalive()?;
        }
        if self.connection.rekey_due() {
            self.connection.rekey(None)?;
        }
        let flushed = self.connection.transport().flush_nonblocking()?;
        while let Some(packet) = self.connection.try_next_packet()? {
            self.on_packet(packet)?;
        }
        if self.channel.close_received {
            self.channel.send_close(self.connection.transport())?;
        }
        Ok(flushed)
    }

    fn block(&mut self, flushed: bool) -> Result<(), Error> {
        let events = self
            .connection
            .transport()
            .wait_with_files(!flushed, None, [None, None], None)?;
        if events.contains(rustix::event::PollFlags::IN) || events.contains(rustix::event::PollFlags::HUP) {
            self.connection.transport().fill_nonblocking()?;
        }
        Ok(())
    }

    fn ended(&self) -> Error {
        Error::Channel {
            detail: "the server closed the channel".to_owned(),
        }
    }

    fn on_packet(&mut self, packet: Packet) -> Result<(), Error> {
        match packet.message_type {
            MessageType::ChannelData => {
                let mut reader = SshReader::new(&packet.payload);
                let recipient = reader.u32()?;
                let data = reader.string()?;
                reader.finish()?;
                self.channel.expect_recipient(recipient)?;
                self.check_open()?;
                self.channel.receive(data.len())?;
                self.inbound.extend_from_slice(data);
            }
            MessageType::ChannelExtendedData => {
                let mut reader = SshReader::new(&packet.payload);
                let recipient = reader.u32()?;
                let _data_type = reader.u32()?;
                let data = reader.string()?;
                reader.finish()?;
                self.channel.expect_recipient(recipient)?;
                self.check_open()?;
                self.channel.receive(data.len())?;
                self.channel.release(data.len());
                self.channel.replenish(self.connection.transport())?;
            }
            MessageType::ChannelWindowAdjust => self.channel.window_adjust(&packet.payload)?,
            MessageType::ChannelRequest => {
                let mut reader = SshReader::new(&packet.payload);
                let recipient = reader.u32()?;
                self.channel.expect_recipient(recipient)?;
                let _request = reader.text()?;
                if reader.u8()? != 0 {
                    let mut reply = Vec::new();
                    MessageType::ChannelFailure.encode(&mut reply);
                    reply.extend_from_slice(&self.channel.remote_id.to_be_bytes());
                    self.connection.transport().reply(&reply)?;
                }
            }
            MessageType::ChannelEof => {
                self.expect_only_recipient(&packet.payload)?;
                self.channel.eof_received = true;
            }
            MessageType::ChannelClose => {
                self.expect_only_recipient(&packet.payload)?;
                self.channel.close_received = true;
            }
            MessageType::RequestSuccess | MessageType::RequestFailure => {
                if !self.connection.transport().keepalive_answered() {
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

    fn expect_only_recipient(&self, payload: &[u8]) -> Result<(), Error> {
        let mut reader = SshReader::new(payload);
        let recipient = reader.u32()?;
        reader.finish()?;
        self.channel.expect_recipient(recipient)
    }

    fn check_open(&self) -> Result<(), Error> {
        if self.channel.eof_received || self.channel.close_received {
            return Err(Error::Protocol {
                detail: "data after the peer ended its output".to_owned(),
            });
        }
        Ok(())
    }

    fn send_inner(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut sent = 0;
        while sent < data.len() {
            let flushed = self.service()?;
            if self.channel.close_received || self.channel.eof_received {
                return Err(self.ended());
            }
            if self.connection.transport().pending_output() >= OUTPUT_HIGH_WATER {
                self.block(false)?;
                continue;
            }
            let queued = self
                .channel
                .send_data(self.connection.transport(), &data[sent..])?;
            if queued == 0 {
                self.block(flushed)?;
                continue;
            }
            sent += queued;
        }
        Ok(())
    }

    fn fill_inner(&mut self, length: usize) -> Result<(), Error> {
        loop {
            let flushed = self.service()?;
            if self.inbound.len() - self.start >= length {
                return Ok(());
            }
            if self.channel.close_received || self.channel.eof_received {
                return Err(self.ended());
            }
            self.block(flushed)?;
        }
    }

    fn consume_inner(&mut self, length: usize) -> Result<(), Error> {
        if length > self.inbound.len() - self.start {
            return Err(Error::Protocol {
                detail: "consumed more than was buffered".to_owned(),
            });
        }
        self.start += length;
        self.channel.release(length);
        if self.start == self.inbound.len() {
            self.inbound.clear();
            self.start = 0;
        } else if self.start >= COMPACT_AFTER {
            self.inbound.drain(..self.start);
            self.start = 0;
        }
        self.channel.replenish(self.connection.transport())
    }

    fn close_inner(&mut self) -> Result<(), Error> {
        self.connection
            .transport()
            .begin_operation(Some(CLOSE_WAIT), self.interrupt.clone());
        self.channel.send_eof(self.connection.transport())?;
        self.channel.send_close(self.connection.transport())?;
        loop {
            let flushed = self.service()?;
            if self.channel.is_closed() && flushed {
                return Ok(());
            }
            self.block(flushed)?;
        }
    }
}

impl Link for Subsystem {
    fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        self.run(|this| this.send_inner(data))
    }

    fn fill_at_least(&mut self, length: usize) -> Result<(), Error> {
        self.run(|this| this.fill_inner(length))
    }

    fn buffered(&self) -> &[u8] {
        &self.inbound[self.start..]
    }

    fn consume(&mut self, length: usize) -> Result<(), Error> {
        self.run(|this| this.consume_inner(length))
    }

    fn close(&mut self) {
        if !self.broken {
            let _ = self.close_inner();
            self.broken = true;
        }
    }
}
