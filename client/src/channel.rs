use oxish_proto::{Encode, MessageType};
use zeroize::Zeroizing;

use crate::client::Connection;
use crate::error::Error;
use crate::session::{PtyRequest, TerminalSize};
use crate::wire::{Packet, SshReader, Transport, plain_text, put_string};

/// The local receive window advertised to the server.
pub const LOCAL_WINDOW: u32 = 2 * 1024 * 1024;
/// The largest packet the local side accepts.
pub const LOCAL_MAX_PACKET: u32 = 32 * 1024;
/// The most payload the local side puts in one data packet.
pub const SEND_CHUNK: usize = 32 * 1024;

fn channel_error(detail: impl Into<String>) -> Error {
    Error::Channel {
        detail: detail.into(),
    }
}

fn protocol_error(detail: impl Into<String>) -> Error {
    Error::Protocol {
        detail: detail.into(),
    }
}

const MAX_ENVIRONMENT: usize = 64;
const MAX_ENVIRONMENT_VALUE: usize = 4096;
const MAX_EARLY_PACKETS: usize = 1024;

/// Refuse an environment the client will not send.
pub fn validate_environment(env: &[(String, String)]) -> Result<(), Error> {
    let invalid = |detail: String| Error::InvalidEnvironment { detail };
    if env.len() > MAX_ENVIRONMENT {
        return Err(invalid(format!("more than {MAX_ENVIRONMENT} variables")));
    }
    for (name, value) in env {
        let mut characters = name.chars();
        let starts = characters
            .next()
            .is_some_and(|first| first == '_' || first.is_ascii_alphabetic());
        if !starts || !characters.all(|c| c == '_' || c.is_ascii_alphanumeric()) || name.len() > 128 {
            return Err(invalid(format!("{name:?} is not a portable variable name")));
        }
        if value.contains('\0') || value.len() > MAX_ENVIRONMENT_VALUE {
            return Err(invalid(format!("the value of {name} has a NUL byte or exceeds {MAX_ENVIRONMENT_VALUE} bytes")));
        }
    }
    Ok(())
}

fn local_open_recipient(recipient: u32, local_id: u32) -> Result<(), Error> {
    if recipient == local_id {
        Ok(())
    } else {
        Err(channel_error(format!("message for unknown channel {recipient}")))
    }
}

/// An open session channel.
#[derive(Debug)]
pub struct Channel {
    /// The local channel identifier.
    pub local_id: u32,
    /// The peer's channel identifier.
    pub remote_id: u32,
    /// Bytes the peer will still accept.
    pub remote_window: u32,
    /// Largest data packet the peer accepts.
    pub remote_max_packet: u32,
    local_window: u32,
    consumed: u32,
    /// Whether the peer announced the end of its data.
    pub eof_received: bool,
    /// Whether the local side announced the end of its data.
    pub eof_sent: bool,
    /// Whether the peer closed the channel.
    pub close_received: bool,
    close_sent: bool,
}

impl Channel {
    /// Open a `session` channel and wait for confirmation.
    pub fn open(connection: &mut Connection) -> Result<Self, Error> {
        let local_id: u32 = 0;
        let mut request = Vec::new();
        MessageType::ChannelOpen.encode(&mut request);
        put_string(&mut request, b"session");
        request.extend_from_slice(&local_id.to_be_bytes());
        request.extend_from_slice(&LOCAL_WINDOW.to_be_bytes());
        request.extend_from_slice(&LOCAL_MAX_PACKET.to_be_bytes());
        connection.transport().send_raw(&request)?;

        let packet = connection.next_packet()?;
        match packet.message_type {
            MessageType::ChannelOpenConfirmation => {
                let mut reader = SshReader::new(&packet.payload);
                let recipient = reader.u32()?;
                let sender = reader.u32()?;
                let window = reader.u32()?;
                let maximum = reader.u32()?;
                reader.finish()?;
                local_open_recipient(recipient, local_id)?;
                if maximum == 0 {
                    return Err(protocol_error("peer allows no data in a packet"));
                }
                Ok(Self {
                    local_id,
                    remote_id: sender,
                    remote_window: window,
                    remote_max_packet: maximum,
                    local_window: LOCAL_WINDOW,
                    consumed: 0,
                    eof_received: false,
                    eof_sent: false,
                    close_received: false,
                    close_sent: false,
                })
            }
            MessageType::ChannelOpenFailure => {
                let mut reader = SshReader::new(&packet.payload);
                let recipient = reader.u32()?;
                let reason = reader.u32()?;
                let description = plain_text(reader.text()?);
                let _language = reader.string()?;
                reader.finish()?;
                local_open_recipient(recipient, local_id)?;
                Err(channel_error(format!(
                    "channel open failed ({reason}): {description}"
                )))
            }
            other => Err(protocol_error(format!(
                "unexpected channel-open message {other:?}"
            ))),
        }
    }

    /// Ask the server to set one environment variable for the command and wait for its answer.
    pub fn set_environment(
        &mut self,
        connection: &mut Connection,
        name: &str,
        value: &str,
    ) -> Result<(), Error> {
        let mut body = Vec::new();
        put_string(&mut body, name.as_bytes());
        put_string(&mut body, value.as_bytes());
        self.request_with_reply(connection, "env", &body)
    }

    /// Ask the server to allocate a pseudo-terminal for the command and wait for its answer.
    pub fn request_pty(&mut self, connection: &mut Connection, pty: &PtyRequest) -> Result<(), Error> {
        let mut body = Vec::new();
        put_string(&mut body, pty.term.as_bytes());
        body.extend_from_slice(&pty.size.cols.to_be_bytes());
        body.extend_from_slice(&pty.size.rows.to_be_bytes());
        body.extend_from_slice(&pty.size.width_px.to_be_bytes());
        body.extend_from_slice(&pty.size.height_px.to_be_bytes());
        put_string(&mut body, &pty.modes);
        self.request_with_reply(connection, "pty-req", &body)
    }

    fn request_with_reply(
        &mut self,
        connection: &mut Connection,
        name: &'static str,
        body: &[u8],
    ) -> Result<(), Error> {
        let mut request = Vec::new();
        MessageType::ChannelRequest.encode(&mut request);
        request.extend_from_slice(&self.remote_id.to_be_bytes());
        put_string(&mut request, name.as_bytes());
        request.push(1);
        request.extend_from_slice(body);
        connection.transport().send_raw(&request)?;
        loop {
            let packet = connection.next_packet()?;
            match packet.message_type {
                MessageType::ChannelSuccess => return self.expect_reply_for(&packet.payload),
                MessageType::ChannelFailure => {
                    self.expect_reply_for(&packet.payload)?;
                    return Err(Error::Rejected { request: name });
                }
                MessageType::ChannelWindowAdjust => self.window_adjust(&packet.payload)?,
                other => {
                    return Err(protocol_error(format!("unexpected {name} reply {other:?}")));
                }
            }
        }
    }

    /// Tell the server the terminal changed size. The request wants no reply.
    pub fn send_window_change(
        &mut self,
        transport: &mut Transport,
        size: TerminalSize,
    ) -> Result<(), Error> {
        let mut packet = Vec::new();
        MessageType::ChannelRequest.encode(&mut packet);
        packet.extend_from_slice(&self.remote_id.to_be_bytes());
        put_string(&mut packet, b"window-change");
        packet.push(0);
        packet.extend_from_slice(&size.cols.to_be_bytes());
        packet.extend_from_slice(&size.rows.to_be_bytes());
        packet.extend_from_slice(&size.width_px.to_be_bytes());
        packet.extend_from_slice(&size.height_px.to_be_bytes());
        transport.encode_raw(&packet)
    }

    /// Send an `exec` request and wait for its reply.
    pub fn exec(&mut self, connection: &mut Connection, command: &[u8]) -> Result<(), Error> {
        self.start(connection, "exec", Some(command))
    }

    /// Send a `shell` request and wait for its reply.
    pub fn shell(&mut self, connection: &mut Connection) -> Result<(), Error> {
        self.start(connection, "shell", None)
    }

    fn start(
        &mut self,
        connection: &mut Connection,
        kind: &'static str,
        command: Option<&[u8]>,
    ) -> Result<(), Error> {
        let mut request = Vec::new();
        MessageType::ChannelRequest.encode(&mut request);
        request.extend_from_slice(&self.remote_id.to_be_bytes());
        put_string(&mut request, kind.as_bytes());
        request.push(1);
        if let Some(command) = command {
            put_string(&mut request, command);
        }
        connection.transport().mark_submitted();
        connection.transport().send_raw(&request)?;

        let mut early = Vec::new();
        let mut early_bytes = 0;
        loop {
            let packet = connection.next_packet()?;
            if early.len() >= MAX_EARLY_PACKETS {
                return Err(protocol_error(
                    "peer sent too many messages before the session reply",
                ));
            }
            match packet.message_type {
                MessageType::ChannelSuccess => {
                    self.expect_reply_for(&packet.payload)?;
                    connection.defer(early);
                    return Ok(());
                }
                MessageType::ChannelFailure => {
                    self.expect_reply_for(&packet.payload)?;
                    return Err(Error::Rejected { request: kind });
                }
                MessageType::ChannelWindowAdjust => self.window_adjust(&packet.payload)?,
                MessageType::ChannelData | MessageType::ChannelExtendedData => {
                    early_bytes += self.pre_reply_data_length(&packet)?;
                    if early_bytes > LOCAL_WINDOW as usize {
                        return Err(protocol_error(
                            "peer sent more than the channel window before the session reply",
                        ));
                    }
                    early.push(packet);
                }
                MessageType::ChannelEof | MessageType::ChannelClose => {
                    self.pre_reply_recipient(&packet.payload)?;
                    early.push(packet);
                }
                MessageType::ChannelRequest => {
                    self.pre_reply_recipient(&packet.payload)?;
                    early.push(packet);
                }
                other => {
                    return Err(protocol_error(format!("unexpected {kind} reply {other:?}")));
                }
            }
        }
    }

    fn pre_reply_recipient(&self, payload: &[u8]) -> Result<(), Error> {
        let mut reader = SshReader::new(payload);
        let recipient = reader.u32()?;
        self.expect_recipient(recipient)
    }

    fn pre_reply_data_length(&self, packet: &Packet) -> Result<usize, Error> {
        let mut reader = SshReader::new(&packet.payload);
        let recipient = reader.u32()?;
        self.expect_recipient(recipient)?;
        if packet.message_type == MessageType::ChannelExtendedData {
            let _data_type = reader.u32()?;
        }
        let data = reader.string()?;
        reader.finish()?;
        Ok(data.len())
    }

    fn expect_reply_for(&self, payload: &[u8]) -> Result<(), Error> {
        let mut reader = SshReader::new(payload);
        let recipient = reader.u32()?;
        reader.finish()?;
        self.expect_recipient(recipient)
    }

    /// Apply a peer window increase.
    pub fn window_adjust(&mut self, payload: &[u8]) -> Result<(), Error> {
        let mut reader = SshReader::new(payload);
        let recipient = reader.u32()?;
        let added = reader.u32()?;
        reader.finish()?;
        self.expect_recipient(recipient)?;
        self.remote_window = self
            .remote_window
            .checked_add(added)
            .ok_or_else(|| protocol_error("peer window exceeds 2^32-1 bytes"))?;
        Ok(())
    }

    /// Reject a message addressed to another channel.
    pub fn expect_recipient(&self, recipient: u32) -> Result<(), Error> {
        if recipient == self.local_id {
            Ok(())
        } else {
            Err(channel_error(format!("message for unknown channel {recipient}")))
        }
    }

    /// Account for received payload against the local window. The window comes back to the
    /// peer only once [`Self::release`] reports the bytes delivered.
    pub fn receive(&mut self, length: usize) -> Result<(), Error> {
        let length = u32::try_from(length)
            .ok()
            .filter(|length| *length <= LOCAL_MAX_PACKET)
            .ok_or_else(|| protocol_error("peer exceeded the advertised packet size"))?;
        self.local_window = self
            .local_window
            .checked_sub(length)
            .ok_or_else(|| protocol_error("peer exceeded the advertised window"))?;
        Ok(())
    }

    /// Record received bytes that have left the client, so their window can be returned.
    pub fn release(&mut self, length: usize) {
        self.consumed += length as u32;
    }

    /// Return released window to the peer once enough has accumulated and the channel is open.
    pub fn replenish(&mut self, transport: &mut Transport) -> Result<(), Error> {
        if self.consumed < LOCAL_WINDOW / 2 || self.close_received || self.close_sent {
            return Ok(());
        }
        let mut packet = Vec::new();
        MessageType::ChannelWindowAdjust.encode(&mut packet);
        packet.extend_from_slice(&self.remote_id.to_be_bytes());
        packet.extend_from_slice(&self.consumed.to_be_bytes());
        transport.reply(&packet)?;
        self.local_window += self.consumed;
        self.consumed = 0;
        Ok(())
    }

    /// Queue data for the peer, bounded by its window and packet size.
    pub fn send_data(&mut self, transport: &mut Transport, data: &[u8]) -> Result<usize, Error> {
        let limit = usize::try_from(self.remote_window.min(self.remote_max_packet))
            .unwrap_or(usize::MAX)
            .min(SEND_CHUNK)
            .min(data.len());
        if limit == 0 {
            return Ok(0);
        }
        let mut packet = Zeroizing::new(Vec::with_capacity(limit + 9));
        MessageType::ChannelData.encode(&mut packet);
        packet.extend_from_slice(&self.remote_id.to_be_bytes());
        put_string(&mut packet, &data[..limit]);
        transport.encode_raw(&packet)?;
        self.remote_window -= limit as u32;
        Ok(limit)
    }

    /// Queue end-of-file for the peer.
    pub fn send_eof(&mut self, transport: &mut Transport) -> Result<(), Error> {
        if self.eof_sent {
            return Ok(());
        }
        let mut packet = Vec::new();
        MessageType::ChannelEof.encode(&mut packet);
        packet.extend_from_slice(&self.remote_id.to_be_bytes());
        transport.encode_raw(&packet)?;
        self.eof_sent = true;
        Ok(())
    }

    /// Queue the channel close once.
    pub fn send_close(&mut self, transport: &mut Transport) -> Result<(), Error> {
        if self.close_sent {
            return Ok(());
        }
        let mut packet = Vec::new();
        MessageType::ChannelClose.encode(&mut packet);
        packet.extend_from_slice(&self.remote_id.to_be_bytes());
        transport.encode_raw(&packet)?;
        self.close_sent = true;
        Ok(())
    }

    /// Whether both sides have closed the channel.
    pub fn is_closed(&self) -> bool {
        self.close_received && self.close_sent
    }
}
