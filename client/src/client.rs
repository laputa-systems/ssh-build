use std::collections::VecDeque;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use oxish_proto::{Encode, MessageType};
use oxish_proto::crypto::CryptoProvider;

use crate::DEFAULT_PROVIDER;
use crate::auth::{self, Identity};
use crate::error::Error;
use crate::exec::{self, ExecOptions, ExecResult};
use crate::host_key::{Fingerprint, HostTrust};
use crate::kex::{self, Algorithms, Established};
use crate::stream::{self, InputSource, StreamOptions};
use crate::wire::{Interrupt, Packet, SshReader, Transport, plain_text, put_string};

/// When to start a new key exchange under the current keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyLimits {
    /// Bytes read and written.
    pub bytes: u64,
    /// Packets read and written.
    pub packets: u64,
    /// Time since the last exchange.
    pub interval: Duration,
}

impl Default for RekeyLimits {
    fn default() -> Self {
        Self {
            bytes: 1 << 30,
            packets: 1 << 28,
            interval: Duration::from_secs(3600),
        }
    }
}

/// The least time connection setup, authentication or one key exchange may take in all, unless
/// the configuration sets its own deadline.
pub const DEFAULT_PHASE_DEADLINE: Duration = Duration::from_secs(30);

/// Explicit connection, authentication, and trust options.
#[derive(Clone)]
pub struct ClientConfig {
    /// The host name or address.
    pub host: String,
    /// The SSH port.
    pub port: u16,
    /// The remote user name.
    pub user: String,
    /// The Ed25519 identity that authenticates the user.
    pub identity: Identity,
    /// How the server host key is trusted.
    pub trust: HostTrust,
    /// How long the peer may stay silent while the client waits on it.
    pub timeout: Duration,
    /// When the client starts its own key exchanges.
    pub rekey: RekeyLimits,
    /// The most time connecting, authenticating and each key exchange may take in all,
    /// however steadily the peer sends.
    pub deadline: Duration,
    /// Reports that the caller wants connecting or authenticating abandoned.
    pub interrupt: Option<Interrupt>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("identity", &self.identity)
            .field("trust", &self.trust)
            .field("timeout", &self.timeout)
            .field("rekey", &self.rekey)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl ClientConfig {
    /// Build a configuration from explicit identity and trust.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        identity: Identity,
        trust: HostTrust,
        timeout: Duration,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            user: user.into(),
            identity,
            trust,
            timeout,
            rekey: RekeyLimits::default(),
            deadline: timeout.max(DEFAULT_PHASE_DEADLINE),
            interrupt: None,
        }
    }

    /// Build a configuration that authenticates with a key file and trusts one fingerprint.
    pub fn pinned(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        key: impl Into<PathBuf>,
        host_key: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        Ok(Self::new(
            host,
            port,
            user,
            Identity::KeyFile(key.into()),
            HostTrust::Pinned(Fingerprint::parse(host_key)?),
            timeout,
        ))
    }
}

/// An authenticated SSH connection.
pub struct Connection {
    config: ClientConfig,
    transport: Transport,
    established: Established,
    pending: VecDeque<Packet>,
    usable: bool,
}

impl Connection {
    /// Connect and verify the host key.
    pub fn connect(config: &ClientConfig) -> Result<Self, Error> {
        Self::connect_with(config, DEFAULT_PROVIDER)
    }

    /// Connect with an explicit cryptographic provider.
    pub fn connect_with(
        config: &ClientConfig,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, Error> {
        crate::cpu::require()?;
        let mut transport = Transport::connect(
            &config.host,
            config.port,
            config.timeout,
            config.deadline,
            config.interrupt.clone(),
            provider,
        )?;
        transport.exchange_identifications(concat!("oxish-client_", env!("CARGO_PKG_VERSION")))?;
        let established = kex::connect(
            &mut transport,
            &kex::Context {
                host: &config.host,
                port: config.port,
                trust: &config.trust,
                provider,
            },
        )?;
        transport.end_operation();
        Ok(Self {
            config: config.clone(),
            transport,
            established,
            pending: VecDeque::new(),
            usable: true,
        })
    }

    /// Authenticate the configured user with the configured Ed25519 key.
    pub fn authenticate(&mut self) -> Result<(), Error> {
        self.authenticate_with(DEFAULT_PROVIDER)
    }

    /// Authenticate with an explicit cryptographic provider.
    pub fn authenticate_with(&mut self, provider: &dyn CryptoProvider) -> Result<(), Error> {
        self.transport
            .begin_operation(Some(self.config.deadline), self.config.interrupt.clone());
        let user = self.config.user.clone();
        let identity = self.config.identity.clone();
        let session_id = self.established.session_id.clone();
        let result = auth::authenticate(self, &user, &identity, session_id.as_ref(), provider);
        self.transport.end_operation();
        result
    }

    /// Run one remote command with bounded captured output.
    pub fn exec(&mut self, command: &str, options: &ExecOptions) -> Result<ExecResult, Error> {
        exec::exec(self, command, options)
    }

    /// Run one remote command with streaming stdin and independent output sinks.
    ///
    /// Each writer is reached through a bounded pipe, so a writer that blocks stops neither the
    /// connection nor the server's requests from being answered. A writer that never returns
    /// still keeps this call from returning.
    pub fn exec_stream(
        &mut self,
        command: &str,
        options: &StreamOptions,
        stdin: Option<&mut dyn InputSource>,
        stdout: &mut dyn std::io::Write,
        stderr: &mut dyn std::io::Write,
    ) -> Result<ExecResult, Error> {
        stream::exec_stream_to_writers(self, command, options, stdin, stdout, stderr)
    }

    /// The host name the connection was made to.
    pub fn host(&self) -> &str {
        &self.config.host
    }

    /// The port the connection was made to.
    pub fn port(&self) -> u16 {
        self.config.port
    }

    /// The authenticated user name.
    pub fn user(&self) -> &str {
        &self.config.user
    }

    /// The verified server fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.established.fingerprint
    }

    /// The algorithms negotiated by the latest key exchange.
    pub fn algorithms(&self) -> &Algorithms {
        &self.established.algorithms
    }

    /// The session identifier used by user authentication.
    pub fn session_id(&self) -> &[u8] {
        self.established.session_id.as_ref()
    }

    /// The server host key blob.
    pub fn host_key_blob(&self) -> &[u8] {
        &self.established.host_key_blob
    }

    /// Whether strict key exchange was negotiated.
    pub fn strict(&self) -> bool {
        self.established.strict
    }

    /// The underlying transport, for the authentication and channel layers.
    pub fn transport(&mut self) -> &mut Transport {
        &mut self.transport
    }

    /// Whether the connection can still carry a request.
    pub fn is_usable(&self) -> bool {
        self.usable
    }

    pub(crate) fn require_usable(&self) -> Result<(), Error> {
        if self.usable {
            Ok(())
        } else {
            Err(Error::Unusable)
        }
    }

    pub(crate) fn mark_unusable(&mut self) {
        self.usable = false;
        self.transport.shutdown();
    }

    pub(crate) fn defer(&mut self, packets: Vec<Packet>) {
        for packet in packets.into_iter().rev() {
            self.pending.push_front(packet);
        }
    }

    /// Say goodbye to the server and release the socket.
    pub fn close(mut self) {
        self.disconnect();
    }

    fn disconnect(&mut self) {
        if !self.usable {
            return;
        }
        self.usable = false;
        let mut message = Vec::new();
        message.push(u8::from(MessageType::Disconnect));
        message.extend_from_slice(&11u32.to_be_bytes());
        put_string(&mut message, b"");
        put_string(&mut message, b"");
        if self.transport.encode_raw(&message).is_ok() {
            let _ = self.transport.flush_nonblocking();
        }
        self.transport.shutdown();
    }

    /// The next message that is not ignorable transport traffic. Ignorable messages are skipped,
    /// server key exchanges are answered, and a disconnect is delivered to the caller.
    pub(crate) fn next_message(&mut self) -> Result<Packet, Error> {
        loop {
            let packet = match self.pending.pop_front() {
                Some(packet) => packet,
                None => {
                    self.rekey_if_due()?;
                    self.transport.recv()?
                }
            };
            if let Some(packet) = self.filter(packet)? {
                return Ok(packet);
            }
        }
    }

    /// The next connection-layer packet, answering transport traffic on the way.
    pub(crate) fn next_packet(&mut self) -> Result<Packet, Error> {
        let packet = self.next_message()?;
        self.reject_disconnect(packet)
    }

    /// The next connection-layer packet already available without blocking.
    pub(crate) fn try_next_packet(&mut self) -> Result<Option<Packet>, Error> {
        loop {
            let packet = match self.pending.pop_front() {
                Some(packet) => packet,
                None => match self.transport.try_recv()? {
                    Some(packet) => packet,
                    None => return Ok(None),
                },
            };
            if let Some(packet) = self.filter(packet)? {
                return self.reject_disconnect(packet).map(Some);
            }
        }
    }

    fn reject_disconnect(&self, packet: Packet) -> Result<Packet, Error> {
        if packet.message_type == MessageType::Disconnect {
            Err(self.disconnected(&packet))
        } else {
            Ok(packet)
        }
    }

    fn filter(&mut self, packet: Packet) -> Result<Option<Packet>, Error> {
        match packet.message_type {
            MessageType::Ignore | MessageType::Debug | MessageType::Unimplemented => Ok(None),
            MessageType::GlobalRequest => {
                let mut reader = SshReader::new(&packet.payload);
                let _name = reader.text()?;
                if reader.u8()? != 0 {
                    self.transport
                        .reply(&[u8::from(MessageType::RequestFailure)])?;
                }
                Ok(None)
            }
            MessageType::ChannelOpen => {
                let mut reader = SshReader::new(&packet.payload);
                let _kind = reader.text()?;
                let sender = reader.u32()?;
                let mut refusal = Vec::new();
                MessageType::ChannelOpenFailure.encode(&mut refusal);
                refusal.extend_from_slice(&sender.to_be_bytes());
                refusal.extend_from_slice(&1u32.to_be_bytes());
                put_string(&mut refusal, b"channels are not accepted");
                put_string(&mut refusal, b"");
                self.transport.reply(&refusal)?;
                Ok(None)
            }
            MessageType::KeyExchangeInit => {
                self.rekey(Some(packet))?;
                Ok(None)
            }
            _ => Ok(Some(packet)),
        }
    }

    fn disconnected(&self, packet: &Packet) -> Error {
        let mut reader = SshReader::new(&packet.payload);
        let reason = reader.u32().unwrap_or(0);
        let description = plain_text(reader.text().unwrap_or(""));
        let detail = format!("server disconnected (reason {reason}): {description}");
        match self.transport.certainty() {
            crate::error::Certainty::NotSubmitted => Error::NotSubmitted { detail },
            crate::error::Certainty::Submitted => Error::Submitted { detail },
        }
    }

    fn rekey_if_due(&mut self) -> Result<(), Error> {
        let limits = self.config.rekey;
        let (bytes, packets, elapsed) = self.transport.kex_usage();
        if bytes >= limits.bytes || packets >= limits.packets || elapsed >= limits.interval {
            self.rekey(None)?;
        }
        Ok(())
    }

    pub(crate) fn rekey_due(&self) -> bool {
        let limits = self.config.rekey;
        let (bytes, packets, elapsed) = self.transport.kex_usage();
        bytes >= limits.bytes || packets >= limits.packets || elapsed >= limits.interval
    }

    pub(crate) fn rekey(&mut self, server_kexinit: Option<Packet>) -> Result<(), Error> {
        let session_id = self.established.session_id.clone();
        let previous = self.transport.bound_phase(self.config.deadline);
        let outcome = kex::rekey(
            &mut self.transport,
            &kex::Context {
                host: &self.config.host,
                port: self.config.port,
                trust: &self.config.trust,
                provider: DEFAULT_PROVIDER,
            },
            &kex::Session {
                id: session_id.as_ref(),
                strict: self.established.strict,
                host_key: &self.established.host_key_blob,
            },
            server_kexinit,
        );
        self.transport.restore_deadline(previous);
        let (algorithms, queued) = outcome?;
        self.established.algorithms = algorithms;
        self.pending.extend(queued);
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.disconnect();
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Connection")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .field("user", &self.config.user)
            .field("fingerprint", &self.established.fingerprint)
            .finish_non_exhaustive()
    }
}
