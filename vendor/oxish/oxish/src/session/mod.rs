use core::time::Duration;

#[cfg(debug_assertions)]
use proto::SessionHostKey;
use proto::{
    Disconnect, GlobalRequest, MessageType, Pretty,
    auth::KeyOptions,
    crypto::CryptoProvider,
    key_exchange::{RekeyState, Rekeyed},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{Instant, sleep},
};
use tracing::{debug, info, instrument, trace, warn};

#[cfg(debug_assertions)]
use crate::KeyExchangeOutput;
use crate::{Connection, Error, GitPolicy, receive};

mod connections;
pub(crate) use connections::Channels;
use connections::{ChannelsFuture, Grant, IncomingChannelMessage};

/// A single SSH session's state
///
/// Call [`Session::run()`] to drive the session forward.
pub struct Session<T> {
    pub(crate) provider: &'static dyn CryptoProvider,
    pub(crate) conn: Connection<T>,
    pub(crate) kx: RekeyState,
    pub(crate) channels: Channels,
    pub(crate) post_quantum_kx: bool,
    pub(crate) options: KeyOptions,
    pub(crate) policy: GitPolicy,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Session<T> {
    #[cfg(debug_assertions)]
    pub(crate) fn new(
        kx: KeyExchangeOutput<'_>,
        conn: Connection<T>,
        provider: &'static dyn CryptoProvider,
        options: KeyOptions,
        policy: GitPolicy,
    ) -> Result<Self, Error> {
        Ok(Self {
            provider,
            conn,
            kx: RekeyState::new(
                kx.session_id,
                kx.strict_kx,
                kx.identities,
                SessionHostKey::from_server(kx.host_key, provider)?,
            ),
            post_quantum_kx: kx.post_quantum_kx,
            channels: Channels::default(),
            options,
            policy,
        })
    }

    /// Run the session, driving the connection forward and handling channel messages
    ///
    /// This function never returns unless the connection is closed or an error occurs.
    #[instrument(name = "connection", skip(self), fields(addr = %self.conn.addr))]
    pub async fn run(mut self) -> Result<(), Error> {
        let result = self.serve().await;
        self.channels.shutdown().await;
        result
    }

    async fn serve(&mut self) -> Result<(), Error> {
        let idle = sleep(IDLE_TIMEOUT);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                result = receive(&mut self.conn.stream, &mut self.conn.read) => {
                    idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                    let packet = result?;
                    let kx = packet.message_type == MessageType::KeyExchangeInit
                        || self.kx.in_progress();
                    match packet.message_type {
                        MessageType::Ignore | MessageType::Debug => {
                            trace!(?packet.message_type, "ignoring transport-layer message");
                            continue;
                        }
                        MessageType::Disconnect => {
                            match Disconnect::try_from(packet) {
                                Ok(disconnect) => info!(?disconnect, "received disconnect packet, closing connection"),
                                Err(error) => warn!(%error, "failed to read disconnect packet"),
                            }
                            return Ok(());
                        }
                        _ if kx => {
                            if let Some(rekeyed) = self.kx.handle(packet, &mut self.conn.write, self.provider)? {
                                let Rekeyed { update, post_quantum_kx } = rekeyed;
                                update.apply(&mut self.conn.write, &mut self.conn.read)?;
                                self.post_quantum_kx = post_quantum_kx;
                                debug!("completed client-initiated rekey");
                            }
                            self.conn.flush().await?;
                            continue;
                        }
                        MessageType::GlobalRequest => {
                            let request = GlobalRequest::try_from(packet)?;
                            debug!(name = %String::from_utf8_lossy(request.name), "refusing unsupported global request");
                            if request.want_reply {
                                self.conn.write.encode(&MessageType::RequestFailure)?;
                                self.conn.flush().await?;
                            }
                            continue;
                        }
                        MessageType::RequestSuccess | MessageType::RequestFailure => {
                            trace!(?packet.message_type, "ignoring unexpected global request reply");
                            continue;
                        }
                        _ => {}
                    }

                    let channel_message = IncomingChannelMessage::try_from(packet)?;
                    debug!(message = %Pretty(&channel_message), "handling channel message");
                    match channel_message {
                        IncomingChannelMessage::Open(open) => self.channels.open(open, &mut self.conn.write),
                        IncomingChannelMessage::Request(request) => {
                            let grant = Grant { policy: &self.policy, options: &self.options };
                            self.channels.request(request, &mut self.conn.write, &grant)
                        }
                        IncomingChannelMessage::Data(data) => self.channels.data(&data).map_err(Into::into),
                        IncomingChannelMessage::WindowAdjust(adjust) => self.channels.adjust_window(&adjust).map_err(Into::into),
                        IncomingChannelMessage::Eof(eof) => self.channels.eof(&eof).map_err(Into::into),
                        IncomingChannelMessage::Close(close) => self.channels.close(&close, &mut self.conn.write),
                    }?;

                    self.conn.flush().await?;
                }
                result = ChannelsFuture::new(&mut self.channels, &mut self.conn.write), if !self.kx.in_progress() => {
                    idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                    result?;
                    self.conn.flush().await?;
                }
                () = &mut idle, if !self.channels.busy() => {
                    info!("closing idle connection");
                    return Ok(());
                }
            }
        }
    }
}

/// How long a connection with no running command may stay silent
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
