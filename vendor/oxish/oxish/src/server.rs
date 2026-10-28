use core::{mem, net::{IpAddr, SocketAddr}, time::Duration};
#[cfg(coverage)]
use std::env;
use std::{collections::HashMap, path::PathBuf, sync::{Arc, Mutex}};

use anyhow::Context as _;
use proto::{HostKeys, ReadState, WriteState, crypto::CryptoProvider};
use serde::Deserialize;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, TryAcquireError},
    time::timeout,
};
use tracing::{debug, instrument, warn};

use crate::{
    Connection, Error, GitPolicy, SessionState, SideState,
    authentication::{Account, Authenticated, authenticate},
    platform::spawn,
};

/// State for an SSH server
pub struct Server {
    pub(crate) provider: &'static dyn CryptoProvider,
    pub(crate) host_keys: HostKeys,
    pub(crate) session: PathBuf,
    pub(crate) account: Account,
    pub(crate) policy: GitPolicy,
    pub(crate) authenticating: Semaphore,
    sessions: Semaphore,
    pre_auth_by_ip: Arc<PerIp>,
    sessions_by_ip: Arc<PerIp>,
    config: Config,
}

impl Server {
    /// Create a new SSH server from the necessary minimal state
    ///
    /// Refuses to run as root: the session process runs as the server's user, so a privileged
    /// server would run untrusted Git commands with full privileges.
    pub fn new(
        account: Account,
        host_keys: HostKeys,
        session: PathBuf,
        policy: GitPolicy,
        provider: &'static dyn CryptoProvider,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            rustix::process::geteuid().as_raw() != 0,
            "refusing to run as root; use a dedicated unprivileged Git account"
        );
        Ok(Self {
            provider,
            host_keys,
            session,
            account,
            policy,
            authenticating: Semaphore::new(MAX_UNAUTHENTICATED),
            sessions: Semaphore::new(Config::default().max_sessions),
            pre_auth_by_ip: Arc::new(PerIp::new(Config::default().max_unauthenticated_per_ip)),
            sessions_by_ip: Arc::new(PerIp::new(Config::default().max_sessions_per_ip)),
            config: Config::default(),
        })
    }

    /// Set additional server configuration
    pub fn with_config(mut self, config: Config) -> Self {
        self.sessions = Semaphore::new(config.max_sessions);
        self.pre_auth_by_ip = Arc::new(PerIp::new(config.max_unauthenticated_per_ip));
        self.sessions_by_ip = Arc::new(PerIp::new(config.max_sessions_per_ip));
        self.config = config;
        self
    }

    /// Run the server, accepting connections on the given listener
    ///
    /// Accepts connections from the `listener` and spawns a task for each accepted connection.
    /// After authentication the server hands the connection to a session process.
    ///
    /// This function never returns unless the listener is closed or an error occurs.
    pub async fn run(self: &Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok((stream, addr)) => (stream, addr),
                Err(error) => {
                    warn!(%error, "failed to accept connection");
                    continue;
                }
            };

            let server = self.clone();
            tokio::spawn(async move {
                debug!(%addr, "accepted connection");
                if let Err(err) = stream.set_nodelay(true) {
                    warn!(%addr, %err, "failed to set TCP_NODELAY on connection");
                }
                if let Err(err) = enable_keepalive(&stream) {
                    warn!(%addr, %err, "failed to enable TCP keepalive on connection");
                }

                let _ = server.accept(stream, addr).await;
            });
        }
    }

    #[instrument(name = "handshake", skip(self, stream, addr), fields(addr = %addr))]
    pub(crate) async fn accept(&self, stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
        let Some(_pre_auth_ip) = PerIp::acquire(&self.pre_auth_by_ip, addr.ip()) else {
            warn!(%addr, "too many unauthenticated connections from this address");
            return Err(anyhow::anyhow!("too many unauthenticated connections from this address"));
        };

        let authenticating = match self.authenticating.try_acquire() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                warn!(%addr, "too many concurrent authentications; rejecting connection");
                return Err(anyhow::anyhow!("too many concurrent authentications"));
            }
            Err(TryAcquireError::Closed) => {
                warn!(%addr, "server is shutting down; rejecting connection");
                return Err(anyhow::anyhow!("server is shutting down"));
            }
        };

        let mut conn = Connection {
            stream,
            addr,
            read: ReadState::default(),
            write: WriteState::new(self.provider.secure_random()),
        };

        let future = conn.exchange_keys(&self.host_keys, self.provider);
        let kx = match timeout(KEY_EXCHANGE_TIMEOUT, future).await {
            Ok(result) => result.context("key exchange failed")?,
            Err(_) => return Err(anyhow::anyhow!("key exchange timed out")),
        };

        let Authenticated { options } = authenticate(
            &kx.session_id,
            &mut conn,
            &self.account,
            self.provider,
        )
        .await
        .context("authentication failed")?;
        drop(authenticating);

        let Some(_session_ip) = PerIp::acquire(&self.sessions_by_ip, addr.ip()) else {
            warn!(%addr, "too many sessions from this address; closing connection");
            return Err(anyhow::anyhow!("too many sessions from this address"));
        };

        let Ok(_session) = self.sessions.try_acquire() else {
            warn!(%addr, "too many concurrent sessions; closing connection");
            return Err(anyhow::anyhow!("too many concurrent sessions"));
        };

        let Connection {
            stream,
            addr,
            mut read,
            write,
        } = conn;

        if !write.buffered().is_empty() {
            return Err(Error::InvalidState("unflushed bytes in write buffer").into());
        }

        // Compact the bytes of the last decoded packet, which are still at the front of
        // the buffer (they are usually dropped at the start of the next `poll_packet()`).
        if read.last_length > 0 {
            read.buf.copy_within(read.last_length.., 0);
            read.buf.truncate(read.buf.len() - read.last_length);
            read.last_length = 0;
        }

        let state = SessionState {
            addr,
            host_key: kx.host_key,
            identities: kx.identities,
            post_quantum_kx: kx.post_quantum_kx,
            strict_kx: kx.strict_kx,
            session_id: kx.session_id,
            read: SideState {
                source: kx.keys.client_to_server,
                counter: read.opener.as_ref().map_or(0, |opener| opener.counter()),
                sequence_number: read.sequence_number,
            },
            write: SideState {
                source: kx.keys.server_to_client,
                counter: write.sealer.as_ref().map_or(0, |sealer| sealer.counter()),
                sequence_number: write.sequence_number,
            },
            read_buf: mem::take(&mut read.buf),
            options,
        };

        let mut child = spawn(state, stream, self)
            .await
            .context("failed to spawn session process")?;

        match child.wait().await {
            Ok(status) if status.success() => {
                debug!(%addr, %status, "session process exited");
                Ok(())
            }
            Ok(status) => Err(anyhow::anyhow!("session process exited with {status}")),
            Err(error) => Err(error).context("failed to wait for session process"),
        }
    }
}

/// Additional configuration for the SSH server
///
/// Can be used with [`Server::with_config()`] to override the default configuration.
#[non_exhaustive]
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    /// Authenticated connections served at once; further ones are closed after authenticating
    pub max_sessions: usize,
    /// Connections one source address may hold in key exchange or authentication at once
    pub max_unauthenticated_per_ip: usize,
    /// Authenticated connections one source address may hold at once
    pub max_sessions_per_ip: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_sessions: 32,
            max_unauthenticated_per_ip: 4,
            max_sessions_per_ip: 8,
        }
    }
}

/// Connections allowed to be in key exchange or authentication at once
const MAX_UNAUTHENTICATED: usize = 32;

/// Time to read the identification string and finish key exchange
const KEY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

/// Counts live connections per source address and refuses more than a fixed number
struct PerIp {
    limit: usize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}

/// Releases one slot of [`PerIp`] when dropped
struct PerIpGuard {
    owner: Arc<PerIp>,
    ip: IpAddr,
}

impl PerIp {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            counts: Mutex::new(HashMap::new()),
        }
    }

    fn acquire(owner: &Arc<Self>, ip: IpAddr) -> Option<PerIpGuard> {
        let mut counts = owner.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = counts.entry(ip).or_insert(0);
        if *count >= owner.limit {
            return None;
        }
        *count += 1;
        Some(PerIpGuard {
            owner: owner.clone(),
            ip,
        })
    }
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut counts = self.owner.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// Probe dead peers within about two minutes instead of the OS default of two hours
fn enable_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    use rustix::net::sockopt;

    sockopt::set_socket_keepalive(stream, true)?;
    sockopt::set_tcp_keepidle(stream, Duration::from_secs(60))?;
    sockopt::set_tcp_keepintvl(stream, Duration::from_secs(15))?;
    sockopt::set_tcp_keepcnt(stream, 4)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_address_limit_releases_on_drop() {
        let owner = Arc::new(PerIp::new(2));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let first = PerIp::acquire(&owner, a).unwrap();
        let _second = PerIp::acquire(&owner, a).unwrap();
        assert!(PerIp::acquire(&owner, a).is_none());
        assert!(PerIp::acquire(&owner, b).is_some());
        drop(first);
        assert!(PerIp::acquire(&owner, a).is_some());
    }
}
