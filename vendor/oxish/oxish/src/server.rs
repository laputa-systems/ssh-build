use core::{hash::Hash, mem, net::{IpAddr, SocketAddr}, time::Duration};
#[cfg(coverage)]
use std::env;
use std::{collections::HashMap, ffi::OsString, path::PathBuf, sync::{Arc, Mutex}};

use anyhow::Context as _;
use proto::{HostKeys, ReadState, WriteState, crypto::CryptoProvider};
use serde::Deserialize;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, TryAcquireError},
    time::{sleep, timeout},
};
use tracing::{debug, instrument, warn};

use crate::{
    Connection, Error, GitPolicy, LoginAccounts, LoginPolicy, LoginSession, SessionState, SideState,
    authentication::{Account, Authenticated, Principals, authenticate, check_trusted_executable},
    platform::{HANDOFF_TIMEOUT, is_resource_exhaustion, spawn},
};

/// What the server serves after authentication
enum Mode {
    /// The one Git account, and the repositories and programs it may use
    Git { account: Account, policy: GitPolicy },
    /// Login accounts, each served by a session process that becomes that account
    Login { accounts: LoginAccounts, policy: LoginPolicy },
}

/// State for an SSH server
pub struct Server {
    pub(crate) provider: &'static dyn CryptoProvider,
    pub(crate) host_keys: HostKeys,
    pub(crate) session: PathBuf,
    mode: Mode,
    pub(crate) authenticating: Semaphore,
    sessions: Semaphore,
    pre_auth_by_ip: Arc<PerIp>,
    sessions_by_ip: Arc<PerIp>,
    sessions_by_account: Arc<PerKey<String>>,
    handoff_timeout: Duration,
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
        Ok(Self::with_mode(provider, host_keys, session, Mode::Git { account, policy }))
    }

    /// Create a login-mode server: authenticated users get a shell or command as their account
    ///
    /// The listener may run as root; each session is served by the `session` binary, which drops
    /// to the account (groups, group, user) before it opens a terminal or runs anything. Every
    /// account must resolve in the user database and be allowed to log in, or this fails. The
    /// session binary and its directory must be owned by the server user or root and not writable
    /// by others, because a privileged listener executes it.
    pub fn login(
        accounts: LoginAccounts,
        host_keys: HostKeys,
        session: PathBuf,
        policy: LoginPolicy,
        provider: &'static dyn CryptoProvider,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(cfg!(target_os = "linux"), "login mode is supported on Linux only");
        policy.validate()?;
        anyhow::ensure!(session.is_absolute(), "the session binary path must be absolute");
        check_trusted_executable(&session)?;
        let database = policy.database();
        for name in accounts.names() {
            let user = database.lookup(name)?;
            user.check(policy.allow_root)?;
        }
        Ok(Self::with_mode(provider, host_keys, session, Mode::Login { accounts, policy }))
    }

    fn with_mode(
        provider: &'static dyn CryptoProvider,
        host_keys: HostKeys,
        session: PathBuf,
        mode: Mode,
    ) -> Self {
        Self {
            provider,
            host_keys,
            session,
            mode,
            authenticating: Semaphore::new(MAX_UNAUTHENTICATED),
            sessions: Semaphore::new(Config::default().max_sessions),
            pre_auth_by_ip: Arc::new(PerIp::new(Config::default().max_unauthenticated_per_ip)),
            sessions_by_ip: Arc::new(PerIp::new(Config::default().max_sessions_per_ip)),
            sessions_by_account: Arc::new(PerKey::new(Config::default().max_sessions_per_account)),
            handoff_timeout: HANDOFF_TIMEOUT,
            config: Config::default(),
        }
    }

    /// Set additional server configuration
    pub fn with_config(mut self, config: Config) -> Self {
        self.sessions = Semaphore::new(config.max_sessions);
        self.pre_auth_by_ip = Arc::new(PerIp::new(config.max_unauthenticated_per_ip));
        self.sessions_by_ip = Arc::new(PerIp::new(config.max_sessions_per_ip));
        self.sessions_by_account = Arc::new(PerKey::new(config.max_sessions_per_account));
        self.config = config;
        self
    }

    /// Shorten the wait for a session process to acknowledge the handoff (tests)
    #[cfg(test)]
    pub(crate) fn with_handoff_timeout(mut self, timeout: Duration) -> Self {
        self.handoff_timeout = timeout;
        self
    }

    /// Run the server, accepting connections on the given listener
    ///
    /// Accepts connections from the `listener` and spawns a task for each accepted connection.
    /// After authentication the server hands the connection to a session process.
    ///
    /// This function never returns: failures to accept a connection are logged and skipped.
    pub async fn run(self: &Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, mut addr) = match listener.accept().await {
                Ok((stream, addr)) => (stream, addr),
                Err(error) if is_resource_exhaustion(&error) => {
                    warn!(%error, "failed to accept connection, retrying in 1s");
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
                Err(error) => {
                    warn!(%error, "failed to accept connection");
                    continue;
                }
            };

            canonicalize(&mut addr);

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
        let Some(pre_auth_ip) = PerKey::acquire(&self.pre_auth_by_ip, addr.ip()) else {
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

        let principals = match &self.mode {
            Mode::Git { account, .. } => Principals::Git(account),
            Mode::Login { accounts, .. } => Principals::Login(accounts),
        };
        let Authenticated { options, user } = authenticate(
            &kx.session_id,
            &mut conn,
            &principals,
            self.provider,
        )
        .await
        .context("authentication failed")?;
        drop(authenticating);
        drop(pre_auth_ip);

        let Some(_session_ip) = PerKey::acquire(&self.sessions_by_ip, addr.ip()) else {
            warn!(%addr, "too many sessions from this address; closing connection");
            return Err(anyhow::anyhow!("too many sessions from this address"));
        };

        // Login mode only: the Git account is one configured name, so its cap is the global one.
        let _session_account = match &self.mode {
            Mode::Login { .. } => match PerKey::acquire(&self.sessions_by_account, user.clone()) {
                Some(guard) => Some(guard),
                None => {
                    warn!(%addr, %user, "too many sessions for this account; closing connection");
                    return Err(anyhow::anyhow!("too many sessions for this account"));
                }
            },
            Mode::Git { .. } => None,
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

        let args = self.session_args(&user).await?;
        let mut child = spawn(state, stream, &self.session, &args, self.handoff_timeout)
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

impl Server {
    /// The arguments that tell the session process what to serve
    async fn session_args(&self, user: &str) -> anyhow::Result<Vec<OsString>> {
        match &self.mode {
            Mode::Git { policy, .. } => Ok(vec![
                policy.repo_root().as_os_str().to_owned(),
                policy.git_dir().as_os_str().to_owned(),
            ]),
            Mode::Login { policy, .. } => {
                let (database, name, session) = (policy.database(), user.to_owned(), self.session.clone());
                // A root listener executes this binary: check it again at every login, not only at startup.
                let entry = tokio::task::spawn_blocking(move || {
                    check_trusted_executable(&session)?;
                    database.lookup(&name)
                })
                .await
                .context("user lookup was interrupted")?
                .context("cannot resolve the account")?;
                entry.check(policy.allow_root).context("account may not log in")?;
                Ok(LoginSession::new(entry, policy, self.session.clone()).to_args())
            }
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
    /// Login mode: authenticated connections one account may hold at once
    pub max_sessions_per_account: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_sessions: 32,
            max_unauthenticated_per_ip: 4,
            max_sessions_per_ip: 8,
            max_sessions_per_account: 8,
        }
    }
}

/// Connections allowed to be in key exchange or authentication at once
const MAX_UNAUTHENTICATED: usize = 32;

/// Time to read the identification string and finish key exchange
const KEY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

/// Counts live connections per key (a source address, an account) and refuses more than a fixed number
struct PerKey<K> {
    limit: usize,
    counts: Mutex<HashMap<K, usize>>,
}

/// Counts live connections per source address
type PerIp = PerKey<IpAddr>;

/// Releases one slot of [`PerKey`] when dropped
struct PerKeyGuard<K: Hash + Eq> {
    owner: Arc<PerKey<K>>,
    key: K,
}

impl<K: Hash + Eq + Clone> PerKey<K> {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            counts: Mutex::new(HashMap::new()),
        }
    }

    fn acquire(owner: &Arc<Self>, key: K) -> Option<PerKeyGuard<K>> {
        let mut counts = owner.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = counts.entry(key.clone()).or_insert(0);
        if *count >= owner.limit {
            return None;
        }
        *count += 1;
        Some(PerKeyGuard {
            owner: owner.clone(),
            key,
        })
    }
}

impl<K: Hash + Eq> Drop for PerKeyGuard<K> {
    fn drop(&mut self) {
        let mut counts = self.owner.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

/// Turn an IPv4-mapped peer address into the plain IPv4 one
///
/// On an IPv6 socket that accepts IPv4, IPv4 peers show up as IPv4-mapped addresses. Without this
/// the same host would be logged, and counted against the per-address limits, as two addresses.
/// `set_ip()` keeps the scope ID of other IPv6 addresses.
fn canonicalize(addr: &mut SocketAddr) {
    addr.set_ip(addr.ip().to_canonical());
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
    fn ipv4_mapped_peers_share_the_ipv4_address() {
        let mut mapped: SocketAddr = "[::ffff:192.0.2.1]:22".parse().unwrap();
        canonicalize(&mut mapped);
        assert_eq!(mapped, "192.0.2.1:22".parse().unwrap());

        let mut scoped: SocketAddr = "[fe80::1%3]:22".parse().unwrap();
        canonicalize(&mut scoped);
        assert_eq!(scoped, "[fe80::1%3]:22".parse().unwrap());

        let owner = Arc::new(PerIp::new(1));
        let _held = PerIp::acquire(&owner, mapped_then_canonical("[::ffff:192.0.2.1]:22")).unwrap();
        assert!(PerIp::acquire(&owner, mapped_then_canonical("192.0.2.1:22")).is_none());
    }

    fn mapped_then_canonical(addr: &str) -> IpAddr {
        let mut addr: SocketAddr = addr.parse().unwrap();
        canonicalize(&mut addr);
        addr.ip()
    }

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
