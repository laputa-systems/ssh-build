#![forbid(unsafe_code)]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Context as _;
use clap::{Parser, ValueEnum};
#[cfg(target_os = "linux")]
use listenfd::ListenFd;
use oxish::{
    Account, Config, DEFAULT_PROVIDER, GitPolicy, LoginAccounts, LoginPolicy, Server, Username, load_host_keys,
    require_supported_cpu,
};
use proto::{
    OpenSshKeyV1, SshPrivateKey,
    named::{Named, PublicKeyAlgorithm},
    pem_encode,
};
use rustix::{io::Errno, net::sockopt};
use tokio::{
    net::{TcpListener, TcpSocket},
    task::JoinSet,
};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    require_supported_cpu()?;
    let provider = DEFAULT_PROVIDER;
    let args = Args::parse();

    if let Some(path) = &args.generate_host_key {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path);

        return match file {
            Ok(mut host_key_file) => {
                let Ok((signing_key, pkcs8)) = provider.generate_signing_key(&args.host_key_type)
                else {
                    anyhow::bail!("failed to generate host key");
                };

                let single = SshPrivateKey::from_pkcs8(&pkcs8, &*signing_key)?;
                let openssh = OpenSshKeyV1::new([single]).context("no host key to encode")?;
                let pem = pem_encode("OPENSSH PRIVATE KEY", &openssh.to_bytes(provider)?);
                let result = host_key_file.write_all(pem.as_bytes());
                result?;

                eprintln!("generated host key at {}", path.display());
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Err(anyhow::anyhow!(
                "host key file `{}` already exists",
                path.display()
            )),
            Err(err) => Err(err.into()),
        };
    }

    anyhow::ensure!(
        !args.host_key_file.is_empty(),
        "at least one --host-key-file is required (create one with --generate-host-key)"
    );
    let host_keys = load_host_keys(&args.host_key_file, provider)?;
    info!(len = host_keys.len(), "loaded host keys");

    let session_bin = match args.session_bin.clone() {
        Some(path) => path,
        None => {
            let exe = env::current_exe()?;
            let Some(dir) = exe.parent() else {
                anyhow::bail!("cannot determine directory of current executable");
            };
            dir.join("oxish-session")
        }
    };

    let session_bin = fs::canonicalize(&session_bin)
        .with_context(|| format!("session binary `{}` not found", session_bin.display()))?;
    if !session_bin.is_file() {
        anyhow::bail!("session binary `{}` not found", session_bin.display());
    }

    #[cfg(target_os = "linux")]
    let listeners = {
        // There may be several, e.g. from separate IPv4 and IPv6 `ListenStream=` lines
        let mut fds = ListenFd::from_env();
        let mut listeners = Vec::new();
        for idx in 0..fds.len() {
            if let Some(listener) = fds.take_tcp_listener(idx)? {
                listener.set_nonblocking(true)?;
                listeners.push(TcpListener::from_std(listener)?);
            }
        }

        match (listeners.is_empty(), args.port) {
            (false, None) if args.bind.is_empty() => listeners,
            (false, None) => anyhow::bail!("LISTEN_FDS and --bind conflict with each other"),
            (true, Some(port)) => bind(&args.bind, port)?,
            (false, Some(_)) => anyhow::bail!("LISTEN_FDS and --port conflict with each other"),
            (true, None) => anyhow::bail!("unless LISTEN_FDS is set, --port is required"),
        }
    };

    #[cfg(not(target_os = "linux"))]
    let listeners = match args.port {
        Some(port) => bind(&args.bind, port)?,
        None => anyhow::bail!("--port is required"),
    };

    let config = match &args.config {
        Some(path) => {
            let s = fs::read_to_string(path)
                .with_context(|| format!("failed to read config file `{}`", path.display()))?;
            toml::from_str::<Config>(&s)
                .with_context(|| format!("failed to parse config file `{}`", path.display()))?
        }
        None => Config::default(),
    };

    let host_keys_loaded = host_keys;
    let server = match args.mode {
        Mode::Git => {
            anyhow::ensure!(
                args.login_options().is_empty(),
                "not valid without --mode login: {}",
                args.login_options().join(", ")
            );
            let (Some(repo_root), Some(git_dir), Some(authorized_keys)) =
                (&args.repo_root, &args.git_dir, &args.authorized_keys)
            else {
                anyhow::bail!("--repo-root, --git-dir and --authorized-keys are required");
            };
            let policy = GitPolicy::new(repo_root, git_dir).context("unsafe git configuration")?;
            let name = Username::try_from(args.user.clone()).context("invalid --user")?;
            let account = Account::from_file(name, authorized_keys, provider)?;
            Server::new(account, host_keys_loaded, session_bin, policy, provider)?
        }
        Mode::Login => {
            anyhow::ensure!(
                args.git_options().is_empty(),
                "not valid with --mode login: {}",
                args.git_options().join(", ")
            );
            let Some(accounts) = &args.accounts else {
                anyhow::bail!("--accounts is required with --mode login");
            };
            let accounts = LoginAccounts::from_file(accounts, provider)?;
            let mut policy = LoginPolicy::default();
            if let Some(path) = &args.login_path {
                policy.path = path.clone();
            }
            if let Some(path) = &args.passwd_file {
                policy.passwd = path.clone();
            }
            if let Some(path) = &args.group_file {
                policy.group = path.clone();
            }
            policy.accept_locale = args.accept_locale;
            policy.allow_root = args.allow_root_login;
            Server::login(accounts, host_keys_loaded, session_bin, policy, provider)?
        }
    };

    let server = Arc::new(server.with_config(config));

    let mut tasks = JoinSet::new();
    for listener in listeners {
        let addr = listener.local_addr()?;
        info!(
            %addr,
            accepting = accepting(&listener, addr)?,
            mode = ?args.mode,
            "listening for connections"
        );
        let server = server.clone();
        tasks.spawn(async move { server.run(listener).await });
    }

    // `Server::run()` doesn't currently return, but if any listener stops (or its task panics),
    // exit rather than keep serving on only some of the addresses
    match tasks.join_next().await {
        Some(result) => result?,
        None => Ok(()),
    }
}

/// What the server serves after authentication
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    /// `git-upload-pack` and `git-receive-pack` for one account
    Git,
    /// A shell or command for each configured account, run as that account
    Login,
}

#[derive(Debug, Parser)]
#[command(about = "SSH server with public-key authentication: Git-only by default, or login accounts with --mode login")]
struct Args {
    /// What to serve; login mode may run as root and drops each session to its account
    #[clap(long, value_enum, default_value_t = Mode::Git)]
    mode: Mode,
    /// TCP port to listen on (or set LISTEN_FDS for socket activation)
    #[clap(short, long)]
    port: Option<u16>,
    /// Address to listen on; repeat for several (default: loopback, `127.0.0.1` and `::1`).
    /// `::` accepts IPv6 and IPv4 on every interface, `0.0.0.0` only IPv4; both are deliberate
    #[clap(long)]
    bind: Vec<IpAddr>,
    /// TOML file with `max-sessions`, `max-unauthenticated-per-ip` and `max-sessions-per-ip`
    #[clap(short, long)]
    config: Option<PathBuf>,
    /// Host key file; repeat to serve several keys (the first of each algorithm is presented)
    #[clap(long)]
    host_key_file: Vec<PathBuf>,
    /// Create a new host key at this path and exit; never overwrites a file
    #[clap(long)]
    generate_host_key: Option<PathBuf>,
    /// Algorithm for a key made with --generate-host-key
    #[clap(long, value_parser = host_key_type, default_value = "ssh-ed25519")]
    host_key_type: PublicKeyAlgorithm<'static>,
    /// Path to the `oxish-session` binary (defaults to a sibling of this executable)
    #[clap(long)]
    session_bin: Option<PathBuf>,
    /// Git mode: directory holding all Git repositories clients may name
    #[clap(long)]
    repo_root: Option<PathBuf>,
    /// Git mode: trusted directory with `git`, `git-upload-pack` and `git-receive-pack` (a git-build install)
    #[clap(long)]
    git_dir: Option<PathBuf>,
    /// Git mode: authorized_keys-format file; every key needs `git-access="read"` or `git-access="write"`
    #[clap(long)]
    authorized_keys: Option<PathBuf>,
    /// Git mode: the one SSH user name clients must use
    #[clap(long, default_value = "git")]
    user: String,
    /// Login mode: accounts file with one `name ssh-ed25519 KEY` per line (never `~/.ssh`)
    #[clap(long)]
    accounts: Option<PathBuf>,
    /// Login mode: passwd file the accounts are resolved from
    #[clap(long)]
    passwd_file: Option<PathBuf>,
    /// Login mode: group file supplementary groups are read from
    #[clap(long)]
    group_file: Option<PathBuf>,
    /// Login mode: the PATH every session gets
    #[clap(long)]
    login_path: Option<String>,
    /// Login mode: pass the client's LANG and LC_* variables to sessions
    #[clap(long)]
    accept_locale: bool,
    /// Login mode: allow accounts with user ID 0 or in group 0
    #[clap(long)]
    allow_root_login: bool,
}

impl Args {
    fn login_options(&self) -> Vec<&'static str> {
        [
            (self.accounts.is_some(), "--accounts"),
            (self.passwd_file.is_some(), "--passwd-file"),
            (self.group_file.is_some(), "--group-file"),
            (self.login_path.is_some(), "--login-path"),
            (self.accept_locale, "--accept-locale"),
            (self.allow_root_login, "--allow-root-login"),
        ]
        .into_iter()
        .filter_map(|(set, name)| set.then_some(name))
        .collect()
    }

    fn git_options(&self) -> Vec<&'static str> {
        [
            (self.repo_root.is_some(), "--repo-root"),
            (self.git_dir.is_some(), "--git-dir"),
            (self.authorized_keys.is_some(), "--authorized-keys"),
        ]
        .into_iter()
        .filter_map(|(set, name)| set.then_some(name))
        .collect()
    }
}

/// Bind a listener for each `--bind` address, or for loopback in both families if there is none
///
/// With `--port 0` every later address reuses the port the first one got. The IPv6 loopback
/// address is skipped, with a warning, when the host has no IPv6 and no `--bind` asked for it.
fn bind(addrs: &[IpAddr], port: u16) -> anyhow::Result<Vec<TcpListener>> {
    let default = [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)];
    let explicit = !addrs.is_empty();
    let mut port = port;
    let mut listeners = Vec::new();
    for &ip in if explicit { addrs } else { &default } {
        match bind_one(ip, port) {
            Ok(bound) => listeners.extend(bound),
            Err(error) if !explicit && ip.is_ipv6() && ipv6_unavailable(&error) => {
                warn!(%error, "IPv6 loopback not available, listening on IPv4 only");
            }
            Err(error) => {
                return Err(error).with_context(|| format!("cannot listen on {}", SocketAddr::new(ip, port)));
            }
        }
        if let (0, Some(first)) = (port, listeners.first()) {
            port = first.local_addr()?.port();
        }
    }

    Ok(listeners)
}

fn bind_one(ip: IpAddr, port: u16) -> io::Result<Vec<TcpListener>> {
    match ip {
        IpAddr::V6(ip) if ip.is_unspecified() => bind_all(port),
        IpAddr::V6(ip) => Ok(vec![listen(TcpSocket::new_v6()?, SocketAddr::new(ip.into(), port))?]),
        IpAddr::V4(ip) => Ok(vec![listen(TcpSocket::new_v4()?, SocketAddr::new(ip.into(), port))?]),
    }
}

/// Whether `error` says the host has no usable IPv6 (no stack, not allowed, or no `::1`)
fn ipv6_unavailable(error: &io::Error) -> bool {
    matches!(
        Errno::from_io_error(error),
        Some(Errno::AFNOSUPPORT | Errno::PROTONOSUPPORT | Errno::ADDRNOTAVAIL)
    )
}

/// Bind listeners on all local addresses, accepting both IPv6 and IPv4 connections
///
/// Uses a single dual-stack socket where the platform supports it, and separate IPv6 and IPv4
/// sockets otherwise. Falls back to listening on IPv4 only if IPv6 is unavailable.
fn bind_all(port: u16) -> io::Result<Vec<TcpListener>> {
    let socket = match TcpSocket::new_v6() {
        Ok(socket) => socket,
        Err(error) => match Errno::from_io_error(&error) {
            // `EAFNOSUPPORT` if the host doesn't support IPv6, `EPROTONOSUPPORT` if it isn't
            // allowed (e.g. in an IPv4-only FreeBSD jail)
            Some(Errno::AFNOSUPPORT | Errno::PROTONOSUPPORT) => {
                warn!(%error, "IPv6 not available, listening on IPv4 only");
                let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
                return Ok(vec![listen(TcpSocket::new_v4()?, addr)?]);
            }
            _ => return Err(error),
        },
    };

    // The default for `IPV6_V6ONLY` varies by platform and system configuration, so clear it
    // explicitly to also accept IPv4 connections (as IPv4-mapped addresses). As far as we know,
    // only OpenBSD and DragonFly don't support those: OpenBSD rejects clearing it with `EINVAL`,
    // while DragonFly accepts it but ignores it (and always reads back as set). Where clearing it
    // did not take effect, bind a separate IPv4 socket next to it.
    let dual_stack = match sockopt::set_ipv6_v6only(&socket, false) {
        Ok(()) => !sockopt::ipv6_v6only(&socket)?,
        Err(Errno::INVAL) => false,
        Err(error) => return Err(error.into()),
    };

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
    let listener = listen(socket, addr)?;
    if dual_stack {
        return Ok(vec![listener]);
    }

    // Use the port the IPv6 socket got, in case `port` is 0
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, listener.local_addr()?.port()));
    Ok(vec![listener, listen(TcpSocket::new_v4()?, addr)?])
}

/// Which address families `listener` accepts connections from
fn accepting(listener: &TcpListener, addr: SocketAddr) -> io::Result<&'static str> {
    Ok(match addr.ip() {
        IpAddr::V6(ip) if ip.is_unspecified() && !sockopt::ipv6_v6only(listener)? => {
            "IPv4 and IPv6"
        }
        // Includes IPv6 sockets bound to an IPv4-mapped address (e.g. from LISTEN_FDS)
        ip if ip.to_canonical().is_ipv4() => "IPv4",
        _ => "IPv6",
    })
}

/// Bind and listen like `tokio::net::TcpListener::bind()`
fn listen(socket: TcpSocket, addr: SocketAddr) -> io::Result<TcpListener> {
    // On Windows, `SO_REUSEADDR` allows binding to a port that is actively in use
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    // The backlog tokio (through mio) and std use on most platforms
    socket.listen(128)
}

fn host_key_type(name: &str) -> Result<PublicKeyAlgorithm<'static>, String> {
    match PublicKeyAlgorithm::typed(name) {
        PublicKeyAlgorithm::Unknown(_) => Err(format!("unsupported host key type `{name}`")),
        algorithm => Ok(algorithm.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpStream;

    use super::*;

    #[tokio::test]
    async fn default_binds_loopback_in_both_families_on_one_port() {
        let listeners = bind(&[], 0).unwrap();
        assert!(!listeners.is_empty() && listeners.len() <= 2);
        let first = listeners[0].local_addr().unwrap();
        assert_eq!(first.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        for listener in &listeners {
            let addr = listener.local_addr().unwrap();
            assert!(addr.ip().is_loopback(), "{addr}");
            assert_eq!(addr.port(), first.port());
        }
    }

    #[tokio::test]
    async fn explicit_addresses_replace_the_default() {
        let listeners = bind(&[IpAddr::V4(Ipv4Addr::LOCALHOST)], 0).unwrap();
        assert_eq!(listeners.len(), 1);
        assert!(listeners[0].local_addr().unwrap().is_ipv4());
        assert!(bind(&[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))], 0).is_err());
    }

    #[tokio::test]
    async fn unspecified_ipv6_accepts_ipv4_peers() {
        let listeners = bind(&[IpAddr::V6(Ipv6Addr::UNSPECIFIED)], 0).unwrap();
        let port = listeners[0].local_addr().unwrap().port();
        assert!(listeners.iter().all(|listener| listener.local_addr().unwrap().port() == port));
        // Dual-stack, or the separate IPv4 socket that comes last; IPv4-only hosts have just that
        let v4 = listeners.last().unwrap();
        let (stream, accepted) =
            tokio::join!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)), v4.accept());
        stream.unwrap();
        let (_, peer) = accepted.unwrap();
        // IPv4-mapped or plain, depending on the socket that took it
        assert_eq!(peer.ip().to_canonical(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
