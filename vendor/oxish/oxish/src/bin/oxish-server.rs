#![forbid(unsafe_code)]

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

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
use tokio::net::TcpListener;
use tracing::info;

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
    let listener = match (ListenFd::from_env().take_tcp_listener(0)?, args.port) {
        (Some(listener), None) => {
            listener.set_nonblocking(true)?;
            TcpListener::from_std(listener)?
        }
        (None, Some(port)) => TcpListener::bind(SocketAddr::new(args.bind, port)).await?,
        (Some(_), Some(_)) => anyhow::bail!("LISTEN_FDS and --port conflict with each other"),
        (None, None) => anyhow::bail!("unless LISTEN_FDS is set, --port is required"),
    };

    #[cfg(not(target_os = "linux"))]
    let listener = match args.port {
        Some(port) => TcpListener::bind(SocketAddr::new(args.bind, port)).await?,
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

    info!(addr = %listener.local_addr()?, mode = ?args.mode, "listening for connections");
    Arc::new(server.with_config(config)).run(listener).await
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
    /// Address to listen on; loopback unless you deliberately choose otherwise
    #[clap(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    bind: IpAddr,
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

fn host_key_type(name: &str) -> Result<PublicKeyAlgorithm<'static>, String> {
    match PublicKeyAlgorithm::typed(name) {
        PublicKeyAlgorithm::Unknown(_) => Err(format!("unsupported host key type `{name}`")),
        algorithm => Ok(algorithm.to_owned()),
    }
}
