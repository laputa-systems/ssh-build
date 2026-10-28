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
use clap::Parser;
#[cfg(target_os = "linux")]
use listenfd::ListenFd;
use oxish::{Account, Config, DEFAULT_PROVIDER, GitPolicy, Server, Username, load_host_keys, require_supported_cpu};
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

    let session_bin = match args.session_bin {
        Some(path) => path,
        None => {
            let exe = env::current_exe()?;
            let Some(dir) = exe.parent() else {
                anyhow::bail!("cannot determine directory of current executable");
            };
            dir.join("oxish-session")
        }
    };

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

    let (Some(repo_root), Some(git_dir), Some(authorized_keys)) =
        (&args.repo_root, &args.git_dir, &args.authorized_keys)
    else {
        anyhow::bail!("--repo-root, --git-dir and --authorized-keys are required");
    };
    let policy = GitPolicy::new(repo_root, git_dir).context("unsafe git configuration")?;
    let name = Username::try_from(args.user).context("invalid --user")?;
    let account = Account::from_file(name, authorized_keys, provider)?;

    info!(addr = %listener.local_addr()?, "listening for connections");
    Arc::new(
        Server::new(account, host_keys, session_bin, policy, provider)?
            .with_config(config),
    )
    .run(listener)
    .await
}

#[derive(Debug, Parser)]
#[command(about = "Git-only SSH server: public-key authentication, git-upload-pack and git-receive-pack")]
struct Args {
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
    /// Directory holding all Git repositories clients may name
    #[clap(long, required_unless_present = "generate_host_key")]
    repo_root: Option<PathBuf>,
    /// Trusted directory with `git`, `git-upload-pack` and `git-receive-pack` (a git-build install)
    #[clap(long, required_unless_present = "generate_host_key")]
    git_dir: Option<PathBuf>,
    /// authorized_keys-format file; every key needs `git-access="read"` or `git-access="write"`
    #[clap(long, required_unless_present = "generate_host_key")]
    authorized_keys: Option<PathBuf>,
    /// The one SSH user name clients must use
    #[clap(long, default_value = "git")]
    user: String,
}

fn host_key_type(name: &str) -> Result<PublicKeyAlgorithm<'static>, String> {
    match PublicKeyAlgorithm::typed(name) {
        PublicKeyAlgorithm::Unknown(_) => Err(format!("unsupported host key type `{name}`")),
        algorithm => Ok(algorithm.to_owned()),
    }
}
