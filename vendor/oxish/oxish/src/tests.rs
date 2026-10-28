use core::{net::Ipv4Addr, net::SocketAddr, time::Duration};

use std::{
    env, fs, io,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{Arc, Once},
};

use anyhow::Context;
use proto::{
    Decoded, Encode, HostKeys, OpenSshKeyV1, ServerHostKey, SshPrivateKey,
    auth::{AuthorizedKey, GitAccess, KeyOptions},
    crypto::{CryptoProvider, Digest, KeySourceSide},
    key_exchange::Identities,
    named::{EncryptionAlgorithm, PublicKeyAlgorithm},
    pem_encode,
};
use tempfile::TempDir;
use tokio::{
    io::AsyncWriteExt, net::TcpListener, process::Command, sync::OnceCell, task::JoinHandle,
    time::timeout,
};
use zeroize::Zeroizing;

use crate::{Account, GitPolicy, SessionState, SideState, Username, server::Server};

/// Check our generated OpenSSH private key accepted by `ssh-keygen -y -f`
#[tokio::test]
async fn openssh_keygen_agrees() {
    let providers = [
        graviola::DEFAULT_PROVIDER,
    ];

    for provider in providers {
        for (algorithm, name) in [
            (PublicKeyAlgorithm::Ed25519, "ssh-ed25519"),
            (PublicKeyAlgorithm::EcdsaSha2Nistp256, "ecdsa-sha2-nistp256"),
        ] {
            let (key, pkcs8) = provider.generate_signing_key(&algorithm).unwrap();
            let pkcs8 = Zeroizing::new(pkcs8);
            let private = SshPrivateKey::from_pkcs8(&pkcs8, &*key).unwrap();
            let pem = pem_encode(
                "OPENSSH PRIVATE KEY",
                &OpenSshKeyV1::new([private])
                    .unwrap()
                    .to_bytes(provider)
                    .unwrap(),
            );

            let dir = TempDir::new().unwrap();
            let path = dir.path().join("key");
            fs::write(&path, pem.as_bytes()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

            let output = Command::new("ssh-keygen")
                .arg("-y")
                .arg("-f")
                .arg(&path)
                .output()
                .await
                .context("failed to run ssh-keygen")
                .unwrap();
            assert!(
                output.status.success(),
                "ssh-keygen rejected our {name} key: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let stdout = String::from_utf8(output.stdout).unwrap();
            let mut fields = stdout.split_whitespace();
            assert_eq!(fields.next(), Some(name));
            let blob = data_encoding::BASE64
                .decode(fields.next().unwrap().as_bytes())
                .unwrap();
            assert!(
                blob.ends_with(key.public_key()),
                "ssh-keygen derived a different {name} public key"
            );
        }
    }
}

/// Exercise a full handshake and session against the graviola provider
/// A scratch world for one server: repositories, Git binaries, and a client key
struct World {
    dir: TempDir,
    repos: PathBuf,
    bin: PathBuf,
    key: PathBuf,
}

/// What the `git`, `git-upload-pack` and `git-receive-pack` programs are
enum Programs {
    /// The system Git behind a wrapper that keeps its own exec path
    System,
    /// A shell script run for every service (`$0` names the service)
    Script(&'static str),
}

const SYSTEM_WRAPPER: &str = r#"#!/bin/sh
unset GIT_EXEC_PATH
PATH="$(dirname "@GIT@"):$PATH"
export PATH
case "$0" in
    *git-upload-pack) exec "@GIT@" upload-pack "$@" ;;
    *git-receive-pack) exec "@GIT@" receive-pack "$@" ;;
    *) exec "@GIT@" "$@" ;;
esac
"#;

fn make_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

async fn system_git() -> String {
    let output = Command::new("sh")
        .args(["-c", "command -v git"])
        .output()
        .await
        .unwrap();
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

impl World {
    async fn new(programs: Programs) -> anyhow::Result<Self> {
        let dir = TempDir::new()?;
        let base = fs::canonicalize(dir.path())?;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755))?;
        let repos = base.join("repos");
        let bin = base.join("bin");
        make_dir(&repos);
        make_dir(&bin);

        let script = match programs {
            Programs::System => SYSTEM_WRAPPER.replace("@GIT@", &system_git().await),
            Programs::Script(body) => format!("#!/bin/sh\n{body}\n"),
        };
        fs::write(bin.join("git"), script)?;
        fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o755))?;
        symlink("git", bin.join("git-upload-pack"))?;
        symlink("git", bin.join("git-receive-pack"))?;

        Ok(Self {
            key: base.join("client_key"),
            dir,
            repos,
            bin,
        })
    }

    fn base(&self) -> PathBuf {
        fs::canonicalize(self.dir.path()).unwrap()
    }

    async fn bare_repo(&self, name: &str) -> anyhow::Result<PathBuf> {
        let path = self.repos.join(name);
        let status = Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .arg(&path)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .await?;
        anyhow::ensure!(status.success(), "git init failed");
        Ok(path)
    }

    /// Start a server that serves connections until the returned guard is dropped
    async fn serve(
        &self,
        algorithm: &PublicKeyAlgorithm<'_>,
        access: Option<&str>,
        config: Option<crate::Config>,
        provider: &'static dyn CryptoProvider,
    ) -> anyhow::Result<(CliClient, ServerGuard)> {
        let account = self.account(algorithm, access, provider).await?;
        let (_, pkcs8) = provider.generate_signing_key(algorithm)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let client = CliClient::new(addr, &self.key);

        let policy = GitPolicy::new(&self.repos, &self.bin)?;
        let server = Server::new(
            account,
            HostKeys::new([Zeroizing::new(pkcs8)].into_iter(), provider)?,
            SESSION_BINARY
                .get_or_try_init(build_session_binary)
                .await
                .cloned()?,
            policy,
            provider,
        )?;
        let server = match config {
            Some(config) => server.with_config(config),
            None => server,
        };

        let server = Arc::new(server);
        let task = tokio::spawn(async move { server.run(listener).await });
        Ok((client, ServerGuard(task)))
    }

    /// Generate the client key and the account that accepts it
    async fn account(
        &self,
        algorithm: &PublicKeyAlgorithm<'_>,
        access: Option<&str>,
        provider: &dyn CryptoProvider,
    ) -> anyhow::Result<Account> {
        let _ = fs::remove_file(&self.key);
        let _ = fs::remove_file(self.key.with_extension("pub"));
        let status = Command::new("ssh-keygen")
            .arg("-q")
            .args(match algorithm {
                PublicKeyAlgorithm::EcdsaSha2Nistp256 => &["-t", "ecdsa", "-b", "256"],
                PublicKeyAlgorithm::Ed25519 => &["-t", "ed25519"][..],
                _ => panic!("unsupported key type for ssh-keygen: {algorithm:?}"),
            })
            .args(["-N", "", "-C", "oxish-e2e", "-f"])
            .arg(&self.key)
            .status()
            .await
            .context("failed to run ssh-keygen")?;
        anyhow::ensure!(status.success(), "ssh-keygen failed");

        let public = fs::read_to_string(self.key.with_extension("pub"))?;
        let line = match access {
            Some(access) => format!(r#"git-access="{access}" {public}"#),
            None => public,
        };
        let key = AuthorizedKey::from_str(&line, provider)
            .ok_or_else(|| anyhow::anyhow!("failed to parse generated public key"))?;
        Ok(Account::new(Username::try_from(USER.to_owned())?, vec![key]))
    }
}

/// Aborts the server task when dropped
struct ServerGuard(JoinHandle<anyhow::Result<()>>);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct CliClient {
    addr: SocketAddr,
    key: PathBuf,
    cmd: Command,
    log_level: &'static str,
}

impl CliClient {
    fn ssh() -> String {
        env::var("OXISH_TEST_SSH").unwrap_or_else(|_| "ssh".to_string())
    }

    fn options(addr: SocketAddr, key_path: &Path) -> Vec<String> {
        let mut args = vec!["-F", "/dev/null"]; // ignore the invoking user's ssh_config
        args.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]);
        args.extend(["-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes"]);
        args.extend(["-o", "BatchMode=yes"]);
        let mut args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        args.extend(["-p".into(), addr.port().to_string()]);
        args.extend(["-i".into(), key_path.display().to_string()]);
        args
    }

    fn new(addr: SocketAddr, key_path: &Path) -> Self {
        let mut cmd = Command::new(Self::ssh());
        cmd.args(Self::options(addr, key_path));
        Self {
            addr,
            key: key_path.to_owned(),
            cmd,
            log_level: "ERROR",
        }
    }

    /// Print the client's own diagnostics, for tests that assert on negotiation
    fn debug(mut self) -> Self {
        self.log_level = "DEBUG3";
        self
    }

    /// A `GIT_SSH_COMMAND` value that uses this client's key and no host key checking
    fn git_ssh_command(&self) -> String {
        let mut words = vec![Self::ssh()];
        words.extend(Self::options(self.addr, &self.key).into_iter().filter(|word| word != "-p" && *word != self.addr.port().to_string()));
        words.join(" ")
    }

    fn url(&self, repo: &str) -> String {
        format!("ssh://{USER}@127.0.0.1:{}/{repo}", self.addr.port())
    }

    async fn run(
        mut self,
        remote_command: Option<&str>,
        stdin: &[u8],
    ) -> anyhow::Result<Run> {
        let cmd = &mut self.cmd;
        cmd.args(["-o", &format!("LogLevel={}", self.log_level)]);
        cmd.arg(format!("{USER}@{}", self.addr.ip()));
        if let Some(remote_command) = remote_command {
            cmd.arg(remote_command);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let mut child_stdin = child.stdin.take().unwrap();
        let input = stdin.to_vec();
        let writer = tokio::spawn(async move {
            // The command can exit before reading its input
            match child_stdin.write_all(&input).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
                Err(error) => return Err(error),
            }
            Ok(())
        });

        let output = timeout(Duration::from_secs(60), child.wait_with_output()).await??;
        writer.await??;
        Ok(Run {
            status: output.status,
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: String,
}

impl Run {
    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

async fn script_world(body: &'static str) -> World {
    subscribe();
    World::new(Programs::Script(body)).await.unwrap()
}

const SERVICE: &str = "git-upload-pack 'a.git'";

async fn handshake(
    provider: &'static dyn CryptoProvider,
    algorithm: PublicKeyAlgorithm<'_>,
) -> anyhow::Result<()> {
    let world = script_world(r#"echo OXISH-$((6*7))"#).await;
    world.bare_repo("a.git").await?;
    let (client, _guard) = world.serve(&algorithm, Some("read"), None, provider).await?;
    let run = client.run(Some(SERVICE), b"").await?;
    anyhow::ensure!(run.status.success(), "ssh failed: {}", run.stderr);
    anyhow::ensure!(run.stdout().contains("OXISH-42"), "no output: {}", run.stdout());
    Ok(())
}

#[tokio::test]
async fn handshake_ecdsa_graviola() {
    handshake(graviola::DEFAULT_PROVIDER, PublicKeyAlgorithm::EcdsaSha2Nistp256)
        .await
        .unwrap();
}

#[tokio::test]
async fn handshake_ed25519_graviola() {
    handshake(graviola::DEFAULT_PROVIDER, PublicKeyAlgorithm::Ed25519)
        .await
        .unwrap();
}

/// Restrict the client to one key exchange or cipher and check the negotiation it logs
async fn negotiates(option: [&str; 2], expected: &str) {
    let world = script_world(r#"echo OXISH-$((6*7))"#).await;
    world.bare_repo("a.git").await.unwrap();
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let mut client = client.debug();
    client.cmd.args(option);
    let run = client.run(Some(SERVICE), b"").await.unwrap();
    assert!(run.status.success(), "ssh failed: {}", run.stderr);
    assert!(run.stdout().contains("OXISH-42"), "{}", run.stdout());
    assert!(run.stderr.contains(expected), "missing {expected:?} in\n{}", run.stderr);
}

#[tokio::test]
async fn handshake_x25519_graviola() {
    negotiates(["-o", "KexAlgorithms=curve25519-sha256"], "kex: algorithm: curve25519-sha256").await;
}

#[tokio::test]
async fn handshake_hybrid_post_quantum_graviola() {
    negotiates(["-o", "KexAlgorithms=mlkem768x25519-sha256"], "kex: algorithm: mlkem768x25519-sha256").await;
}

#[tokio::test]
async fn handshake_chacha_graviola() {
    negotiates(["-c", "chacha20-poly1305@openssh.com"], "cipher: chacha20-poly1305@openssh.com").await;
}

#[tokio::test]
async fn channel_stderr_arrives_on_stderr_with_exit_status() {
    let world = script_world("echo to-stdout; echo to-stderr >&2; exit 3").await;
    world.bare_repo("a.git").await.unwrap();
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let run = client.run(Some(SERVICE), b"").await.unwrap();
    assert_eq!(run.status.code(), Some(3), "{}", run.stderr);
    assert_eq!(run.stdout(), "to-stdout\n");
    assert_eq!(run.stderr, "to-stderr\n");
}

#[tokio::test]
async fn channel_stdout_and_stderr_both_drain_completely() {
    let world = script_world(
        "PATH=/usr/bin:/bin; (head -c 3000000 /dev/zero | tr '\\0' 'o') & (head -c 2000000 /dev/zero | tr '\\0' 'e' >&2) & wait; exit 5",
    )
    .await;
    world.bare_repo("a.git").await.unwrap();
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let run = client.run(Some(SERVICE), b"").await.unwrap();
    assert_eq!(run.status.code(), Some(5));
    assert_eq!(run.stdout.len(), 3_000_000);
    assert!(run.stdout.iter().all(|&b| b == b'o'));
    assert_eq!(run.stderr.len(), 2_000_000);
    assert!(run.stderr.bytes().all(|b| b == b'e'));
}

#[tokio::test]
async fn channel_large_stdin_reaches_a_slow_reader_while_output_flows() {
    // The command emits output and sleeps before reading, so its stdin pipe fills; the server
    // must keep forwarding output and must not stall on the unread input.
    let world = script_world(
        "PATH=/usr/bin:/bin; head -c 2000000 /dev/zero | tr '\\0' 'x'; sleep 2; wc -c | tr -d ' '",
    )
    .await;
    world.bare_repo("a.git").await.unwrap();
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let input = vec![7u8; 6_000_000];
    let run = client.run(Some(SERVICE), &input).await.unwrap();
    assert!(run.status.success(), "{}", run.stderr);
    let stdout = run.stdout();
    assert!(stdout.starts_with(&"x".repeat(2_000_000)));
    assert_eq!(&stdout[2_000_000..], "6000000\n");
}

#[tokio::test]
async fn channel_command_that_ignores_stdin_does_not_wedge_the_session() {
    let world = script_world("echo done").await;
    world.bare_repo("a.git").await.unwrap();
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let input = vec![1u8; 8_000_000];
    let run = client.run(Some(SERVICE), &input).await.unwrap();
    assert!(run.status.success(), "{}", run.stderr);
    assert_eq!(run.stdout(), "done\n");
}

async fn pid_is_gone(pid: i32) -> bool {
    for _ in 0..50 {
        let alive = Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap()
            .success();
        if !alive {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn channel_early_disconnect_kills_the_command() {
    let world = script_world("PATH=/usr/bin:/bin; echo $$ > \"$(dirname \"$0\")/../pid\"; exec sleep 120").await;
    world.bare_repo("a.git").await.unwrap();
    let pid_file = world.base().join("pid");
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();

    let mut cmd = client.cmd;
    cmd.args(["-o", "LogLevel=ERROR"]);
    cmd.arg(format!("{USER}@{}", client.addr.ip())).arg(SERVICE);
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let mut pid = None;
    for _ in 0..100 {
        if let Ok(text) = fs::read_to_string(&pid_file) {
            if let Ok(parsed) = text.trim().parse::<i32>() {
                pid = Some(parsed);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pid = pid.expect("the command never started");
    child.kill().await.unwrap();
    assert!(pid_is_gone(pid).await, "command {pid} outlived its connection");
}

#[tokio::test]
async fn channel_disconnect_asks_the_command_to_stop_before_killing_it() {
    let world = script_world(
        "PATH=/usr/bin:/bin; d=\"$(dirname \"$0\")/..\"; trap 'echo term > \"$d/term\"; exit 0' TERM; echo ready > \"$d/ready\"; sleep 120 & wait",
    )
    .await;
    world.bare_repo("a.git").await.unwrap();
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("write"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let mut cmd = client.cmd;
    cmd.args(["-o", "LogLevel=ERROR"]);
    cmd.arg(format!("{USER}@{}", client.addr.ip())).arg("git-receive-pack 'a.git'");
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    for _ in 0..100 {
        if world.base().join("ready").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(world.base().join("ready").exists(), "the command never started");
    child.kill().await.unwrap();
    for _ in 0..50 {
        if world.base().join("term").exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the command was killed without a chance to clean up");
}

#[tokio::test]
async fn sessions_beyond_the_limit_are_refused() {
    let world = script_world("PATH=/usr/bin:/bin; sleep 4; echo FIRST").await;
    world.bare_repo("a.git").await.unwrap();
    let config = crate::Config {
        max_sessions: 1,
        ..crate::Config::default()
    };
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), Some(config), graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();

    let addr = client.addr;
    let key = client.key.clone();
    let first = tokio::spawn(async move { client.run(Some(SERVICE), b"").await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    let second = CliClient::new(addr, &key).run(Some(SERVICE), b"").await.unwrap();
    assert!(!second.status.success(), "a second session was served: {}", second.stdout());
    let first = first.await.unwrap().unwrap();
    assert!(first.status.success(), "{}", first.stderr);
    assert_eq!(first.stdout(), "FIRST\n");
}

#[tokio::test]
async fn idle_connections_from_one_address_cannot_lock_out_logins() {
    let world = script_world("echo OK").await;
    world.bare_repo("a.git").await.unwrap();
    let config = crate::Config {
        max_unauthenticated_per_ip: 2,
        ..crate::Config::default()
    };
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), Some(config), graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();

    let addr = client.addr;
    let key = client.key.clone();
    let idle: Vec<_> = futures_idle(addr, 2).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let refused = client.run(Some(SERVICE), b"").await.unwrap();
    assert!(!refused.status.success(), "a third pre-auth connection was served: {}", refused.stdout());

    drop(idle);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let served = CliClient::new(addr, &key).run(Some(SERVICE), b"").await.unwrap();
    assert!(served.status.success(), "{}", served.stderr);
    assert_eq!(served.stdout(), "OK\n");
}

/// Open `count` TCP connections that never send anything
async fn futures_idle(addr: SocketAddr, count: usize) -> Vec<tokio::net::TcpStream> {
    let mut streams = Vec::new();
    for _ in 0..count {
        streams.push(tokio::net::TcpStream::connect(addr).await.unwrap());
    }
    streams
}

#[tokio::test]
async fn exec_rejects_non_git_commands() {
    let world = script_world("echo SHOULD-NOT-RUN").await;
    world.bare_repo("a.git").await.unwrap();
    for command in [
        "rm -rf /",
        "sh -c id",
        "/bin/sh",
        "git-upload-pack 'a.git'; id",
        "/usr/bin/git-upload-pack 'a.git'",
        "git-upload-pack '../a.git'",
        "git-upload-pack '/etc/passwd'",
    ] {
        let (client, _guard) = world
            .serve(&PublicKeyAlgorithm::Ed25519, Some("write"), None, graviola::DEFAULT_PROVIDER)
            .await
            .unwrap();
        let run = client.run(Some(command), b"").await.unwrap();
        assert!(!run.status.success(), "{command:?} was accepted: {}", run.stdout());
        assert!(!run.stdout().contains("SHOULD-NOT-RUN"), "{command:?} ran");
    }
}

#[tokio::test]
async fn read_only_key_cannot_push_and_is_told_why() {
    let world = script_world("echo RAN").await;
    world.bare_repo("a.git").await.unwrap();
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let run = client.run(Some("git-receive-pack 'a.git'"), b"").await.unwrap();
    assert_eq!(run.status.code(), Some(1));
    assert!(run.stderr.contains("access denied"), "{}", run.stderr);
    assert!(!run.stdout().contains("RAN"));
}

#[tokio::test]
async fn write_key_can_push_and_missing_repository_is_reported() {
    let world = script_world("echo RAN").await;
    world.bare_repo("a.git").await.unwrap();
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("write"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let run = client.run(Some("git-receive-pack 'a.git'"), b"").await.unwrap();
    assert!(run.status.success(), "{}", run.stderr);
    assert!(run.stdout().contains("RAN"));
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("write"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let run = client.run(Some("git-receive-pack 'missing.git'"), b"").await.unwrap();
    assert_eq!(run.status.code(), Some(1));
    assert!(run.stderr.contains("not found"), "{}", run.stderr);
}

#[tokio::test]
async fn shell_and_pty_requests_are_refused() {
    let world = script_world("echo RAN").await;
    world.bare_repo("a.git").await.unwrap();
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("write"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let run = client.run(None, b"echo shell-ran\nexit\n").await.unwrap();
    assert!(!run.status.success());
    assert!(!run.stdout().contains("shell-ran"));

    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("write"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let mut client = client;
    client.cmd.arg("-tt");
    let run = client.run(Some(SERVICE), b"").await.unwrap();
    assert!(run.stderr.contains("PTY allocation request failed"), "{}", run.stderr);
}

#[tokio::test]
async fn only_validated_git_protocol_reaches_the_command() {
    let world = script_world(r#"echo "protocol=[$GIT_PROTOCOL] foo=[$FOO] path=[$PATH]""#).await;
    world.bare_repo("a.git").await.unwrap();
    for (value, expected) in [
        ("version=2", "protocol=[version=2]"),
        ("version=1", "protocol=[]"),
        ("version=2:extra=1", "protocol=[]"),
    ] {
        let (client, _guard) = world
            .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
            .await
            .unwrap();
        let mut client = client;
        client.cmd.args(["-o", "SendEnv=GIT_PROTOCOL FOO"]);
        client.cmd.env("GIT_PROTOCOL", value).env("FOO", "bar");
        let run = client.run(Some(SERVICE), b"").await.unwrap();
        let stdout = run.stdout();
        assert!(stdout.contains(expected), "{value:?}: {stdout}");
        assert!(stdout.contains("foo=[]"), "arbitrary environment leaked: {stdout}");
        assert!(stdout.contains(&format!("path=[{}]", world.bin.display())), "{stdout}");
    }
}

fn commit_args<'a>(message: &'a str) -> Vec<&'a str> {
    vec![
        "-c",
        "user.name=oxish-e2e",
        "-c",
        "user.email=oxish-e2e@example.com",
        "commit",
        "-qm",
        message,
    ]
}

async fn seeded_repo(world: &World, name: &str, extra_bytes: usize) -> (PathBuf, String) {
    let bare = world.bare_repo(name).await.unwrap();
    let work = world.base().join(format!("seed-{name}"));
    fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q", "-b", "main"]).await.unwrap();
    fs::write(work.join("hello.txt"), "hello oxish\n").unwrap();
    if extra_bytes > 0 {
        let output = Command::new("head")
            .args(["-c", &extra_bytes.to_string(), "/dev/urandom"])
            .output()
            .await
            .unwrap();
        fs::write(work.join("random.bin"), output.stdout).unwrap();
    }
    git(&work, &["add", "."]).await.unwrap();
    git(&work, &commit_args("seed")).await.unwrap();
    git(&work, &["tag", "v1"]).await.unwrap();
    git(&work, &["push", "-q", bare.to_str().unwrap(), "main", "v1"]).await.unwrap();
    let sha = git_output(&work, &["rev-parse", "HEAD"]).await.unwrap();
    (work, sha)
}

async fn git_over_ssh(client: &CliClient, dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_SSH_COMMAND", client.git_ssh_command())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .await?;
    anyhow::ensure!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(String::from_utf8_lossy(&output.stderr).into_owned()
        + &String::from_utf8_lossy(&output.stdout))
}

#[tokio::test]
async fn exec_git_clone_fetch_and_push_round_trip() {
    subscribe();
    let world = World::new(Programs::System).await.unwrap();
    let (seed, sha) = seeded_repo(&world, "a.git", 0).await;
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("write"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();

    let url = client.url("a.git");
    let clone = world.base().join("clone");
    git_over_ssh(&client, &world.base(), &["clone", "-q", &url, clone.to_str().unwrap()]).await.unwrap();
    assert_eq!(git_output(&clone, &["rev-parse", "HEAD"]).await.unwrap(), sha);
    assert_eq!(fs::read_to_string(clone.join("hello.txt")).unwrap(), "hello oxish\n");

    fs::write(clone.join("new.txt"), "pushed\n").unwrap();
    git(&clone, &["add", "new.txt"]).await.unwrap();
    git(&clone, &commit_args("push me")).await.unwrap();
    git_over_ssh(&client, &clone, &["push", "-q", "origin", "main"]).await.unwrap();
    let pushed = git_output(&clone, &["rev-parse", "HEAD"]).await.unwrap();

    git_over_ssh(&client, &seed, &["pull", "-q", "--ff-only", &url, "main"]).await.unwrap();
    assert_eq!(git_output(&seed, &["rev-parse", "HEAD"]).await.unwrap(), pushed);
    let listing = git_over_ssh(&client, &world.base(), &["ls-remote", &url]).await.unwrap();
    assert!(listing.contains("refs/tags/v1"), "{listing}");
}

#[tokio::test]
async fn exec_git_large_pack_is_byte_exact() {
    subscribe();
    let world = World::new(Programs::System).await.unwrap();
    let (seed, _) = seeded_repo(&world, "big.git", 24 * 1024 * 1024).await;
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let clone = world.base().join("big-clone");
    git_over_ssh(&client, &world.base(), &["clone", "-q", &client.url("big.git"), clone.to_str().unwrap()])
        .await
        .unwrap();
    assert_eq!(
        fs::read(clone.join("random.bin")).unwrap(),
        fs::read(seed.join("random.bin")).unwrap()
    );
}

#[tokio::test]
async fn exec_git_push_with_read_key_fails_with_a_diagnostic() {
    subscribe();
    let world = World::new(Programs::System).await.unwrap();
    world.bare_repo("a.git").await.unwrap();
    let (seed, _) = seeded_repo(&world, "b.git", 0).await;
    let (client, _guard) = world
        .serve(&PublicKeyAlgorithm::Ed25519, Some("read"), None, graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
    let error = git_over_ssh(&client, &seed, &["push", &client.url("b.git"), "main:other"])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("access denied"), "{error}");
}

#[test]
fn session_state_round_trip() {
    use crate::DEFAULT_PROVIDER;
    let (key, pkcs8) = DEFAULT_PROVIDER
        .generate_signing_key(&PublicKeyAlgorithm::Ed25519)
        .expect("failed to generate signing key");
    let pkcs8 = Zeroizing::new(pkcs8);
    let host_key = ServerHostKey::from((&pkcs8, &*key));

    let state = SessionState {
        addr: SocketAddr::from(([192, 0, 2, 7], 22022)),
        identities: Identities {
            client: b"client-identity".to_vec(),
            server: b"server-identity".to_vec(),
        },
        post_quantum_kx: false,
        strict_kx: None,
        host_key,
        session_id: Digest::new(b"session-id"),
        read: SideState {
            source: KeySourceSide {
                algorithm: EncryptionAlgorithm::Aes128Gcm,
                initial_iv: vec![2; 12],
                encryption_key: vec![1; 16],
            },
            counter: 42,
            sequence_number: 17,
        },
        write: SideState {
            source: KeySourceSide {
                algorithm: EncryptionAlgorithm::Aes128Gcm,
                initial_iv: vec![4; 12],
                encryption_key: vec![3; 16],
            },
            counter: 7,
            sequence_number: 23,
        },
        read_buf: b"pipelined".to_vec(),
        options: KeyOptions {
            git_access: Some(GitAccess::Read),
        },
    };

    let mut buf = Vec::new();
    state.encode(&mut buf);

    let Decoded {
        value: decoded,
        next,
    } = SessionState::decode(&buf, DEFAULT_PROVIDER).unwrap();
    assert!(next.is_empty());

    assert_eq!(decoded.addr, state.addr);
    assert_eq!(decoded.identities.client, state.identities.client);
    assert_eq!(decoded.identities.server, state.identities.server);
    assert_eq!(decoded.strict_kx.is_some(), state.strict_kx.is_some());
    assert_eq!(decoded.post_quantum_kx, state.post_quantum_kx);
    assert_eq!(decoded.session_id.as_ref(), state.session_id.as_ref());
    assert_eq!(decoded.read_buf, state.read_buf);
    assert_eq!(decoded.read.source.algorithm, EncryptionAlgorithm::Aes128Gcm);
    assert_eq!(decoded.read.source.encryption_key, [1; 16]);
    assert_eq!(decoded.read.source.initial_iv, [2; 12]);
    assert_eq!(decoded.write.source.algorithm, EncryptionAlgorithm::Aes128Gcm);
    assert_eq!(decoded.write.source.encryption_key, [3; 16]);
    assert_eq!(decoded.write.source.initial_iv, [4; 12]);
    assert_eq!(decoded.read.counter, 42);
    assert_eq!(decoded.read.sequence_number, 17);
    assert_eq!(decoded.write.counter, 7);
    assert_eq!(decoded.write.sequence_number, 23);
    assert_eq!(decoded.options.git_access, Some(GitAccess::Read));
}

const USER: &str = "oxish-e2e";

async fn git(dir: &Path, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .status()
        .await?;
    anyhow::ensure!(status.success(), "git {} failed", args.join(" "));
    Ok(())
}

async fn git_output(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .await?;
    anyhow::ensure!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(String::from_utf8(output.stdout)?.trim_end().to_owned())
}

#[tokio::test]
async fn host_keys_from_files_graviola() {
    host_keys_from_files(graviola::DEFAULT_PROVIDER)
        .await
        .unwrap();
}

async fn host_keys_from_files(provider: &'static dyn CryptoProvider) -> anyhow::Result<()> {
    let dir = TempDir::new()?;
    let mut paths = Vec::new();
    for key_type in ["ed25519", "ecdsa", "rsa"] {
        let path = dir.path().join(format!("ssh_host_{key_type}_key"));
        let status = Command::new("ssh-keygen")
            .arg("-q")
            .args(["-t", key_type])
            .args(["-N", ""])
            .args(["-C", "oxish-e2e"])
            .arg("-f")
            .arg(&path)
            .status()
            .await
            .context("failed to run ssh-keygen")?;
        assert!(status.success(), "ssh-keygen failed");
        paths.push(path);
    }

    let host_keys = HostKeys::from_files(paths.iter(), provider)?;
    let mut algorithms = Vec::new();
    for algorithm in host_keys.algorithms() {
        algorithms.push(algorithm);
    }

    assert_eq!(algorithms.len(), 2, "unexpected algorithms: {algorithms:?}");
    assert!(algorithms.contains(&PublicKeyAlgorithm::Ed25519));
    assert!(algorithms.contains(&PublicKeyAlgorithm::EcdsaSha2Nistp256));

    Ok(())
}

#[tokio::test]
async fn verify_keys() {
    let providers = [
        graviola::DEFAULT_PROVIDER,
    ];

    for signer in providers {
        for verifier in providers {
            let (signing_key, _) = signer
                .generate_signing_key(&PublicKeyAlgorithm::Ed25519)
                .expect("failed to generate signing key");

            let message = b"the quick brown fox";
            let signature = signing_key.sign(message);
            let verifying_key = verifier
                .verifying_key(signing_key.public_key(), &PublicKeyAlgorithm::Ed25519)
                .expect("failed to build verifying key");

            verifying_key
                .verify(message, &signature)
                .expect("valid signature should verify");

            verifying_key
                .verify(b"the quick brown cat", &signature)
                .expect_err("signature over a different message must not verify");
        }
    }
}

static SESSION_BINARY: OnceCell<PathBuf> = OnceCell::const_new();

/// Build and locate the `oxish-session` binary
///
/// `cargo test` only builds the crate's binaries as test harnesses, so build the real
/// binary here (a no-op when fresh). Unit tests run from `target/<profile>/deps/` (or
/// `target/<profile>/build/<package>/<hash>/out/` with Cargo's newer build directory layout),
/// while cargo places the binary in `target/<profile>/`.
async fn build_session_binary() -> anyhow::Result<PathBuf> {
    let exe = env::current_exe()?;
    // TODO: simplify for new build directory layout once MSRV hits 1.100
    let Some(profile_dir) = exe
        .ancestors()
        .find(|dir| {
            dir.file_name()
                .is_some_and(|name| name == "deps" || name == "build")
        })
        .and_then(Path::parent)
    else {
        anyhow::bail!("no profile directory found for `{}`", exe.display());
    };

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.args(["build", "-q", "-p", "oxish", "--bin", "oxish-session"]);
    command
        .arg("--target-dir")
        .arg(profile_dir.parent().unwrap());
    if profile_dir
        .file_name()
        .is_some_and(|name| name == "release")
    {
        command.arg("--release");
    }

    let status = command.status().await?;
    assert!(status.success(), "failed to build oxish-session");

    let bin = profile_dir.join("oxish-session");
    assert!(
        bin.is_file(),
        "oxish-session binary not found at `{}`",
        bin.display(),
    );
    Ok(bin)
}

fn subscribe() {
    static INSTALL_TRACING_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACING_SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

