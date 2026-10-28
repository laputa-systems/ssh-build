use core::{net::Ipv4Addr, net::SocketAddr, time::Duration};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    env, fs, io,
    panic::resume_unwind,
    path::Path,
    path::PathBuf,
    process::{ExitStatus, Stdio},
    sync::Once,
};

use anyhow::Context;
use proto::{
    Decoded, Encode, HostKeys, OpenSshKeyV1, ServerHostKey, SshPrivateKey,
    auth::{AuthorizedKey, KeyOptions},
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

use crate::{
    Config, SessionState, SideState, UserStore, Username,
    authentication::{SingleUser, User},
    server::Server,
};

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
#[tokio::test]
async fn handshake_ecdsa_graviola() {
    handshake(
        graviola::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::EcdsaSha2Nistp256,
    )
    .await
    .unwrap();
}

/// Exercise an ssh-ed25519 client key against the graviola provider
#[tokio::test]
async fn handshake_ed25519_graviola() {
    handshake(graviola::DEFAULT_PROVIDER, PublicKeyAlgorithm::Ed25519)
        .await
        .unwrap();
}

/// Exercise the curve25519-sha256 key exchange against the graviola provider
#[tokio::test]
async fn handshake_x25519_graviola() {
    handshake_x25519(graviola::DEFAULT_PROVIDER).await.unwrap();
}

/// Exercise the chacha20-poly1305@openssh.com cipher against the graviola provider
#[tokio::test]
async fn handshake_chacha_graviola() {
    subscribe();

    let (_key_dir, mut client, server) = setup(
        &PublicKeyAlgorithm::Ed25519,
        None,
        None,
        graviola::DEFAULT_PROVIDER,
    )
    .await
    .expect("failed to set up test");
    // Restrict the client to the OpenSSH packet cipher so the test fails if the
    // server no longer negotiates it.
    client.cmd.args(["-c", "chacha20-poly1305@openssh.com"]);

    let (status, stdout, stderr) = client
        .run(COMMAND, Duration::from_secs(10), server)
        .await
        .unwrap();
    assert!(
        status.success(),
        "client exited with {status}.\n--- stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains(OUTPUT),
        "expected command output {OUTPUT:?} in session output.\n\
        --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
    assert!(
        stderr.contains("cipher: chacha20-poly1305@openssh.com"),
        "client did not negotiate chacha20-poly1305@openssh.com.\n\
        --- stderr ---\n{stderr}",
    );
    assert!(
        !stderr.contains("cipher: aes128-gcm"),
        "client negotiated a non-chacha cipher.\n--- stderr ---\n{stderr}",
    );
}

async fn handshake_x25519(provider: &'static dyn CryptoProvider) -> anyhow::Result<()> {
    subscribe();

    let (_key_dir, mut client, server) =
        setup(&PublicKeyAlgorithm::Ed25519, None, None, provider).await?;
    // Restrict the client to the non-PQ key exchange so the test fails if the
    // server no longer supports it.
    client.cmd.args(["-o", "KexAlgorithms=curve25519-sha256"]);

    let (_, stdout, stderr) = client
        .assert_run(COMMAND, Duration::from_secs(10), server)
        .await?;
    anyhow::ensure!(
        stderr.contains("kex: algorithm: curve25519-sha256"),
        "client did not negotiate curve25519-sha256"
    );

    // A non-post-quantum key exchange must surface a warning banner in the terminal
    anyhow::ensure!(
        stdout.contains(KX_WARNING_MARKER),
        "expected key exchange warning banner in session output:\n{stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn no_spawn() {
    subscribe();

    let (_key_dir, client, server) = setup(
        &PublicKeyAlgorithm::Ed25519,
        None,
        Some(Config {
            spawn: false,
            ..Config::default()
        }),
        graviola::DEFAULT_PROVIDER,
    )
    .await
    .expect("failed to set up test");

    client
        .assert_run(
            COMMAND,
            // In the rekey scenario, keep the session open long enough for several rekeys before the
            // sentinel; it only arrives if the session survived them.
            Duration::from_secs(10),
            server,
        )
        .await
        .unwrap();
}

/// Check that a `command` key option replaces the command the client asked to run
#[tokio::test]
async fn force_command() {
    subscribe();

    let (_key_dir, client, server) = setup(
        &PublicKeyAlgorithm::Ed25519,
        Some(r#"command="echo OXISH-FORCED-$((6*7))""#),
        None,
        graviola::DEFAULT_PROVIDER,
    )
    .await
    .expect("failed to set up test");

    // The arithmetic is only expanded when a shell runs the command, so the terminal echoing
    // the client's input back cannot satisfy these assertions.
    let (_, stdout, stderr) = client
        .run(COMMAND, Duration::from_secs(10), server)
        .await
        .unwrap();

    assert!(
        stdout.contains(FORCED),
        "forced command did not run.\n\
        --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
    assert!(
        !stdout.contains(OUTPUT),
        "client command ran despite the forced command.\n\
        --- stdout ---\n{stdout}",
    );
}

/// Exercise non-PTY `exec` end to end: clone a fixture repo through the server,
/// proving `git-upload-pack` runs with stdin/stdout forwarding and exit status.
#[tokio::test]
async fn exec_git_clone() {
    subscribe();

    let origin = TempDir::new().unwrap();
    git(origin.path(), &["init", "-q"]).await.unwrap();
    fs::write(origin.path().join("hello.txt"), "hello oxish\n").unwrap();
    git(origin.path(), &["add", "hello.txt"]).await.unwrap();
    git(
        origin.path(),
        &[
            "-c",
            "user.name=oxish-e2e",
            "-c",
            "user.email=oxish-e2e@example.com",
            "commit",
            "-qm",
            "fixture commit",
        ],
    )
    .await
    .unwrap();
    let sha = git_output(origin.path(), &["rev-parse", "HEAD"])
        .await
        .unwrap();

    let (key_dir, client, server) = setup(
        &PublicKeyAlgorithm::Ed25519,
        None,
        None,
        graviola::DEFAULT_PROVIDER,
    )
    .await
    .expect("failed to set up test");

    let ssh = env::var("OXISH_TEST_SSH").unwrap_or_else(|_| "ssh".to_string());
    let git_ssh = format!(
        "{ssh} -F /dev/null -i {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o LogLevel=ERROR",
        key_dir.path().join("key").display(),
    );
    let url = format!(
        "ssh://{USER}@127.0.0.1:{}/{}",
        client.addr.port(),
        origin.path().display(),
    );
    let parent = TempDir::new().unwrap();
    let output = timeout(
        Duration::from_secs(25),
        Command::new("git")
            .args(["clone", &url, "clone"])
            .current_dir(parent.path())
            .env("GIT_SSH_COMMAND", &git_ssh)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output(),
    )
    .await
    .expect("git clone timed out")
    .expect("failed to run git clone");
    assert!(
        output.status.success(),
        "git clone failed.\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let cloned = fs::read_to_string(parent.path().join("clone/hello.txt")).unwrap();
    assert_eq!(cloned, "hello oxish\n");
    let cloned_sha = git_output(&parent.path().join("clone"), &["rev-parse", "HEAD"])
        .await
        .unwrap();
    assert_eq!(cloned_sha, sha);

    join_server(server).await;
}

/// A non-Git `exec` request must be rejected: failure reply plus non-zero exit.
#[tokio::test]
async fn exec_rejects_non_git() {
    subscribe();

    let (_key_dir, client, server) = setup(
        &PublicKeyAlgorithm::Ed25519,
        None,
        None,
        graviola::DEFAULT_PROVIDER,
    )
    .await
    .expect("failed to set up test");

    let (status, stdout, stderr) = client
        .run_exec("rm -rf /", b"", Duration::from_secs(10), server)
        .await
        .unwrap();
    assert!(
        !status.success(),
        "disallowed exec unexpectedly succeeded.\n\
        --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// An authorized-key forced command wins over the requested `exec` command.
#[tokio::test]
async fn exec_forced_command() {
    subscribe();

    let (_key_dir, client, server) = setup(
        &PublicKeyAlgorithm::Ed25519,
        Some(r#"command="echo OXISH-EXEC-FORCED-$((6*7))""#),
        None,
        graviola::DEFAULT_PROVIDER,
    )
    .await
    .expect("failed to set up test");

    let (status, stdout, stderr) = client
        .run_exec(
            "git-upload-pack '/nonexistent'",
            b"",
            Duration::from_secs(10),
            server,
        )
        .await
        .unwrap();
    assert!(
        status.success(),
        "forced command exited with {status}.\n--- stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains("OXISH-EXEC-FORCED-42"),
        "forced command did not run.\n\
        --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

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

/// Exercise a client-initiated rekey against the graviola provider
#[tokio::test]
#[ignore = "slow"]
async fn rekey_graviola() {
    subscribe();
    let (_key_dir, mut client, server) = setup(
        &PublicKeyAlgorithm::Ed25519,
        None,
        None,
        graviola::DEFAULT_PROVIDER,
    )
    .await
    .expect("failed to set up test");

    // A short time-based rekey interval makes the client send a fresh SSH_MSG_KEXINIT every
    // couple of seconds, exercising client-initiated rekeying. A time trigger keeps the
    // session near-idle, avoiding the data volume a byte-based trigger would need.
    client.cmd.args(["-o", "RekeyLimit=default 1"]);

    let (status, _stdout, stderr) = client
        .assert_run(
            b"sleep 10\necho OXISH-$((6*7))\nexit\n",
            // In the rekey scenario, keep the session open long enough for several rekeys before the
            // sentinel; it only arrives if the session survived them.
            Duration::from_secs(30),
            server,
        )
        .await
        .unwrap();

    // The client logs "SSH2_MSG_KEXINIT received" once per key exchange the server answered,
    // but the matching "SSH2_MSG_NEWKEYS received" line only appears when a key exchange ran
    // to completion. One of each belongs to the initial handshake, so two or more completed
    // exchanges prove the server carried a client-initiated rekey through NEWKEYS.
    let started = stderr.matches("SSH2_MSG_KEXINIT received").count();
    let completed = stderr.matches("SSH2_MSG_NEWKEYS received").count();
    assert!(
        started >= 2 && completed >= 2,
        "expected at least one completed rekey, saw {started} started and {completed} completed \
             key exchange(s).\n\
             --- stderr ({stderr_len} bytes) ---\n{stderr}",
        stderr_len = stderr.len(),
    );

    // A protocol violation during a rekey (e.g. the server sending channel data between
    // KEXINIT and NEWKEYS) makes the client abort with a fatal error instead of tearing the
    // session down cleanly after `exit`, which surfaces as a non-zero exit status.
    assert!(
        status.success(),
        "client exited with {status}.\n\
             --- stderr ({stderr_len} bytes) ---\n{stderr}",
        stderr_len = stderr.len(),
    );
}

async fn handshake(
    provider: &'static dyn CryptoProvider,
    algorithm: PublicKeyAlgorithm<'_>,
) -> anyhow::Result<()> {
    subscribe();

    let (_key_dir, client, server) = setup(&algorithm, None, None, provider).await?;

    let (_, stdout, stderr) = client
        .assert_run(
            COMMAND,
            // In the rekey scenario, keep the session open long enough for several rekeys before the
            // sentinel; it only arrives if the session survived them.
            Duration::from_secs(10),
            server,
        )
        .await?;

    if stderr.contains("kex: algorithm: mlkem768x25519-sha256") {
        anyhow::ensure!(
            !stdout.contains(KX_WARNING_MARKER),
            "unexpected key exchange warning banner in session output:\n{stdout}"
        );
    }

    Ok(())
}

async fn setup(
    algorithm: &PublicKeyAlgorithm<'_>,
    options: Option<&str>,
    config: Option<Config>,
    provider: &'static dyn CryptoProvider,
) -> anyhow::Result<(TempDir, CliClient, JoinHandle<anyhow::Result<()>>)> {
    let (key_dir, store) = store(algorithm, options, provider).await?;
    let (_, pkcs8) = provider.generate_signing_key(algorithm)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let client = CliClient::new(addr, &key_dir.path().join("key"));

    let server = Server::new(
        store,
        HostKeys::new([Zeroizing::new(pkcs8)].into_iter(), provider)?,
        SESSION_BINARY
            .get_or_try_init(build_session_binary)
            .await
            .cloned()?,
        provider,
    )?;

    let server = match config {
        Some(config) => server.with_config(config),
        None => server,
    };

    // Start the server and serve exactly one connection
    let handle = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        server.accept(stream, peer).await
    });

    Ok((key_dir, client, handle))
}

struct CliClient {
    addr: SocketAddr,
    cmd: Command,
    pty: bool,
}

impl CliClient {
    fn new(addr: SocketAddr, key_path: &Path) -> Self {
        // Honor an explicit client binary (the interop script prefers the
        // just-built no-libcrypto client, falling back to the system ssh).
        let ssh = env::var("OXISH_TEST_SSH").unwrap_or_else(|_| "ssh".to_string());
        let mut cmd = Command::new(ssh);
        cmd.args(["-F", "/dev/null"]) // ignore the invoking user's ssh_config
            .args(["-p", &addr.port().to_string()]) // port to connect to
            .arg("-i") // identity (private key) file to authenticate with
            .arg(key_path)
            .args(["-o", "StrictHostKeyChecking=no"]) // ignore the host key
            .args(["-o", "UserKnownHostsFile=/dev/null"])
            .args(["-o", "GlobalKnownHostsFile=/dev/null"]) // ignore system known hosts
            .args(["-o", "IdentitiesOnly=yes"]) // don't offer agent keys
            .args(["-o", "LogLevel=DEBUG3"]); // verbose client diagnostics, captured on stderr for failure triage

        Self { addr, cmd, pty: true }
    }

    async fn assert_run(
        self,
        command: &[u8],
        wait_for: Duration,
        server: JoinHandle<anyhow::Result<()>>,
    ) -> anyhow::Result<(ExitStatus, String, String)> {
        let (status, stdout, stderr) = self.run(command, wait_for, server).await?;
        assert!(
            stdout.contains(OUTPUT),
            "expected command output {OUTPUT:?} in session output.\n\
            --- ssh exit status: {status} ---\n\
            --- stdout ({stdout_len} bytes) ---\n{stdout}\n\
            --- stderr ({stderr_len} bytes) ---\n{stderr}",
            stdout_len = stdout.len(),
            stderr_len = stderr.len(),
        );
        Ok((status, stdout, stderr))
    }

    async fn run(
        mut self,
        command: &[u8],
        wait_for: Duration,
        server: JoinHandle<anyhow::Result<()>>,
    ) -> anyhow::Result<(ExitStatus, String, String)> {
        if self.pty {
            // Force PTY allocation even though our stdin is a pipe, not a terminal.
            self.cmd.arg("-tt");
        }
        self.execute(command, None, wait_for, server).await
    }

    /// Run a remote command via a non-PTY `exec` request, feeding `stdin` to it.
    async fn run_exec(
        self,
        remote_command: &str,
        stdin: &[u8],
        wait_for: Duration,
        server: JoinHandle<anyhow::Result<()>>,
    ) -> anyhow::Result<(ExitStatus, String, String)> {
        self.execute(stdin, Some(remote_command), wait_for, server).await
    }

    async fn execute(
        mut self,
        command: &[u8],
        remote_command: Option<&str>,
        wait_for: Duration,
        server: JoinHandle<anyhow::Result<()>>,
    ) -> anyhow::Result<(ExitStatus, String, String)> {
        let mut cmd = &mut self.cmd;
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

        let mut stdin = child.stdin.take().unwrap();
        // A forced command can exit before reading stdin, so a broken pipe is not a failure
        match stdin.write_all(command).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
            Err(error) => return Err(error.into()),
        }
        drop(stdin); // close stdin so the session ends after `exit`

        let output = timeout(wait_for, child.wait_with_output()).await??;

        join_server(server).await;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok((output.status, stdout.into_owned(), stderr.into_owned()))
    }
}

/// Wait for the server task to finish after the client disconnected.
///
/// The server task completes on its own once the ssh client tears down the connection: cleanly
/// (Ok) if the client sent a disconnect, or with Err if it just closed the socket. The client
/// process can be reaped a moment before the server observes that teardown, so give the server a
/// bounded window to finish rather than aborting it out from under that race. Only a genuine hang
/// — the server never noticing the disconnect — should fail the test.
async fn join_server(server: JoinHandle<anyhow::Result<()>>) {
    match timeout(Duration::from_secs(10), server).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => println!("server task yielded {error:#}"),
        Ok(Err(err)) => resume_unwind(err.into_panic()),
        Err(_elapsed) => panic!("server still running after client disconnected"),
    }
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
            command: Some("/bin/true".to_owned()),
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
    assert_eq!(
        decoded.read.source.algorithm,
        EncryptionAlgorithm::Aes128Gcm
    );
    assert_eq!(decoded.read.source.encryption_key, [1; 16]);
    assert_eq!(decoded.read.source.initial_iv, [2; 12]);
    assert_eq!(
        decoded.write.source.algorithm,
        EncryptionAlgorithm::Aes128Gcm
    );
    assert_eq!(decoded.write.source.encryption_key, [3; 16]);
    assert_eq!(decoded.write.source.initial_iv, [4; 12]);
    assert_eq!(decoded.read.counter, 42);
    assert_eq!(decoded.read.sequence_number, 17);
    assert_eq!(decoded.write.counter, 7);
    assert_eq!(decoded.write.sequence_number, 23);
    assert_eq!(decoded.options.command.as_deref(), Some("/bin/true"));
}

async fn store(
    algorithm: &PublicKeyAlgorithm<'_>,
    options: Option<&str>,
    provider: &dyn CryptoProvider,
) -> anyhow::Result<(TempDir, Box<dyn UserStore>)> {
    let dir = TempDir::new()?;
    let key_path = dir.path().join("key");

    // Generate the client key; ssh-keygen writes the private key with 0600
    // permissions, which the ssh client requires.
    let status = Command::new("ssh-keygen")
        .arg("-q") // quiet: suppress the interactive progress output
        .args(match algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => &["-t", "ecdsa", "-b", "256"],
            PublicKeyAlgorithm::Ed25519 => &["-t", "ed25519"][..],
            _ => panic!("unsupported key type for ssh-keygen: {algorithm:?}"),
        }) // key type (and size, where applicable)
        .args(["-N", ""]) // empty passphrase, so the private key is not encrypted
        .args(["-C", "oxish-e2e"]) // key comment
        .arg("-f") // output file for the private key (public key gets a .pub suffix)
        .arg(&key_path)
        .status()
        .await
        .context("failed to run ssh-keygen")?;
    assert!(status.success(), "ssh-keygen failed");

    let authorized_key = fs::read_to_string(key_path.with_extension("pub"))?;
    let authorized_key = match options {
        Some(options) => format!("{options} {authorized_key}"),
        None => authorized_key,
    };

    let key = AuthorizedKey::from_str(&authorized_key, provider)
        .ok_or_else(|| anyhow::anyhow!("failed to parse generated public key"))?;

    let user = User {
        name: Username::try_from(USER.to_string())?,
        id: 1000,
        gid: 1000,
        home_dir: PathBuf::from("/var/empty"),
        shell: PathBuf::from("/bin/sh"),
    };

    Ok((dir, Box::new(SingleUser::with_keys(user, vec![key]))))
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

const USER: &str = "oxish-e2e";
const COMMAND: &[u8] = b"echo OXISH-$((6*7))\nexit\n";
const OUTPUT: &str = "OXISH-42";
const FORCED: &str = "OXISH-FORCED-42";
const KX_WARNING_MARKER: &str = "post-quantum secure";
