use core::{net::Ipv4Addr, net::SocketAddr, time::Duration};
use std::{
    env, fs,
    os::{fd::OwnedFd, unix::fs::PermissionsExt as _},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::Arc,
};

use proto::{
    Encode as _, HostKeys, OpenSshKeyV1, SshPrivateKey, named::PublicKeyAlgorithm, pem_encode,
};
use rustix::{
    fs::OFlags,
    pty::{self, OpenptFlags},
    termios::{self, Winsize},
};
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt as _, net::TcpListener, process::Command, task::JoinHandle, time::timeout};
use zeroize::Zeroizing;

use crate::{
    DEFAULT_PROVIDER, LoginAccounts, LoginPolicy, Server,
    tests::{build_session_binary, subscribe},
};

struct KeyPair {
    path: PathBuf,
    public: String,
}

fn make_key(dir: &Path, name: &str) -> KeyPair {
    let provider = DEFAULT_PROVIDER;
    let (key, pkcs8) = provider.generate_signing_key(&PublicKeyAlgorithm::Ed25519).unwrap();
    let pkcs8 = Zeroizing::new(pkcs8);
    let private = SshPrivateKey::from_pkcs8(&pkcs8, &*key).unwrap();
    let pem = pem_encode(
        "OPENSSH PRIVATE KEY",
        &OpenSshKeyV1::new([private]).unwrap().to_bytes(provider).unwrap(),
    );
    let path = dir.join(name);
    fs::write(&path, pem.as_bytes()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let mut blob = Vec::new();
    b"ssh-ed25519".as_slice().encode(&mut blob);
    key.public_key().encode(&mut blob);
    KeyPair {
        path,
        public: format!("ssh-ed25519 {}", data_encoding::BASE64.encode(&blob)),
    }
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Where each account lives: the test user's own identity, or distinct IDs when running as root
struct Identity {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

fn identity(index: u32) -> Identity {
    match is_root() {
        true => Identity {
            uid: 20_001 + index,
            gid: 20_001 + index,
            groups: vec![20_001 + index, 30_000],
        },
        false => {
            let gid = rustix::process::getegid().as_raw();
            Identity {
                uid: rustix::process::geteuid().as_raw(),
                gid,
                groups: vec![gid],
            }
        }
    }
}

struct Guard(JoinHandle<anyhow::Result<()>>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A scratch world for one login-mode server
struct World {
    dir: TempDir,
    keys: Vec<(String, KeyPair)>,
    passwd: String,
    group: String,
    policy: LoginPolicy,
}

impl World {
    fn new(accounts: &[&str]) -> Self {
        subscribe();
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(dir.path().join("home")).unwrap();
        fs::set_permissions(dir.path().join("home"), fs::Permissions::from_mode(0o777)).unwrap();
        let mut passwd = String::from("daemon:x:1:1::/:/sbin/nologin\n");
        let mut group = String::new();
        let mut keys = Vec::new();
        for (index, name) in accounts.iter().enumerate() {
            let id = identity(index as u32);
            let home = dir.path().join("home").display().to_string();
            passwd.push_str(&format!("{name}:x:{}:{}::{home}:/bin/sh\n", id.uid, id.gid));
            for extra in id.groups.iter().filter(|group| **group != id.gid) {
                group.push_str(&format!("extra{extra}:x:{extra}:{name}\n"));
            }
            keys.push(((*name).to_owned(), make_key(dir.path(), &format!("key-{name}"))));
        }
        let mut policy = LoginPolicy::default();
        policy.passwd = dir.path().join("passwd");
        policy.group = dir.path().join("group");
        policy.path = "/usr/bin:/bin".to_owned();
        Self { dir, keys, passwd, group, policy }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn key(&self, name: &str) -> &KeyPair {
        &self.keys.iter().find(|(account, _)| account == name).unwrap().1
    }

    fn write_files(&self) -> PathBuf {
        let accounts = self.dir.path().join("accounts");
        let lines: String = self
            .keys
            .iter()
            .map(|(name, key)| format!("{name} {} {name}@test\n", key.public))
            .collect();
        for (path, contents, mode) in [
            (accounts.clone(), lines, 0o600),
            (self.policy.passwd.clone(), self.passwd.clone(), 0o644),
            (self.policy.group.clone(), self.group.clone(), 0o644),
        ] {
            fs::write(&path, contents).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        }
        accounts
    }

    async fn server(&self) -> anyhow::Result<Server> {
        let accounts = LoginAccounts::from_file(&self.write_files(), DEFAULT_PROVIDER)?;
        let (_, pkcs8) = DEFAULT_PROVIDER.generate_signing_key(&PublicKeyAlgorithm::Ed25519)?;
        Server::login(
            accounts,
            HostKeys::new([Zeroizing::new(pkcs8)].into_iter(), DEFAULT_PROVIDER)?,
            build_session_binary().await?,
            self.policy.clone(),
            DEFAULT_PROVIDER,
        )
    }

    async fn serve(&self) -> (SocketAddr, Guard) {
        let server = Arc::new(self.server().await.unwrap());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        (addr, Guard(tokio::spawn(async move { server.run(listener).await })))
    }
}

fn ssh_program() -> PathBuf {
    let name = env::var("OXISH_TEST_SSH").unwrap_or_else(|_| "ssh".to_owned());
    if name.contains('/') {
        return PathBuf::from(name);
    }
    env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join(&name))
        .find(|candidate| candidate.is_file())
        .expect("no ssh client for the tests")
}

/// The test ssh client for one account, with `options` ahead of the destination
fn ssh_command(addr: SocketAddr, key: &Path, user: &str, options: &[&str]) -> Command {
    let mut command = Command::new(ssh_program());
    command.args(options);
    command.args([
        "-F", "/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=ERROR",
    ]);
    command.args(["-p".to_owned(), addr.port().to_string(), "-i".to_owned(), key.display().to_string()]);
    command.arg(format!("{user}@127.0.0.1"));
    command.env_remove("SSH_AUTH_SOCK").kill_on_drop(true);
    command
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

async fn finish(mut command: Command, stdin: &[u8]) -> Run {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child_stdin = child.stdin.take().unwrap();
    let input = stdin.to_vec();
    let writer = tokio::spawn(async move {
        let _ = child_stdin.write_all(&input).await;
    });
    let output = timeout(Duration::from_secs(60), child.wait_with_output()).await.unwrap().unwrap();
    writer.await.unwrap();
    Run {
        status: output.status,
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Run a remote command as `user` with the given client options and stdin
async fn ssh(addr: SocketAddr, key: &Path, user: &str, options: &[&str], remote: &str, stdin: &[u8]) -> Run {
    let mut command = ssh_command(addr, key, user, options);
    if !remote.is_empty() {
        command.arg(remote);
    }
    finish(command, stdin).await
}

#[tokio::test]
async fn login_refuses_unknown_keys_and_wrong_accounts() {
    let world = World::new(&["alice", "bob"]);
    let (addr, _guard) = world.serve().await;
    let stranger = make_key(world.dir.path(), "key-stranger");

    let run = ssh(addr, &world.key("alice").path, "alice", &[], "echo WELCOME", b"").await;
    assert!(run.status.success(), "{}", run.stderr);
    assert_eq!(run.stdout(), "WELCOME\n");

    for (key, user) in [
        (&stranger.path, "alice"),
        (&stranger.path, "bob"),
        (&world.key("alice").path, "bob"),
        (&world.key("bob").path, "alice"),
        (&world.key("alice").path, "carol"),
        (&world.key("alice").path, "root"),
        (&world.key("alice").path, "daemon"),
    ] {
        let run = ssh(addr, key, user, &[], "echo SHOULD-NOT-RUN", b"").await;
        assert!(!run.status.success(), "{user} was accepted");
        assert!(run.stderr.contains("Permission denied"), "{user}: {}", run.stderr);
        assert!(!run.stdout().contains("SHOULD-NOT-RUN"));
    }
}

#[tokio::test]
async fn login_exec_returns_output_and_exit_status() {
    let world = World::new(&["alice"]);
    let (addr, _guard) = world.serve().await;
    let key = &world.key("alice").path;

    let run = ssh(addr, key, "alice", &[], "echo out; echo err >&2; exit 7", b"").await;
    assert_eq!(run.status.code(), Some(7), "{}", run.stderr);
    assert_eq!(run.stdout(), "out\n");
    assert_eq!(run.stderr, "err\n");

    let run = ssh(addr, key, "alice", &[], "exit 0", b"").await;
    assert_eq!(run.status.code(), Some(0), "{}", run.stderr);

    let input = vec![b'x'; 300_000];
    let run = ssh(addr, key, "alice", &[], "cat", &input).await;
    assert!(run.status.success(), "{}", run.stderr);
    assert_eq!(run.stdout, input, "stdin must reach the command and end with EOF");

    let run = ssh(addr, key, "alice", &[], "head -c 3000000 /dev/zero", b"").await;
    assert_eq!(run.stdout.len(), 3_000_000);

    let run = ssh(addr, key, "alice", &[], "if [ -t 0 ]; then echo tty; else echo notty; fi", b"").await;
    assert_eq!(run.stdout(), "notty\n");

    let run = ssh(addr, key, "alice", &[], "echo before; kill -9 $$", b"").await;
    assert_eq!(run.stdout(), "before\n");
    assert_eq!(run.status.code(), Some(255), "a command killed by a signal has no exit status: {}", run.stderr);
}

#[tokio::test]
async fn login_exec_goes_through_the_account_shell_with_a_fixed_environment() {
    let world = World::new(&["alice"]);
    let (addr, _guard) = world.serve().await;
    let key = &world.key("alice").path;
    let home = world.home().display().to_string();

    let run = ssh(addr, key, "alice", &[], "echo \"$HOME|$USER|$LOGNAME|$SHELL|$PATH|$0\"", b"").await;
    assert_eq!(run.stdout(), format!("{home}|alice|alice|/bin/sh|/usr/bin:/bin|sh\n"), "{}", run.stderr);

    let run = ssh(addr, key, "alice", &[], "pwd", b"").await;
    assert_eq!(run.stdout().trim(), home, "{}", run.stderr);

    let run = ssh(
        addr,
        key,
        "alice",
        &[],
        "if [ -r /proc/$PPID/mem ] || [ -r /proc/$PPID/environ ]; then echo exposed; else echo sealed; fi",
        b"",
    )
    .await;
    assert_eq!(run.stdout(), "sealed\n", "the account can read the session process that holds the host key");

    let mut command = ssh_command(addr, key, "alice", &["-o", "SendEnv=LANG LC_ALL FOO"]);
    command.arg("env").env("LANG", "C.UTF-8").env("LC_ALL", "en_US.UTF-8").env("FOO", "bar");
    let run = finish(command, b"").await;
    let names: Vec<_> = run
        .stdout()
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.to_owned()))
        .collect();
    for name in &names {
        assert!(
            ["HOME", "USER", "LOGNAME", "SHELL", "PATH", "PWD", "OLDPWD", "SHLVL", "_"].contains(&name.as_str()),
            "unexpected variable {name} in {names:?}"
        );
    }
    for name in ["HOME", "USER", "LOGNAME", "SHELL", "PATH"] {
        assert!(names.iter().any(|candidate| candidate == name), "{name} missing from {names:?}");
    }
}

async fn locale_output(world: &World) -> String {
    let (addr, _guard) = world.serve().await;
    let mut command = ssh_command(addr, &world.key("alice").path, "alice", &["-o", "SendEnv=LANG LC_ALL FOO"]);
    command
        .arg("echo \"$LANG|$LC_ALL|$FOO\"")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "en_US.UTF-8")
        .env("FOO", "bar");
    finish(command, b"").await.stdout()
}

#[tokio::test]
async fn login_locale_variables_pass_only_when_allowed() {
    let mut world = World::new(&["alice"]);
    assert_eq!(locale_output(&world).await, "||\n");
    world.policy.accept_locale = true;
    assert_eq!(locale_output(&world).await, "C.UTF-8|en_US.UTF-8|\n");
}

#[tokio::test]
async fn login_refuses_forwarding_and_subsystems() {
    let world = World::new(&["alice"]);
    let (addr, _guard) = world.serve().await;
    let key = &world.key("alice").path;

    let run = ssh(addr, key, "alice", &["-W", "127.0.0.1:9"], "", b"").await;
    assert!(!run.status.success(), "stdio forwarding was accepted");
    assert!(run.stderr.contains("forwarding failed"), "{}", run.stderr);

    let run = ssh(addr, key, "alice", &["-s"], "sftp", b"").await;
    assert!(!run.status.success(), "a subsystem was accepted");
    assert!(run.stdout.is_empty());
}

#[tokio::test]
async fn login_exec_with_a_terminal_runs_on_a_pty() {
    let world = World::new(&["alice"]);
    let (addr, _guard) = world.serve().await;
    let key = &world.key("alice").path;

    let run = ssh(
        addr,
        key,
        "alice",
        &["-tt"],
        "if [ -t 0 ] && [ -t 1 ]; then echo ISATTY; fi; echo \"term=$TERM\"; exit 4",
        b"",
    )
    .await;
    assert_eq!(run.status.code(), Some(4), "{}", run.stderr);
    let stdout = run.stdout();
    assert!(stdout.contains("ISATTY"), "{stdout}");
    assert!(stdout.contains("term="), "{stdout}");
}

struct Terminal {
    master: OwnedFd,
    seen: String,
}

impl Terminal {
    fn open(rows: u16, cols: u16) -> (Self, OwnedFd) {
        let master = pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        pty::grantpt(&master).unwrap();
        pty::unlockpt(&master).unwrap();
        let slave = rustix::fs::open(
            pty::ptsname(&master, Vec::new()).unwrap(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let size = Winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
        termios::tcsetwinsize(&slave, size).unwrap();
        rustix::fs::fcntl_setfl(&master, OFlags::NONBLOCK).unwrap();
        (Self { master, seen: String::new() }, slave)
    }

    fn resize(&self, rows: u16, cols: u16) {
        let size = Winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
        termios::tcsetwinsize(&self.master, size).unwrap();
    }

    fn type_text(&self, text: &str) {
        let mut rest = text.as_bytes();
        while !rest.is_empty() {
            match rustix::io::write(&self.master, rest) {
                Ok(written) => rest = &rest[written..],
                Err(rustix::io::Errno::AGAIN) => std::thread::sleep(Duration::from_millis(5)),
                Err(error) => panic!("terminal write failed: {error}"),
            }
        }
    }

    /// Collect output for up to `limit`; true once `needle` has appeared
    async fn wait_for(&mut self, needle: &str, limit: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        let mut buf = [0u8; 4096];
        while !self.seen.contains(needle) {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            match rustix::io::read(&self.master, &mut buf) {
                Ok(0) | Err(rustix::io::Errno::IO) => return false,
                Ok(read) => self.seen.push_str(&String::from_utf8_lossy(&buf[..read])),
                Err(rustix::io::Errno::AGAIN) => tokio::time::sleep(Duration::from_millis(20)).await,
                Err(error) => panic!("terminal read failed: {error}"),
            }
        }
        true
    }

    async fn expect(&mut self, needle: &str) {
        assert!(
            self.wait_for(needle, Duration::from_secs(30)).await,
            "no {needle:?} in {:?}",
            self.seen
        );
    }
}

#[tokio::test]
async fn login_pty_shell_echoes_input_and_follows_window_changes() {
    let world = World::new(&["alice"]);
    let (addr, _guard) = world.serve().await;
    let (mut terminal, slave) = Terminal::open(30, 100);
    let launcher = build_session_binary().await.unwrap();

    let client = ssh_command(addr, &world.key("alice").path, "alice", &["-tt"]);
    let (program, args): (_, Vec<_>) = {
        let std = client.as_std();
        (std.get_program().to_owned(), std.get_args().map(ToOwned::to_owned).collect())
    };
    let mut client = Command::new(&launcher);
    client
        .arg("launch")
        .arg(&program)
        .arg("ssh")
        .args(args)
        .env_clear()
        .env("TERM", "xterm-256color")
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave))
        .kill_on_drop(true);
    let mut child = client.spawn().unwrap();
    drop(client);

    terminal.type_text("echo MARK$((6*7))\n");
    terminal.expect("echo MARK$((6*7))").await;
    terminal.expect("MARK42").await;

    terminal.type_text("echo \"term=$TERM size=$(stty size) tty=$(tty)\"\n");
    terminal.expect("term=xterm-256color size=30 100 tty=/dev/").await;

    terminal.resize(50, 120);
    let mut changed = false;
    for attempt in 0..40 {
        terminal.type_text(&format!("echo \"resized[{attempt}]=$(stty size)\"\n"));
        if terminal.wait_for(&format!("resized[{attempt}]=50 120"), Duration::from_millis(500)).await {
            changed = true;
            break;
        }
    }
    assert!(changed, "window change did not reach the remote terminal: {:?}", terminal.seen);

    terminal.type_text("exit 7\n");
    let status = timeout(Duration::from_secs(30), child.wait()).await.unwrap().unwrap();
    assert_eq!(status.code(), Some(7), "{:?}", terminal.seen);
}

#[tokio::test]
async fn login_sessions_become_their_account_when_the_server_is_root() {
    if !is_root() {
        eprintln!("skipping: needs root; run in a container (see docs/development.md)");
        return;
    }
    let world = World::new(&["alice", "bob"]);
    let (addr, _guard) = world.serve().await;

    for (name, index) in [("alice", 0), ("bob", 1)] {
        let id = identity(index);
        let key = &world.key(name).path;
        let script = "id -u; id -g; id -G | tr ' ' '\\n' | sort -n | tr '\\n' ' '; echo; \
            grep -E '^(Uid|Gid|Groups):' /proc/self/status | tr -s '\\t ' ' '; \
            touch \"$HOME/owned-by-$USER\"";
        let run = ssh(addr, key, name, &[], script, b"").await;
        assert!(run.status.success(), "{}", run.stderr);
        let groups: Vec<String> = id.groups.iter().map(u32::to_string).collect();
        let (uid, gid, groups) = (id.uid, id.gid, groups.join(" "));
        let expected = format!(
            "{uid}\n{gid}\n{groups} \nUid: {uid} {uid} {uid} {uid}\nGid: {gid} {gid} {gid} {gid}\nGroups: {groups} \n"
        );
        assert_eq!(run.stdout(), expected, "{name}: {}", run.stderr);

        let meta = fs::metadata(world.home().join(format!("owned-by-{name}"))).unwrap();
        assert_eq!(std::os::unix::fs::MetadataExt::uid(&meta), id.uid);
        assert_eq!(std::os::unix::fs::MetadataExt::gid(&meta), id.gid);

        let run = ssh(addr, key, name, &["-tt"], "id -u", b"").await;
        assert_eq!(run.stdout().trim(), id.uid.to_string(), "a terminal session must be the account too");
    }
}

#[tokio::test]
async fn login_sessions_refuse_to_switch_account_when_the_server_is_not_root() {
    if is_root() {
        eprintln!("skipping: the non-root refusal path needs an unprivileged server");
        return;
    }
    let mut world = World::new(&["alice"]);
    let me = identity(0);
    world.passwd = world.passwd.replace(
        &format!("alice:x:{}:{}::", me.uid, me.gid),
        &format!("alice:x:{}:{}::", me.uid + 1, me.gid),
    );
    let (addr, _guard) = world.serve().await;

    let run = ssh(addr, &world.key("alice").path, "alice", &[], "echo SHOULD-NOT-RUN", b"").await;
    assert!(!run.status.success(), "a session for a different account started");
    assert!(!run.stdout().contains("SHOULD-NOT-RUN"));
}

#[tokio::test]
async fn login_server_refuses_root_accounts_unless_allowed() {
    let mut world = World::new(&["alice"]);
    let me = identity(0);
    let original = format!("alice:x:{}:{}::", me.uid, me.gid);

    world.passwd = world.passwd.replace(&original, "alice:x:0:0::");
    assert!(world.server().await.is_err(), "a uid 0 account was accepted");

    world.passwd = world.passwd.replace("alice:x:0:0::", &format!("alice:x:{}:0::", me.uid));
    assert!(world.server().await.is_err(), "an account in group 0 was accepted");

    world.policy.allow_root = true;
    assert!(world.server().await.is_ok(), "the explicit flag was ignored");
    world.policy.allow_root = false;

    world.passwd = world.passwd.replace("alice:x:", "carol:x:");
    assert!(world.server().await.is_err(), "an account missing from passwd was accepted");

    world.passwd = String::from("alice:x:1000:1000::/home/alice:/usr/sbin/nologin\n");
    assert!(world.server().await.is_err(), "a nologin account was accepted");
}
