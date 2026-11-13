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
    pty,
    termios::{self, Winsize},
};
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt as _, net::TcpListener, process::Command, task::JoinHandle, time::timeout};
use zeroize::Zeroizing;

use crate::{
    Config, DEFAULT_PROVIDER, LoginAccounts, LoginPolicy, Server,
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
    /// The session binary to run instead of the real one
    session: Option<PathBuf>,
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
        Self { dir, keys, passwd, group, policy, session: None }
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
            match &self.session {
                Some(session) => session.clone(),
                None => build_session_binary().await?,
            },
            self.policy.clone(),
            DEFAULT_PROVIDER,
        )
    }

    async fn serve(&self) -> (SocketAddr, Guard) {
        self.serve_with(|server| server).await
    }

    async fn serve_with(&self, adjust: impl FnOnce(Server) -> Server) -> (SocketAddr, Guard) {
        let server = Arc::new(adjust(self.server().await.unwrap()));
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
        let master = crate::unix::open_controller().unwrap();
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

/// `sid tty_nr` of the shell running a command, from `/proc/$$/stat` (comm is `sh`, no spaces)
const SESSION_AND_TERMINAL: &str = "read -r a b c d e sid tty rest < /proc/$$/stat; echo \"$sid $tty\"";

#[tokio::test]
async fn login_commands_without_a_terminal_leave_the_listeners_session() {
    let world = World::new(&["alice"]);
    let (addr, _guard) = world.serve().await;
    let listener_session = rustix::process::getsid(None).unwrap().as_raw_nonzero().get();

    let run = ssh(addr, &world.key("alice").path, "alice", &[], SESSION_AND_TERMINAL, b"").await;
    let (session, terminal) = run.stdout().trim().split_once(' ').map(|(a, b)| (a.to_owned(), b.to_owned())).unwrap();
    assert_ne!(session, listener_session.to_string(), "the command shares the listener's session: {}", run.stderr);
    assert_eq!(terminal, "0", "the command has a controlling terminal it did not ask for");
}

#[tokio::test]
async fn login_session_process_is_sealed_from_the_account() {
    let world = World::new(&["alice"]);
    let (addr, _guard) = world.serve().await;
    let key = &world.key("alice").path;

    let run = ssh(
        addr,
        key,
        "alice",
        &[],
        "for f in mem environ maps; do if head -c 1 /proc/$PPID/$f >/dev/null 2>&1; then echo \"$f readable\"; fi; done; \
         if ls /proc/$PPID/fd >/dev/null 2>&1; then echo fd listable; fi; \
         if ls /proc/$PPID/task >/dev/null 2>&1 && ls /proc/$PPID/task/$PPID/fd >/dev/null 2>&1; then echo task fd listable; fi; \
         echo checked",
        b"",
    )
    .await;
    assert_eq!(run.stdout(), "checked\n", "the account can inspect the session process: {}", run.stderr);

    // ptrace attach and process_vm_readv need a program that can issue them; Python's ctypes is the
    // only one the test hosts reliably have
    let Some(python) = env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join("python3"))
        .find(|candidate| candidate.is_file())
    else {
        eprintln!("skipping the ptrace and process_vm_readv checks: no python3 on PATH");
        return;
    };
    let probe = world.dir.path().join("probe.py");
    fs::write(
        &probe,
        r#"
import ctypes, errno, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.process_vm_readv.restype = ctypes.c_ssize_t
pid = int(sys.argv[1])
def code():
    return errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
attached = libc.ptrace(16, pid, None, None)  # PTRACE_ATTACH
ptrace = "ATTACHED" if attached == 0 else code()
class Iov(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
buf = ctypes.create_string_buffer(16)
local = Iov(ctypes.addressof(buf), 16)
remote = Iov(0x400000, 16)
ctypes.set_errno(0)
n = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
readv = code() if n < 0 else "READ"
print("ptrace=%s readv=%s" % (ptrace, readv))
"#,
    )
    .unwrap();
    let run = ssh(addr, key, "alice", &[], &format!("{} {} $PPID", python.display(), probe.display()), b"").await;
    assert_eq!(
        run.stdout(),
        "ptrace=EPERM readv=EPERM\n",
        "the account can attach to or read the session process: {}",
        run.stderr
    );
}

#[tokio::test]
async fn login_terminals_belong_to_the_account_and_are_private() {
    let world = World::new(&["alice"]);
    let (addr, _guard) = world.serve().await;
    let uid = identity(0).uid;

    let run = ssh(addr, &world.key("alice").path, "alice", &["-tt"], "stat -c 'tty=%a:%u' \"$(tty)\"", b"").await;
    assert!(run.stdout().contains(&format!("tty=600:{uid}")), "{:?} {}", run.stdout(), run.stderr);
}

/// A stand-in session binary: its first run stops itself, later runs are the real session
fn write_stalling_session(world: &World, real: &Path) -> PathBuf {
    let stub = world.dir.path().join("session-stub");
    let state = world.dir.path().join("stalled");
    fs::write(
        &stub,
        format!(
            "#!/bin/sh\nif mkdir '{dir}' 2>/dev/null; then echo $$ > '{dir}/pid'; kill -STOP $$; exit 0; fi\nexec '{real}' \"$@\"\n",
            dir = state.display(),
            real = real.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
    stub
}

fn process_state(pid: u32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?.1.chars().next()
}

async fn eventually(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    while !condition() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

#[tokio::test]
async fn login_a_session_process_that_stops_cannot_stall_the_listener() {
    let mut world = World::new(&["alice"]);
    world.session = Some(write_stalling_session(&world, &build_session_binary().await.unwrap()));
    let server = Arc::new(world.server().await.unwrap().with_handoff_timeout(Duration::from_secs(6)));
    let std_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();

    // The whole listener gets one worker thread: a blocking handoff would stop it from accepting
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            tokio::select! {
                _ = server.run(listener) => {}
                _ = stopped => {}
            }
        });
    });

    let key = world.key("alice").path.clone();
    let first = tokio::spawn({
        let key = key.clone();
        async move { ssh(addr, &key, "alice", &[], "echo FIRST", b"").await }
    });
    let pid_file = world.dir.path().join("stalled/pid");
    assert!(eventually(Duration::from_secs(30), || pid_file.exists()).await, "the stand-in session never started");
    let pid: u32 = fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
    assert!(
        eventually(Duration::from_secs(10), || process_state(pid) == Some('T')).await,
        "the stand-in session did not stop itself"
    );

    // While the first connection's session process is stopped, another connection is served
    let second = timeout(Duration::from_secs(20), ssh(addr, &key, "alice", &[], "echo SECOND", b""))
        .await
        .expect("a stopped session process stalled the listener");
    assert_eq!(second.stdout(), "SECOND\n", "{}", second.stderr);

    // The listener gives up on the stopped process, kills it and reaps it
    let first = timeout(Duration::from_secs(30), first).await.unwrap().unwrap();
    assert!(!first.status.success() && !first.stdout().contains("FIRST"), "{}", first.stdout());
    assert!(
        eventually(Duration::from_secs(10), || process_state(pid).is_none()).await,
        "the stopped session process was not killed and reaped (state {:?})",
        process_state(pid)
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn login_one_account_cannot_hold_every_session() {
    let world = World::new(&["alice", "bob"]);
    let config = Config { max_sessions_per_account: 1, ..Config::default() };
    let (addr, _guard) = world.serve_with(|server| server.with_config(config)).await;
    let alice = world.key("alice").path.clone();

    let marker = world.home().join("first-is-up");
    let held = tokio::spawn({
        let (alice, script) = (alice.clone(), format!("touch '{}'; sleep 10; echo FIRST", marker.display()));
        async move { ssh(addr, &alice, "alice", &[], &script, b"").await }
    });
    assert!(eventually(Duration::from_secs(30), || marker.exists()).await, "the first session never started");

    let second = ssh(addr, &alice, "alice", &[], "echo SECOND", b"").await;
    assert!(!second.status.success() && !second.stdout().contains("SECOND"), "{}", second.stdout());
    let other = ssh(addr, &world.key("bob").path, "bob", &[], "echo BOB", b"").await;
    assert_eq!(other.stdout(), "BOB\n", "another account was refused: {}", other.stderr);

    let held = held.await.unwrap();
    assert_eq!(held.stdout(), "FIRST\n", "{}", held.stderr);
    let third = ssh(addr, &alice, "alice", &[], "echo THIRD", b"").await;
    assert_eq!(third.stdout(), "THIRD\n", "the slot was not released: {}", third.stderr);
}

#[tokio::test]
async fn login_session_binary_and_its_directory_must_be_trusted() {
    let mut world = World::new(&["alice"]);
    let dir = world.dir.path().join("bin");
    fs::create_dir(&dir).unwrap();
    let program = dir.join("oxish-session");
    fs::write(&program, "#!/bin/sh\n").unwrap();
    let mode = |path: &Path, mode: u32| fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    world.session = Some(program.clone());

    mode(&dir, 0o755);
    mode(&program, 0o755);
    assert!(world.server().await.is_ok(), "a trusted session binary was refused");
    mode(&program, 0o775);
    assert!(world.server().await.is_err(), "a group-writable session binary was accepted");
    mode(&program, 0o757);
    assert!(world.server().await.is_err(), "a world-writable session binary was accepted");
    mode(&program, 0o644);
    assert!(world.server().await.is_err(), "a session binary that cannot run was accepted");
    mode(&program, 0o755);
    mode(&dir, 0o777);
    assert!(world.server().await.is_err(), "a session binary in a world-writable directory was accepted");
    mode(&dir, 0o755);

    let link = dir.join("link");
    std::os::unix::fs::symlink(&program, &link).unwrap();
    world.session = Some(link);
    assert!(world.server().await.is_err(), "a symlinked session binary was accepted");

    if is_root() {
        world.session = Some(program.clone());
        rustix::fs::chown(&program, Some(rustix::process::Uid::from_raw(12_345)), None).unwrap();
        assert!(world.server().await.is_err(), "a session binary owned by another user was accepted");
    }
}

#[tokio::test]
async fn login_allows_an_account_in_group_zero_only_when_root_login_is_allowed() {
    if !is_root() {
        eprintln!("skipping: needs root; run in a container (see docs/development.md)");
        return;
    }
    let mut world = World::new(&["alice"]);
    let me = identity(0);
    world.passwd = world.passwd.replace(&format!("alice:x:{}:{}::", me.uid, me.gid), &format!("alice:x:{}:0::", me.uid));
    assert!(world.server().await.is_err(), "an account in group 0 was accepted without the flag");

    world.policy.allow_root = true;
    let (addr, _guard) = world.serve().await;
    let run = ssh(addr, &world.key("alice").path, "alice", &[], "id -u; id -g", b"").await;
    assert_eq!(run.stdout(), format!("{}\n0\n", me.uid), "{}", run.stderr);
}
