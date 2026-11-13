use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{Mode, OFlags, open};
use rustix::process::{Pid, Signal, kill_process};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{LocalModes, Winsize, tcgetattr, tcsetwinsize};

const LIMIT: Duration = Duration::from_secs(40);

fn variable(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set; run this test through client/fixture/ssh-fixture.sh exec")
    })
}

struct Target {
    host: String,
    port: String,
    pin: String,
    pub_key: String,
    user: String,
    key: String,
}

fn target() -> Target {
    Target {
        host: variable("XINFRA_FIXTURE_A_HOST"),
        port: variable("XINFRA_FIXTURE_A_PORT"),
        pin: variable("XINFRA_FIXTURE_A_HOST_KEY"),
        pub_key: variable("XINFRA_FIXTURE_A_HOST_KEY_PUB"),
        user: variable("XINFRA_FIXTURE_USER"),
        key: variable("XINFRA_FIXTURE_KEY"),
    }
}

impl Target {
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oxish"));
        command
            .env("TERM", "xterm")
            .args(["-p", &self.port, "-i", &self.key, "--host-key", &self.pin]);
        command
    }

    fn address(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }
}

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Guard {
    fn signal(&self, signal: Signal) {
        let pid = Pid::from_raw(self.0.id() as i32).expect("child pid");
        kill_process(pid, signal).expect("signal the client");
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + LIMIT;
        loop {
            if let Some(status) = self.0.try_wait().expect("wait") {
                return status;
            }
            assert!(Instant::now() < deadline, "the client did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

struct Terminal {
    master: std::fs::File,
    slave: OwnedFd,
    output: Vec<u8>,
}

fn terminal(rows: u16, cols: u16) -> Terminal {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("pty master");
    grantpt(&master).expect("grant");
    unlockpt(&master).expect("unlock");
    let name = ptsname(&master, Vec::new()).expect("slave name");
    let slave =
        open(name.as_c_str(), OFlags::RDWR | OFlags::NOCTTY, Mode::empty()).expect("pty slave");
    tcsetwinsize(
        &slave,
        Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .expect("initial size");
    Terminal {
        master: std::fs::File::from(master),
        slave,
        output: Vec::new(),
    }
}

fn attributes(fd: impl AsFd) -> Vec<u8> {
    use std::os::fd::AsRawFd;
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::tcgetattr(fd.as_fd().as_raw_fd(), &mut termios) };
    assert_eq!(result, 0, "tcgetattr");
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&raw const termios).cast::<u8>(),
            std::mem::size_of::<libc::termios>(),
        )
    };
    bytes.to_vec()
}

impl Terminal {
    fn stdio(&self) -> (Stdio, Stdio, Stdio) {
        let one = || Stdio::from(self.slave.try_clone().expect("dup slave"));
        (one(), one(), one())
    }

    fn spawn(&self, mut command: Command) -> Guard {
        let (stdin, stdout, stderr) = self.stdio();
        Guard(
            command
                .stdin(stdin)
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .expect("spawn oxish"),
        )
    }

    fn wait_raw(&self) {
        let deadline = Instant::now() + LIMIT;
        while tcgetattr(&self.slave)
            .expect("termios")
            .local_modes
            .contains(LocalModes::ICANON)
        {
            assert!(Instant::now() < deadline, "the client never entered raw mode");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn type_in(&mut self, text: &str) {
        self.master.write_all(text.as_bytes()).expect("type");
    }

    fn read_until(&mut self, needle: &str) {
        self.read_until_with(needle, |text| text.contains(needle));
    }

    fn read_until_with(&mut self, what: &str, found: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + LIMIT;
        loop {
            if found(&String::from_utf8_lossy(&self.output)) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "did not see {what:?} in {:?}",
                String::from_utf8_lossy(&self.output)
            );
            let mut fds = [PollFd::new(&self.master, PollFlags::IN)];
            let ready = poll(&mut fds, Some(&rustix::time::Timespec { tv_sec: 0, tv_nsec: 100_000_000 }))
                .expect("poll");
            if ready == 0 {
                continue;
            }
            let mut buffer = [0u8; 8192];
            match self.master.read(&mut buffer) {
                Ok(count) => self.output.extend_from_slice(&buffer[..count]),
                Err(error) if error.raw_os_error() == Some(5) => return,
                Err(error) => panic!("read the terminal: {error}"),
            }
        }
    }

    fn query(&mut self, command: &str, prefix: &str) -> u64 {
        self.output.clear();
        self.type_in(command);
        self.read_until_with(prefix, |text| number_in(text, prefix).is_some());
        number_in(&String::from_utf8_lossy(&self.output), prefix).expect("number")
    }
}

fn number_in(text: &str, prefix: &str) -> Option<u64> {
    text.rmatch_indices(prefix).find_map(|(at, _)| {
        let rest = &text[at + prefix.len()..];
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        (digits > 0 && digits < rest.len()).then(|| rest[..digits].parse().ok()).flatten()
    })
}

#[test]
fn an_interactive_shell_runs_a_command_and_exits_with_the_remote_status() {
    let target = target();
    let mut terminal = terminal(30, 100);
    let before = attributes(&terminal.slave);
    let mut command = target.command();
    command.arg(target.address());
    let mut client = terminal.spawn(command);
    terminal.wait_raw();
    assert_ne!(attributes(&terminal.slave), before, "raw mode changed the terminal");
    terminal.type_in("echo marker; exit 7\r");
    terminal.read_until("\r\nmarker\r\n");
    assert_eq!(client.wait().code(), Some(7));
    assert_eq!(attributes(&terminal.slave), before);
}

#[test]
fn a_window_size_change_reaches_the_remote_pty() {
    let target = target();
    let mut terminal = terminal(30, 100);
    let before = attributes(&terminal.slave);
    let mut command = target.command();
    command.arg(target.address());
    let mut client = terminal.spawn(command);
    terminal.wait_raw();
    terminal.type_in("stty size\r");
    terminal.read_until("\r\n30 100\r\n");

    tcsetwinsize(
        &terminal.slave,
        Winsize {
            ws_row: 41,
            ws_col: 123,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .expect("resize");
    client.signal(Signal::WINCH);
    std::thread::sleep(Duration::from_millis(500));
    terminal.type_in("stty size\r");
    terminal.read_until("\r\n41 123\r\n");

    terminal.type_in("exit\r");
    assert_eq!(client.wait().code(), Some(0));
    assert_eq!(attributes(&terminal.slave), before);
}

#[test]
fn a_large_output_under_a_pty_arrives_whole() {
    let target = target();
    let mut terminal = terminal(24, 80);
    let mut command = target.command();
    command.arg(target.address());
    let mut client = terminal.spawn(command);
    terminal.wait_raw();
    terminal.type_in("seq 1 200000; exit 0\r");
    terminal.read_until("\r\n200000\r\n");
    assert_eq!(client.wait().code(), Some(0));
}

#[test]
fn the_tilde_dot_escape_disconnects_and_restores_the_terminal() {
    let target = target();
    let mut terminal = terminal(24, 80);
    let before = attributes(&terminal.slave);
    let mut command = target.command();
    command.arg(target.address());
    let mut client = terminal.spawn(command);
    terminal.wait_raw();
    terminal.type_in("echo up\r");
    terminal.read_until("\r\nup\r\n");
    terminal.type_in("~.");
    assert_eq!(client.wait().code(), Some(255));
    assert_eq!(attributes(&terminal.slave), before);
}

#[test]
fn termination_signals_restore_the_terminal_and_set_the_exit_status() {
    for (signal, status) in [(Signal::TERM, 143), (Signal::HUP, 129), (Signal::INT, 130)] {
        let target = target();
        let terminal = terminal(24, 80);
        let before = attributes(&terminal.slave);
        let mut command = target.command();
        command.arg(target.address());
        let mut client = terminal.spawn(command);
        terminal.wait_raw();
        client.signal(signal);
        assert_eq!(client.wait().code(), Some(status), "{signal:?}");
        assert_eq!(attributes(&terminal.slave), before, "{signal:?}");
    }
}

#[test]
fn a_command_gets_no_pty_unless_asked_and_a_requested_pty_is_restored() {
    let target = target();
    let mut terminal = terminal(24, 80);
    let before = attributes(&terminal.slave);

    let mut command = target.command();
    command.arg(target.address()).arg("[ -t 0 ] && echo tty || echo notty; exit 5");
    let mut client = terminal.spawn(command);
    assert_eq!(client.wait().code(), Some(5));
    terminal.read_until("notty");
    assert_eq!(attributes(&terminal.slave), before);

    let mut command = target.command();
    command
        .arg("-t")
        .arg(target.address())
        .arg("[ -t 0 ] && echo tty || echo notty; exit 6");
    let mut client = terminal.spawn(command);
    assert_eq!(client.wait().code(), Some(6));
    terminal.output.clear();
    terminal.read_until("tty");
    assert!(!String::from_utf8_lossy(&terminal.output).contains("notty"));
    assert_eq!(attributes(&terminal.slave), before);
}

fn run_exec(target: &Target, script: &str) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let output = target
        .command()
        .arg("-T")
        .arg(target.address())
        .arg(script)
        .stdin(Stdio::null())
        .output()
        .expect("run oxish");
    (output.status.code(), output.stdout, output.stderr)
}

#[test]
fn exec_without_a_pty_returns_streams_and_status() {
    let target = target();
    let (code, stdout, stderr) = run_exec(&target, "echo out; echo err >&2; exit 3");
    assert_eq!(code, Some(3));
    assert_eq!(stdout, b"out\n");
    assert_eq!(stderr, b"err\n");
}

#[test]
fn exec_exits_128_plus_the_remote_signal() {
    let target = target();
    let (code, _, _) = run_exec(&target, "kill -9 $$");
    assert_eq!(code, Some(137));
}

#[test]
fn exec_streams_stdin_to_the_command_and_a_large_output_back() {
    let target = target();
    let mut child = target
        .command()
        .arg(target.address())
        .arg("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn(move || {
        let block = vec![b'x'; 64 * 1024];
        for _ in 0..160 {
            stdin.write_all(&block).expect("write");
        }
    });
    let mut stdout = child.stdout.take().expect("stdout");
    let mut total = 0usize;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = stdout.read(&mut buffer).expect("read");
        if count == 0 {
            break;
        }
        total += count;
    }
    writer.join().expect("writer");
    assert!(child.wait().expect("wait").success());
    assert_eq!(total, 160 * 64 * 1024);
}

#[test]
fn a_known_hosts_file_authenticates_the_host() {
    let target = target();
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("known_hosts");
    let mut fields = target.pub_key.split_whitespace();
    let (kind, blob) = (fields.next().expect("type"), fields.next().expect("blob"));
    std::fs::write(
        &path,
        format!("[{}]:{} {kind} {blob}\n", target.host, target.port),
    )
    .expect("known_hosts");
    let output = Command::new(env!("CARGO_BIN_EXE_oxish"))
        .args(["-p", &target.port, "-i", &target.key, "--known-hosts"])
        .arg(&path)
        .args(["-T", &target.address(), "echo trusted"])
        .stdin(Stdio::null())
        .output()
        .expect("run oxish");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"trusted\n");
}

#[test]
fn a_wrong_host_key_fails_before_authentication() {
    let target = target();
    let other = variable("XINFRA_FIXTURE_B_HOST_KEY");
    let output = Command::new(env!("CARGO_BIN_EXE_oxish"))
        .args(["-p", &target.port, "-i", &target.key, "--host-key", &other])
        .args(["-T", &target.address(), "echo never"])
        .stdin(Stdio::null())
        .output()
        .expect("run oxish");
    assert_eq!(output.status.code(), Some(255));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("host key mismatch"));
}

#[test]
fn trust_is_never_assumed() {
    let target = target();
    let output = Command::new(env!("CARGO_BIN_EXE_oxish"))
        .args(["-p", &target.port, "-i", &target.key])
        .args(["-T", &target.address(), "echo never"])
        .stdin(Stdio::null())
        .output()
        .expect("run oxish");
    assert_eq!(output.status.code(), Some(255));
    assert!(output.stdout.is_empty());
}

const UP: u8 = 0;
const DOWN: u8 = 1;
const BLACKHOLE: u8 = 2;

struct Proxy {
    port: u16,
    connections: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>>,
    mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

impl Proxy {
    fn start(target: &Target) -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let upstream = format!("{}:{}", target.host, target.port);
        let connections = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mode = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(UP));
        let held = std::sync::Arc::clone(&connections);
        let state = std::sync::Arc::clone(&mode);
        std::thread::spawn(move || {
            while let Ok((client, _)) = listener.accept() {
                if state.load(Ordering::SeqCst) != UP {
                    continue;
                }
                let Ok(server) = std::net::TcpStream::connect(&upstream) else {
                    continue;
                };
                let mut held = held.lock().expect("lock");
                held.push(client.try_clone().expect("clone"));
                held.push(server.try_clone().expect("clone"));
                for (mut from, mut to) in [
                    (client.try_clone().expect("clone"), server.try_clone().expect("clone")),
                    (server, client),
                ] {
                    let state = std::sync::Arc::clone(&state);
                    std::thread::spawn(move || {
                        let mut buffer = [0u8; 16 * 1024];
                        loop {
                            match from.read(&mut buffer) {
                                Ok(0) | Err(_) => break,
                                Ok(count) => {
                                    if state.load(Ordering::SeqCst) == BLACKHOLE {
                                        continue;
                                    }
                                    if to.write_all(&buffer[..count]).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = to.shutdown(std::net::Shutdown::Both);
                    });
                }
            }
        });
        Self {
            port,
            connections,
            mode,
        }
    }

    fn set(&self, mode: u8) {
        self.mode.store(mode, std::sync::atomic::Ordering::SeqCst);
    }

    fn cut(&self) {
        for stream in self.connections.lock().expect("lock").drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

#[test]
fn transport_loss_restores_the_terminal_and_fails_the_session() {
    let target = target();
    let proxy = Proxy::start(&target);
    let mut terminal = terminal(24, 80);
    let before = attributes(&terminal.slave);
    let mut command = target.command();
    command.args(["-p", &proxy.port.to_string()]).arg(target.address());
    let mut client = terminal.spawn(command);
    terminal.wait_raw();
    terminal.type_in("echo alive\r");
    terminal.read_until("\r\nalive\r\n");
    proxy.cut();
    assert_eq!(client.wait().code(), Some(255));
    assert_eq!(attributes(&terminal.slave), before);
}

fn attach_command(target: &Target, proxy: &Proxy, name: &str, extra: &[&str]) -> Command {
    let mut command = target.command();
    command
        .args(["-p", &proxy.port.to_string()])
        .args(["--attach", name])
        .args(extra)
        .arg(target.address());
    command
}

fn resize(terminal: &Terminal, rows: u16, cols: u16) {
    tcsetwinsize(
        &terminal.slave,
        Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .expect("resize");
}

#[test]
fn attach_reconnects_to_the_same_tmux_session_and_drops_input_typed_while_disconnected() {
    let target = target();
    let proxy = Proxy::start(&target);
    let mut terminal = terminal(24, 80);
    let before = attributes(&terminal.slave);
    let mut client = terminal.spawn(attach_command(&target, &proxy, "reattach", &[]));
    terminal.wait_raw();

    terminal.type_in("echo MARKER_$((40+2))\r");
    terminal.read_until("MARKER_42");
    terminal.type_in("(i=0; while :; do i=$((i+1)); echo $i > /tmp/oxish-counter; sleep 1; done) &\r");
    let created = terminal.query("tmux display -p 'CR=#{session_created}'\r", "CR=");
    std::thread::sleep(Duration::from_millis(1500));
    let counter = terminal.query("echo C1=$(cat /tmp/oxish-counter)\r", "C1=");

    proxy.set(DOWN);
    proxy.cut();
    terminal.read_until("oxish: connection lost; reconnecting to 127.0.0.1 (attempt 1)\u{2026}");
    assert_eq!(attributes(&terminal.slave), before, "the terminal is cooked while disconnected");

    terminal.type_in("touch /tmp/oxish-leak-line\r");
    terminal.type_in("LEAKPARTIAL");
    resize(&terminal, 33, 111);
    client.signal(Signal::WINCH);
    terminal.read_until("(attempt 2)");
    assert_eq!(attributes(&terminal.slave), before, "the terminal stays cooked between attempts");
    std::thread::sleep(Duration::from_millis(1500));
    proxy.set(UP);

    terminal.wait_raw();
    terminal.output.clear();
    terminal.read_until("MARKER_42");

    let same = terminal.query("tmux display -p 'CR=#{session_created}'\r", "CR=");
    assert_eq!(same, created, "the same tmux session is attached");
    let advanced = terminal.query("echo C2=$(cat /tmp/oxish-counter)\r", "C2=");
    assert!(advanced >= counter + 3, "the counter kept running: {counter} then {advanced}");
    let leaked = terminal.query("[ -e /tmp/oxish-leak-line ]; echo LEAKCHECK=$?\r", "LEAKCHECK=");
    assert_eq!(leaked, 1, "input typed while disconnected was replayed");
    terminal.type_in("stty size\r");
    terminal.read_until("32 111");

    terminal.type_in("exit\r");
    assert_eq!(client.wait().code(), Some(0));
    assert_eq!(attributes(&terminal.slave), before);
}

#[test]
fn attach_notices_a_silent_peer_and_ctrl_c_ends_the_reconnecting() {
    let target = target();
    let proxy = Proxy::start(&target);
    let mut terminal = terminal(24, 80);
    let before = attributes(&terminal.slave);
    let command = attach_command(
        &target,
        &proxy,
        "silent",
        &["--keepalive-interval", "1", "--keepalive-timeout", "4"],
    );
    let mut client = terminal.spawn(command);
    terminal.wait_raw();
    terminal.type_in("echo UP_$((1+1))\r");
    terminal.read_until("UP_2");

    proxy.set(BLACKHOLE);
    let silent_since = Instant::now();
    terminal.read_until("oxish: connection lost; reconnecting to 127.0.0.1 (attempt 1)");
    let noticed = silent_since.elapsed();
    assert!(noticed >= Duration::from_secs(3), "declared dead after {noticed:?}");
    assert!(noticed < Duration::from_secs(12), "declared dead after {noticed:?}");
    assert_eq!(attributes(&terminal.slave), before);

    client.signal(Signal::INT);
    assert_eq!(client.wait().code(), Some(255));
    assert_eq!(attributes(&terminal.slave), before);
}

#[test]
fn an_idle_attached_session_answers_keepalives_and_stays_up() {
    let target = target();
    let proxy = Proxy::start(&target);
    let mut terminal = terminal(24, 80);
    let before = attributes(&terminal.slave);
    let command = attach_command(
        &target,
        &proxy,
        "idle",
        &["--keepalive-interval", "1", "--keepalive-timeout", "3"],
    );
    let mut client = terminal.spawn(command);
    terminal.wait_raw();
    terminal.type_in("echo FIRST_$((1+1))\r");
    terminal.read_until("FIRST_2");
    std::thread::sleep(Duration::from_secs(6));
    terminal.type_in("echo SECOND_$((1+2))\r");
    terminal.read_until("SECOND_3");
    assert!(!String::from_utf8_lossy(&terminal.output).contains("connection lost"));
    terminal.type_in("exit\r");
    assert_eq!(client.wait().code(), Some(0));
    assert_eq!(attributes(&terminal.slave), before);
}

#[test]
fn attach_does_not_reconnect_after_tilde_dot_or_a_detach() {
    let target = target();
    let proxy = Proxy::start(&target);
    let mut terminal = terminal(24, 80);
    let before = attributes(&terminal.slave);
    let mut client = terminal.spawn(attach_command(&target, &proxy, "leaving", &[]));
    terminal.wait_raw();
    terminal.type_in("echo HERE_$((1+1))\r");
    terminal.read_until("HERE_2");
    terminal.type_in("~.");
    assert_eq!(client.wait().code(), Some(255));
    assert!(!String::from_utf8_lossy(&terminal.output).contains("connection lost"));
    assert_eq!(attributes(&terminal.slave), before);

    let mut client = terminal.spawn(attach_command(&target, &proxy, "leaving", &[]));
    terminal.wait_raw();
    terminal.type_in("echo BACK_$((1+1))\r");
    terminal.read_until("BACK_2");
    terminal.type_in("tmux detach-client\r");
    assert_eq!(client.wait().code(), Some(0));
    assert!(!String::from_utf8_lossy(&terminal.output).contains("connection lost"));
    assert_eq!(attributes(&terminal.slave), before);
}

#[test]
fn attach_refuses_unsafe_names_and_a_missing_terminal() {
    for name in ["a;touch x", "a b", "-w", "a$(id)", ""] {
        let output = Command::new(env!("CARGO_BIN_EXE_oxish"))
            .args(["-i", "key", "--host-key", "SHA256:x", "--attach", name, "user@127.0.0.1"])
            .stdin(Stdio::null())
            .output()
            .expect("run oxish");
        assert_eq!(output.status.code(), Some(255), "{name:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("--attach needs a name"), "{name:?}");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_oxish"))
        .args(["-i", "key", "--host-key", "SHA256:x", "--attach", "work", "user@127.0.0.1"])
        .stdin(Stdio::null())
        .output()
        .expect("run oxish");
    assert_eq!(output.status.code(), Some(255));
    assert!(String::from_utf8_lossy(&output.stderr).contains("needs a terminal"));
}
