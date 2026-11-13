use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::io::Write;
use std::time::{Duration, Instant};

use oxish_client::terminal::{EscapeInput, RawMode, discard_input, pty_request, terminal_size};
use oxish_client::{
    ClientConfig, Connection, Error, ExecStatus, FileSink, Fingerprint, HostTrust, Identity,
    InputSource, Interrupt, Keepalive, KnownHosts, SessionEvents, SessionRequest, TerminalSize,
};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::termios::isatty;

const USAGE: &str = "usage: oxish [-p PORT] [-i KEY | --agent SOCKET --agent-identity SHA256:...]
             (--host-key SHA256:... | --known-hosts PATH) [-t | -T] user@host [command ...]
       oxish [-p PORT] [-i KEY | --agent SOCKET --agent-identity SHA256:...]
             (--host-key SHA256:... | --known-hosts PATH) --attach NAME
             [--keepalive-interval SECONDS] [--keepalive-timeout SECONDS] user@host";

const EXIT_FAILURE: u8 = 255;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const STABLE_AFTER: Duration = Duration::from_secs(10);
const OUTAGE_POLL: Duration = Duration::from_millis(100);
const ATTACH_NAME_MAX: usize = 64;

const TERMINAL_RESET: &str = "\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1004l\x1b[?2004l\x1b[?1l\x1b>\x1b[0m\x1b[?25h";

static WAKE: AtomicI32 = AtomicI32::new(-1);
static TERMINATED: AtomicI32 = AtomicI32::new(0);
static RESIZED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(target_vendor = "apple")]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

extern "C" fn on_signal(signal: libc::c_int) {
    let errno = errno_location();
    let saved = unsafe { *errno };
    if signal == libc::SIGWINCH {
        RESIZED.store(true, Ordering::Relaxed);
    } else {
        let _ = TERMINATED.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
    }
    let fd = WAKE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = 1u8;
        unsafe { libc::write(fd, (&raw const byte).cast(), 1) };
    }
    unsafe { *errno = saved };
}

fn install_handlers() -> std::io::Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGWINCH] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        action.sa_flags = 0;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn nonblocking(fd: impl AsFd) -> std::io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok(())
}

struct Terminal {
    wake: File,
    _wake_writer: OwnedFd,
    tty: OwnedFd,
    interactive: bool,
    size: TerminalSize,
    raw: Option<RawMode>,
    discard_typeahead: bool,
    started_at: Option<Instant>,
}

impl Terminal {
    fn new(
        tty: OwnedFd,
        interactive: bool,
        size: TerminalSize,
        discard_typeahead: bool,
    ) -> std::io::Result<Self> {
        let (reader, writer) = rustix::pipe::pipe()?;
        nonblocking(&reader)?;
        nonblocking(&writer)?;
        WAKE.store(writer.as_raw_fd(), Ordering::Relaxed);
        Ok(Self {
            wake: File::from(reader),
            _wake_writer: writer,
            tty,
            interactive,
            size,
            raw: None,
            discard_typeahead,
            started_at: None,
        })
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        WAKE.store(-1, Ordering::Relaxed);
    }
}

impl SessionEvents for Terminal {
    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        Some(self.wake.as_fd())
    }

    fn started(&mut self) -> std::io::Result<()> {
        self.started_at = Some(Instant::now());
        if self.interactive {
            if self.discard_typeahead {
                discard_input(&self.tty)?;
            }
            self.raw = Some(RawMode::enter(self.tty.as_fd())?);
        }
        Ok(())
    }

    fn window_change(&mut self) -> Option<TerminalSize> {
        let mut scratch = [0u8; 64];
        while matches!(self.wake.read(&mut scratch), Ok(count) if count > 0) {}
        if !self.interactive || !RESIZED.swap(false, Ordering::Relaxed) {
            return None;
        }
        let size = terminal_size(&self.tty);
        (size != self.size).then(|| {
            self.size = size;
            size
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pty {
    Auto,
    Force,
    Never,
}

enum Trust {
    Pinned(String),
    KnownHosts(PathBuf),
}

enum Credential {
    Key(PathBuf),
    Agent { socket: PathBuf, identity: String },
}

struct Options {
    port: u16,
    credential: Credential,
    trust: Trust,
    pty: Pty,
    attach: Option<String>,
    keepalive: Keepalive,
    user: String,
    host: String,
    command: Vec<String>,
}

fn attach_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= ATTACH_NAME_MAX
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(format!(
            "--attach needs a name of 1 to {ATTACH_NAME_MAX} letters, digits, '_' or '-', not starting with '-'"
        ))
    }
}

fn seconds(args: &mut impl Iterator<Item = String>, option: &str) -> Result<Duration, String> {
    match value(args, option)?.parse::<u64>() {
        Ok(count) if count > 0 => Ok(Duration::from_secs(count)),
        _ => Err(format!("{option} needs a whole number of seconds above zero")),
    }
}

fn value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{option} needs a value"))
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut port = 22u16;
    let mut key = None;
    let mut agent = None;
    let mut agent_identity = None;
    let mut host_key = None;
    let mut known_hosts = None;
    let mut pty = Pty::Auto;
    let mut attach = None;
    let mut interval = None;
    let mut timeout = None;
    let mut target = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--" => {
                target = args.next();
                break;
            }
            "-t" => pty = Pty::Force,
            "-T" => pty = Pty::Never,
            "-p" => {
                port = value(&mut args, "-p")?
                    .parse()
                    .map_err(|_| "-p needs a port number".to_owned())?;
            }
            "--attach" => {
                let name = value(&mut args, "--attach")?;
                attach_name(&name)?;
                attach = Some(name);
            }
            "--keepalive-interval" => interval = Some(seconds(&mut args, "--keepalive-interval")?),
            "--keepalive-timeout" => timeout = Some(seconds(&mut args, "--keepalive-timeout")?),
            "-i" => key = Some(PathBuf::from(value(&mut args, "-i")?)),
            "--agent" => agent = Some(PathBuf::from(value(&mut args, "--agent")?)),
            "--agent-identity" => agent_identity = Some(value(&mut args, "--agent-identity")?),
            "--host-key" => host_key = Some(value(&mut args, "--host-key")?),
            "--known-hosts" => known_hosts = Some(PathBuf::from(value(&mut args, "--known-hosts")?)),
            "-h" | "--help" => return Err(String::new()),
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option {other}"));
            }
            _ => {
                target = Some(argument);
                break;
            }
        }
    }
    let target = target.ok_or_else(|| "missing user@host".to_owned())?;
    let (user, host) = match target.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() && !host.is_empty() => {
            (user.to_owned(), host.to_owned())
        }
        _ => return Err("the target must be user@host".to_owned()),
    };
    let credential = match (key, agent, agent_identity) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            return Err("-i and --agent are exclusive".to_owned());
        }
        (None, Some(socket), Some(identity)) => Credential::Agent { socket, identity },
        (None, Some(_), None) => return Err("--agent needs --agent-identity".to_owned()),
        (None, None, Some(_)) => return Err("--agent-identity needs --agent".to_owned()),
        (Some(key), None, None) => Credential::Key(key),
        (None, None, None) => {
            let home = std::env::var_os("HOME").ok_or_else(|| "no -i and HOME is unset".to_owned())?;
            Credential::Key(PathBuf::from(home).join(".ssh/id_ed25519"))
        }
    };
    let trust = match (host_key, known_hosts) {
        (Some(pin), None) => Trust::Pinned(pin),
        (None, Some(path)) => Trust::KnownHosts(path),
        (None, None) => return Err("one of --host-key and --known-hosts is required".to_owned()),
        (Some(_), Some(_)) => return Err("--host-key and --known-hosts are exclusive".to_owned()),
    };
    let command: Vec<String> = args.collect();
    if attach.is_some() {
        if !command.is_empty() {
            return Err("--attach and a command are exclusive".to_owned());
        }
        if pty == Pty::Never {
            return Err("--attach needs a terminal, so -T is not allowed".to_owned());
        }
    } else if interval.is_some() || timeout.is_some() {
        return Err("--keepalive-interval and --keepalive-timeout need --attach".to_owned());
    }
    let keepalive = Keepalive {
        interval: interval.unwrap_or(KEEPALIVE_INTERVAL),
        dead_after: timeout.unwrap_or(KEEPALIVE_TIMEOUT),
    };
    if keepalive.dead_after <= keepalive.interval {
        return Err("--keepalive-timeout must exceed --keepalive-interval".to_owned());
    }
    Ok(Options {
        port,
        credential,
        trust,
        pty,
        attach,
        keepalive,
        user,
        host,
        command,
    })
}

fn signal_number(name: &str) -> Option<u8> {
    Some(match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        _ => return None,
    })
}

fn exit_code(status: &ExecStatus) -> u8 {
    match status {
        ExecStatus::Exited(code) => (*code & 0xff) as u8,
        ExecStatus::Signaled(name) => signal_number(name.trim_start_matches("SIG"))
            .map_or(EXIT_FAILURE, |number| 128 + number),
        ExecStatus::Missing => EXIT_FAILURE,
    }
}

fn duplicate(fd: BorrowedFd<'_>) -> Result<File, String> {
    fd.try_clone_to_owned()
        .map(File::from)
        .map_err(|error| format!("cannot duplicate a standard descriptor: {error}"))
}

fn config(options: &Options, interrupt: Interrupt) -> Result<ClientConfig, Error> {
    let identity = match &options.credential {
        Credential::Key(path) => Identity::KeyFile(path.clone()),
        Credential::Agent { socket, identity } => Identity::Agent {
            socket: socket.clone(),
            fingerprint: Fingerprint::parse(identity)?,
        },
    };
    let trust = match &options.trust {
        Trust::Pinned(pin) => HostTrust::Pinned(Fingerprint::parse(pin)?),
        Trust::KnownHosts(path) => HostTrust::KnownHosts(KnownHosts::from_file(path)?),
    };
    let mut config = ClientConfig::new(
        options.host.clone(),
        options.port,
        options.user.clone(),
        identity,
        trust,
        CONNECT_TIMEOUT,
    );
    config.interrupt = Some(interrupt);
    Ok(config)
}

fn fail(message: impl std::fmt::Display) -> u8 {
    eprintln!("oxish: {message}");
    EXIT_FAILURE
}

struct Backoff {
    next: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self { next: BACKOFF_FIRST }
    }

    fn after(&mut self, lasted: Option<Duration>) -> Duration {
        if lasted.is_some_and(|lasted| lasted >= STABLE_AFTER) {
            self.next = BACKOFF_FIRST;
            return Duration::ZERO;
        }
        let delay = self.next;
        self.next = (self.next * 2).min(BACKOFF_MAX);
        delay
    }
}

fn is_transient(error: &Error) -> bool {
    matches!(
        error,
        Error::NotSubmitted { .. } | Error::Submitted { .. } | Error::Timeout { .. }
    )
}

fn termination_code(signal: i32, reconnecting: bool) -> u8 {
    if reconnecting && signal == libc::SIGINT {
        EXIT_FAILURE
    } else {
        128 + signal as u8
    }
}

struct Plan {
    options: Options,
    interactive: bool,
    attach: bool,
    command: Option<String>,
    interrupt: Interrupt,
    disconnect: Arc<AtomicBool>,
}

enum Attempt {
    Done(u8),
    Lost { lasted: Option<Duration> },
}

impl Plan {
    fn finish(&self, error: Error, reconnecting: bool) -> u8 {
        let signal = TERMINATED.load(Ordering::Relaxed);
        if matches!(error, Error::Cancelled { .. }) && signal != 0 {
            return termination_code(signal, reconnecting);
        }
        if self.disconnect.load(Ordering::Relaxed) {
            eprintln!("Connection to {} closed.", self.options.host);
            return EXIT_FAILURE;
        }
        fail(error)
    }

    fn stopping(&self) -> bool {
        TERMINATED.load(Ordering::Relaxed) != 0 || self.disconnect.load(Ordering::Relaxed)
    }

    fn lose_or_finish(
        &self,
        error: Error,
        started_at: Option<Instant>,
        reconnecting: bool,
    ) -> Attempt {
        if self.attach && (reconnecting || started_at.is_some()) && is_transient(&error) && !self.stopping() {
            return Attempt::Lost {
                lasted: started_at.map(|started| started.elapsed()),
            };
        }
        Attempt::Done(self.finish(error, reconnecting))
    }

    fn attempt(&self, reconnecting: bool) -> Attempt {
        let config = match config(&self.options, Arc::clone(&self.interrupt)) {
            Ok(config) => config,
            Err(error) => return Attempt::Done(self.finish(error, reconnecting)),
        };
        let mut connection = match Connection::connect(&config) {
            Ok(connection) => connection,
            Err(error) => return self.lose_or_finish(error, None, reconnecting),
        };
        if let Err(error) = connection.authenticate() {
            return self.lose_or_finish(error, None, reconnecting);
        }

        let setup = || -> Result<_, String> {
            let stdin = duplicate(std::io::stdin().as_fd())?;
            let stdout = duplicate(std::io::stdout().as_fd())?;
            let stderr = duplicate(std::io::stderr().as_fd())?;
            let tty = std::io::stdin()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|error| format!("cannot duplicate stdin: {error}"))?;
            Ok((stdin, FileSink::new(stdout), FileSink::new(stderr), tty))
        };
        let (stdin, mut stdout, mut stderr, tty) = match setup() {
            Ok(streams) => streams,
            Err(message) => return Attempt::Done(fail(message)),
        };
        let pty = if self.interactive {
            let term = std::env::var("TERM").unwrap_or_else(|_| "dumb".to_owned());
            match pty_request(&tty, &term) {
                Ok(request) => Some(request),
                Err(error) => return Attempt::Done(fail(format!("cannot read the terminal: {error}"))),
            }
        } else {
            None
        };
        let size = pty.as_ref().map_or_else(|| terminal_size(&tty), |request| request.size);
        let mut input: Box<dyn InputSource> = if self.interactive {
            Box::new(EscapeInput::new(stdin, Arc::clone(&self.disconnect)))
        } else {
            Box::new(stdin)
        };
        let request = SessionRequest {
            command: self.command.clone(),
            pty,
            env: Vec::new(),
            timeout: None,
            interrupt: Some(Arc::clone(&self.interrupt)),
            keepalive: self.attach.then_some(self.options.keepalive),
        };

        let (result, started_at) = {
            let mut terminal = match Terminal::new(tty, self.interactive, size, reconnecting) {
                Ok(terminal) => terminal,
                Err(error) => {
                    return Attempt::Done(fail(format!("cannot prepare the terminal: {error}")));
                }
            };
            let result = connection.session(
                &request,
                Some(&mut *input),
                &mut stdout,
                &mut stderr,
                Some(&mut terminal),
            );
            (result, terminal.started_at)
        };
        match result {
            Ok(result) if self.attach && matches!(result.status, ExecStatus::Missing) && !self.stopping() => {
                Attempt::Lost {
                    lasted: started_at.map(|started| started.elapsed()),
                }
            }
            Ok(result) => Attempt::Done(exit_code(&result.status)),
            Err(error) => self.lose_or_finish(error, started_at, reconnecting),
        }
    }

    fn supervise(&self, tty: &OwnedFd) -> u8 {
        let mut backoff = Backoff::new();
        let mut attempts = 0u32;
        let mut reconnecting = false;
        let mut delay = Duration::ZERO;
        let mut reset = false;
        loop {
            if reconnecting {
                attempts += 1;
                let mut screen = std::io::stderr().lock();
                if reset {
                    let _ = screen.write_all(TERMINAL_RESET.as_bytes());
                }
                let _ = writeln!(
                    screen,
                    "\roxish: connection lost; reconnecting to {} (attempt {attempts})\u{2026}",
                    self.options.host
                );
                let _ = screen.flush();
                drop(screen);
                if let Pause::Terminated = pause(tty, delay) {
                    return termination_code(TERMINATED.load(Ordering::Relaxed), true);
                }
            }
            match self.attempt(reconnecting) {
                Attempt::Done(code) => return code,
                Attempt::Lost { lasted } => {
                    reset = lasted.is_some();
                    if lasted.is_some_and(|lasted| lasted >= STABLE_AFTER) {
                        attempts = 0;
                    }
                    delay = backoff.after(lasted);
                    reconnecting = true;
                }
            }
        }
    }
}

enum Pause {
    Elapsed,
    Terminated,
}

fn pause(tty: &OwnedFd, delay: Duration) -> Pause {
    let end = Instant::now() + delay;
    loop {
        if TERMINATED.load(Ordering::Relaxed) != 0 {
            return Pause::Terminated;
        }
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Pause::Elapsed;
        }
        let tick = left.min(OUTAGE_POLL);
        let timespec = rustix::time::Timespec {
            tv_sec: tick.as_secs() as _,
            tv_nsec: tick.subsec_nanos() as _,
        };
        let mut ready = [PollFd::new(tty, PollFlags::IN)];
        match poll(&mut ready, Some(&timespec)) {
            Ok(0) => {}
            Ok(_) => {
                if discard_input(tty).is_err() {
                    std::thread::sleep(tick);
                }
            }
            Err(_) => {}
        }
    }
}

fn run() -> u8 {
    let options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("oxish: {message}");
            }
            eprintln!("{USAGE}");
            return EXIT_FAILURE;
        }
    };
    let stdin_is_terminal = isatty(std::io::stdin());
    let attach = options.attach.is_some();
    let interactive = if attach {
        if !stdin_is_terminal {
            return fail("--attach needs a terminal on stdin");
        }
        true
    } else {
        match options.pty {
            Pty::Never => false,
            Pty::Force if !stdin_is_terminal => {
                eprintln!("oxish: pseudo-terminal not allocated because stdin is not a terminal");
                false
            }
            Pty::Force => true,
            Pty::Auto => stdin_is_terminal && options.command.is_empty(),
        }
    };
    let command = match &options.attach {
        Some(name) => Some(format!("tmux new-session -A -s {name}")),
        None => (!options.command.is_empty()).then(|| options.command.join(" ")),
    };

    if let Err(error) = install_handlers() {
        return fail(format!("cannot install signal handlers: {error}"));
    }
    let disconnect = Arc::new(AtomicBool::new(false));
    let interrupt: Interrupt = {
        let disconnect = Arc::clone(&disconnect);
        Arc::new(move || TERMINATED.load(Ordering::Relaxed) != 0 || disconnect.load(Ordering::Relaxed))
    };
    let tty = match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(tty) => tty,
        Err(error) => return fail(format!("cannot duplicate stdin: {error}")),
    };
    let plan = Plan {
        options,
        interactive,
        attach,
        command,
        interrupt,
        disconnect,
    };
    plan.supervise(&tty)
}

fn main() -> ExitCode {
    ExitCode::from(run())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(text: &str) -> impl Iterator<Item = String> {
        text.split_whitespace().map(str::to_owned).collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn exit_codes_follow_the_remote_outcome() {
        assert_eq!(exit_code(&ExecStatus::Exited(7)), 7);
        assert_eq!(exit_code(&ExecStatus::Exited(256)), 0);
        assert_eq!(exit_code(&ExecStatus::Signaled("TERM".to_owned())), 143);
        assert_eq!(exit_code(&ExecStatus::Signaled("SIGKILL".to_owned())), 137);
        assert_eq!(exit_code(&ExecStatus::Signaled("WEIRD".to_owned())), 255);
        assert_eq!(exit_code(&ExecStatus::Missing), 255);
    }

    #[test]
    fn the_command_starts_after_the_target() {
        let options = parse(arguments(
            "-p 2222 -i key --host-key SHA256:x -T user@host ls -l --host-key",
        ))
        .expect("parses");
        assert_eq!(options.port, 2222);
        assert_eq!(options.user, "user");
        assert_eq!(options.host, "host");
        assert_eq!(options.command, ["ls", "-l", "--host-key"]);
        assert!(options.pty == Pty::Never);
    }

    #[test]
    fn host_trust_is_required_and_exclusive() {
        assert!(parse(arguments("-i key user@host")).is_err());
        assert!(parse(arguments("-i key --host-key SHA256:x --known-hosts f user@host")).is_err());
    }

    #[test]
    fn backoff_doubles_to_its_ceiling() {
        let mut backoff = Backoff::new();
        let delays: Vec<u64> = (0..9)
            .map(|_| backoff.after(None).as_secs())
            .collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30, 30]);
    }

    #[test]
    fn a_short_session_does_not_reset_the_backoff() {
        let mut backoff = Backoff::new();
        assert_eq!(backoff.after(None), Duration::from_secs(1));
        assert_eq!(backoff.after(Some(Duration::from_secs(3))), Duration::from_secs(2));
        assert_eq!(backoff.after(Some(STABLE_AFTER - Duration::from_millis(1))), Duration::from_secs(4));
    }

    #[test]
    fn a_stable_session_retries_at_once_and_restarts_the_backoff() {
        let mut backoff = Backoff::new();
        for _ in 0..4 {
            backoff.after(None);
        }
        assert_eq!(backoff.after(Some(STABLE_AFTER)), Duration::ZERO);
        assert_eq!(backoff.after(None), Duration::from_secs(1));
        assert_eq!(backoff.after(None), Duration::from_secs(2));
    }

    #[test]
    fn only_transport_failures_are_retried() {
        assert!(is_transient(&Error::NotSubmitted { detail: String::new() }));
        assert!(is_transient(&Error::Submitted { detail: String::new() }));
        assert!(is_transient(&Error::Timeout {
            certainty: oxish_client::Certainty::Submitted
        }));
        assert!(!is_transient(&Error::Cancelled {
            certainty: oxish_client::Certainty::Submitted
        }));
        assert!(!is_transient(&Error::HostKeyMismatch {
            expected: String::new(),
            actual: String::new()
        }));
        assert!(!is_transient(&Error::UnknownHostKey {
            host: String::new(),
            fingerprint: String::new()
        }));
        assert!(!is_transient(&Error::Authentication { detail: String::new() }));
        assert!(!is_transient(&Error::Rejected { request: "exec" }));
        assert!(!is_transient(&Error::Protocol { detail: String::new() }));
    }

    #[test]
    fn interrupting_a_reconnect_exits_255_and_other_signals_keep_their_status() {
        assert_eq!(termination_code(libc::SIGINT, true), 255);
        assert_eq!(termination_code(libc::SIGINT, false), 130);
        assert_eq!(termination_code(libc::SIGTERM, true), 143);
        assert_eq!(termination_code(libc::SIGHUP, false), 129);
    }

    #[test]
    fn attach_names_are_limited_to_tmux_safe_characters() {
        for name in ["work", "a", "Work_1-b", &"x".repeat(ATTACH_NAME_MAX)] {
            assert!(attach_name(name).is_ok(), "{name}");
        }
        let long = "x".repeat(ATTACH_NAME_MAX + 1);
        for name in ["", "-w", "a b", "a.b", "a:b", "a;b", "a$b", "a`b", "a'b", "a\"b", "a\nb", "a/b", "\u{e9}", &long] {
            assert!(attach_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn attach_runs_no_command_and_takes_keepalive_limits() {
        let options = parse(arguments(
            "-i key --host-key SHA256:x --attach work --keepalive-interval 2 --keepalive-timeout 7 user@host",
        ))
        .expect("parses");
        assert_eq!(options.attach.as_deref(), Some("work"));
        assert_eq!(options.keepalive.interval, Duration::from_secs(2));
        assert_eq!(options.keepalive.dead_after, Duration::from_secs(7));
        let options = parse(arguments("-i key --host-key SHA256:x --attach work user@host")).expect("parses");
        assert_eq!(options.keepalive.interval, KEEPALIVE_INTERVAL);
        assert_eq!(options.keepalive.dead_after, KEEPALIVE_TIMEOUT);
        assert!(parse(arguments("-i key --host-key SHA256:x --attach work user@host ls")).is_err());
        assert!(parse(arguments("-i key --host-key SHA256:x -T --attach work user@host")).is_err());
        assert!(parse(arguments("-i key --host-key SHA256:x --attach a;b user@host")).is_err());
        assert!(parse(arguments("-i key --host-key SHA256:x --keepalive-interval 5 user@host")).is_err());
        assert!(
            parse(arguments(
                "-i key --host-key SHA256:x --attach w --keepalive-interval 5 --keepalive-timeout 5 user@host"
            ))
            .is_err()
        );
        assert!(parse(arguments("-i key --host-key SHA256:x --attach w --keepalive-interval 0 user@host")).is_err());
    }

    #[test]
    fn the_agent_needs_its_identity() {
        assert!(parse(arguments("--agent sock --host-key SHA256:x user@host")).is_err());
        assert!(parse(arguments("--agent sock --agent-identity SHA256:y -i key --host-key SHA256:x user@host")).is_err());
        assert!(parse(arguments("--agent sock --agent-identity SHA256:y --host-key SHA256:x user@host")).is_ok());
    }
}
