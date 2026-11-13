use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use oxish_client::terminal::{EscapeInput, RawMode, pty_request, terminal_size};
use oxish_client::{
    ClientConfig, Connection, Error, ExecStatus, FileSink, Fingerprint, HostTrust, Identity,
    InputSource, Interrupt, KnownHosts, SessionEvents, SessionRequest, TerminalSize,
};
use rustix::termios::isatty;

const USAGE: &str = "usage: oxish [-p PORT] [-i KEY | --agent SOCKET --agent-identity SHA256:...]
             (--host-key SHA256:... | --known-hosts PATH) [-t | -T] user@host [command ...]";

const EXIT_FAILURE: u8 = 255;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

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
}

impl Terminal {
    fn new(tty: OwnedFd, interactive: bool) -> std::io::Result<Self> {
        let (reader, writer) = rustix::pipe::pipe()?;
        nonblocking(&reader)?;
        nonblocking(&writer)?;
        WAKE.store(writer.as_raw_fd(), Ordering::Relaxed);
        let size = terminal_size(&tty);
        Ok(Self {
            wake: File::from(reader),
            _wake_writer: writer,
            tty,
            interactive,
            size,
            raw: None,
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
        if self.interactive {
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
    user: String,
    host: String,
    command: Vec<String>,
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
    Ok(Options {
        port,
        credential,
        trust,
        pty,
        user,
        host,
        command: args.collect(),
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
    let interactive = match options.pty {
        Pty::Never => false,
        Pty::Force if !stdin_is_terminal => {
            eprintln!("oxish: pseudo-terminal not allocated because stdin is not a terminal");
            false
        }
        Pty::Force => true,
        Pty::Auto => stdin_is_terminal && options.command.is_empty(),
    };

    if let Err(error) = install_handlers() {
        return fail(format!("cannot install signal handlers: {error}"));
    }
    let disconnect = Arc::new(AtomicBool::new(false));
    let interrupt: Interrupt = {
        let disconnect = Arc::clone(&disconnect);
        Arc::new(move || TERMINATED.load(Ordering::Relaxed) != 0 || disconnect.load(Ordering::Relaxed))
    };
    let finish = |error: Error| -> u8 {
        let signal = TERMINATED.load(Ordering::Relaxed);
        if matches!(error, Error::Cancelled { .. }) && signal != 0 {
            return 128 + signal as u8;
        }
        if disconnect.load(Ordering::Relaxed) {
            eprintln!("Connection to {} closed.", options.host);
            return EXIT_FAILURE;
        }
        fail(error)
    };

    let config = match config(&options, Arc::clone(&interrupt)) {
        Ok(config) => config,
        Err(error) => return finish(error),
    };
    let mut connection = match Connection::connect(&config) {
        Ok(connection) => connection,
        Err(error) => return finish(error),
    };
    if let Err(error) = connection.authenticate() {
        return finish(error);
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
        Err(message) => return fail(message),
    };
    let pty = if interactive {
        let term = std::env::var("TERM").unwrap_or_else(|_| "dumb".to_owned());
        match pty_request(&tty, &term) {
            Ok(request) => Some(request),
            Err(error) => return fail(format!("cannot read the terminal: {error}")),
        }
    } else {
        None
    };
    let mut input: Box<dyn InputSource> = if interactive {
        Box::new(EscapeInput::new(stdin, Arc::clone(&disconnect)))
    } else {
        Box::new(stdin)
    };
    let request = SessionRequest {
        command: (!options.command.is_empty()).then(|| options.command.join(" ")),
        pty,
        env: Vec::new(),
        timeout: None,
        interrupt: Some(Arc::clone(&interrupt)),
    };

    let result = {
        let mut terminal = match Terminal::new(tty, interactive) {
            Ok(terminal) => terminal,
            Err(error) => return fail(format!("cannot prepare the terminal: {error}")),
        };
        connection.session(
            &request,
            Some(&mut *input),
            &mut stdout,
            &mut stderr,
            Some(&mut terminal),
        )
    };
    match result {
        Ok(result) => exit_code(&result.status),
        Err(error) => finish(error),
    }
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
    fn the_agent_needs_its_identity() {
        assert!(parse(arguments("--agent sock --host-key SHA256:x user@host")).is_err());
        assert!(parse(arguments("--agent sock --agent-identity SHA256:y -i key --host-key SHA256:x user@host")).is_err());
        assert!(parse(arguments("--agent sock --agent-identity SHA256:y --host-key SHA256:x user@host")).is_ok());
    }
}
