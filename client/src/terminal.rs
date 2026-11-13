use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::termios::{
    ControlModes, InputModes, LocalModes, OptionalActions, OutputModes, SpecialCodeIndex, Termios,
    Winsize, tcgetattr, tcgetwinsize, tcsetattr,
};

use crate::session::{PtyRequest, TerminalSize};
use crate::stream::InputSource;

const TTY_OP_END: u8 = 0;
const TTY_OP_ISPEED: u8 = 128;
const TTY_OP_OSPEED: u8 = 129;
const DISABLED: u32 = 255;

#[cfg(target_os = "linux")]
const VDISABLE: u8 = 0;
#[cfg(not(target_os = "linux"))]
const VDISABLE: u8 = 0xff;

const FALLBACK_SIZE: TerminalSize = TerminalSize {
    cols: 80,
    rows: 24,
    width_px: 0,
    height_px: 0,
};

fn put(out: &mut Vec<u8>, opcode: u8, value: u32) {
    out.push(opcode);
    out.extend_from_slice(&value.to_be_bytes());
}

fn character(code: u8) -> u32 {
    if code == VDISABLE { DISABLED } else { u32::from(code) }
}

/// Encode the terminal modes of `termios` as the RFC 4254 section 8 string, with the characters
/// and flags that the local terminal and the remote operating system both define.
pub fn encode_modes(termios: &Termios) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 * 64 + 1);
    let codes = &termios.special_codes;
    put(&mut out, 1, character(codes[SpecialCodeIndex::VINTR]));
    put(&mut out, 2, character(codes[SpecialCodeIndex::VQUIT]));
    put(&mut out, 3, character(codes[SpecialCodeIndex::VERASE]));
    put(&mut out, 4, character(codes[SpecialCodeIndex::VKILL]));
    put(&mut out, 5, character(codes[SpecialCodeIndex::VEOF]));
    put(&mut out, 6, character(codes[SpecialCodeIndex::VEOL]));
    put(&mut out, 7, character(codes[SpecialCodeIndex::VEOL2]));
    put(&mut out, 8, character(codes[SpecialCodeIndex::VSTART]));
    put(&mut out, 9, character(codes[SpecialCodeIndex::VSTOP]));
    put(&mut out, 10, character(codes[SpecialCodeIndex::VSUSP]));
    #[cfg(target_vendor = "apple")]
    put(&mut out, 11, character(codes[SpecialCodeIndex::VDSUSP]));
    put(&mut out, 12, character(codes[SpecialCodeIndex::VREPRINT]));
    put(&mut out, 13, character(codes[SpecialCodeIndex::VWERASE]));
    put(&mut out, 14, character(codes[SpecialCodeIndex::VLNEXT]));
    #[cfg(target_vendor = "apple")]
    put(&mut out, 17, character(codes[SpecialCodeIndex::VSTATUS]));
    put(&mut out, 18, character(codes[SpecialCodeIndex::VDISCARD]));

    let input = termios.input_modes;
    let flag = |out: &mut Vec<u8>, opcode: u8, set: bool| put(out, opcode, u32::from(set));
    flag(&mut out, 30, input.contains(InputModes::IGNPAR));
    flag(&mut out, 31, input.contains(InputModes::PARMRK));
    flag(&mut out, 32, input.contains(InputModes::INPCK));
    flag(&mut out, 33, input.contains(InputModes::ISTRIP));
    flag(&mut out, 34, input.contains(InputModes::INLCR));
    flag(&mut out, 35, input.contains(InputModes::IGNCR));
    flag(&mut out, 36, input.contains(InputModes::ICRNL));
    #[cfg(target_os = "linux")]
    flag(&mut out, 37, input.contains(InputModes::IUCLC));
    flag(&mut out, 38, input.contains(InputModes::IXON));
    flag(&mut out, 39, input.contains(InputModes::IXANY));
    flag(&mut out, 40, input.contains(InputModes::IXOFF));
    flag(&mut out, 41, input.contains(InputModes::IMAXBEL));
    flag(&mut out, 42, input.contains(InputModes::IUTF8));

    let local = termios.local_modes;
    flag(&mut out, 50, local.contains(LocalModes::ISIG));
    flag(&mut out, 51, local.contains(LocalModes::ICANON));
    #[cfg(target_os = "linux")]
    flag(&mut out, 52, local.contains(LocalModes::XCASE));
    flag(&mut out, 53, local.contains(LocalModes::ECHO));
    flag(&mut out, 54, local.contains(LocalModes::ECHOE));
    flag(&mut out, 55, local.contains(LocalModes::ECHOK));
    flag(&mut out, 56, local.contains(LocalModes::ECHONL));
    flag(&mut out, 57, local.contains(LocalModes::NOFLSH));
    flag(&mut out, 58, local.contains(LocalModes::TOSTOP));
    flag(&mut out, 59, local.contains(LocalModes::IEXTEN));
    flag(&mut out, 60, local.contains(LocalModes::ECHOCTL));
    flag(&mut out, 61, local.contains(LocalModes::ECHOKE));
    flag(&mut out, 62, local.contains(LocalModes::PENDIN));

    let output = termios.output_modes;
    flag(&mut out, 70, output.contains(OutputModes::OPOST));
    #[cfg(target_os = "linux")]
    flag(&mut out, 71, output.contains(OutputModes::OLCUC));
    flag(&mut out, 72, output.contains(OutputModes::ONLCR));
    flag(&mut out, 73, output.contains(OutputModes::OCRNL));
    flag(&mut out, 74, output.contains(OutputModes::ONOCR));
    flag(&mut out, 75, output.contains(OutputModes::ONLRET));

    let control = termios.control_modes;
    let size = control & ControlModes::CSIZE;
    flag(&mut out, 90, size == ControlModes::CS7);
    flag(&mut out, 91, size == ControlModes::CS8);
    flag(&mut out, 92, control.contains(ControlModes::PARENB));
    flag(&mut out, 93, control.contains(ControlModes::PARODD));

    put(&mut out, TTY_OP_ISPEED, termios.input_speed());
    put(&mut out, TTY_OP_OSPEED, termios.output_speed());
    out.push(TTY_OP_END);
    out
}

/// The size of the terminal on `fd`, or 80 by 24 when it reports none.
pub fn terminal_size(fd: impl AsFd) -> TerminalSize {
    match tcgetwinsize(fd) {
        Ok(Winsize {
            ws_row,
            ws_col,
            ws_xpixel,
            ws_ypixel,
        }) if ws_row != 0 && ws_col != 0 => TerminalSize {
            cols: u32::from(ws_col),
            rows: u32::from(ws_row),
            width_px: u32::from(ws_xpixel),
            height_px: u32::from(ws_ypixel),
        },
        _ => FALLBACK_SIZE,
    }
}

/// The `pty-req` for the terminal on `fd`: its size and its present modes. Call it before
/// [`RawMode::enter`] so the remote terminal starts with the user's settings.
pub fn pty_request(fd: impl AsFd, term: &str) -> io::Result<PtyRequest> {
    let termios = tcgetattr(&fd)?;
    Ok(PtyRequest {
        term: term.to_owned(),
        size: terminal_size(&fd),
        modes: encode_modes(&termios),
    })
}

/// A terminal in raw mode. Dropping it restores the attributes the terminal had when it was
/// entered, including when a panic unwinds through it.
pub struct RawMode {
    fd: OwnedFd,
    original: Termios,
}

impl RawMode {
    /// Put the terminal on `fd` in raw mode once its output has drained.
    pub fn enter(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let fd = fd.try_clone_to_owned()?;
        let original = tcgetattr(&fd)?;
        let mut raw = original.clone();
        raw.make_raw();
        tcsetattr(&fd, OptionalActions::Drain, &raw)?;
        Ok(Self { fd, original })
    }

    /// The attributes the terminal had before raw mode.
    pub fn original(&self) -> &Termios {
        &self.original
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = tcsetattr(&self.fd, OptionalActions::Drain, &self.original);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineState {
    Start,
    Tilde,
    Middle,
}

/// Finds the `~.` disconnect escape at the start of a line, and unescapes `~~`. Any other
/// `~` pair passes through unchanged, and a `~` at the start of a line waits for the next
/// byte before it is sent.
#[derive(Debug, Clone)]
pub struct EscapeDetector {
    state: LineState,
}

impl Default for EscapeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EscapeDetector {
    /// A detector at the start of a line, as at the start of a session.
    pub fn new() -> Self {
        Self {
            state: LineState::Start,
        }
    }

    /// Append the bytes to forward to `out` and return whether the disconnect escape was
    /// typed. Bytes after the escape are dropped.
    pub fn filter(&mut self, input: &[u8], out: &mut Vec<u8>) -> bool {
        for &byte in input {
            let newline = byte == b'\r' || byte == b'\n';
            match self.state {
                LineState::Start | LineState::Middle => {
                    if self.state == LineState::Start && byte == b'~' {
                        self.state = LineState::Tilde;
                        continue;
                    }
                    out.push(byte);
                    self.state = if newline {
                        LineState::Start
                    } else {
                        LineState::Middle
                    };
                }
                LineState::Tilde => match byte {
                    b'.' => return true,
                    b'~' => {
                        out.push(b'~');
                        self.state = LineState::Middle;
                    }
                    _ => {
                        out.extend_from_slice(&[b'~', byte]);
                        self.state = if newline {
                            LineState::Start
                        } else {
                            LineState::Middle
                        };
                    }
                },
            }
        }
        false
    }
}

const ESCAPE_READ: usize = 4096;

/// An input source that applies [`EscapeDetector`] to what it reads. When the disconnect
/// escape arrives it sets `disconnect` and forwards nothing more.
pub struct EscapeInput<S> {
    inner: S,
    detector: EscapeDetector,
    disconnect: Arc<AtomicBool>,
    raw: Vec<u8>,
    ready: Vec<u8>,
    taken: usize,
}

impl<S> EscapeInput<S> {
    /// Filter `inner`, reporting the disconnect escape through `disconnect`.
    pub fn new(inner: S, disconnect: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            detector: EscapeDetector::new(),
            disconnect,
            raw: vec![0; ESCAPE_READ],
            ready: Vec::new(),
            taken: 0,
        }
    }
}

impl<S: Read> Read for EscapeInput<S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.taken == self.ready.len() {
            self.ready.clear();
            self.taken = 0;
            let read = self.inner.read(&mut self.raw)?;
            if read == 0 {
                return Ok(0);
            }
            if self.disconnect.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if self.detector.filter(&self.raw[..read], &mut self.ready) {
                self.disconnect.store(true, Ordering::Relaxed);
            }
            if self.ready.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let count = buffer.len().min(self.ready.len() - self.taken);
        buffer[..count].copy_from_slice(&self.ready[self.taken..self.taken + count]);
        self.taken += count;
        Ok(count)
    }
}

impl<S: InputSource> InputSource for EscapeInput<S> {
    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        self.inner.descriptor()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::OwnedFd;

    use rustix::fs::{Mode, OFlags, open};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    use super::*;

    fn pty() -> (OwnedFd, OwnedFd) {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("open a pty master");
        grantpt(&master).expect("grant the slave");
        unlockpt(&master).expect("unlock the slave");
        let name = ptsname(&master, Vec::new()).expect("slave name");
        let slave = open(name.as_c_str(), OFlags::RDWR | OFlags::NOCTTY, Mode::empty())
            .expect("open the slave");
        (master, slave)
    }

    fn decode(modes: &[u8]) -> Vec<(u8, u32)> {
        let mut pairs = Vec::new();
        let mut rest = modes;
        loop {
            let (&opcode, tail) = rest.split_first().expect("opcode");
            if opcode == TTY_OP_END {
                assert!(tail.is_empty(), "bytes after the terminator");
                return pairs;
            }
            let value = u32::from_be_bytes(tail[..4].try_into().expect("four value bytes"));
            pairs.push((opcode, value));
            rest = &tail[4..];
        }
    }

    fn value(pairs: &[(u8, u32)], opcode: u8) -> u32 {
        pairs
            .iter()
            .find(|(candidate, _)| *candidate == opcode)
            .unwrap_or_else(|| panic!("opcode {opcode} is absent"))
            .1
    }

    #[test]
    fn modes_follow_the_termios_flags_and_characters() {
        let (_master, slave) = pty();
        let mut termios = tcgetattr(&slave).expect("termios");
        termios.local_modes |= LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG;
        termios.local_modes -= LocalModes::ECHOK;
        termios.input_modes |= InputModes::ICRNL;
        termios.input_modes -= InputModes::ISTRIP;
        termios.output_modes |= OutputModes::OPOST | OutputModes::ONLCR;
        termios.control_modes -= ControlModes::CSIZE;
        termios.control_modes |= ControlModes::CS8;
        termios.special_codes[SpecialCodeIndex::VINTR] = 0x03;
        termios.special_codes[SpecialCodeIndex::VERASE] = 0x7f;
        termios.special_codes[SpecialCodeIndex::VEOF] = 0x04;
        termios.special_codes[SpecialCodeIndex::VEOL] = VDISABLE;
        termios.set_input_speed(9600).expect("input speed");
        termios.set_output_speed(9600).expect("output speed");

        let pairs = decode(&encode_modes(&termios));
        assert_eq!(value(&pairs, 1), 3);
        assert_eq!(value(&pairs, 3), 0x7f);
        assert_eq!(value(&pairs, 5), 4);
        assert_eq!(value(&pairs, 6), 255);
        assert_eq!(value(&pairs, 53), 1);
        assert_eq!(value(&pairs, 51), 1);
        assert_eq!(value(&pairs, 50), 1);
        assert_eq!(value(&pairs, 55), 0);
        assert_eq!(value(&pairs, 36), 1);
        assert_eq!(value(&pairs, 33), 0);
        assert_eq!(value(&pairs, 70), 1);
        assert_eq!(value(&pairs, 72), 1);
        assert_eq!(value(&pairs, 91), 1);
        assert_eq!(value(&pairs, 90), 0);
        assert_eq!(value(&pairs, TTY_OP_ISPEED), 9600);
        assert_eq!(value(&pairs, TTY_OP_OSPEED), 9600);
        let mut opcodes: Vec<u8> = pairs.iter().map(|pair| pair.0).collect();
        opcodes.sort_unstable();
        opcodes.dedup();
        assert_eq!(opcodes.len(), pairs.len(), "each opcode appears once");
    }

    #[test]
    fn pty_request_carries_size_and_modes() {
        let (_master, slave) = pty();
        rustix::termios::tcsetwinsize(
            &slave,
            Winsize {
                ws_row: 31,
                ws_col: 97,
                ws_xpixel: 970,
                ws_ypixel: 620,
            },
        )
        .expect("set the size");
        let request = pty_request(&slave, "xterm-256color").expect("request");
        assert_eq!(request.term, "xterm-256color");
        assert_eq!(
            request.size,
            TerminalSize {
                cols: 97,
                rows: 31,
                width_px: 970,
                height_px: 620
            }
        );
        assert_eq!(request.modes.last(), Some(&0));
        assert_eq!((request.modes.len() - 1) % 5, 0);
    }

    #[test]
    fn a_terminal_without_a_size_reports_the_fallback() {
        let (_master, slave) = pty();
        assert_eq!(terminal_size(&slave), FALLBACK_SIZE);
    }

    fn escape(chunks: &[&[u8]]) -> (Vec<u8>, bool) {
        let mut detector = EscapeDetector::new();
        let mut out = Vec::new();
        for chunk in chunks {
            if detector.filter(chunk, &mut out) {
                return (out, true);
            }
        }
        (out, false)
    }

    #[test]
    fn tilde_dot_at_the_start_of_the_session_disconnects() {
        assert_eq!(escape(&[b"~."]), (Vec::new(), true));
    }

    #[test]
    fn tilde_dot_after_a_newline_disconnects() {
        assert_eq!(escape(&[b"ls\r~."]), (b"ls\r".to_vec(), true));
        assert_eq!(escape(&[b"ls\n~."]), (b"ls\n".to_vec(), true));
    }

    #[test]
    fn tilde_dot_in_the_middle_of_a_line_is_data() {
        assert_eq!(escape(&[b"echo ~."]), (b"echo ~.".to_vec(), false));
    }

    #[test]
    fn the_escape_works_across_reads() {
        assert_eq!(escape(&[b"x\r", b"~", b"."]), (b"x\r".to_vec(), true));
    }

    #[test]
    fn a_lone_tilde_is_held_until_the_next_byte() {
        let mut detector = EscapeDetector::new();
        let mut out = Vec::new();
        assert!(!detector.filter(b"~", &mut out));
        assert!(out.is_empty());
        assert!(!detector.filter(b"x", &mut out));
        assert_eq!(out, b"~x");
    }

    #[test]
    fn double_tilde_sends_one_tilde() {
        assert_eq!(escape(&[b"~~."]), (b"~.".to_vec(), false));
    }

    #[test]
    fn other_escapes_pass_through_and_a_newline_restarts_the_line() {
        assert_eq!(escape(&[b"~?\r~."]), (b"~?\r".to_vec(), true));
        assert_eq!(escape(&[b"~\r~."]), (b"~\r".to_vec(), true));
    }

    #[test]
    fn bytes_after_the_escape_are_dropped() {
        assert_eq!(escape(&[b"~.rm -rf /\r"]), (Vec::new(), true));
    }

    #[test]
    fn escape_input_forwards_filtered_bytes_and_flags_the_disconnect() {
        let flag = Arc::new(AtomicBool::new(false));
        let mut input = EscapeInput::new(&b"ab\r~.cd"[..], Arc::clone(&flag));
        let mut buffer = [0u8; 16];
        let count = input.read(&mut buffer).expect("read");
        assert_eq!(&buffer[..count], b"ab\r");
        assert!(flag.load(Ordering::Relaxed));
    }

    #[test]
    fn escape_input_reports_would_block_while_it_holds_a_tilde() {
        let flag = Arc::new(AtomicBool::new(false));
        let mut input = EscapeInput::new(&b"~"[..], Arc::clone(&flag));
        let mut buffer = [0u8; 16];
        let error = input.read(&mut buffer).expect_err("nothing to forward");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(!flag.load(Ordering::Relaxed));
    }

    #[test]
    fn raw_mode_restores_the_original_attributes_on_drop_and_on_panic() {
        let (_master, slave) = pty();
        let before = format!("{:?}", tcgetattr(&slave).expect("termios"));
        {
            let raw = RawMode::enter(slave.as_fd()).expect("enter");
            let during = tcgetattr(&slave).expect("termios");
            assert!(!during.local_modes.contains(LocalModes::ICANON));
            assert!(!during.local_modes.contains(LocalModes::ECHO));
            assert_eq!(format!("{:?}", raw.original()), before);
        }
        assert_eq!(format!("{:?}", tcgetattr(&slave).expect("termios")), before);

        let fd = slave.as_fd();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _raw = RawMode::enter(fd).expect("enter");
            panic!("session failed");
        }));
        assert!(unwound.is_err());
        assert_eq!(format!("{:?}", tcgetattr(&slave).expect("termios")), before);
        drop(File::from(slave));
    }
}
