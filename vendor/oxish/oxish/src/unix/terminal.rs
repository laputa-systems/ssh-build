use core::task::{Context, Poll, ready};
use std::{
    collections::BTreeMap,
    io,
    os::fd::{AsFd, OwnedFd},
    sync::Arc,
};

use bitflags::Flags;
use proto::channels::{Mode, PtyReq, WindowChange};
use rustix::{
    fs::OFlags,
    io::{Errno, read, write},
    pty::{self, OpenptFlags},
    termios::{
        self, ControlModes, InputModes, LocalModes, OptionalActions, OutputModes, SpecialCodeIndex,
        Winsize,
    },
};
use tokio::io::{ReadBuf, unix::AsyncFd};
use tracing::debug;

/// The controlling side of a pseudo-terminal
///
/// Clones share one descriptor: the reader and the writer of a command, and the handle that
/// resizes the window. The terminal hangs up on the command once the last clone is dropped.
#[derive(Clone)]
pub(crate) struct PtyMaster(Arc<AsyncFd<OwnedFd>>);

impl PtyMaster {
    /// Allocate a terminal sized and configured as the client requested; returns the slave side
    pub(crate) fn open(req: &PtyReq<'_>) -> io::Result<(Self, OwnedFd)> {
        debug!(?req, "allocating a terminal");
        let controller = open_controller()?;
        pty::grantpt(&controller)?;
        pty::unlockpt(&controller)?;

        let user_path = pty::ptsname(&controller, Vec::new())?;
        let user_fd = rustix::fs::open(
            &user_path,
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;

        // The slave belongs to the account that opened it (this process, after the privilege drop);
        // `grantpt` and devpts may give it group `tty` or other write access, so close that.
        rustix::fs::fchmod(&user_fd, rustix::fs::Mode::from_raw_mode(0o600))?;
        termios::tcsetwinsize(&user_fd, winsize(req.cols, req.rows, req.width_px, req.height_px))?;
        apply_terminal_modes(&user_fd, &req.terminal_modes)?;

        let flags = rustix::fs::fcntl_getfl(&controller)?;
        rustix::fs::fcntl_setfl(&controller, flags | OFlags::NONBLOCK)?;
        Ok((Self(Arc::new(register(controller)?)), user_fd))
    }

    /// Resize the window (in response to a window-change request)
    pub(crate) fn resize(&self, size: &WindowChange) -> io::Result<()> {
        debug!(?size, "resizing the terminal window");
        termios::tcsetwinsize(self.0.get_ref(), winsize(size.cols, size.rows, size.width_px, size.height_px))?;
        Ok(())
    }

    /// Read output; the terminal reports `EIO` once every process on it has gone, which is end of file
    pub(crate) fn poll_read(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let result = guard.try_io(|inner| {
                read(inner.get_ref(), buf.initialize_unfilled()).map_err(io::Error::from)
            });
            match result {
                Ok(Ok(read)) => {
                    buf.advance(read);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.raw_os_error() == Some(Errno::IO.raw_os_error()) => {
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write input to the command
    pub(crate) fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            match guard.try_io(|inner| write(inner.get_ref(), buf).map_err(io::Error::from)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Tokio deprecates the safe constructor because a generic `AsRawFd` could lie; an `OwnedFd` cannot
#[allow(deprecated)]
fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    AsyncFd::new(fd)
}

fn winsize(cols: u32, rows: u32, width_px: u32, height_px: u32) -> Winsize {
    let clamp = |value: u32| u16::try_from(value).unwrap_or(u16::MAX);
    Winsize {
        ws_col: clamp(cols),
        ws_row: clamp(rows),
        ws_xpixel: clamp(width_px),
        ws_ypixel: clamp(height_px),
    }
}

/// Apply SSH terminal modes to a PTY.
///
/// Maps SSH terminal mode opcodes (RFC 4254) to POSIX termios settings.
fn apply_terminal_modes(fd: impl AsFd, modes: &BTreeMap<Mode, u32>) -> io::Result<()> {
    if modes.is_empty() {
        return Ok(());
    }

    let mut tio = termios::tcgetattr(&fd)?;
    for (&mode, &value) in modes {
        match mode {
            // Special characters (control characters)
            Mode::VIntr => tio.special_codes[SpecialCodeIndex::VINTR] = value as u8,
            Mode::VQuit => tio.special_codes[SpecialCodeIndex::VQUIT] = value as u8,
            Mode::VErase => tio.special_codes[SpecialCodeIndex::VERASE] = value as u8,
            Mode::VKill => tio.special_codes[SpecialCodeIndex::VKILL] = value as u8,
            Mode::VEof => tio.special_codes[SpecialCodeIndex::VEOF] = value as u8,
            Mode::VEol => tio.special_codes[SpecialCodeIndex::VEOL] = value as u8,
            Mode::VEol2 => tio.special_codes[SpecialCodeIndex::VEOL2] = value as u8,
            Mode::VStart => tio.special_codes[SpecialCodeIndex::VSTART] = value as u8,
            Mode::VStop => tio.special_codes[SpecialCodeIndex::VSTOP] = value as u8,
            Mode::VSusp => tio.special_codes[SpecialCodeIndex::VSUSP] = value as u8,
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            Mode::VDSusp => tio.special_codes[SpecialCodeIndex::VDSUSP] = value as u8,
            #[cfg(not(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            Mode::VDSusp => {} // Not available on Linux
            Mode::VReprint => tio.special_codes[SpecialCodeIndex::VREPRINT] = value as u8,
            Mode::VWErase => tio.special_codes[SpecialCodeIndex::VWERASE] = value as u8,
            Mode::VLNext => tio.special_codes[SpecialCodeIndex::VLNEXT] = value as u8,
            Mode::VFlush | Mode::VDiscard => {
                tio.special_codes[SpecialCodeIndex::VDISCARD] = value as u8
            }
            #[cfg(target_os = "linux")]
            Mode::VSwtch => tio.special_codes[SpecialCodeIndex::VSWTC] = value as u8,
            #[cfg(not(target_os = "linux"))]
            Mode::VSwtch => {} // VSWTC not available on macOS/BSDs
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            Mode::VStatus => tio.special_codes[SpecialCodeIndex::VSTATUS] = value as u8,
            #[cfg(not(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            Mode::VStatus => {} // Not available on Linux

            // Input modes
            Mode::IgnPar => set_flag(&mut tio.input_modes, InputModes::IGNPAR, value),
            Mode::ParMrk => set_flag(&mut tio.input_modes, InputModes::PARMRK, value),
            Mode::INPck => set_flag(&mut tio.input_modes, InputModes::INPCK, value),
            Mode::IStrip => set_flag(&mut tio.input_modes, InputModes::ISTRIP, value),
            Mode::INlCr => set_flag(&mut tio.input_modes, InputModes::INLCR, value),
            Mode::IgnCr => set_flag(&mut tio.input_modes, InputModes::IGNCR, value),
            Mode::ICrNl => set_flag(&mut tio.input_modes, InputModes::ICRNL, value),
            #[cfg(target_os = "linux")]
            Mode::IUcLc => set_flag(&mut tio.input_modes, InputModes::IUCLC, value),
            #[cfg(not(target_os = "linux"))]
            Mode::IUcLc => {} // Not available on macOS/BSDs
            Mode::IxOn => set_flag(&mut tio.input_modes, InputModes::IXON, value),
            Mode::IxAny => set_flag(&mut tio.input_modes, InputModes::IXANY, value),
            Mode::IxOff => set_flag(&mut tio.input_modes, InputModes::IXOFF, value),
            Mode::IMaxBel => set_flag(&mut tio.input_modes, InputModes::IMAXBEL, value),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
            Mode::IUtf8 => set_flag(&mut tio.input_modes, InputModes::IUTF8, value),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
            Mode::IUtf8 => {} // Not available on some platforms

            // Local modes
            Mode::ISig => set_flag(&mut tio.local_modes, LocalModes::ISIG, value),
            Mode::ICanon => set_flag(&mut tio.local_modes, LocalModes::ICANON, value),
            #[cfg(target_os = "linux")]
            Mode::XCase => set_flag(&mut tio.local_modes, LocalModes::XCASE, value),
            #[cfg(not(target_os = "linux"))]
            Mode::XCase => {} // Not available on macOS/BSDs
            Mode::Echo => set_flag(&mut tio.local_modes, LocalModes::ECHO, value),
            Mode::EchoE => set_flag(&mut tio.local_modes, LocalModes::ECHOE, value),
            Mode::EchoK => set_flag(&mut tio.local_modes, LocalModes::ECHOK, value),
            Mode::EchoNl => set_flag(&mut tio.local_modes, LocalModes::ECHONL, value),
            Mode::NoFlsh => set_flag(&mut tio.local_modes, LocalModes::NOFLSH, value),
            Mode::TOStop => set_flag(&mut tio.local_modes, LocalModes::TOSTOP, value),
            Mode::IExten => set_flag(&mut tio.local_modes, LocalModes::IEXTEN, value),
            Mode::EchoCtl => set_flag(&mut tio.local_modes, LocalModes::ECHOCTL, value),
            Mode::EchoKe => set_flag(&mut tio.local_modes, LocalModes::ECHOKE, value),
            Mode::Pendin => set_flag(&mut tio.local_modes, LocalModes::PENDIN, value),

            // Output modes
            Mode::OPost => set_flag(&mut tio.output_modes, OutputModes::OPOST, value),
            #[cfg(target_os = "linux")]
            Mode::OLcUc => set_flag(&mut tio.output_modes, OutputModes::OLCUC, value),
            #[cfg(not(target_os = "linux"))]
            Mode::OLcUc => {} // Not available on macOS/BSDs
            Mode::ONlCr => set_flag(&mut tio.output_modes, OutputModes::ONLCR, value),
            Mode::OCrNl => set_flag(&mut tio.output_modes, OutputModes::OCRNL, value),
            Mode::ONoCr => set_flag(&mut tio.output_modes, OutputModes::ONOCR, value),
            Mode::ONlRet => set_flag(&mut tio.output_modes, OutputModes::ONLRET, value),

            // Control modes
            Mode::Cs7 => {
                tio.control_modes.remove(ControlModes::CSIZE);
                tio.control_modes.insert(ControlModes::CS7);
            }
            Mode::Cs8 => {
                tio.control_modes.remove(ControlModes::CSIZE);
                tio.control_modes.insert(ControlModes::CS8);
            }
            Mode::ParenB => set_flag(&mut tio.control_modes, ControlModes::PARENB, value),
            Mode::ParOdd => set_flag(&mut tio.control_modes, ControlModes::PARODD, value),

            // Baud rates
            Mode::TtyOpISpeed => {
                let _ = tio.set_input_speed(value);
            }
            Mode::TtyOpOSpeed => {
                let _ = tio.set_output_speed(value);
            }
        }
    }

    termios::tcsetattr(&fd, OptionalActions::Now, &tio)?;
    Ok(())
}

fn set_flag<T: Flags>(flags: &mut T, flag: T, value: u32) {
    match value {
        0 => flags.remove(flag),
        _ => flags.insert(flag),
    }
}

/// Open a pseudoterminal controller that is not inherited across exec
pub(crate) fn open_controller() -> io::Result<OwnedFd> {
    // posix_openpt has no O_CLOEXEC on macOS and the BSDs, so the flag is set right after there.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let controller = pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let controller = {
        let controller = pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        rustix::io::fcntl_setfd(&controller, rustix::io::FdFlags::CLOEXEC)?;
        controller
    };
    Ok(controller)
}
