use std::os::fd::BorrowedFd;
use std::time::Duration;

use crate::wire::Interrupt;

/// A terminal's size in characters and pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    /// Columns.
    pub cols: u32,
    /// Rows.
    pub rows: u32,
    /// Width in pixels, or zero when unknown.
    pub width_px: u32,
    /// Height in pixels, or zero when unknown.
    pub height_px: u32,
}

/// A `pty-req` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyRequest {
    /// The `TERM` value.
    pub term: String,
    /// The initial terminal size.
    pub size: TerminalSize,
    /// The RFC 4254 section 8 encoded terminal modes, including the terminating opcode.
    pub modes: Vec<u8>,
}

/// Liveness probing for a session whose peer may vanish without closing the connection.
///
/// After `interval` without any bytes from the server the client sends a
/// `keepalive@openssh.com` global request, and repeats it every further `interval` of silence.
/// Any received byte restarts the count. The session fails with a timeout once the server has
/// been silent for `dead_after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keepalive {
    /// Silence that triggers a probe, and the spacing between probes.
    pub interval: Duration,
    /// Silence after which the peer is declared dead.
    pub dead_after: Duration,
}

/// One session channel: a shell or a command, with or without a pseudo-terminal.
#[derive(Clone, Default)]
pub struct SessionRequest {
    /// The command to run, or `None` for the account's shell.
    pub command: Option<String>,
    /// The pseudo-terminal to allocate before the shell or command starts.
    pub pty: Option<PtyRequest>,
    /// Variables to ask the server to set, by SSH `env` request.
    pub env: Vec<(String, String)>,
    /// The whole-session deadline; without one only the interrupt ends a silent session.
    pub timeout: Option<Duration>,
    /// Reports that the caller wants the session abandoned.
    pub interrupt: Option<Interrupt>,
    /// Probe a silent peer and fail the session when it stays silent too long.
    pub keepalive: Option<Keepalive>,
}

impl std::fmt::Debug for SessionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionRequest")
            .field("command", &self.command)
            .field("pty", &self.pty.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Caller-side events the session loop serves between packets.
pub trait SessionEvents {
    /// A descriptor that polls readable while [`Self::window_change`] has something to report.
    /// The loop calls `window_change` on every wakeup, so it must drain that descriptor.
    fn descriptor(&self) -> Option<BorrowedFd<'_>>;

    /// Called once the server accepted the shell or command and before any data moves.
    fn started(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// The new terminal size, if it changed since the last call.
    fn window_change(&mut self) -> Option<TerminalSize>;
}
