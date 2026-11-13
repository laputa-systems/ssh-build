use core::{cmp::Ordering, mem::MaybeUninit, time::Duration};
use std::{
    ffi::OsString,
    io::{self, IoSlice, IoSliceMut},
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::Path,
    process::Stdio,
};

use proto::{
    Decoded, Encode, ReadState, ServerHostKey, SessionHostKey, WriteState,
    crypto::CryptoProvider, key_exchange::RekeyState,
};
use rustix::{
    io::{Errno, FdFlags},
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags,
    },
};
use tokio::{
    io::Interest,
    net::TcpStream,
    process::{Child, Command},
    time::timeout,
};
use tracing::debug;
use zeroize::Zeroizing;

use crate::{
    Connection, Error, GitPolicy, LoginSession, SessionState,
    session::{Channels, Policy, Session},
};

mod exec;
pub(crate) use exec::{Output, Process, STOP_LIMIT};
mod privileges;
mod terminal;

/// Leave the listener's session and process group, and with them its controlling terminal
///
/// The session process of login mode does this before it becomes the account, so that no child
/// of the account inherits the listener's session or terminal. It fails if the process already
/// leads a process group (then it would keep the session it has).
pub fn detach_session() -> io::Result<()> {
    rustix::process::setsid().map(|_| ()).map_err(io::Error::from)
}

/// Become the account a login session serves, before anything else runs in the process
pub fn drop_privileges(login: &LoginSession) -> io::Result<()> {
    privileges::drop_to(login.user(), login.allow_root())
}

/// Replace this process with a shell on the terminal it was started on
///
/// The helper for terminal sessions: it takes the terminal on standard input as its controlling
/// terminal, then executes `program` with `argv0` and `args`, keeping the environment it was
/// given. It returns only when that fails.
pub fn launch(program: &OsString, argv0: &OsString, args: &[OsString]) -> io::Error {
    use std::os::unix::process::CommandExt as _;

    if let Err(error) = rustix::process::setsid() {
        return error.into();
    }
    if let Err(error) = rustix::process::ioctl_tiocsctty(rustix::stdio::stdin()) {
        return error.into();
    }
    std::process::Command::new(program).arg0(argv0).args(args).exec()
}

/// How long the session process has to acknowledge the handoff
///
/// In login mode the session process already runs as the account when it acknowledges, so the
/// account can stop or signal it; a listener must never wait on it without a bound.
pub(crate) const HANDOFF_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn the session process for an authenticated connection
///
/// The session process runs with an empty environment and receives the connection and the
/// negotiated state over a Unix socket. `args` select what it serves: the validated Git policy
/// directories, or a login account (the session process then drops to that account itself).
///
/// The handoff is asynchronous and bounded by `handoff_timeout`. A session process that has not
/// acknowledged by then (stopped, stuck or dead) is killed and reaped and the connection is
/// dropped; no thread of the listener ever blocks on it.
pub(crate) async fn spawn(
    state: SessionState<ServerHostKey<'_>>,
    stream: TcpStream,
    session: &Path,
    args: &[OsString],
    handoff_timeout: Duration,
) -> Result<Child, Error> {
    let tcp = stream.into_std()?;

    let (parent, child_sock) = UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    let parent = tokio::net::UnixStream::from_std(parent)?;
    let mut command = Command::new(session);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(child_sock)))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    #[cfg(coverage)]
    if let Some(file) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", file);
    }

    let mut child = command.spawn()?;
    drop(command);

    // The `[u8]` encoding yields the `u32` length prefix followed by the state itself.
    let mut message = Zeroizing::new(vec![0; 4]);
    state.encode(&mut message);
    let payload_len = (message.len() - 4) as u32;
    message[..4].copy_from_slice(&payload_len.to_be_bytes());

    let outcome = match timeout(handoff_timeout, handoff(&parent, &message, &tcp)).await {
        Ok(result) => result,
        Err(_) => Err(Error::InvalidState("session process did not acknowledge the handoff in time")),
    };
    match outcome {
        Ok(()) => Ok(child),
        Err(error) => {
            // SIGKILL ends a stopped process too; reaping it is prompt and does not block a thread.
            let _ = child.kill().await;
            Err(error)
        }
    }
}

/// Send the state and the connection to the session process and wait for its acknowledgement
async fn handoff(
    parent: &tokio::net::UnixStream,
    message: &[u8],
    tcp: &std::net::TcpStream,
) -> Result<(), Error> {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = [tcp.as_fd()];
    control.push(SendAncillaryMessage::ScmRights(&fds));

    // The file descriptor rides along with the first message; if the socket buffer cannot
    // hold the full message, send the rest without ancillary data.
    let mut sent = 0;
    while sent < message.len() {
        let from = sent;
        sent += parent
            .async_io(Interest::WRITABLE, || {
                match from {
                    0 => rustix::net::sendmsg(parent, &[IoSlice::new(message)], &mut control, SendFlags::empty()),
                    _ => rustix::net::send(parent, &message[from..], SendFlags::empty()),
                }
                .map_err(io::Error::from)
            })
            .await?;
    }

    // Keep the connection's file descriptor open until the child acknowledges the
    // handoff; observed on macOS: closing the parent's copy while the descriptor is
    // still in flight tears down the connection.
    let received = parent
        .async_io(Interest::READABLE, || {
            let mut ack = [0];
            let mut iov = [IoSliceMut::new(&mut ack)];
            let mut control = RecvAncillaryBuffer::default();
            rustix::net::recvmsg(parent, &mut iov, &mut control, RecvFlags::empty())
                .map(|received| received.bytes)
                .map_err(io::Error::from)
        })
        .await?;
    match received {
        0 => Err(Error::InvalidState("session process exited before acknowledging handoff")),
        _ => Ok(()),
    }
}

/// Resume an SSH session from the session state received over the Unix socket `source`
pub fn resume(
    provider: &'static dyn CryptoProvider,
    policy: GitPolicy,
) -> Result<Session<TcpStream>, Error> {
    resume_with(provider, Policy::Git(policy))
}

/// Resume an SSH session of login mode from the session state received over the Unix socket
pub fn resume_login(
    provider: &'static dyn CryptoProvider,
    login: LoginSession,
) -> Result<Session<TcpStream>, Error> {
    resume_with(provider, Policy::Login(login))
}

fn resume_with(
    provider: &'static dyn CryptoProvider,
    policy: Policy,
) -> Result<Session<TcpStream>, Error> {
    let source = rustix::stdio::stdin();
    let mut length = None;
    let mut received = Zeroizing::new(Vec::new());
    let mut tcp = None;
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    // Chunks of the handoff carry the host key: wipe the buffer when it goes out of scope.
    let mut chunk = Zeroizing::new(vec![0; 16_384]);

    loop {
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [IoSliceMut::new(&mut chunk)];
        let message = rustix::net::recvmsg(source, &mut iov, &mut control, RecvFlags::empty())
            .map_err(io::Error::from)?;

        let Some((buffered, _)) = chunk.split_at_checked(message.bytes) else {
            return Err(Error::InvalidState("invalid message length received"));
        };

        if buffered.is_empty() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF while receiving handoff message",
            )));
        }

        for ancillary in control.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = ancillary {
                if tcp.is_none() {
                    tcp = fds.into_iter().next();
                }
            }
        }

        match length {
            Some(len) => match (received.len() + buffered.len()).cmp(&len) {
                Ordering::Greater => {
                    return Err(Error::InvalidState("received more bytes than expected"));
                }
                Ordering::Equal => {
                    received.extend_from_slice(&chunk[..message.bytes]);
                    break;
                }
                Ordering::Less => received.extend_from_slice(&chunk[..message.bytes]),
            },
            None => match buffered.split_first_chunk::<4>() {
                Some((len, rest)) => {
                    let len = u32::from_be_bytes(*len) as usize;
                    length = Some(len);
                    received.extend_from_slice(rest);
                    match received.len().cmp(&len) {
                        Ordering::Greater => {
                            return Err(Error::InvalidState("received more bytes than expected"));
                        }
                        Ordering::Equal => break,
                        Ordering::Less => continue,
                    }
                }
                None => {
                    return Err(Error::InvalidState(
                        "received fewer than 4 bytes for length prefix",
                    ));
                }
            },
        }
    }

    let Some(fd) = tcp else {
        return Err(Error::InvalidState("no file descriptor received"));
    };

    // Mark the connection close-on-exec so the session does not inherit a copy of the socket.
    rustix::io::fcntl_setfd(&fd, FdFlags::CLOEXEC).map_err(io::Error::from)?;

    let Decoded { value: state, next } =
        SessionState::<SessionHostKey>::decode(&received, provider)?;
    if !next.is_empty() {
        return Err(Error::InvalidState("trailing bytes after message"));
    }

    // Acknowledge the handoff so the parent releases its copy of the descriptor
    rustix::net::send(source, &[1], SendFlags::empty()).map_err(io::Error::from)?;
    debug!(?state, "received session state, reconstructing connection");

    let SessionState {
        addr,
        host_key,
        identities,
        post_quantum_kx,
        strict_kx,
        session_id,
        read,
        write,
        read_buf,
        options,
    } = state;

    let opener = provider.opening_key(read.counter, &read.source)?;
    let sealer = provider.sealing_key(write.counter, &write.source)?;

    let mut write_state = WriteState::new(provider.secure_random());
    write_state.sequence_number = write.sequence_number;
    write_state.sealer = Some(sealer);

    let stream = std::net::TcpStream::from(fd);
    stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(stream)?;

    Ok(Session {
        provider,
        conn: Connection {
            stream,
            addr,
            read: ReadState {
                buf: read_buf,
                last_length: 0,
                sequence_number: read.sequence_number,
                opener: Some(opener),
            },
            write: write_state,
        },
        kx: RekeyState::new(session_id, strict_kx, identities, host_key),
        channels: Channels::default(),
        post_quantum_kx,
        options,
        policy,
    })
}

/// Whether an `accept()` error is caused by the process or system running out of resources
///
/// Unlike errors for an individual connection, these persist until resources are released.
pub(crate) fn is_resource_exhaustion(error: &io::Error) -> bool {
    // Match on the raw errno, as `io::ErrorKind` can't express most of these on stable: std maps
    // `EMFILE` and `ENFILE` to the unstable `TooManyOpenFiles`, and doesn't categorize `ENOBUFS`
    // or `ENOSR` at all
    match Errno::from_io_error(error) {
        // TODO: on Windows, `accept()` reports these as `WSAEMFILE` and `WSAENOBUFS`
        Some(Errno::MFILE | Errno::NFILE | Errno::NOBUFS | Errno::NOMEM) => true,
        // Out of STREAMS resources
        #[cfg(any(target_os = "illumos", target_os = "solaris"))]
        Some(Errno::NOSR) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_resource_exhaustion_is_backed_off_from() {
        for errno in [Errno::MFILE, Errno::NFILE, Errno::NOBUFS, Errno::NOMEM] {
            assert!(is_resource_exhaustion(&io::Error::from(errno)), "{errno}");
        }
        for errno in [Errno::CONNABORTED, Errno::INTR, Errno::PERM] {
            assert!(!is_resource_exhaustion(&io::Error::from(errno)), "{errno}");
        }
        assert!(!is_resource_exhaustion(&io::Error::other("not an OS error")));
    }
}
