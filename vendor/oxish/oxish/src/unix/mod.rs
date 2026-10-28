use core::{cmp::Ordering, mem::MaybeUninit};
use std::{
    io::{self, IoSlice, IoSliceMut},
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream,
    },
    process::Stdio,
};

use proto::{
    Decoded, Encode, ReadState, ServerHostKey, SessionHostKey, WriteState,
    crypto::CryptoProvider, key_exchange::RekeyState,
};
use rustix::{
    io::FdFlags,
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags,
    },
};
use tokio::{
    net::TcpStream,
    process::{Child, Command},
};
use tracing::debug;
use zeroize::Zeroizing;

use crate::{
    Connection, Error, GitPolicy, SessionState,
    server::Server,
    session::Channels,
    session::Session,
};

mod exec;
pub(crate) use exec::{GitProcess, Output};

/// Spawn the session process for an authenticated connection
///
/// The session process runs as the server's user (the server refuses to run as root) with an
/// empty environment. It receives the connection and the negotiated state over a Unix socket
/// and the validated Git policy directories as arguments.
pub(crate) async fn spawn(
    state: SessionState<ServerHostKey<'_>>,
    stream: TcpStream,
    server: &Server,
) -> Result<Child, Error> {
    let tcp = stream.into_std()?;

    let (parent, child_sock) = UnixStream::pair()?;
    let mut command = Command::new(&server.session);
    command
        .arg(server.policy.repo_root())
        .arg(server.policy.git_dir())
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(child_sock)))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    #[cfg(coverage)]
    if let Some(file) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", file);
    }

    let child = command.spawn()?;

    // The `[u8]` encoding yields the `u32` length prefix followed by the state itself.
    let mut message = Zeroizing::new(vec![0; 4]);
    state.encode(&mut message);
    let payload_len = (message.len() - 4) as u32;
    message[..4].copy_from_slice(&payload_len.to_be_bytes());

    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = [tcp.as_fd()];
    control.push(SendAncillaryMessage::ScmRights(&fds));

    // The file descriptor rides along with the first message; if the socket buffer cannot
    // hold the full message, send the rest without ancillary data.
    let mut sent = rustix::net::sendmsg(
        &parent,
        &[IoSlice::new(&message)],
        &mut control,
        SendFlags::empty(),
    )
    .map_err(io::Error::from)?;

    while sent < message.len() {
        sent += rustix::net::send(&parent, &message[sent..], SendFlags::empty())
            .map_err(io::Error::from)?;
    }

    // Keep the connection's file descriptor open until the child acknowledges the
    // handoff; observed on macOS: closing the parent's copy while the descriptor is
    // still in flight tears down the connection.
    let mut ack = [0];
    let mut iov = [IoSliceMut::new(&mut ack)];
    let mut control = RecvAncillaryBuffer::default();
    let received = rustix::net::recvmsg(&parent, &mut iov, &mut control, RecvFlags::empty())
        .map_err(io::Error::from)?;
    match received.bytes {
        0 => Err(Error::InvalidState(
            "session process exited before acknowledging handoff",
        )),
        _ => Ok(child),
    }
}

/// Resume an SSH session from the session state received over the Unix socket `source`
pub fn resume(
    provider: &'static dyn CryptoProvider,
    policy: GitPolicy,
) -> Result<Session<TcpStream>, Error> {
    let source = rustix::stdio::stdin();
    let mut length = None;
    let mut received = Zeroizing::new(Vec::new());
    let mut tcp = None;
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut chunk = vec![0; 16_384];

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
