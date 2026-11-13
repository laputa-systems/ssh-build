use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::time::Timespec;

use crate::error::{Certainty, Error};
use crate::wire::{Interrupt, SshReader, put_string};

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const MAX_MESSAGE: usize = 256 * 1024;
const MAX_IDENTITIES: u32 = 1024;
const ED25519_SIGNATURE: usize = 64;
const INTERRUPT_POLL: Duration = Duration::from_millis(50);

fn agent_error(detail: impl Into<String>) -> Error {
    Error::Agent {
        detail: detail.into(),
    }
}

/// A connection to a local `ssh-agent` that signs on the client's behalf.
///
/// The agent keeps private keys, including encrypted ones, out of this process.
/// The client only asks it to sign the authentication request for one identity
/// chosen by fingerprint, and never forwards the agent to the server.
pub struct Agent {
    stream: UnixStream,
    idle: Duration,
    deadline: Option<Instant>,
    interrupt: Option<Interrupt>,
}

impl Agent {
    /// Establish the agent connection within `timeout`; subsequent I/O may stay
    /// silent for at most `timeout` at a time.
    pub fn connect(socket: &Path, timeout: Duration) -> Result<Self, Error> {
        Self::connect_bounded(socket, timeout, None, None)
    }

    pub(crate) fn connect_bounded(
        socket: &Path,
        timeout: Duration,
        deadline: Option<Instant>,
        interrupt: Option<Interrupt>,
    ) -> Result<Self, Error> {
        use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

        let failed = |error| agent_error(format!("cannot connect to {}: {error}", socket.display()));
        let address = SocketAddrUnix::new(socket).map_err(failed)?;
        let started = Instant::now();
        loop {
            let stream = socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
                None,
            ).map_err(failed)?;
            let agent = Self { stream: UnixStream::from(stream), idle: timeout, deadline, interrupt: interrupt.clone() };
            agent.wait_slice(started)?;
            match connect(&agent.stream, &address) {
                Ok(()) => return Ok(agent),
                Err(error) if error == rustix::io::Errno::AGAIN => {
                    // Linux AF_UNIX EAGAIN means the listen queue is full, not a pending connect.
                    let slice = agent.wait_slice(started)?;
                    let timespec = Timespec::try_from(slice).map_err(|error| agent_error(format!("agent wait failed: {error}")))?;
                    match poll(&mut [], Some(&timespec)) {
                        Ok(_) | Err(rustix::io::Errno::INTR) => {}
                        Err(error) => return Err(agent_error(format!("agent wait failed: {error}"))),
                    }
                }
                Err(error) if error == rustix::io::Errno::INPROGRESS || error == rustix::io::Errno::INTR => {
                    agent.wait(PollFlags::OUT, started)?;
                    if let Some(error) = agent.stream.take_error().map_err(|error| agent_error(format!("agent connect failed: {error}")))? {
                        return Err(agent_error(format!("cannot connect to {}: {error}", socket.display())));
                    }
                    agent.stream.peer_addr().map_err(|error| agent_error(format!("agent connect failed: {error}")))?;
                    return Ok(agent);
                }
                Err(error) => return Err(failed(error)),
            }
        }
    }

    /// End every exchange at `deadline` however steadily the agent answers, and as soon as
    /// `interrupt` reports that the caller wants the operation abandoned.
    pub fn bounded(mut self, deadline: Option<Instant>, interrupt: Option<Interrupt>) -> Self {
        self.deadline = deadline;
        self.interrupt = interrupt;
        self
    }

    fn wait_slice(&self, last_progress: Instant) -> Result<Duration, Error> {
        if self.interrupt.as_ref().is_some_and(|interrupt| interrupt()) {
            return Err(Error::Cancelled {
                certainty: Certainty::NotSubmitted,
            });
        }
        let now = Instant::now();
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(Error::Timeout {
                certainty: Certainty::NotSubmitted,
            });
        }
        let silent = now.duration_since(last_progress);
        if silent >= self.idle {
            return Err(agent_error(format!("agent did not answer within {:?}", self.idle)));
        }
        let mut slice = INTERRUPT_POLL.min(self.idle - silent);
        if let Some(deadline) = self.deadline {
            slice = slice.min(deadline.saturating_duration_since(now));
        }
        Ok(slice)
    }

    fn wait(&self, events: PollFlags, last_progress: Instant) -> Result<(), Error> {
        loop {
            let slice = self.wait_slice(last_progress)?;
            let mut descriptors = [PollFd::new(&self.stream, events)];
            let timespec = Timespec {
                tv_sec: slice.as_secs() as _,
                tv_nsec: slice.subsec_nanos() as _,
            };
            match poll(&mut descriptors, Some(&timespec)) {
                Ok(0) => {}
                Ok(_) => return Ok(()),
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) => return Err(agent_error(format!("agent wait failed: {error}"))),
            }
        }
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        let mut progress = Instant::now();
        while !bytes.is_empty() {
            match self.stream.write(bytes) {
                Ok(0) => return Err(agent_error("agent write failed: connection closed")),
                Ok(written) => {
                    bytes = &bytes[written..];
                    progress = Instant::now();
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    self.wait(PollFlags::OUT, progress)?;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(agent_error(format!("agent write failed: {error}"))),
            }
        }
        Ok(())
    }

    fn read_exact(&mut self, mut buffer: &mut [u8]) -> Result<(), Error> {
        let mut progress = Instant::now();
        while !buffer.is_empty() {
            match self.stream.read(buffer) {
                Ok(0) => return Err(agent_error("agent read failed: connection closed")),
                Ok(read) => {
                    buffer = &mut buffer[read..];
                    progress = Instant::now();
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    self.wait(PollFlags::IN, progress)?;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(agent_error(format!("agent read failed: {error}"))),
            }
        }
        Ok(())
    }

    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        let mut framed = (request.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(request);
        self.write_all(&framed)?;
        let mut length = [0u8; 4];
        self.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_MESSAGE {
            return Err(agent_error(format!("agent reply of {length} bytes is out of bounds")));
        }
        let mut reply = vec![0u8; length];
        self.read_exact(&mut reply)?;
        Ok(reply)
    }

    /// The public key blobs of every identity the agent holds.
    pub fn identities(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let reply = self.exchange(&[REQUEST_IDENTITIES])?;
        if reply[0] != IDENTITIES_ANSWER {
            return Err(agent_error("agent refused to list identities"));
        }
        let mut reader = SshReader::new(&reply[1..]);
        let count = reader.u32()?;
        if count > MAX_IDENTITIES {
            return Err(agent_error(format!("agent lists {count} identities")));
        }
        let mut blobs = Vec::new();
        for _ in 0..count {
            blobs.push(reader.string()?.to_vec());
            let _comment = reader.string()?;
        }
        reader.finish()?;
        Ok(blobs)
    }

    /// Sign `data` with the identity whose public key blob is `blob`, returning the SSH signature blob.
    pub fn sign(&mut self, blob: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut request = vec![SIGN_REQUEST];
        put_string(&mut request, blob);
        put_string(&mut request, data);
        request.extend_from_slice(&0u32.to_be_bytes());
        let reply = self.exchange(&request)?;
        if reply[0] != SIGN_RESPONSE {
            return Err(agent_error("agent refused to sign"));
        }
        let mut reader = SshReader::new(&reply[1..]);
        let signature = reader.string()?.to_vec();
        reader.finish()?;
        let mut inner = SshReader::new(&signature);
        let algorithm = inner.string()?;
        let raw = inner.string()?;
        inner.finish()?;
        if algorithm != b"ssh-ed25519" || raw.len() != ED25519_SIGNATURE {
            return Err(agent_error("agent returned a malformed Ed25519 signature"));
        }
        Ok(signature)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;

    fn full_backlog() -> (tempfile::TempDir, UnixListener, UnixStream) {
        use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, bind, listen, socket_with};
        let directory = tempfile::tempdir().expect("agent directory");
        let path = directory.path().join("agent.sock");
        let socket = socket_with(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None).expect("socket");
        bind(&socket, &SocketAddrUnix::new(&path).expect("address")).expect("bind");
        listen(&socket, 0).expect("listen");
        let listener = UnixListener::from(socket);
        let queued = UnixStream::connect(path).expect("fill backlog");
        (directory, listener, queued)
    }

    fn blocked_attempt(timeout: Duration, deadline: Option<Instant>, interrupt: Option<Interrupt>) -> Error {
        let (directory, listener, _queued) = full_backlog();
        let socket = directory.path().join("agent.sock");
        let (sender, receiver) = mpsc::channel();
        let child = thread::spawn(move || {
            sender.send(Agent::connect_bounded(&socket, timeout, deadline, interrupt).map(|_| ())).expect("send");
        });
        let result = receiver.recv_timeout(Duration::from_secs(1));
        if result.is_err() {
            let _ = listener.accept().expect("release blocked connect");
        }
        child.join().expect("connect worker");
        result.expect("agent connect must be bounded even with a full backlog").expect_err("full backlog must not appear connected")
    }

    #[test]
    fn a_full_agent_backlog_obeys_the_idle_timeout() {
        assert!(matches!(blocked_attempt(Duration::from_millis(30), None, None), Error::Agent { .. }));
    }

    #[test]
    fn a_full_agent_backlog_obeys_the_authentication_deadline() {
        let error = blocked_attempt(Duration::from_secs(3), Some(Instant::now() + Duration::from_millis(30)), None);
        assert!(matches!(error, Error::Timeout { certainty: Certainty::NotSubmitted }));
    }

    #[test]
    fn a_full_agent_backlog_obeys_cancellation() {
        let checks = Arc::new(AtomicUsize::new(0));
        let interrupt: Interrupt = Arc::new(move || checks.fetch_add(1, Ordering::Relaxed) > 0);
        let error = blocked_attempt(Duration::from_secs(3), None, Some(interrupt));
        assert!(matches!(error, Error::Cancelled { certainty: Certainty::NotSubmitted }));
    }

    #[test]
    fn a_full_agent_backlog_connects_after_the_listener_accepts() {
        let (directory, listener, _queued) = full_backlog();
        let socket = directory.path().join("agent.sock");
        let (sender, receiver) = mpsc::channel();
        let child = thread::spawn(move || {
            sender.send(Agent::connect(&socket, Duration::from_secs(2)).map(|agent| agent.stream.peer_addr().is_ok())).expect("send");
        });
        let premature = receiver.recv_timeout(Duration::from_millis(30));
        let returned_early = premature.is_ok();
        let _ = listener.accept().expect("drain backlog");
        let connected = if returned_early { premature } else { receiver.recv_timeout(Duration::from_secs(1)) };
        child.join().expect("connect worker");
        assert!(!returned_early, "a full backlog is not an established connection");
        assert!(connected.expect("connect returns after drain").expect("agent connects"));
    }
}
