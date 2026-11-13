mod support;

use std::time::Duration;

use support::*;
use oxish_client::{Connection, Error};

const TIMEOUT: Duration = Duration::from_secs(5);
const DEBUG: u8 = 4;
const UNIMPLEMENTED: u8 = 3;

#[cfg(target_os = "linux")]
enum AgentStop {
    Deadline,
    Cancellation,
}

#[cfg(target_os = "linux")]
fn authentication_with_a_full_agent_backlog(stop: AgentStop) -> Error {
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc};
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, bind, listen, socket_with};

    let peer = spawn(Behavior::default(), |link| link.linger());
    let directory = tempfile::tempdir().expect("agent directory");
    let path = directory.path().join("agent.sock");
    let socket = socket_with(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None).expect("socket");
    bind(&socket, &SocketAddrUnix::new(&path).expect("address")).expect("bind");
    listen(&socket, 0).expect("listen");
    let listener = UnixListener::from(socket);
    let _queued = UnixStream::connect(&path).expect("fill backlog");
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut config = peer.config(Duration::from_secs(3));
    config.deadline = Duration::from_millis(100);
    config.identity = oxish_client::Identity::Agent {
        socket: path,
        fingerprint: oxish_client::Fingerprint::parse(&peer.pin).expect("fingerprint"),
    };
    let flag = cancelled.clone();
    config.interrupt = Some(Arc::new(move || flag.load(Ordering::SeqCst)));
    let mut connection = Connection::connect(&config).expect("verified host connection");
    cancelled.store(matches!(stop, AgentStop::Cancellation), Ordering::SeqCst);
    let (sender, receiver) = mpsc::channel();
    let child = std::thread::spawn(move || {
        let result = connection.authenticate();
        drop(connection);
        sender.send(result).expect("send authentication outcome");
    });
    let result = receiver.recv_timeout(Duration::from_secs(1));
    if result.is_err() {
        let _ = listener.accept().expect("release blocked connect");
    }
    child.join().expect("authentication worker");
    peer.finish();
    result.expect("agent socket establishment must honor authentication bounds").expect_err("full agent queue")
}

#[cfg(target_os = "linux")]
#[test]
fn authentication_deadline_covers_agent_socket_establishment() {
    let error = authentication_with_a_full_agent_backlog(AgentStop::Deadline);
    assert!(matches!(error, Error::Timeout { certainty: oxish_client::Certainty::NotSubmitted }));
}

#[cfg(target_os = "linux")]
#[test]
fn authentication_cancellation_covers_agent_socket_establishment() {
    let error = authentication_with_a_full_agent_backlog(AgentStop::Cancellation);
    assert!(matches!(error, Error::Cancelled { certainty: oxish_client::Certainty::NotSubmitted }));
}

fn transport_noise() -> Vec<Vec<u8>> {
    vec![
        message(IGNORE, &[&text(b"padding")]),
        message(DEBUG, &[&[1], &text(b"note"), &text(b"")]),
        message(UNIMPLEMENTED, &[&number(0)]),
    ]
}

#[test]
fn transport_messages_before_the_service_accept_do_not_break_authentication() {
    for noise in transport_noise() {
        let peer = spawn(Behavior::default(), move |link| {
            link.expect(SERVICE_REQUEST);
            link.send(&noise);
            link.send(&message(SERVICE_ACCEPT, &[&text(b"ssh-userauth")]));
            link.expect(USERAUTH_REQUEST);
            link.send(&[USERAUTH_SUCCESS]);
        });
        let mut connection = Connection::connect(&peer.config(TIMEOUT)).expect("connect");
        connection.authenticate().expect("noise is skipped");
        drop(connection);
        peer.finish();
    }
}

#[test]
fn transport_messages_while_the_server_decides_do_not_break_authentication() {
    for noise in transport_noise() {
        let peer = spawn(Behavior::default(), move |link| {
            link.accept_service();
            link.expect(USERAUTH_REQUEST);
            link.send(&noise);
            link.send(&[USERAUTH_SUCCESS]);
        });
        let mut connection = Connection::connect(&peer.config(TIMEOUT)).expect("connect");
        connection.authenticate().expect("noise is skipped");
        drop(connection);
        peer.finish();
    }
}

#[test]
fn a_service_accept_for_another_service_is_refused() {
    let peer = spawn(Behavior::default(), |link| {
        link.expect(SERVICE_REQUEST);
        link.send(&message(SERVICE_ACCEPT, &[&text(b"ssh-connection")]));
    });
    let mut connection = Connection::connect(&peer.config(TIMEOUT)).expect("connect");
    match connection.authenticate() {
        Err(Error::Protocol { detail }) => assert!(detail.contains("different service"), "{detail}"),
        other => panic!("expected a protocol failure, got {other:?}"),
    }
    drop(connection);
    peer.finish();
}

fn authenticate_with_key_at(prepare: impl FnOnce(&std::path::Path)) -> Result<(), Error> {
    let peer = spawn(Behavior::default(), |link| link.linger());
    prepare(&peer.key);
    let mut connection = Connection::connect(&peer.config(TIMEOUT)).expect("connect");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = connection.authenticate();
        let _ = sender.send(outcome);
    });
    let outcome = receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("authentication returns instead of blocking on the key file");
    drop(peer);
    outcome
}

fn key_file_failure(outcome: Result<(), Error>) -> String {
    match outcome {
        Err(Error::KeyFile { detail }) => detail,
        other => panic!("expected a key file failure, got {other:?}"),
    }
}

#[test]
fn a_private_key_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    for mode in [0o640, 0o604, 0o644, 0o660] {
        let detail = key_file_failure(authenticate_with_key_at(|path| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        }));
        assert!(detail.contains("too open"), "{mode:o}: {detail}");
    }
}

#[test]
fn a_fifo_at_the_key_path_is_refused_without_blocking() {
    let detail = key_file_failure(authenticate_with_key_at(|path| {
        std::fs::remove_file(path).expect("remove key");
        let status = std::process::Command::new("mkfifo").arg(path).status().expect("mkfifo");
        assert!(status.success());
    }));
    assert!(detail.contains("not a regular file"), "{detail}");
}

#[test]
fn a_key_file_past_the_size_bound_is_refused() {
    let detail = key_file_failure(authenticate_with_key_at(|path| {
        std::fs::write(path, vec![b'a'; 1 << 20]).expect("write");
    }));
    assert!(detail.contains("larger than"), "{detail}");
}
