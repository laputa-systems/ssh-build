mod support;

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use support::*;
use oxish_client::{
    Certainty, ClientConfig, Connection, Error, ExecOptions, ExecStatus, RekeyLimits, StreamOptions,
};

const TIMEOUT: Duration = Duration::from_secs(5);

fn serve_exec(
    behavior: Behavior,
    window: u32,
    body: impl FnOnce(&mut Link, u32) + Send + 'static,
) -> Peer {
    spawn(behavior, move |link| {
        link.accept_authentication();
        let opened = link.accept_exec(window, 32 * 1024);
        body(link, opened.client_channel);
    })
}

fn run(peer: &Peer) -> Result<oxish_client::ExecResult, Error> {
    peer.connect(TIMEOUT).exec("command", &ExecOptions::default())
}

#[test]
fn completion_and_output_arrive_through_the_scripted_peer() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.data(channel, b"hi\n");
        link.extended_data(channel, b"warn\n");
        link.exit_status(channel, 3);
        link.eof(channel);
        link.close(channel);
        link.expect_close();
    });
    let result = run(&peer).expect("exec");
    assert_eq!(result.status, ExecStatus::Exited(3));
    assert_eq!(result.stdout, b"hi\n");
    assert_eq!(result.stderr, b"warn\n");
    peer.finish();
}

#[test]
fn output_and_completion_before_the_exec_reply_are_delivered() {
    let peer = spawn(Behavior::default(), |link| {
        link.accept_authentication();
        let open = link.expect(CHANNEL_OPEN);
        let kind_length = open.u32_at(0) as usize;
        let channel = open.u32_at(4 + kind_length);
        link.send(&message(
            CHANNEL_CONFIRMATION,
            &[
                &number(channel),
                &number(SERVER_CHANNEL),
                &number(1 << 20),
                &number(32 * 1024),
            ],
        ));
        let request = link.expect(CHANNEL_REQUEST);
        assert_eq!(request.string_at(4), b"exec");
        link.data(channel, b"before the reply");
        link.extended_data(channel, b"stderr before the reply");
        link.exit_status(channel, 9);
        link.send(&message(CHANNEL_SUCCESS, &[&number(channel)]));
        link.eof(channel);
        link.close(channel);
        link.expect_close();
    });
    let mut connection = peer.connect(TIMEOUT);
    let result = connection
        .exec(
            "command",
            &ExecOptions {
                timeout: Some(TIMEOUT),
                ..ExecOptions::default()
            },
        )
        .expect("data and completion before the exec reply are accepted");
    assert_eq!(result.status, ExecStatus::Exited(9));
    assert_eq!(result.stdout, b"before the reply");
    assert_eq!(result.stderr, b"stderr before the reply");
    drop(connection);
    peer.finish();
}

#[test]
fn a_channel_closed_without_completion_is_missing_never_zero() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.data(channel, b"partial");
        link.eof(channel);
        link.close(channel);
        link.expect_close();
    });
    let result = run(&peer).expect("exec");
    assert_eq!(result.status, ExecStatus::Missing);
    assert_eq!(result.stdout, b"partial");
    peer.finish();
}

#[test]
fn a_disconnect_after_submission_is_potentially_executed() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, _| link.disconnect());
    let error = run(&peer).expect_err("disconnect fails the command");
    assert!(matches!(error, Error::Submitted { .. }), "{error:?}");
    assert_eq!(error.certainty(), Certainty::Submitted);
    peer.finish();
}

#[test]
fn a_connection_closed_after_the_exit_status_still_returns_the_result() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.data(channel, b"done\n");
        link.exit_status(channel, 3);
        link.expect(CHANNEL_EOF);
        link.hangup();
    });
    let mut connection = peer.connect(TIMEOUT);
    let result = connection.exec("command", &ExecOptions::default()).expect("result");
    assert_eq!(result.status, ExecStatus::Exited(3));
    assert_eq!(result.stdout, b"done\n");
    assert!(!connection.is_usable());
    peer.finish();
}

#[test]
fn a_dropped_connection_after_submission_is_potentially_executed() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.data(channel, b"some");
        link.hangup();
    });
    let error = run(&peer).expect_err("a dropped connection fails the command");
    assert_eq!(error.certainty(), Certainty::Submitted, "{error:?}");
    peer.finish();
}

#[test]
fn a_rejected_exec_request_did_not_run() {
    let peer = spawn(Behavior::default(), |link| {
        link.accept_authentication();
        let open = link.expect(CHANNEL_OPEN);
        let client = open.u32_at(4 + open.u32_at(0) as usize);
        link.send(&message(
            CHANNEL_CONFIRMATION,
            &[&number(client), &number(SERVER_CHANNEL), &number(1 << 20), &number(32768)],
        ));
        link.expect(CHANNEL_REQUEST);
        link.send(&message(CHANNEL_FAILURE, &[&number(client)]));
    });
    let error = run(&peer).expect_err("rejected");
    assert!(matches!(error, Error::Rejected { request: "exec" }), "{error:?}");
    assert_eq!(error.certainty(), Certainty::NotSubmitted);
    peer.finish();
}

#[test]
fn oversized_data_packets_are_a_protocol_violation() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.data(channel, &vec![0; 32 * 1024 + 1]);
    });
    let error = run(&peer).expect_err("oversized packet");
    assert_eq!(error.certainty(), Certainty::Submitted, "{error:?}");
    assert!(error.to_string().contains("packet size"), "{error}");
    peer.finish();
}

#[test]
fn data_for_another_channel_is_refused() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.data(channel + 1, b"stray");
    });
    let error = run(&peer).expect_err("wrong channel");
    assert!(error.to_string().contains("unknown channel"), "{error}");
    peer.finish();
}

#[test]
fn data_after_end_of_file_is_refused() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.eof(channel);
        link.data(channel, b"late");
    });
    let error = run(&peer).expect_err("data after eof");
    assert!(error.to_string().contains("ended its output"), "{error}");
    peer.finish();
}

#[test]
fn a_window_larger_than_the_protocol_allows_is_refused() {
    let peer = serve_exec(Behavior::default(), u32::MAX, |link, channel| {
        link.send(&message(CHANNEL_WINDOW_ADJUST, &[&number(channel), &number(1)]));
    });
    let error = run(&peer).expect_err("window overflow");
    assert!(error.to_string().contains("window"), "{error}");
    peer.finish();
}

#[test]
fn completion_reported_twice_is_ambiguous_and_refused() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.exit_status(channel, 0);
        link.exit_status(channel, 1);
    });
    let error = run(&peer).expect_err("two statuses");
    assert!(error.to_string().contains("completion twice"), "{error}");
    peer.finish();
}

#[test]
fn a_message_from_the_wrong_protocol_state_is_refused() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, _| {
        link.send(&[USERAUTH_SUCCESS]);
    });
    let error = run(&peer).expect_err("wrong state");
    assert_eq!(error.certainty(), Certainty::Submitted, "{error:?}");
    peer.finish();
}

#[test]
fn a_forged_authentication_tag_is_refused() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.send_with_flipped_tag(&message(CHANNEL_DATA, &[&number(channel), &text(b"forged")]));
    });
    let error = run(&peer).expect_err("bad tag");
    assert_eq!(error.certainty(), Certainty::Submitted, "{error:?}");
    peer.finish();
}

#[test]
fn unsupported_global_and_channel_requests_are_answered() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.send(&message(GLOBAL_REQUEST, &[&text(b"keepalive@openssh.com"), &[1]]));
        link.expect_reply(REQUEST_FAILURE);
        link.send(&message(
            CHANNEL_REQUEST,
            &[&number(channel), &text(b"xon-xoff"), &[1], &[1]],
        ));
        link.expect_reply(CHANNEL_FAILURE);
        link.exit_status(channel, 0);
        link.eof(channel);
        link.close(channel);
        link.expect_close();
    });
    let result = run(&peer).expect("exec");
    assert_eq!(result.status, ExecStatus::Exited(0));
    peer.finish();
}

fn server_requests_that_want_an_answer(link: &mut Link) {
    link.send(&message(GLOBAL_REQUEST, &[&text(b"hostkeys-00@openssh.com"), &[1]]));
    link.send(&message(
        CHANNEL_OPEN,
        &[&text(b"forwarded-tcpip"), &number(41), &number(1 << 20), &number(32768)],
    ));
    link.expect(REQUEST_FAILURE);
    let refusal = link.expect(CHANNEL_OPEN_FAILURE);
    assert_eq!(refusal.u32_at(0), 41);
}

#[test]
fn server_opened_channels_and_global_requests_are_refused_while_the_open_is_pending() {
    let peer = spawn(Behavior::default(), |link| {
        link.accept_authentication();
        let open = link.expect(CHANNEL_OPEN);
        let client = open.u32_at(4 + open.u32_at(0) as usize);
        server_requests_that_want_an_answer(link);
        link.send(&message(
            CHANNEL_CONFIRMATION,
            &[&number(client), &number(SERVER_CHANNEL), &number(1 << 20), &number(32768)],
        ));
        link.expect(CHANNEL_REQUEST);
        link.send(&message(CHANNEL_SUCCESS, &[&number(client)]));
        link.exit_status(client, 0);
        link.eof(client);
        link.close(client);
        link.expect_close();
    });
    let result = run(&peer).expect("exec");
    assert_eq!(result.status, ExecStatus::Exited(0));
    peer.finish();
}

#[test]
fn server_opened_channels_and_global_requests_are_refused_while_env_and_exec_are_pending() {
    let peer = spawn(Behavior::default(), |link| {
        link.accept_authentication();
        let open = link.expect(CHANNEL_OPEN);
        let client = open.u32_at(4 + open.u32_at(0) as usize);
        link.send(&message(
            CHANNEL_CONFIRMATION,
            &[&number(client), &number(SERVER_CHANNEL), &number(1 << 20), &number(32768)],
        ));
        let environment = link.expect(CHANNEL_REQUEST);
        assert_eq!(environment.string_at(4), b"env");
        server_requests_that_want_an_answer(link);
        link.send(&message(CHANNEL_SUCCESS, &[&number(client)]));
        let exec = link.expect(CHANNEL_REQUEST);
        assert_eq!(exec.string_at(4), b"exec");
        server_requests_that_want_an_answer(link);
        link.send(&message(CHANNEL_SUCCESS, &[&number(client)]));
        link.exit_status(client, 0);
        link.eof(client);
        link.close(client);
        link.expect_close();
    });
    let options = ExecOptions {
        env: vec![("NAME".to_owned(), "value".to_owned())],
        ..ExecOptions::default()
    };
    let result = peer.connect(TIMEOUT).exec("command", &options).expect("exec");
    assert_eq!(result.status, ExecStatus::Exited(0));
    peer.finish();
}

#[test]
fn a_channel_open_failure_for_another_channel_is_refused() {
    let peer = spawn(Behavior::default(), |link| {
        link.accept_authentication();
        let open = link.expect(CHANNEL_OPEN);
        let client = open.u32_at(4 + open.u32_at(0) as usize);
        link.send(&message(
            CHANNEL_OPEN_FAILURE,
            &[&number(client + 1), &number(2), &text(b"no"), &text(b"")],
        ));
        link.linger();
    });
    let error = run(&peer).expect_err("wrong recipient");
    assert!(error.to_string().contains("unknown channel"), "{error}");
    peer.finish();
}

#[test]
fn identification_split_across_segments_is_assembled() {
    let behavior = Behavior {
        fragment_identification: true,
        ..Behavior::default()
    };
    let peer = serve_exec(behavior, 1 << 20, |link, channel| {
        link.exit_status(channel, 0);
        link.eof(channel);
        link.close(channel);
        link.expect_close();
    });
    assert_eq!(run(&peer).expect("exec").status, ExecStatus::Exited(0));
    peer.finish();
}

#[test]
fn a_tampered_host_signature_is_refused_before_authentication() {
    let behavior = Behavior {
        corrupt_signature: true,
        ..Behavior::default()
    };
    let peer = spawn(behavior, |_| {});
    match Connection::connect(&peer.config(TIMEOUT)) {
        Err(Error::HostKey { detail }) => assert!(detail.contains("signature"), "{detail}"),
        other => panic!("expected a host key failure, got {other:?}"),
    }
}

#[test]
fn a_message_before_kexinit_breaks_strict_key_exchange() {
    let behavior = Behavior {
        ignore_before_kexinit: true,
        ..Behavior::default()
    };
    let peer = spawn(behavior, |_| {});
    match Connection::connect(&peer.config(TIMEOUT)) {
        Err(Error::Protocol { detail }) => assert!(detail.contains("expected"), "{detail}"),
        other => panic!("expected a protocol failure, got {other:?}"),
    }
}

#[test]
fn a_silent_peer_hits_the_deadline_after_submission() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |_, _| {});
    let mut connection = peer.connect(TIMEOUT);
    let started = Instant::now();
    let error = connection
        .exec(
            "command",
            &ExecOptions {
                timeout: Some(Duration::from_millis(300)),
                ..ExecOptions::default()
            },
        )
        .expect_err("deadline");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(matches!(
        error,
        Error::Timeout {
            certainty: Certainty::Submitted
        }
    ));
    assert!(matches!(
        connection.exec("again", &ExecOptions::default()),
        Err(Error::Unusable)
    ));
    drop(connection);
    peer.finish();
}

struct Endless;

impl oxish_client::InputSource for Endless {
    fn descriptor(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        None
    }
}

impl Read for Endless {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        buffer.fill(7);
        Ok(buffer.len())
    }
}

#[test]
fn a_peer_that_stops_reading_stalls_the_sender_into_a_timeout() {
    let peer = serve_exec(Behavior::default(), u32::MAX / 2, |_, _| {
        std::thread::sleep(Duration::from_secs(2));
    });
    let mut connection = peer.connect(Duration::from_millis(400));
    let started = Instant::now();
    let error = connection
        .exec_stream(
            "command",
            &StreamOptions::default(),
            Some(&mut Endless),
            &mut io::sink(),
            &mut io::sink(),
        )
        .expect_err("stalled");
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert!(
        matches!(error, Error::Timeout { certainty: Certainty::Submitted }),
        "{error:?}"
    );
    drop(connection);
    peer.finish();
}

#[test]
fn the_caller_can_cancel_a_running_command() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let peer = serve_exec(Behavior::default(), 1 << 20, |_, _| {});
    let mut connection = peer.connect(TIMEOUT);
    let flag = Arc::clone(&cancelled);
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        flag.store(true, Ordering::SeqCst);
    });
    let observed = Arc::clone(&cancelled);
    let started = Instant::now();
    let error = connection
        .exec(
            "command",
            &ExecOptions {
                interrupt: Some(Arc::new(move || observed.load(Ordering::SeqCst))),
                ..ExecOptions::default()
            },
        )
        .expect_err("cancelled");
    handle.join().expect("timer");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(matches!(
        error,
        Error::Cancelled {
            certainty: Certainty::Submitted
        }
    ));
    drop(connection);
    peer.finish();
}

#[test]
fn output_past_the_capture_limit_is_reported_and_poisons_the_session() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.data(channel, &[1; 4096]);
    });
    let mut connection = peer.connect(TIMEOUT);
    let error = connection
        .exec(
            "command",
            &ExecOptions {
                max_output: 1024,
                ..ExecOptions::default()
            },
        )
        .expect_err("limit");
    assert!(matches!(error, Error::OutputLimit { stream: "stdout" }), "{error:?}");
    assert_eq!(error.certainty(), Certainty::Submitted);
    assert!(!connection.is_usable());
    drop(connection);
    peer.finish();
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn client_initiated_rekeys_carry_queued_traffic_without_loss() {
    let payload: Vec<u8> = (0..400_000u32).map(|index| (index % 251) as u8).collect();
    let sent = payload.clone();
    let peer = serve_exec(Behavior::default(), 1 << 20, move |link, channel| {
        let (first, second) = sent.split_at(sent.len() / 2);
        for (rekeys, half) in [first, second].into_iter().enumerate() {
            for chunk in half.chunks(16 * 1024) {
                link.data(channel, chunk);
            }
            let mut frames = 0;
            while link.rekeys <= rekeys as u32 {
                link.recv();
                frames += 1;
                assert!(frames < 1000, "client did not rekey after burst {rekeys}");
            }
        }
        link.exit_status(channel, 0);
        link.eof(channel);
        link.close(channel);
        link.expect_close();
    });
    let mut config = peer.config(TIMEOUT);
    config.rekey = RekeyLimits {
        bytes: 64 * 1024,
        ..RekeyLimits::default()
    };
    let mut connection = Connection::connect(&config).expect("connect");
    connection.authenticate().expect("authenticate");
    let result = connection.exec("command", &ExecOptions::default()).expect("exec");
    assert_eq!(result.status, ExecStatus::Exited(0));
    assert_eq!(digest(&result.stdout), digest(&payload));
    drop(connection);
    peer.finish();
}

#[test]
fn a_server_message_between_its_rekey_reply_and_newkeys_is_skipped() {
    let peer = serve_exec(
        Behavior {
            ignore_between_rekey_reply_and_newkeys: true,
            ..Behavior::default()
        },
        1 << 20,
        |link, channel| {
            for _ in 0..40 {
                link.data(channel, &[9; 4096]);
            }
            while link.rekeys == 0 {
                link.recv();
            }
            link.exit_status(channel, 0);
            link.eof(channel);
            link.close(channel);
            link.expect_close();
        },
    );
    let mut config = peer.config(TIMEOUT);
    config.rekey = RekeyLimits {
        bytes: 32 * 1024,
        ..RekeyLimits::default()
    };
    let mut connection = Connection::connect(&config).expect("connect");
    connection.authenticate().expect("authenticate");
    let result = connection.exec("command", &ExecOptions::default()).expect("exec");
    assert_eq!(result.status, ExecStatus::Exited(0));
    drop(connection);
    peer.finish();
}

#[test]
fn the_session_identity_survives_a_client_rekey() {
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        for _ in 0..40 {
            link.data(channel, &[9; 4096]);
        }
        while link.rekeys == 0 {
            link.recv();
        }
        link.exit_status(channel, 0);
        link.eof(channel);
        link.close(channel);
        link.expect_close();
    });
    let mut config = peer.config(TIMEOUT);
    config.rekey = RekeyLimits {
        bytes: 32 * 1024,
        ..RekeyLimits::default()
    };
    let mut connection = Connection::connect(&config).expect("connect");
    connection.authenticate().expect("authenticate");
    let before = connection.session_id().to_vec();
    connection.exec("command", &ExecOptions::default()).expect("exec");
    assert_eq!(connection.session_id(), before);
    drop(connection);
    peer.finish();
}

#[test]
fn an_unreachable_server_is_not_submitted() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    let config = ClientConfig::pinned(
        "127.0.0.1",
        port,
        "tester",
        "/nonexistent",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        TIMEOUT,
    )
    .expect("pin");
    let error = Connection::connect(&config).expect_err("refused");
    assert_eq!(error.certainty(), Certainty::NotSubmitted);
    let _ = io::stdout().flush();
}

fn serve_with_environment(reply: u8, accepted: usize) -> Peer {
    spawn(Behavior::default(), move |link| {
        link.accept_authentication();
        let open = link.expect(CHANNEL_OPEN);
        let client = open.u32_at(4 + open.u32_at(0) as usize);
        link.send(&message(
            CHANNEL_CONFIRMATION,
            &[&number(client), &number(SERVER_CHANNEL), &number(1 << 20), &number(32768)],
        ));
        for round in 0..accepted {
            let request = link.expect(CHANNEL_REQUEST);
            assert_eq!(request.string_at(4), b"env", "environment request {round}");
            link.send(&message(CHANNEL_SUCCESS, &[&number(client)]));
        }
        let request = link.expect(CHANNEL_REQUEST);
        if reply == CHANNEL_SUCCESS {
            assert_eq!(request.string_at(4), b"exec");
            link.send(&message(CHANNEL_SUCCESS, &[&number(client)]));
            link.exit_status(client, 0);
            link.eof(client);
            link.close(client);
            link.expect_close();
        } else {
            assert_eq!(request.string_at(4), b"env");
            link.send(&message(CHANNEL_FAILURE, &[&number(client)]));
        }
    })
}

#[test]
fn environment_requests_precede_the_command_in_order() {
    let peer = serve_with_environment(CHANNEL_SUCCESS, 2);
    let mut connection = peer.connect(TIMEOUT);
    let result = connection
        .exec(
            "command",
            &ExecOptions {
                env: vec![
                    ("LC_ALL".to_owned(), "C".to_owned()),
                    ("LANG".to_owned(), "C".to_owned()),
                ],
                ..ExecOptions::default()
            },
        )
        .expect("exec");
    assert_eq!(result.status, ExecStatus::Exited(0));
    drop(connection);
    peer.finish();
}

#[test]
fn a_refused_environment_request_means_the_command_did_not_run() {
    let peer = serve_with_environment(CHANNEL_FAILURE, 0);
    let mut connection = peer.connect(TIMEOUT);
    let error = connection
        .exec(
            "command",
            &ExecOptions {
                env: vec![("NOT_ACCEPTED".to_owned(), "x".to_owned())],
                ..ExecOptions::default()
            },
        )
        .expect_err("refused");
    assert!(matches!(error, Error::Rejected { request: "env" }), "{error:?}");
    assert_eq!(error.certainty(), Certainty::NotSubmitted);
    drop(connection);
    peer.finish();
}

#[test]
fn environment_names_and_values_are_validated_before_anything_is_sent() {
    let peer = spawn(Behavior::default(), |link| {
        link.accept_authentication();
    });
    let mut connection = peer.connect(TIMEOUT);
    for bad in [
        ("", "x"),
        ("1BAD", "x"),
        ("A-B", "x"),
        ("NAME", "has\0nul"),
    ] {
        let error = connection
            .exec(
                "command",
                &ExecOptions {
                    env: vec![(bad.0.to_owned(), bad.1.to_owned())],
                    ..ExecOptions::default()
                },
            )
            .expect_err("invalid");
        assert!(matches!(error, Error::InvalidEnvironment { .. }), "{bad:?}: {error:?}");
        assert_eq!(error.certainty(), Certainty::NotSubmitted);
    }
    assert!(connection.is_usable(), "nothing was sent, so the session is intact");
    drop(connection);
    peer.finish();
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn arbitrary_connection_messages_never_hang_or_panic_the_client() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for round in 0..60 {
        let kind = 80 + (next_random(&mut state) % 21) as u8;
        let length = (next_random(&mut state) % 96) as usize;
        let body: Vec<u8> = (0..length).map(|_| next_random(&mut state) as u8).collect();
        let peer = serve_exec(Behavior::default(), 1 << 20, move |link, channel| {
            let mut payload = vec![kind];
            if round % 2 == 0 {
                payload.extend_from_slice(&number(channel));
            }
            payload.extend_from_slice(&body);
            link.send(&payload);
        });
        let mut connection = peer.connect(Duration::from_millis(800));
        let started = Instant::now();
        let outcome = connection.exec(
            "command",
            &ExecOptions {
                timeout: Some(Duration::from_secs(2)),
                ..ExecOptions::default()
            },
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "round {round}: message {kind} left the client waiting"
        );
        if let Ok(result) = outcome {
            assert!(
                matches!(result.status, ExecStatus::Missing | ExecStatus::Exited(_) | ExecStatus::Signaled(_)),
                "round {round}"
            );
        }
        drop(connection);
        peer.finish();
    }
}

fn rekeyed_under(limits: RekeyLimits, packets: usize, pause: Duration) -> bool {
    let peer = serve_exec(Behavior::default(), 1 << 20, move |link, channel| {
        for _ in 0..packets {
            link.data(channel, &[3; 100]);
        }
        thread::sleep(pause);
        link.data(channel, &[3; 100]);
        let mut frames = 0;
        while link.rekeys == 0 && frames < 200 {
            link.recv();
            frames += 1;
        }
        let rekeys = link.rekeys;
        link.exit_status(channel, u32::from(rekeys > 0));
        link.eof(channel);
        link.close(channel);
        link.expect_close();
    });
    let mut config = peer.config(TIMEOUT);
    config.rekey = limits;
    let mut connection = Connection::connect(&config).expect("connect");
    connection.authenticate().expect("authenticate");
    let result = connection.exec("command", &ExecOptions::default()).expect("exec");
    drop(connection);
    peer.finish();
    match result.status {
        ExecStatus::Exited(status) => status == 1,
        other => panic!("unexpected status {other:?}"),
    }
}

#[test]
fn the_packet_count_alone_starts_a_rekey() {
    let limits = RekeyLimits {
        packets: 30,
        ..RekeyLimits::default()
    };
    assert!(rekeyed_under(limits, 60, Duration::ZERO));
}

#[test]
fn the_elapsed_time_alone_starts_a_rekey() {
    let limits = RekeyLimits {
        interval: Duration::from_millis(300),
        ..RekeyLimits::default()
    };
    assert!(rekeyed_under(limits, 1, Duration::from_millis(500)));
}

fn framed_ignore_outcome(body: usize, padding: usize) -> Result<oxish_client::ExecResult, Error> {
    let peer = serve_exec(Behavior::default(), 1 << 20, move |link, channel| {
        let mut ignore = vec![IGNORE];
        ignore.extend_from_slice(&text(&vec![0x2e; body]));
        link.send_framed(&ignore, padding);
        link.exit_status(channel, 0);
        link.eof(channel);
        link.close(channel);
    });
    let outcome = run(&peer);
    peer.finish();
    outcome
}

#[test]
fn a_well_framed_packet_with_minimum_padding_is_accepted() {
    let result = framed_ignore_outcome(6, 4).expect("1 + 11 + 4 bytes fill one block");
    assert_eq!(result.status, ExecStatus::Exited(0));
}

#[test]
fn a_packet_length_off_the_cipher_block_is_refused() {
    let error = framed_ignore_outcome(0, 6).expect_err("1 + 5 + 6 bytes is not a whole block");
    assert!(error.to_string().contains("block"), "{error:?}");
}

#[test]
fn padding_under_four_bytes_is_refused() {
    let error = framed_ignore_outcome(7, 3).expect_err("1 + 12 + 3 bytes has 3 bytes of padding");
    assert!(error.to_string().contains("padding"), "{error:?}");
}
