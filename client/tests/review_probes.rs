mod support;

use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use oxish_client::{Certainty, Connection, Error, ExecOptions, ExecStatus, RekeyLimits};
use support::*;

const TIMEOUT: Duration = Duration::from_secs(5);
const MEMORY_BUDGET: usize = 24 * 1024 * 1024;

fn exclusive() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

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

#[test]
fn a_connection_end_between_the_exit_status_and_channel_eof_is_not_a_complete_result() {
    let _guard = exclusive();
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.data(channel, b"head of the output\n");
        link.exit_status(channel, 0);
        link.expect(CHANNEL_EOF);
        link.hangup();
    });
    let mut connection = peer.connect(TIMEOUT);
    let outcome = connection.exec(
        "command",
        &ExecOptions {
            timeout: Some(TIMEOUT),
            ..ExecOptions::default()
        },
    );
    assert!(
        outcome.is_err(),
        "a TCP end that no authenticated CHANNEL_EOF preceded must not complete the command: {outcome:?}"
    );
    assert_eq!(outcome.unwrap_err().certainty(), Certainty::Submitted);
    peer.finish();
}

#[test]
fn requests_held_before_the_exec_reply_stay_within_the_memory_budget() {
    let _guard = exclusive();
    let peer = spawn(Behavior::default(), |link| {
        link.accept_authentication();
        let open = link.expect(CHANNEL_OPEN);
        let channel = open.u32_at(4 + open.u32_at(0) as usize);
        link.send(&message(
            CHANNEL_CONFIRMATION,
            &[
                &number(channel),
                &number(SERVER_CHANNEL),
                &number(1 << 20),
                &number(32 * 1024),
            ],
        ));
        link.expect(CHANNEL_REQUEST);
        let filler = vec![0x5a; 60_000];
        let request = message(
            CHANNEL_REQUEST,
            &[&number(channel), &text(b"x@example"), &[0], &filler],
        );
        for _ in 0..1000 {
            link.send(&request);
        }
        link.send(&message(CHANNEL_SUCCESS, &[&number(channel)]));
        link.exit_status(channel, 0);
        link.eof(channel);
        link.close(channel);
        link.expect_close();
    });
    let mut connection = peer.connect(TIMEOUT);
    let (outcome, growth) = peak_memory_growth(|| {
        connection.exec(
            "command",
            &ExecOptions {
                timeout: Some(Duration::from_secs(20)),
                ..ExecOptions::default()
            },
        )
    });
    let result = outcome.expect("the command completes");
    assert_eq!(result.status, ExecStatus::Exited(0));
    assert!(
        growth < MEMORY_BUDGET,
        "held {growth} bytes of channel requests that arrived before the exec reply"
    );
    drop(connection);
    peer.finish();
}

#[test]
fn a_client_rekey_due_during_authentication_keeps_the_in_flight_service_accept() {
    let _guard = exclusive();
    let peer = spawn(Behavior::default(), |link| {
        link.expect(SERVICE_REQUEST);
        link.send(&message(SERVICE_ACCEPT, &[&text(b"ssh-userauth")]));
        loop {
            match link.try_recv() {
                Ok(frame) if frame.kind == REKEYED => {}
                Ok(frame) if frame.kind == USERAUTH_REQUEST => {
                    link.send(&[USERAUTH_SUCCESS]);
                    return;
                }
                Ok(frame) => panic!("unexpected frame {frame:?}"),
                Err(_) => return,
            }
        }
    });
    let mut config = peer.config(TIMEOUT);
    config.rekey = RekeyLimits {
        interval: Duration::from_millis(300),
        ..RekeyLimits::default()
    };
    let mut connection = Connection::connect(&config).expect("connect");
    thread::sleep(Duration::from_millis(400));
    let outcome = connection.authenticate();
    assert!(
        outcome.is_ok(),
        "a SERVICE_ACCEPT sent before the server saw the client's KEXINIT must survive the rekey: {outcome:?}"
    );
    drop(connection);
    peer.finish();
}

#[test]
fn a_host_key_change_at_a_rekey_after_submission_is_still_a_host_key_mismatch() {
    let _guard = exclusive();
    let peer = serve_exec(
        Behavior {
            rekey_with_another_host_key: true,
            ..Behavior::default()
        },
        1 << 20,
        |link, channel| {
            for _ in 0..40 {
                link.data(channel, &[9; 4096]);
            }
            thread::sleep(Duration::from_secs(1));
            link.exit_status(channel, 0);
            link.eof(channel);
            link.close(channel);
        },
    );
    let mut config = peer.known_hosts_config(TIMEOUT);
    config.rekey = RekeyLimits {
        bytes: 32 * 1024,
        ..RekeyLimits::default()
    };
    let mut connection = Connection::connect(&config).expect("connect");
    connection.authenticate().expect("authenticate");
    let error = connection
        .exec("command", &ExecOptions::default())
        .expect_err("the host key changed");
    assert!(
        matches!(&error, Error::AfterSubmission { cause } if matches!(cause.as_ref(), Error::HostKeyMismatch { .. })),
        "a substituted host key mid-command must keep its trust variant: {error:?}"
    );
    assert_eq!(error.certainty(), Certainty::Submitted, "{error:?}");
    drop(connection);
    peer.finish();
}

#[test]
fn a_finished_channel_is_closed_by_the_client_when_the_server_waits_for_it() {
    let _guard = exclusive();
    let peer = serve_exec(Behavior::default(), 1 << 20, |link, channel| {
        link.data(channel, b"out");
        link.exit_status(channel, 0);
        link.eof(channel);
        loop {
            match link.try_recv() {
                Ok(frame) if frame.kind == CHANNEL_CLOSE => {
                    link.close(channel);
                    return;
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    let mut connection = peer.connect(TIMEOUT);
    let started = Instant::now();
    let outcome = connection.exec(
        "command",
        &ExecOptions {
            timeout: Some(Duration::from_secs(3)),
            ..ExecOptions::default()
        },
    );
    let result = outcome.unwrap_or_else(|error| {
        panic!(
            "exit status and EOF arrived, yet the client waited {:?} for the server to close first: {error:?}",
            started.elapsed()
        )
    });
    assert_eq!(result.status, ExecStatus::Exited(0));
    assert_eq!(result.stdout, b"out");
    drop(connection);
    peer.finish();
}
