use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use oxish_client::{Certainty, ClientConfig, Connection, Error, ExecOptions, ExecResult, ExecStatus};

struct Fixture {
    host: String,
    port: u16,
    pin: String,
    user: String,
    key: String,
}

fn variable(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set; run this test through client/fixture/ssh-fixture.sh exec")
    })
}

fn fixture() -> Fixture {
    Fixture {
        host: variable("XINFRA_FIXTURE_A_HOST"),
        port: variable("XINFRA_FIXTURE_A_PORT")
            .parse()
            .expect("fixture port is a number"),
        pin: variable("XINFRA_FIXTURE_A_HOST_KEY"),
        user: variable("XINFRA_FIXTURE_USER"),
        key: variable("XINFRA_FIXTURE_KEY"),
    }
}

fn config(fixture: &Fixture, user: &str, key: &Path) -> ClientConfig {
    ClientConfig::pinned(
        fixture.host.clone(),
        fixture.port,
        user,
        key,
        &fixture.pin,
        Duration::from_secs(10),
    )
    .expect("fixture pin is valid")
}

fn authenticated(fixture: &Fixture) -> Connection {
    let mut connection = Connection::connect(&config(
        fixture,
        &fixture.user,
        Path::new(&fixture.key),
    ))
    .expect("connection succeeds");
    connection.authenticate().expect("fixture key authenticates");
    connection
}

fn generate_key(directory: &Path, name: &str, passphrase: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    let status = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            passphrase,
            "-C",
            "oxish-client-test",
            "-f",
        ])
        .arg(&path)
        .status()
        .expect("ssh-keygen runs");
    assert!(status.success(), "ssh-keygen failed");
    path
}

#[test]
fn exact_stdout_stderr_and_status() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let result = connection
        .exec(
            "printf 'out'; printf 'err' >&2; exit 7",
            &ExecOptions::default(),
        )
        .expect("exec succeeds");
    assert_eq!(result.status, ExecStatus::Exited(7));
    assert_eq!(result.stdout, b"out");
    assert_eq!(result.stderr, b"err");
}

#[test]
fn binary_output_is_exact() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let result = connection
        .exec("printf 'A\\000B'", &ExecOptions::default())
        .expect("exec succeeds");
    assert_eq!(result.status, ExecStatus::Exited(0));
    assert_eq!(result.stdout, b"A\0B");
    assert!(result.stderr.is_empty());
}

#[test]
fn remote_zero_status_is_data() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let result = connection
        .exec("true", &ExecOptions::default())
        .expect("exec succeeds");
    assert_eq!(result.status, ExecStatus::Exited(0));
}

#[test]
fn signal_is_an_outcome() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let result = connection
        .exec("kill -TERM $$", &ExecOptions::default())
        .expect("exec succeeds");
    assert_eq!(result.status, ExecStatus::Signaled("TERM".to_owned()));
}

#[test]
fn wrong_key_is_rejected() {
    let fixture = fixture();
    let directory = tempfile::tempdir().expect("tempdir");
    let key = generate_key(directory.path(), "wrong", "");
    let mut connection = Connection::connect(&config(&fixture, &fixture.user, &key))
        .expect("connection succeeds");
    assert!(matches!(
        connection.authenticate(),
        Err(Error::Authentication { .. })
    ));
}

#[test]
fn unknown_user_is_rejected() {
    let fixture = fixture();
    let mut connection = Connection::connect(&config(
        &fixture,
        "xinfra-no-such-user",
        Path::new(&fixture.key),
    ))
    .expect("connection succeeds");
    assert!(matches!(
        connection.authenticate(),
        Err(Error::Authentication { .. })
    ));
}

#[test]
fn encrypted_key_is_rejected_explicitly() {
    let fixture = fixture();
    let directory = tempfile::tempdir().expect("tempdir");
    let key = generate_key(directory.path(), "encrypted", "secret");
    let mut connection = Connection::connect(&config(&fixture, &fixture.user, &key))
        .expect("connection succeeds");
    assert!(matches!(connection.authenticate(), Err(Error::EncryptedKey)));
}

#[test]
fn timeout_after_submission_is_certain() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let options = ExecOptions {
        timeout: Some(Duration::from_millis(300)),
        ..ExecOptions::default()
    };
    match connection.exec("sleep 5", &options) {
        Err(Error::Timeout {
            certainty: Certainty::Submitted,
        }) => {}
        other => panic!("expected a submitted timeout, got {other:?}"),
    }
}

#[test]
fn debug_does_not_expose_payloads() {
    let options = ExecOptions {
        stdin: Some(b"canary-payload".to_vec()),
        ..ExecOptions::default()
    };
    assert!(!format!("{options:?}").contains("canary-payload"));
    let result = ExecResult {
        status: ExecStatus::Exited(0),
        stdout: b"canary-payload".to_vec(),
        stderr: Vec::new(),
    };
    assert!(!format!("{result:?}").contains("canary-payload"));
}

#[test]
fn timeout_before_submission_is_certain() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let port = listener.local_addr().expect("address").port();
    thread::spawn(move || {
        if let Ok((_stream, _address)) = listener.accept() {
            thread::sleep(Duration::from_secs(2));
        }
    });
    let fixture = fixture();
    let config = ClientConfig::pinned(
        "127.0.0.1",
        port,
        &fixture.user,
        &fixture.key,
        &fixture.pin,
        Duration::from_millis(200),
    )
    .expect("pin");
    match Connection::connect(&config) {
        Err(Error::Timeout {
            certainty: Certainty::NotSubmitted,
        }) => {}
        other => panic!("expected a pre-submission timeout, got {other:?}"),
    }
}

#[test]
fn stdin_larger_than_the_window_is_echoed_exactly() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let input: Vec<u8> = (0..8 * 1024 * 1024u32).map(|index| (index % 253) as u8).collect();
    let result = connection
        .exec(
            "cat",
            &ExecOptions {
                stdin: Some(input.clone()),
                timeout: Some(Duration::from_secs(60)),
                ..ExecOptions::default()
            },
        )
        .expect("exec succeeds");
    assert_eq!(result.status, ExecStatus::Exited(0));
    assert!(result.stdout == input, "echo differs from the input");
}

#[test]
fn one_connection_serves_successive_commands() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    for round in 0..5 {
        let result = connection
            .exec(&format!("printf 'round-{round}'; exit {round}"), &ExecOptions::default())
            .expect("exec succeeds");
        assert_eq!(result.status, ExecStatus::Exited(round));
        assert_eq!(result.stdout, format!("round-{round}").into_bytes());
    }
}

#[test]
fn independent_sessions_run_in_parallel() {
    let fixture = fixture();
    let started = std::time::Instant::now();
    let workers: Vec<_> = (0..4)
        .map(|index| {
            let mut connection = authenticated(&fixture);
            thread::spawn(move || {
                connection
                    .exec(&format!("sleep 1; printf {index}"), &ExecOptions::default())
                    .expect("exec succeeds")
            })
        })
        .collect();
    for (index, worker) in workers.into_iter().enumerate() {
        let result = worker.join().expect("worker finishes");
        assert_eq!(result.stdout, index.to_string().into_bytes());
    }
    assert!(started.elapsed() < Duration::from_secs(3), "sessions ran serially");
}

#[test]
fn server_initiated_rekeys_do_not_disturb_captured_output() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let result = connection
        .exec(
            "head -c 6291456 /dev/zero",
            &ExecOptions {
                timeout: Some(Duration::from_secs(60)),
                ..ExecOptions::default()
            },
        )
        .expect("exec succeeds");
    assert_eq!(result.status, ExecStatus::Exited(0));
    assert_eq!(result.stdout.len(), 6 * 1024 * 1024);
    let after = connection
        .exec("printf alive", &ExecOptions::default())
        .expect("the connection survives the rekey");
    assert_eq!(after.stdout, b"alive");
}

#[test]
fn a_failed_command_makes_the_session_unusable() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let options = ExecOptions {
        timeout: Some(Duration::from_millis(300)),
        ..ExecOptions::default()
    };
    assert!(connection.exec("sleep 5", &options).is_err());
    assert!(matches!(
        connection.exec("true", &ExecOptions::default()),
        Err(Error::Unusable)
    ));
}

#[test]
fn cancellation_reports_remote_stop_or_unacknowledged_for_exec_and_stream() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use std::time::Instant;
    use oxish_client::{RemoteStop, StreamOptions};

    for stream in [false, true] {
        for (command, acknowledged) in [("sleep 30", true),
            ("trap '' TERM; sleep 30", false)] {
            let mut connection = authenticated(&fixture());
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&cancelled);
            let timer = thread::spawn(move || {
                thread::sleep(Duration::from_millis(500));
                flag.store(true, Ordering::SeqCst);
            });
            let interrupt = Arc::new(move || cancelled.load(Ordering::SeqCst));
            let start = Instant::now();
            let error = if stream {
                connection.exec_stream(command, &StreamOptions {
                    interrupt: Some(interrupt), ..StreamOptions::default()
                }, None, std::io::sink(), std::io::sink()).map(|_| ())
            } else {
                connection.exec(command, &ExecOptions {
                    interrupt: Some(interrupt), ..ExecOptions::default()
                }).map(|_| ())
            }.expect_err("cancelled");
            timer.join().expect("timer");
            assert!(start.elapsed() < Duration::from_secs(4), "{command}: {error:?}");
            match error {
                Error::Cancelled { certainty: Certainty::Submitted, remote } => {
                    assert_eq!(matches!(remote, RemoteStop::Acknowledged { .. }), acknowledged,
                        "{command}, stream={stream}: {remote:?}");
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
}

#[test]
fn cancellation_wait_does_not_extend_the_command_deadline() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use std::time::Instant;
    use oxish_client::RemoteStop;

    let mut connection = authenticated(&fixture());
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancelled);
    let timer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        flag.store(true, Ordering::SeqCst);
    });
    let start = Instant::now();
    let error = connection.exec("trap '' TERM; sleep 30", &ExecOptions {
        timeout: Some(Duration::from_secs(1)),
        interrupt: Some(Arc::new(move || cancelled.load(Ordering::SeqCst))),
        ..ExecOptions::default()
    }).expect_err("cancelled");
    timer.join().expect("timer");
    assert!(start.elapsed() < Duration::from_millis(1800), "{error:?}");
    assert!(matches!(error, Error::Cancelled {
        certainty: Certainty::Submitted, remote: RemoteStop::Unacknowledged
    }));
}
