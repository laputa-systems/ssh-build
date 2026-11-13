use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use oxish_client::{Certainty, ClientConfig, Connection, Error, ExecStatus, StreamOptions};

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

fn authenticated(fixture: &Fixture) -> Connection {
    let config = ClientConfig::pinned(
        fixture.host.clone(),
        fixture.port,
        &fixture.user,
        &fixture.key,
        &fixture.pin,
        Duration::from_secs(10),
    )
    .expect("fixture pin is valid");
    let mut connection = Connection::connect(&config).expect("connection succeeds");
    connection.authenticate().expect("fixture key authenticates");
    connection
}

struct HashSink(Sha256);

impl HashSink {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn hex(self) -> String {
        hex(&self.0.finalize())
    }
}

impl Write for HashSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CountSink(usize);

impl Write for CountSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0 += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn pattern_file(path: &Path, size: usize) -> String {
    let mut file = File::create(path).expect("create artifact");
    let mut hash = Sha256::new();
    let mut block = vec![0u8; 1024 * 1024];
    let mut written = 0;
    let mut seed = 0u8;
    while written < size {
        for byte in &mut block {
            *byte = seed;
            seed = seed.wrapping_add(1);
        }
        let take = block.len().min(size - written);
        file.write_all(&block[..take]).expect("write artifact");
        hash.update(&block[..take]);
        written += take;
    }
    hex(&hash.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn large_echo_has_equal_digests_and_survives_rekey() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let directory = tempfile::tempdir().expect("tempdir");
    let artifact = directory.path().join("large.bin");
    let expected = pattern_file(&artifact, 128 * 1024 * 1024);
    let mut input = File::open(&artifact).expect("open artifact");
    let mut output = HashSink::new();
    let mut errors = io::sink();
    let result = connection
        .exec_stream(
            "cat",
            &StreamOptions {
                interrupt: None,
                env: Vec::new(),
                timeout: Some(Duration::from_secs(180)),
            },
            Some(&mut input),
            &mut output,
            &mut errors,
        )
        .expect("128 MiB echo succeeds");
    assert_eq!(result.status, ExecStatus::Exited(0));
    assert_eq!(output.hex(), expected);
}

#[test]
fn saturated_stderr_does_not_deadlock() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let mut output = io::sink();
    let mut errors = CountSink(0);
    let result = connection
        .exec_stream(
            "head -c 8388608 /dev/zero >&2",
            &StreamOptions {
                interrupt: None,
                env: Vec::new(),
                timeout: Some(Duration::from_secs(30)),
            },
            None,
            &mut output,
            &mut errors,
        )
        .expect("saturated stderr succeeds");
    assert_eq!(result.status, ExecStatus::Exited(0));
    assert_eq!(errors.0, 8 * 1024 * 1024);
}

#[test]
fn deadline_cancels_a_running_stream() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let mut output = io::sink();
    let mut errors = io::sink();
    match connection.exec_stream(
        "sleep 5",
        &StreamOptions {
                interrupt: None,
                env: Vec::new(),
            timeout: Some(Duration::from_millis(200)),
        },
        None,
        &mut output,
        &mut errors,
    ) {
        Err(Error::Timeout {
            certainty: Certainty::Submitted,
        }) => {}
        other => panic!("expected a submitted timeout, got {other:?}"),
    }
}

#[test]
fn large_stdin_is_hashed_remotely() {
    let fixture = fixture();
    let mut connection = authenticated(&fixture);
    let directory = tempfile::tempdir().expect("tempdir");
    let artifact = directory.path().join("large.bin");
    let expected = pattern_file(&artifact, 128 * 1024 * 1024);
    let mut input = File::open(&artifact).expect("open artifact");
    let mut output = Vec::new();
    let mut errors = io::sink();
    let result = connection
        .exec_stream(
            "sha256sum",
            &StreamOptions {
                interrupt: None,
                env: Vec::new(),
                timeout: Some(Duration::from_secs(180)),
            },
            Some(&mut input),
            &mut output,
            &mut errors,
        )
        .expect("128 MiB stdin succeeds");
    assert_eq!(result.status, ExecStatus::Exited(0));
    let text = String::from_utf8(output).expect("sha256sum output is text");
    assert_eq!(text.split_whitespace().next(), Some(expected.as_str()));
}
