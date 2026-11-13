use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;
use oxish_client::agent::Agent;
use oxish_client::{ClientConfig, Connection, Error, ExecOptions, ExecStatus, Fingerprint, Identity};

fn variable(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set; run this test through client/fixture/ssh-fixture.sh exec")
    })
}

struct RunningAgent {
    child: Child,
    socket: PathBuf,
    _directory: TempDir,
}

impl Drop for RunningAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_agent_holding(key: &Path, passphrase: &str) -> RunningAgent {
    let directory = tempfile::tempdir().expect("tempdir");
    let socket = directory.path().join("agent.sock");
    let child = Command::new("ssh-agent")
        .args(["-D", "-a"])
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("ssh-agent starts");
    let agent = RunningAgent {
        child,
        socket,
        _directory: directory,
    };
    for _ in 0..100 {
        if agent.socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let askpass = agent._directory.path().join("askpass");
    std::fs::write(&askpass, format!("#!/bin/sh\necho '{passphrase}'\n")).expect("askpass");
    Command::new("chmod").args(["700"]).arg(&askpass).status().expect("chmod");
    let status = Command::new("ssh-add")
        .arg(key)
        .env("SSH_AUTH_SOCK", &agent.socket)
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "unused")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("ssh-add runs");
    assert!(status.success(), "ssh-add failed");
    agent
}

fn fingerprint_of(public_key_file: &Path) -> Fingerprint {
    let output = Command::new("ssh-keygen")
        .args(["-lf"])
        .arg(public_key_file)
        .output()
        .expect("ssh-keygen -l");
    let text = String::from_utf8(output.stdout).expect("utf-8");
    Fingerprint::parse(text.split_whitespace().nth(1).expect("fingerprint field")).expect("valid")
}

fn config_with(identity: Identity) -> ClientConfig {
    let mut config = ClientConfig::pinned(
        variable("XINFRA_FIXTURE_A_HOST"),
        variable("XINFRA_FIXTURE_A_PORT").parse().expect("port"),
        variable("XINFRA_FIXTURE_USER"),
        variable("XINFRA_FIXTURE_KEY"),
        &variable("XINFRA_FIXTURE_A_HOST_KEY"),
        Duration::from_secs(10),
    )
    .expect("fixture pin is valid");
    config.identity = identity;
    config
}

#[test]
fn an_encrypted_identity_signs_through_the_agent() {
    let key = PathBuf::from(variable("XINFRA_FIXTURE_AGENT_KEY"));
    let agent = start_agent_holding(&key, &variable("XINFRA_FIXTURE_AGENT_PASSPHRASE"));
    let identity = Identity::Agent {
        socket: agent.socket.clone(),
        fingerprint: fingerprint_of(&key.with_extension("pub")),
    };
    let mut connection = Connection::connect(&config_with(identity)).expect("connects");
    connection.authenticate().expect("the agent signs for the encrypted identity");
    let result = connection
        .exec("id -un", &ExecOptions::default())
        .expect("exec succeeds");
    assert_eq!(result.status, ExecStatus::Exited(0));
    assert_eq!(result.stdout, b"xinfra\n");
}

#[test]
fn an_identity_the_agent_does_not_hold_is_refused() {
    let key = PathBuf::from(variable("XINFRA_FIXTURE_AGENT_KEY"));
    let agent = start_agent_holding(&key, &variable("XINFRA_FIXTURE_AGENT_PASSPHRASE"));
    let other = PathBuf::from(variable("XINFRA_FIXTURE_KEY"));
    let identity = Identity::Agent {
        socket: agent.socket.clone(),
        fingerprint: fingerprint_of(&other.with_extension("pub")),
    };
    let mut connection = Connection::connect(&config_with(identity)).expect("connects");
    match connection.authenticate() {
        Err(Error::Agent { detail }) => assert!(detail.contains("no identity"), "{detail}"),
        other => panic!("expected an agent error, got {other:?}"),
    }
}

#[test]
fn a_missing_agent_is_a_clear_error() {
    let missing = Path::new("/nonexistent/agent.sock");
    match Agent::connect(missing, Duration::from_secs(1)) {
        Err(Error::Agent { detail }) => assert!(detail.contains("cannot connect"), "{detail}"),
        Err(other) => panic!("expected an agent error, got {other:?}"),
        Ok(_) => panic!("connected to a missing agent"),
    }
}

fn fake_agent(reply: Vec<u8>) -> (PathBuf, TempDir, thread::JoinHandle<()>) {
    let directory = tempfile::tempdir().expect("tempdir");
    let socket = directory.path().join("fake.sock");
    let listener = UnixListener::bind(&socket).expect("bind");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).expect("request length");
        let mut request = vec![0u8; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut request).expect("request");
        let _ = stream.write_all(&reply);
    });
    (socket, directory, handle)
}

#[test]
fn an_oversized_agent_reply_is_refused_without_reading_it() {
    let (socket, _directory, handle) = fake_agent(u32::MAX.to_be_bytes().to_vec());
    let mut agent = Agent::connect(&socket, Duration::from_secs(2)).expect("connects");
    match agent.identities() {
        Err(Error::Agent { detail }) => assert!(detail.contains("out of bounds"), "{detail}"),
        other => panic!("expected an agent error, got {other:?}"),
    }
    handle.join().expect("fake agent");
}

#[test]
fn an_agent_that_lists_too_many_identities_is_refused() {
    let mut body = vec![12u8];
    body.extend_from_slice(&5000u32.to_be_bytes());
    let mut reply = (body.len() as u32).to_be_bytes().to_vec();
    reply.extend_from_slice(&body);
    let (socket, _directory, handle) = fake_agent(reply);
    let mut agent = Agent::connect(&socket, Duration::from_secs(2)).expect("connects");
    match agent.identities() {
        Err(Error::Agent { detail }) => assert!(detail.contains("5000"), "{detail}"),
        other => panic!("expected an agent error, got {other:?}"),
    }
    handle.join().expect("fake agent");
}

#[test]
fn a_malformed_signature_from_the_agent_is_refused() {
    let mut inner = Vec::new();
    for part in [&b"ssh-ed25519"[..], &[0u8; 10][..]] {
        inner.extend_from_slice(&(part.len() as u32).to_be_bytes());
        inner.extend_from_slice(part);
    }
    let mut body = vec![14u8];
    body.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    body.extend_from_slice(&inner);
    let mut reply = (body.len() as u32).to_be_bytes().to_vec();
    reply.extend_from_slice(&body);
    let (socket, _directory, handle) = fake_agent(reply);
    let mut agent = Agent::connect(&socket, Duration::from_secs(2)).expect("connects");
    match agent.sign(b"blob", b"data") {
        Err(Error::Agent { detail }) => assert!(detail.contains("malformed"), "{detail}"),
        other => panic!("expected an agent error, got {other:?}"),
    }
    handle.join().expect("fake agent");
}
