use std::time::Duration;

use oxish_client::{ClientConfig, Connection, Error, Fingerprint, HostTrust, KnownHosts};

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

fn fixture(suffix: &str) -> Fixture {
    Fixture {
        host: variable(&format!("XINFRA_FIXTURE_{suffix}_HOST")),
        port: variable(&format!("XINFRA_FIXTURE_{suffix}_PORT"))
            .parse()
            .expect("fixture port is a number"),
        pin: variable(&format!("XINFRA_FIXTURE_{suffix}_HOST_KEY")),
        user: variable("XINFRA_FIXTURE_USER"),
        key: variable("XINFRA_FIXTURE_KEY"),
    }
}

fn config(fixture: &Fixture, pin: &str) -> ClientConfig {
    ClientConfig::pinned(
        fixture.host.clone(),
        fixture.port,
        fixture.user.clone(),
        fixture.key.clone(),
        pin,
        Duration::from_secs(10),
    )
    .expect("test pin is valid")
}

#[test]
fn correct_pin_connects_to_both_fixtures() {
    for suffix in ["A", "B"] {
        let fixture = fixture(suffix);
        let connection = Connection::connect(&config(&fixture, &fixture.pin))
            .expect("pinned connection succeeds");
        assert_eq!(connection.fingerprint(), fixture.pin);
        assert!(connection.strict(), "strict key exchange is mandatory");
        assert!(!connection.session_id().is_empty());
        assert!(!connection.host_key_blob().is_empty());
    }
}

#[test]
fn another_fixture_pin_is_rejected() {
    let a = fixture("A");
    let b = fixture("B");
    match Connection::connect(&config(&a, &b.pin)) {
        Err(Error::HostKeyMismatch { expected, actual }) => {
            assert_eq!(expected, b.pin);
            assert_eq!(actual, a.pin);
        }
        Ok(_) => panic!("expected a host key mismatch, but the connection succeeded"),
        Err(other) => panic!("expected a host key mismatch, got {other:?}"),
    }
}

#[test]
fn changed_pin_is_rejected() {
    let fixture = fixture("A");
    let mut changed = fixture.pin.clone();
    let last = changed.pop().expect("pin has a fingerprint");
    changed.push(if last == 'A' { 'E' } else { 'A' });
    match Connection::connect(&config(&fixture, &changed)) {
        Err(Error::HostKeyMismatch { actual, .. }) => assert_eq!(actual, fixture.pin),
        Ok(_) => panic!("expected a host key mismatch, but the connection succeeded"),
        Err(other) => panic!("expected a host key mismatch, got {other:?}"),
    }
}

#[test]
fn missing_pin_is_rejected() {
    assert!(matches!(
        Fingerprint::parse(""),
        Err(Error::InvalidFingerprint { .. })
    ));
}

#[test]
fn malformed_pin_is_rejected() {
    assert!(matches!(
        Fingerprint::parse("SHA256:not-base64"),
        Err(Error::InvalidFingerprint { .. })
    ));
    assert!(matches!(
        Fingerprint::parse("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Err(Error::InvalidFingerprint { .. })
    ));
}

#[test]
fn hybrid_post_quantum_exchange_is_negotiated() {
    let fixture = fixture("A");
    let connection = Connection::connect(&config(&fixture, &fixture.pin)).expect("connects");
    let algorithms = connection.algorithms();
    assert_eq!(algorithms.kex, "mlkem768x25519-sha256");
    assert_eq!(algorithms.host_key, "ssh-ed25519");
    assert!(
        ["aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"]
            .contains(&algorithms.cipher_client_to_server.as_str())
    );
}

fn known_hosts_line(fixture_suffix: &str, marker: &str, key_suffix: &str) -> String {
    let host = variable(&format!("XINFRA_FIXTURE_{fixture_suffix}_HOST"));
    let port = variable(&format!("XINFRA_FIXTURE_{fixture_suffix}_PORT"));
    let public = variable(&format!("XINFRA_FIXTURE_{key_suffix}_HOST_KEY_PUB"));
    let key: Vec<&str> = public.split_whitespace().take(2).collect();
    format!("{marker}[{host}]:{port} {} {}\n", key[0], key[1])
}

fn known_hosts_config(fixture: &Fixture, text: &str) -> ClientConfig {
    let mut config = config(fixture, &fixture.pin);
    config.trust = HostTrust::KnownHosts(KnownHosts::parse(text).expect("known_hosts parses"));
    config
}

#[test]
fn a_known_hosts_entry_for_the_endpoint_connects() {
    let fixture = fixture("A");
    let text = known_hosts_line("A", "", "A") + &known_hosts_line("B", "", "B");
    let connection = Connection::connect(&known_hosts_config(&fixture, &text)).expect("connects");
    assert_eq!(connection.fingerprint(), fixture.pin);
}

#[test]
fn an_unknown_server_is_refused_before_authentication() {
    let fixture = fixture("A");
    let text = known_hosts_line("B", "", "B");
    match Connection::connect(&known_hosts_config(&fixture, &text)) {
        Err(Error::UnknownHostKey { fingerprint, .. }) => assert_eq!(fingerprint, fixture.pin),
        other => panic!("expected an unknown host key, got {other:?}"),
    }
}

#[test]
fn a_changed_server_key_is_refused_before_authentication() {
    let fixture = fixture("A");
    let text = known_hosts_line("A", "", "B");
    match Connection::connect(&known_hosts_config(&fixture, &text)) {
        Err(Error::HostKeyMismatch { actual, .. }) => assert_eq!(actual, fixture.pin),
        other => panic!("expected a host key mismatch, got {other:?}"),
    }
}

#[test]
fn a_revoked_server_key_is_refused_even_when_another_line_trusts_it() {
    let fixture = fixture("A");
    let text = known_hosts_line("A", "", "A") + &known_hosts_line("A", "@revoked ", "A");
    match Connection::connect(&known_hosts_config(&fixture, &text)) {
        Err(Error::RevokedHostKey { fingerprint }) => assert_eq!(fingerprint, fixture.pin),
        other => panic!("expected a revoked host key, got {other:?}"),
    }
}
