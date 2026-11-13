#![allow(dead_code)]

use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tempfile::TempDir;
use oxish_client::oxish_proto::crypto::HandshakeBuffer;
use oxish_client::oxish_proto::{HostKeys, SessionHostKey};
use oxish_client::oxish_proto::key_exchange::{
    Established, Identities, InitialKeyExchangeState, KeyExchangeOutput, RekeyState,
};
use oxish_client::oxish_proto::named::PublicKeyAlgorithm;
use oxish_client::oxish_proto::{Completion, Encode, ProtoError, ReadState, WriteState};
use oxish_client::{ClientConfig, Connection, DEFAULT_PROVIDER, HostTrust, Identity, KnownHosts};
use zeroize::Zeroizing;

pub const DISCONNECT: u8 = 1;
pub const IGNORE: u8 = 2;
pub const SERVICE_REQUEST: u8 = 5;
pub const SERVICE_ACCEPT: u8 = 6;
pub const KEXINIT: u8 = 20;
pub const USERAUTH_REQUEST: u8 = 50;
pub const USERAUTH_SUCCESS: u8 = 52;
pub const USERAUTH_FAILURE: u8 = 51;
pub const USERAUTH_BANNER: u8 = 53;
pub const GLOBAL_REQUEST: u8 = 80;
pub const REQUEST_FAILURE: u8 = 82;
pub const CHANNEL_OPEN: u8 = 90;
pub const CHANNEL_CONFIRMATION: u8 = 91;
pub const CHANNEL_OPEN_FAILURE: u8 = 92;
pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const CHANNEL_DATA: u8 = 94;
pub const CHANNEL_EXTENDED_DATA: u8 = 95;
pub const CHANNEL_EOF: u8 = 96;
pub const CHANNEL_CLOSE: u8 = 97;
pub const CHANNEL_REQUEST: u8 = 98;
pub const CHANNEL_SUCCESS: u8 = 99;
pub const CHANNEL_FAILURE: u8 = 100;
pub const SERVER_CHANNEL: u32 = 7;
pub const REKEYED: u8 = 255;

struct Raw<'a>(&'a [u8]);

impl Encode for Raw<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.0);
    }
}

impl fmt::Debug for Raw<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Raw({})", self.0.len())
    }
}

pub fn text(value: &[u8]) -> Vec<u8> {
    let mut encoded = (value.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(value);
    encoded
}

pub fn message(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut payload = vec![kind];
    for part in parts {
        payload.extend_from_slice(part);
    }
    payload
}

pub fn number(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

#[derive(Clone, Copy, Default)]
pub struct Behavior {
    pub fragment_identification: bool,
    pub ignore_before_kexinit: bool,
    pub corrupt_signature: bool,
    pub rekey_with_another_host_key: bool,
    pub ignore_between_rekey_reply_and_newkeys: bool,
}

pub struct Peer {
    pub port: u16,
    pub pin: String,
    pub key: PathBuf,
    pub host_key_blob: Vec<u8>,
    pub other_host_key_blob: Vec<u8>,
    directory: TempDir,
    thread: Option<JoinHandle<()>>,
}

pub fn spawn(behavior: Behavior, script: impl FnOnce(&mut Link) + Send + 'static) -> Peer {
    let directory = tempfile::tempdir().expect("tempdir");
    let key = directory.path().join("client");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "scripted", "-f"])
        .arg(&key)
        .status()
        .expect("ssh-keygen runs");
    assert!(status.success(), "ssh-keygen failed");

    let provider = DEFAULT_PROVIDER;
    let (signing, pkcs8) = provider
        .generate_signing_key(&PublicKeyAlgorithm::Ed25519)
        .expect("host key");
    let mut blob = Vec::new();
    PublicKeyAlgorithm::Ed25519.encode(&mut blob);
    signing.public_key().encode(&mut blob);
    let pin = oxish_client::host_key::fingerprint(&blob, provider).expect("fingerprint");

    let (other_signing, other_pkcs8) = provider
        .generate_signing_key(&PublicKeyAlgorithm::Ed25519)
        .expect("second host key");
    let mut other_blob = Vec::new();
    PublicKeyAlgorithm::Ed25519.encode(&mut other_blob);
    other_signing.public_key().encode(&mut other_blob);

    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let port = listener.local_addr().expect("address").port();
    let thread = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("client connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("read timeout");
        let host_keys =
            HostKeys::new([Zeroizing::new(pkcs8)].into_iter(), provider).expect("host keys");
        let mut link = Link::establish(stream, behavior, &host_keys, &other_pkcs8);
        script(&mut link);
        link.linger();
    });
    Peer {
        port,
        pin,
        key,
        host_key_blob: blob,
        other_host_key_blob: other_blob,
        directory,
        thread: Some(thread),
    }
}

impl Peer {
    pub fn config(&self, timeout: Duration) -> ClientConfig {
        ClientConfig::pinned("127.0.0.1", self.port, "tester", &self.key, &self.pin, timeout)
            .expect("pin is valid")
    }

    pub fn known_hosts_config(&self, timeout: Duration) -> ClientConfig {
        let path = self.directory.path().join("known_hosts");
        let line = |blob: &[u8]| {
            format!(
                "[127.0.0.1]:{} ssh-ed25519 {}\n",
                self.port,
                data_encoding::BASE64.encode(blob)
            )
        };
        std::fs::write(
            &path,
            line(&self.host_key_blob) + &line(&self.other_host_key_blob),
        )
        .expect("known_hosts");
        let trust = HostTrust::KnownHosts(KnownHosts::from_file(&path).expect("known_hosts parses"));
        ClientConfig::new(
            "127.0.0.1",
            self.port,
            "tester",
            Identity::KeyFile(self.key.clone()),
            trust,
            timeout,
        )
    }

    pub fn connect(&self, timeout: Duration) -> Connection {
        let mut connection = Connection::connect(&self.config(timeout))
            .expect("scripted peer accepts the connection");
        connection.authenticate().expect("scripted peer accepts any key");
        connection
    }

    pub fn finish(mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("scripted peer finished its script");
        }
    }
}

pub struct Link {
    pub stream: TcpStream,
    read: ReadState,
    write: WriteState,
    rekey: Option<RekeyState>,
    ignore_before_newkeys: bool,
    pub rekeys: u32,
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub kind: u8,
    pub body: Vec<u8>,
}

impl Frame {
    pub fn u32_at(&self, offset: usize) -> u32 {
        u32::from_be_bytes(self.body[offset..offset + 4].try_into().expect("four bytes"))
    }

    pub fn string_at(&self, offset: usize) -> &[u8] {
        let length = self.u32_at(offset) as usize;
        &self.body[offset + 4..offset + 4 + length]
    }
}

pub struct OpenedExec {
    pub client_channel: u32,
    pub command: String,
}

impl Link {
    fn establish(
        mut stream: TcpStream,
        behavior: Behavior,
        host_keys: &HostKeys,
        other_pkcs8: &[u8],
    ) -> Self {
        let provider = DEFAULT_PROVIDER;
        let mut client_identification = Vec::new();
        while !client_identification.ends_with(b"\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).expect("client identification");
            client_identification.push(byte[0]);
        }
        client_identification.truncate(client_identification.len() - 2);
        let server_identification = b"SSH-2.0-scripted_peer".to_vec();

        let mut line = server_identification.clone();
        line.extend_from_slice(b"\r\n");
        if behavior.fragment_identification {
            let cut = line.len() - 1;
            for part in [&line[..5], &line[5..cut]] {
                stream.write_all(part).expect("identification fragment");
                stream.flush().expect("flush");
                thread::sleep(Duration::from_millis(50));
            }
            stream.write_all(&line[cut..]).expect("identification tail");
        } else {
            stream.write_all(&line).expect("identification");
        }

        if behavior.ignore_before_kexinit {
            stream
                .write_all(&[0, 0, 0, 12, 6, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                .expect("plaintext IGNORE");
        }

        let mut exchange = HandshakeBuffer::default();
        exchange.prefixed(&client_identification);
        exchange.prefixed(&server_identification);
        let identities = Identities {
            client: client_identification,
            server: server_identification,
        };
        let mut link = Self {
            stream,
            read: ReadState::default(),
            write: WriteState::new(provider.secure_random()),
            rekey: None,
            ignore_before_newkeys: behavior.ignore_between_rekey_reply_and_newkeys,
            rekeys: 0,
        };
        let mut state = InitialKeyExchangeState::new(exchange, identities, host_keys);
        let mut step = 0;
        let established = loop {
            let finished = match link.read.poll_packet() {
                Ok(Completion::Complete((sequence, length))) => {
                    let packet = link
                        .read
                        .decode_packet(sequence, length)
                        .expect("decode key exchange packet");
                    state
                        .handle(packet, &mut link.write, provider)
                        .expect("server key exchange step")
                }
                Ok(Completion::Incomplete(_)) | Err(ProtoError::Incomplete(_)) => {
                    link.pump_in().expect("key exchange input");
                    continue;
                }
                Err(error) => panic!("key exchange read: {error}"),
            };
            step += 1;
            if step == 2 && behavior.corrupt_signature {
                let packet_length =
                    u32::from_be_bytes(link.write.buffered()[..4].try_into().expect("length"));
                let padding = link.write.buffered()[4] as u32;
                let last_payload_byte = (4 + packet_length - padding - 1) as usize;
                let mut tampered = link.write.buffered().to_vec();
                tampered[last_payload_byte] ^= 0x01;
                link.stream.write_all(&tampered).expect("tampered reply");
                link.write.clear();
            }
            link.flush();
            if let Some(established) = finished {
                break established;
            }
        };
        let Established { output, update, .. } = established;
        let KeyExchangeOutput {
            identities,
            host_key,
            strict_kx,
            session_id,
            ..
        } = output;
        let host_key = if behavior.rekey_with_another_host_key {
            let mut encoded = Vec::new();
            encoded.extend_from_slice(&(other_pkcs8.len() as u32).to_be_bytes());
            encoded.extend_from_slice(other_pkcs8);
            SessionHostKey::decode(&encoded, provider)
                .expect("second session host key")
                .value
        } else {
            SessionHostKey::from_server(host_key, provider).expect("session host key")
        };
        update
            .apply(&mut link.write, &mut link.read)
            .expect("install keys");
        link.flush();
        link.rekey = Some(RekeyState::new(session_id, strict_kx, identities, host_key));
        link
    }

    fn flush(&mut self) {
        let buffered = self.write.buffered().to_vec();
        if !buffered.is_empty() {
            match self.stream.write_all(&buffered) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) => {}
                Err(error) => panic!("peer write: {error}"),
            }
            self.write.clear();
        }
    }

    fn pump_in(&mut self) -> Result<(), ProtoError> {
        let mut buffer = [0u8; 16_384];
        let read = self.stream.read(&mut buffer)?;
        if read == 0 {
            return Err(ProtoError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        self.read.buf.extend_from_slice(&buffer[..read]);
        Ok(())
    }

    pub fn try_recv(&mut self) -> Result<Frame, ProtoError> {
        loop {
            match self.read.poll_packet() {
                Ok(Completion::Complete((sequence, length))) => {
                    let packet = self.read.decode_packet(sequence, length)?;
                    let kind = u8::from(packet.message_type);
                    let rekeying = self.rekey.as_ref().is_some_and(RekeyState::in_progress);
                    if kind == KEXINIT || rekeying {
                        let state = self.rekey.as_mut().expect("rekey state");
                        let finished = state.handle(packet, &mut self.write, DEFAULT_PROVIDER)?;
                        self.flush();
                        if let Some(rekeyed) = finished {
                            if self.ignore_before_newkeys {
                                self.send(&[IGNORE, 0, 0, 0, 0]);
                            }
                            rekeyed.update.apply(&mut self.write, &mut self.read)?;
                            self.flush();
                            self.rekeys += 1;
                            return Ok(Frame {
                                kind: REKEYED,
                                body: Vec::new(),
                            });
                        }
                        continue;
                    }
                    return Ok(Frame {
                        kind,
                        body: packet.payload().to_vec(),
                    });
                }
                Ok(Completion::Incomplete(_)) | Err(ProtoError::Incomplete(_)) => self.pump_in()?,
                Err(error) => return Err(error),
            }
        }
    }

    pub fn linger(&mut self) {
        while self.try_recv().is_ok() {}
    }

    pub fn hangup(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    pub fn recv(&mut self) -> Frame {
        self.try_recv().expect("scripted peer reads a frame")
    }

    pub fn expect(&mut self, kind: u8) -> Frame {
        let frame = self.recv();
        assert_eq!(frame.kind, kind, "unexpected frame {frame:?}");
        frame
    }

    pub fn expect_reply(&mut self, kind: u8) -> Frame {
        loop {
            let frame = self.recv();
            if frame.kind != CHANNEL_EOF {
                assert_eq!(frame.kind, kind, "unexpected frame {frame:?}");
                return frame;
            }
        }
    }

    pub fn send(&mut self, payload: &[u8]) {
        self.write.encode(&Raw(payload)).expect("encode");
        self.flush();
    }

    pub fn send_with_flipped_tag(&mut self, payload: &[u8]) {
        self.write.encode(&Raw(payload)).expect("encode");
        let mut buffered = self.write.buffered().to_vec();
        let last = buffered.len() - 1;
        buffered[last] ^= 0x01;
        self.stream.write_all(&buffered).expect("peer write");
        self.write.clear();
    }

    /// Seal `payload` with exactly `padding` bytes of padding, whatever the block size requires.
    pub fn send_framed(&mut self, payload: &[u8], padding: usize) {
        let mut packet = ((1 + payload.len() + padding) as u32).to_be_bytes().to_vec();
        packet.push(padding as u8);
        packet.extend_from_slice(payload);
        packet.extend(std::iter::repeat_n(0x5a, padding));
        let sequence = self.write.sequence_number;
        let sealer = self.write.sealer.as_mut().expect("keys are installed");
        let mut tag = vec![0u8; sealer.tag_len()];
        sealer
            .seal_in_place(sequence, &mut packet, &mut tag)
            .expect("seal");
        self.write.sequence_number = sequence.wrapping_add(1);
        packet.extend_from_slice(&tag);
        self.stream.write_all(&packet).expect("peer write");
    }

    pub fn try_send(&mut self, payload: &[u8]) -> bool {
        if self.write.encode(&Raw(payload)).is_err() {
            return false;
        }
        let buffered = self.write.buffered().to_vec();
        self.write.clear();
        self.stream.write_all(&buffered).is_ok()
    }

    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("raw write");
    }

    pub fn accept_service(&mut self) {
        self.expect(SERVICE_REQUEST);
        self.send(&message(SERVICE_ACCEPT, &[&text(b"ssh-userauth")]));
    }

    pub fn accept_authentication(&mut self) {
        self.expect(SERVICE_REQUEST);
        self.send(&message(SERVICE_ACCEPT, &[&text(b"ssh-userauth")]));
        self.expect(USERAUTH_REQUEST);
        self.send(&[USERAUTH_SUCCESS]);
    }

    pub fn accept_exec(&mut self, window: u32, max_packet: u32) -> OpenedExec {
        let open = self.expect(CHANNEL_OPEN);
        let kind_length = open.u32_at(0) as usize;
        let client_channel = open.u32_at(4 + kind_length);
        self.send(&message(
            CHANNEL_CONFIRMATION,
            &[
                &number(client_channel),
                &number(SERVER_CHANNEL),
                &number(window),
                &number(max_packet),
            ],
        ));
        let request = self.expect(CHANNEL_REQUEST);
        assert_eq!(request.string_at(4), b"exec");
        let command = String::from_utf8(request.string_at(13).to_vec()).expect("utf-8 command");
        self.send(&message(CHANNEL_SUCCESS, &[&number(client_channel)]));
        OpenedExec {
            client_channel,
            command,
        }
    }

    pub fn expect_close(&mut self) {
        loop {
            let frame = self.recv();
            match frame.kind {
                CHANNEL_CLOSE => return,
                CHANNEL_EOF | CHANNEL_WINDOW_ADJUST | CHANNEL_DATA => {}
                other => panic!("unexpected frame {other} while waiting for close"),
            }
        }
    }

    pub fn data(&mut self, channel: u32, data: &[u8]) {
        self.send(&message(CHANNEL_DATA, &[&number(channel), &text(data)]));
    }

    pub fn extended_data(&mut self, channel: u32, data: &[u8]) {
        self.send(&message(
            CHANNEL_EXTENDED_DATA,
            &[&number(channel), &number(1), &text(data)],
        ));
    }

    pub fn exit_status(&mut self, channel: u32, status: u32) {
        self.send(&message(
            CHANNEL_REQUEST,
            &[&number(channel), &text(b"exit-status"), &[0], &number(status)],
        ));
    }

    pub fn eof(&mut self, channel: u32) {
        self.send(&message(CHANNEL_EOF, &[&number(channel)]));
    }

    pub fn close(&mut self, channel: u32) {
        self.send(&message(CHANNEL_CLOSE, &[&number(channel)]));
    }

    pub fn disconnect(&mut self) {
        self.send(&message(DISCONNECT, &[&number(11), &text(b"bye"), &text(b"")]));
    }
}

pub fn kexinit() -> Vec<u8> {
    let mut payload = vec![KEXINIT];
    payload.extend_from_slice(&[7; 16]);
    for names in [
        "curve25519-sha256",
        "ssh-ed25519",
        "aes128-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "none",
        "none",
        "",
        "",
    ] {
        payload.extend_from_slice(&text(names.as_bytes()));
    }
    payload.push(0);
    payload.extend_from_slice(&number(0));
    payload
}

pub fn peak_memory_growth<R>(run: impl FnOnce() -> R) -> (R, usize) {
    fn kibibytes(field: &str) -> usize {
        let status = std::fs::read_to_string("/proc/self/status").expect("status");
        status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
            .expect("status field")
    }
    std::fs::write("/proc/self/clear_refs", "5").expect("reset the peak resident size");
    let before = kibibytes("VmRSS:");
    let result = run();
    let peak = kibibytes("VmHWM:");
    (result, peak.saturating_sub(before) * 1024)
}
