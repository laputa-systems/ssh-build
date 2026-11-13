use graviola::key_agreement::{mlkem768, x25519};
use oxish_proto::crypto::{
    CryptoProvider, Digest, HandshakeBuffer, KeyDerivation, KeySourceSide, SharedSecret,
};
use oxish_proto::key_exchange::encode_mpint;
use oxish_proto::named::{EncryptionAlgorithm, KeyExchangeAlgorithm, Named, PublicKeyAlgorithm};
use oxish_proto::{Encode, MessageType};

use crate::error::Error;
use crate::host_key::{HostTrust, verify as verify_host_key};
use crate::channel::LOCAL_WINDOW;
use crate::wire::{Packet, SshReader, Transport, plain_text, put_string};
use zeroize::Zeroizing;

const HYBRID_KEX: &str = "mlkem768x25519-sha256";
const CLASSICAL_KEX: &str = "curve25519-sha256";
const KEX_ALGORITHMS: &[&str] = &[HYBRID_KEX, CLASSICAL_KEX, STRICT_KEX_CLIENT];
const HOST_KEY_ALGORITHMS: &[&str] = &["ssh-ed25519"];
const ENCRYPTION_ALGORITHMS: &[&str] = &[
    "aes128-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
];
const MAC_ALGORITHMS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
];
const COMPRESSION_ALGORITHMS: &[&str] = &["none"];
const STRICT_KEX_CLIENT: &str = "kex-strict-c-v00@openssh.com";
const STRICT_KEX_SERVER: &str = "kex-strict-s-v00@openssh.com";
const MLKEM768_CIPHERTEXT: usize = 1088;
const X25519_KEY: usize = 32;

/// The algorithms a connection negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Algorithms {
    /// The key-exchange method.
    pub kex: String,
    /// The host-key signature algorithm.
    pub host_key: String,
    /// The client-to-server cipher.
    pub cipher_client_to_server: String,
    /// The server-to-client cipher.
    pub cipher_server_to_client: String,
}

#[derive(Debug)]
struct ServerKexInit {
    kex: Vec<String>,
    host_key: Vec<String>,
    encryption_client_to_server: Vec<String>,
    encryption_server_to_client: Vec<String>,
    compression_client_to_server: Vec<String>,
    compression_server_to_client: Vec<String>,
    first_kex_packet_follows: bool,
}

#[derive(Debug)]
struct Negotiated {
    kex: KeyExchangeAlgorithm<'static>,
    host_key: PublicKeyAlgorithm<'static>,
    encryption_client_to_server: EncryptionAlgorithm<'static>,
    encryption_server_to_client: EncryptionAlgorithm<'static>,
    strict: bool,
    names: Algorithms,
}

/// The authenticated transport facts established by key exchange.
#[derive(Debug)]
pub struct Established {
    /// The session identifier used by authentication.
    pub session_id: Digest,
    /// The pinned host-key fingerprint.
    pub fingerprint: String,
    /// The server's encoded host key blob.
    pub host_key_blob: Vec<u8>,
    /// Whether strict key exchange was negotiated.
    pub strict: bool,
    /// The algorithms in force after this exchange.
    pub algorithms: Algorithms,
}

/// What a key exchange verifies against and runs on.
pub struct Context<'a> {
    /// The host name the client connected to.
    pub host: &'a str,
    /// The port the client connected to.
    pub port: u16,
    /// How the host key is trusted.
    pub trust: &'a HostTrust,
    /// The cryptographic provider.
    pub provider: &'a dyn CryptoProvider,
}

/// The identity of an established session, kept across rekeys.
pub struct Session<'a> {
    /// The session identifier from the first exchange.
    pub id: &'a [u8],
    /// Whether strict key exchange is in force.
    pub strict: bool,
    /// The host key the first exchange established; every later exchange must present it.
    pub host_key: &'a [u8],
}

enum ClientEphemeral {
    X25519 {
        private: x25519::PrivateKey,
        public: [u8; X25519_KEY],
    },
    Hybrid(Box<HybridEphemeral>),
}

struct HybridEphemeral {
    decapsulation: mlkem768::DecapKey,
    private: x25519::PrivateKey,
    public: Vec<u8>,
}

fn protocol(detail: impl Into<String>) -> Error {
    Error::Protocol {
        detail: detail.into(),
    }
}

impl ClientEphemeral {
    fn new(algorithm: &KeyExchangeAlgorithm<'static>) -> Result<Self, Error> {
        let private = x25519::PrivateKey::new_random()
            .map_err(|error| protocol(format!("cannot generate X25519 key: {error}")))?;
        let x25519_public = private.public_key().as_bytes();
        match algorithm {
            KeyExchangeAlgorithm::Curve25519Sha256 => Ok(Self::X25519 {
                private,
                public: x25519_public,
            }),
            KeyExchangeAlgorithm::MlKem768X25519Sha256 => {
                let decapsulation = mlkem768::DecapKey::generate()
                    .map_err(|error| protocol(format!("cannot generate ML-KEM key: {error}")))?;
                let mut public = decapsulation.encapsulation_key().as_bytes().to_vec();
                public.extend_from_slice(&x25519_public);
                Ok(Self::Hybrid(Box::new(HybridEphemeral {
                    decapsulation,
                    private,
                    public,
                })))
            }
            other => Err(Error::UnsupportedAlgorithm {
                category: "key exchange",
                name: other.name().to_owned(),
            }),
        }
    }

    fn public_key(&self) -> &[u8] {
        match self {
            Self::X25519 { public, .. } => public,
            Self::Hybrid(hybrid) => &hybrid.public,
        }
    }

    fn complete(
        self,
        peer_public_key: &[u8],
        provider: &dyn CryptoProvider,
        algorithm: &KeyExchangeAlgorithm<'static>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        match self {
            Self::X25519 { private, .. } => {
                let shared = agree(private, peer_public_key)?;
                let mut encoded = Zeroizing::new(Vec::new());
                encode_mpint(&shared, &mut encoded);
                Ok(encoded)
            }
            Self::Hybrid(hybrid) => {
                let HybridEphemeral {
                    decapsulation,
                    private,
                    ..
                } = *hybrid;
                if peer_public_key.len() != MLKEM768_CIPHERTEXT + X25519_KEY {
                    return Err(protocol("hybrid key-exchange reply has the wrong length"));
                }
                let (ciphertext, peer_x25519) = peer_public_key.split_at(MLKEM768_CIPHERTEXT);
                let ciphertext: [u8; MLKEM768_CIPHERTEXT] = ciphertext
                    .try_into()
                    .map_err(|_| protocol("hybrid key-exchange ciphertext has the wrong length"))?;
                let post_quantum = decapsulation.decaps(&mlkem768::Ciphertext::from(ciphertext));
                let classical = agree(private, peer_x25519)?;
                let mut context = provider.hash(algorithm)?.start();
                context.update(post_quantum.as_ref());
                context.update(&classical);
                let mut encoded = Zeroizing::new(Vec::new());
                context.finish().as_ref().encode(&mut encoded);
                Ok(encoded)
            }
        }
    }
}

fn agree(
    private: x25519::PrivateKey,
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let peer = x25519::PublicKey::try_from_slice(peer_public_key)
        .map_err(|error| protocol(format!("invalid X25519 peer key: {error}")))?;
    let shared = private
        .diffie_hellman(&peer)
        .map_err(|error| protocol(format!("X25519 key agreement failed: {error}")))?;
    Ok(Zeroizing::new(shared.as_bytes().to_vec()))
}

fn put_name_list(buffer: &mut Vec<u8>, names: &[&str]) {
    put_string(buffer, names.join(",").as_bytes());
}

fn kexinit_payload(provider: &dyn CryptoProvider) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    MessageType::KeyExchangeInit.encode(&mut buffer);
    let mut cookie = [0u8; 16];
    provider
        .secure_random()
        .fill(&mut cookie)
        .map_err(|error| protocol(format!("cannot generate KEXINIT cookie: {error}")))?;
    buffer.extend_from_slice(&cookie);
    put_name_list(&mut buffer, KEX_ALGORITHMS);
    put_name_list(&mut buffer, HOST_KEY_ALGORITHMS);
    put_name_list(&mut buffer, ENCRYPTION_ALGORITHMS);
    put_name_list(&mut buffer, ENCRYPTION_ALGORITHMS);
    put_name_list(&mut buffer, MAC_ALGORITHMS);
    put_name_list(&mut buffer, MAC_ALGORITHMS);
    put_name_list(&mut buffer, COMPRESSION_ALGORITHMS);
    put_name_list(&mut buffer, COMPRESSION_ALGORITHMS);
    put_name_list(&mut buffer, &[]);
    put_name_list(&mut buffer, &[]);
    buffer.push(0);
    buffer.extend_from_slice(&0u32.to_be_bytes());
    Ok(buffer)
}

fn parse_kexinit(payload: &[u8]) -> Result<ServerKexInit, Error> {
    let mut reader = SshReader::new(payload);
    for _ in 0..16 {
        reader.u8()?;
    }
    let kex = reader.name_list()?;
    let host_key = reader.name_list()?;
    let encryption_client_to_server = reader.name_list()?;
    let encryption_server_to_client = reader.name_list()?;
    let _mac_client_to_server = reader.name_list()?;
    let _mac_server_to_client = reader.name_list()?;
    let compression_client_to_server = reader.name_list()?;
    let compression_server_to_client = reader.name_list()?;
    let _language_client_to_server = reader.name_list()?;
    let _language_server_to_client = reader.name_list()?;
    let first_kex_packet_follows = reader.u8()? != 0;
    let _reserved = reader.u32()?;
    reader.finish()?;
    Ok(ServerKexInit {
        kex,
        host_key,
        encryption_client_to_server,
        encryption_server_to_client,
        compression_client_to_server,
        compression_server_to_client,
        first_kex_packet_follows,
    })
}

/// Parse a server `KEXINIT` payload and negotiate algorithms with it exactly as a client does.
pub fn negotiate_payload(payload: &[u8], require_strict: bool) -> Result<Algorithms, Error> {
    negotiate(&parse_kexinit(payload)?, require_strict).map(|negotiated| negotiated.names)
}

fn first_common(
    client: &[&str],
    server: &[String],
    category: &'static str,
) -> Result<String, Error> {
    client
        .iter()
        .find(|name| server.iter().any(|candidate| candidate == *name))
        .map(|name| (*name).to_owned())
        .ok_or_else(|| Error::UnsupportedAlgorithm {
            category,
            name: plain_text(&server.join(",")),
        })
}

fn negotiate(server: &ServerKexInit, require_strict: bool) -> Result<Negotiated, Error> {
    if server.first_kex_packet_follows {
        return Err(protocol("server sent a guessed key-exchange packet"));
    }
    let kex_name = first_common(KEX_ALGORITHMS, &server.kex, "key exchange")?;
    let kex = match kex_name.as_str() {
        HYBRID_KEX => KeyExchangeAlgorithm::MlKem768X25519Sha256,
        CLASSICAL_KEX => KeyExchangeAlgorithm::Curve25519Sha256,
        other => {
            return Err(Error::UnsupportedAlgorithm {
                category: "key exchange",
                name: other.to_owned(),
            });
        }
    };
    let host_key_name = first_common(HOST_KEY_ALGORITHMS, &server.host_key, "host key")?;
    let host_key = match host_key_name.as_str() {
        "ssh-ed25519" => PublicKeyAlgorithm::Ed25519,
        other => {
            return Err(Error::UnsupportedAlgorithm {
                category: "host key",
                name: other.to_owned(),
            });
        }
    };
    let c2s_name = first_common(
        ENCRYPTION_ALGORITHMS,
        &server.encryption_client_to_server,
        "client-to-server encryption",
    )?;
    let s2c_name = first_common(
        ENCRYPTION_ALGORITHMS,
        &server.encryption_server_to_client,
        "server-to-client encryption",
    )?;
    first_common(
        COMPRESSION_ALGORITHMS,
        &server.compression_client_to_server,
        "client-to-server compression",
    )?;
    first_common(
        COMPRESSION_ALGORITHMS,
        &server.compression_server_to_client,
        "server-to-client compression",
    )?;
    let strict = server.kex.iter().any(|name| name == STRICT_KEX_SERVER);
    if require_strict && !strict {
        return Err(Error::StrictKexUnsupported);
    }
    Ok(Negotiated {
        kex,
        host_key,
        encryption_client_to_server: encryption(&c2s_name)?,
        encryption_server_to_client: encryption(&s2c_name)?,
        strict,
        names: Algorithms {
            kex: kex_name,
            host_key: host_key_name,
            cipher_client_to_server: c2s_name,
            cipher_server_to_client: s2c_name,
        },
    })
}

fn encryption(name: &str) -> Result<EncryptionAlgorithm<'static>, Error> {
    match name {
        "aes128-gcm@openssh.com" => Ok(EncryptionAlgorithm::Aes128Gcm),
        "chacha20-poly1305@openssh.com" => Ok(EncryptionAlgorithm::Chacha20Poly1305),
        other => Err(Error::UnsupportedAlgorithm {
            category: "encryption",
            name: other.to_owned(),
        }),
    }
}

fn is_connection_layer(message_type: MessageType) -> bool {
    matches!(
        message_type,
        MessageType::GlobalRequest
            | MessageType::RequestSuccess
            | MessageType::RequestFailure
            | MessageType::ChannelOpen
            | MessageType::ChannelOpenConfirmation
            | MessageType::ChannelOpenFailure
            | MessageType::ChannelWindowAdjust
            | MessageType::ChannelData
            | MessageType::ChannelExtendedData
            | MessageType::ChannelEof
            | MessageType::ChannelClose
            | MessageType::ChannelRequest
            | MessageType::ChannelSuccess
            | MessageType::ChannelFailure
    )
}

const MAX_QUEUED_PACKETS: usize = 4096;
const MAX_QUEUED_BYTES: usize = LOCAL_WINDOW as usize + 256 * 1024;

struct Queue {
    packets: Vec<Packet>,
    bytes: usize,
    server_kexinit_seen: bool,
}

impl Queue {
    fn new(server_kexinit_seen: bool) -> Self {
        Self {
            packets: Vec::new(),
            bytes: 0,
            server_kexinit_seen,
        }
    }

    fn admit(&mut self, packet: Packet) -> Result<(), Error> {
        if self.server_kexinit_seen {
            return Err(protocol(format!(
                "server sent {:?} after its key-exchange init",
                packet.message_type
            )));
        }
        self.bytes += packet.payload.len() + 1;
        if self.packets.len() >= MAX_QUEUED_PACKETS || self.bytes > MAX_QUEUED_BYTES {
            return Err(protocol(
                "server sent more than the channel windows allow while the key exchange was starting",
            ));
        }
        self.packets.push(packet);
        Ok(())
    }
}

fn receive(
    transport: &mut Transport,
    expected: MessageType,
    mut queue: Option<&mut Queue>,
) -> Result<Packet, Error> {
    loop {
        let packet = transport.recv()?;
        if packet.message_type == expected {
            return Ok(packet);
        }
        match (&mut queue, packet.message_type) {
            (Some(queue), message_type) if is_connection_layer(message_type) => {
                queue.admit(packet)?;
            }
            (Some(_), MessageType::Ignore | MessageType::Debug | MessageType::Unimplemented) => {}
            (_, MessageType::Disconnect) => {
                return Err(protocol("server disconnected during key exchange"));
            }
            (_, other) => {
                return Err(protocol(format!("expected {expected:?}, got {other:?}")));
            }
        }
    }
}

/// Run client key exchange and verify the host key.
pub fn connect(transport: &mut Transport, context: &Context<'_>) -> Result<Established, Error> {
    exchange(transport, context, None, None, None)
}

/// Run a rekey. `server_kexinit` is the server's `KEXINIT` when the server started the exchange.
/// Connection-layer packets that arrive meanwhile are returned in order.
pub fn rekey(
    transport: &mut Transport,
    context: &Context<'_>,
    session: &Session<'_>,
    server_kexinit: Option<Packet>,
) -> Result<(Algorithms, Vec<Packet>), Error> {
    let mut queue = Queue::new(server_kexinit.is_some());
    let established = exchange(
        transport,
        context,
        Some(session),
        server_kexinit,
        Some(&mut queue),
    )?;
    Ok((established.algorithms, queue.packets))
}

fn exchange(
    transport: &mut Transport,
    context: &Context<'_>,
    session: Option<&Session<'_>>,
    server_kexinit: Option<Packet>,
    mut queued: Option<&mut Queue>,
) -> Result<Established, Error> {
    let provider = context.provider;
    let mut exchange: HandshakeBuffer = transport.handshake_buffer();
    let client_kexinit = kexinit_payload(provider)?;
    exchange.prefixed(&client_kexinit);
    let server_kexinit = match server_kexinit {
        Some(packet) => {
            transport.send_raw(&client_kexinit)?;
            packet
        }
        None => {
            transport.send_raw(&client_kexinit)?;
            let packet = receive(
                transport,
                MessageType::KeyExchangeInit,
                queued.as_deref_mut(),
            )?;
            if let Some(queue) = queued.as_deref_mut() {
                queue.server_kexinit_seen = true;
            }
            packet
        }
    };
    exchange.prefixed(&server_kexinit.encoded_payload());
    let server = parse_kexinit(&server_kexinit.payload)?;
    let negotiated = negotiate(&server, session.is_none())?;
    let strict = session.map_or(negotiated.strict, |session| session.strict);

    let hash_algorithm = provider.hash(&negotiated.kex)?;
    let mut exchange_hash = exchange.hash(hash_algorithm);

    let ephemeral = ClientEphemeral::new(&negotiated.kex)?;
    let client_public = ephemeral.public_key().to_vec();
    let mut init = Vec::new();
    MessageType::KeyExchangeEcdhInit.encode(&mut init);
    put_string(&mut init, &client_public);
    transport.send_raw(&init)?;

    let reply = receive(
        transport,
        MessageType::KeyExchangeEcdhReply,
        queued.as_deref_mut(),
    )?;
    let mut reader = SshReader::new(&reply.payload);
    let host_key_blob = reader.string()?.to_vec();
    let server_public = reader.string()?.to_vec();
    let signature_blob = reader.string()?.to_vec();
    reader.finish()?;

    if let Some(session) = session
        && session.host_key != host_key_blob
    {
        return Err(Error::HostKeyMismatch {
            expected: crate::host_key::fingerprint(session.host_key, provider)?,
            actual: crate::host_key::fingerprint(&host_key_blob, provider)?,
        });
    }
    exchange_hash.prefixed(&host_key_blob);
    exchange_hash.prefixed(&client_public);
    exchange_hash.prefixed(&server_public);
    let mut shared_secret = ephemeral.complete(&server_public, provider, &negotiated.kex)?;
    exchange_hash.update(&shared_secret);
    let exchange_digest = exchange_hash.finish();

    let fingerprint = crate::host_key::fingerprint(&host_key_blob, provider)?;
    context
        .trust
        .verify(context.host, context.port, &host_key_blob, &fingerprint)?;
    verify_host_key(
        &host_key_blob,
        &signature_blob,
        exchange_digest.as_ref(),
        provider,
        &negotiated.host_key,
    )?;

    let session_id = match session {
        Some(session) => Digest::new(session.id),
        None => exchange_digest.clone(),
    };
    let derivation = KeyDerivation {
        hash: hash_algorithm,
        shared_secret: SharedSecret::from(std::mem::take(&mut *shared_secret)),
        exchange_hash: exchange_digest,
        session_id: session_id.clone(),
    };
    let client_to_server =
        KeySourceSide::client_to_server(&derivation, negotiated.encryption_client_to_server)?;
    let server_to_client =
        KeySourceSide::server_to_client(&derivation, negotiated.encryption_server_to_client)?;

    transport.send_newkeys(strict)?;
    transport.install_sealer(&client_to_server, provider)?;
    receive(transport, MessageType::NewKeys, queued)?;
    transport.accept_newkeys(strict);
    transport.install_opener(&server_to_client, provider)?;

    Ok(Established {
        session_id,
        fingerprint,
        host_key_blob,
        strict,
        algorithms: negotiated.names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(kex: &[&str]) -> ServerKexInit {
        let names = |list: &[&str]| list.iter().map(|name| (*name).to_owned()).collect();
        ServerKexInit {
            kex: names(kex),
            host_key: names(&["ssh-ed25519"]),
            encryption_client_to_server: names(&["aes128-gcm@openssh.com"]),
            encryption_server_to_client: names(&["aes128-gcm@openssh.com"]),
            compression_client_to_server: names(&["none"]),
            compression_server_to_client: names(&["none"]),
            first_kex_packet_follows: false,
        }
    }

    #[test]
    fn hybrid_exchange_is_preferred_over_classical() {
        let server = offer(&[CLASSICAL_KEX, HYBRID_KEX, STRICT_KEX_SERVER]);
        let negotiated = negotiate(&server, true).expect("negotiates");
        assert_eq!(negotiated.names.kex, HYBRID_KEX);
    }

    #[test]
    fn classical_exchange_is_the_only_fallback() {
        let server = offer(&[CLASSICAL_KEX, "diffie-hellman-group14-sha256", STRICT_KEX_SERVER]);
        let negotiated = negotiate(&server, true).expect("negotiates");
        assert_eq!(negotiated.names.kex, CLASSICAL_KEX);
        let legacy = offer(&["diffie-hellman-group14-sha256", STRICT_KEX_SERVER]);
        assert!(matches!(
            negotiate(&legacy, true),
            Err(Error::UnsupportedAlgorithm { category: "key exchange", .. })
        ));
    }

    #[test]
    fn strict_exchange_is_mandatory_for_the_first_exchange_only() {
        let server = offer(&[HYBRID_KEX]);
        assert!(matches!(negotiate(&server, true), Err(Error::StrictKexUnsupported)));
        assert!(negotiate(&server, false).is_ok());
    }

    #[test]
    fn arbitrary_server_proposals_are_parsed_or_refused_never_panicked_on() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..4000 {
            let length = (next() % 200) as usize;
            let bytes: Vec<u8> = (0..length).map(|_| next() as u8).collect();
            let _ = parse_kexinit(&bytes);
        }
        let mut valid = vec![0u8; 16];
        for _ in 0..10 {
            valid.extend_from_slice(&0u32.to_be_bytes());
        }
        valid.push(0);
        valid.extend_from_slice(&0u32.to_be_bytes());
        assert!(parse_kexinit(&valid).is_ok());
        for cut in 0..valid.len() {
            assert!(parse_kexinit(&valid[..cut]).is_err(), "truncated at {cut}");
        }
    }

    #[test]
    fn a_guessed_packet_is_refused() {
        let mut server = offer(&[HYBRID_KEX, STRICT_KEX_SERVER]);
        server.first_kex_packet_follows = true;
        assert!(matches!(negotiate(&server, true), Err(Error::Protocol { .. })));
    }

    #[test]
    fn a_server_without_a_mandatory_none_compression_is_refused() {
        let mut server = offer(&[HYBRID_KEX, STRICT_KEX_SERVER]);
        server.compression_server_to_client = vec!["zlib@openssh.com".to_owned()];
        assert!(matches!(
            negotiate(&server, true),
            Err(Error::UnsupportedAlgorithm { category: "server-to-client compression", .. })
        ));
    }
}
