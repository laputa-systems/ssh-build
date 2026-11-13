use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use data_encoding::BASE64;
use zeroize::Zeroizing;
use oxish_proto::auth::SignatureData;
use oxish_proto::crypto::{CryptoProvider, SigningKey};
use oxish_proto::named::{MethodName, PublicKeyAlgorithm, ServiceName};
use oxish_proto::{Encode, MessageType, OpenSshKeyV1};

use crate::agent::Agent;
use crate::client::Connection;
use crate::error::Error;
use crate::host_key::Fingerprint;
use crate::wire::{SshReader, Transport, plain_text, put_string};

const SERVICE_USERAUTH: &str = "ssh-userauth";
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Load an unencrypted Ed25519 key from an OpenSSH private-key file.
pub fn load_key(
    path: &Path,
    provider: &dyn CryptoProvider,
) -> Result<Box<dyn SigningKey>, Error> {
    let text = read_key_file(path)?;
    if is_encrypted(&text) {
        return Err(Error::EncryptedKey);
    }
    let file = OpenSshKeyV1::from_str(&text).map_err(|error| Error::KeyFile {
        detail: format!("cannot parse {}: {error}", path.display()),
    })?;
    let pkcs8 = file
        .pkcs8_keys()
        .next()
        .ok_or_else(|| Error::KeyFile {
            detail: "key file contains no keys".to_owned(),
        })?;
    let key = provider
        .signing_key_from_pkcs8(&pkcs8)
        .map_err(|error| Error::KeyFile {
            detail: format!("cannot load {}: {error}", path.display()),
        })?;
    if key.algorithm() != PublicKeyAlgorithm::Ed25519 {
        return Err(Error::KeyFile {
            detail: "only Ed25519 keys are supported".to_owned(),
        });
    }
    Ok(key)
}

fn read_key_file(path: &Path) -> Result<Zeroizing<String>, Error> {
    let refuse = |detail: String| Error::KeyFile {
        detail: format!("{}: {detail}", path.display()),
    };
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)
        .map_err(|error| refuse(format!("cannot read: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| refuse(format!("cannot read: {error}")))?;
    if !metadata.is_file() {
        return Err(refuse("not a regular file".to_owned()));
    }
    if metadata.uid() == rustix::process::getuid().as_raw() && metadata.mode() & 0o077 != 0 {
        return Err(refuse(format!(
            "permissions {:04o} are too open; a private key must not be accessible by group or others",
            metadata.mode() & 0o7777
        )));
    }
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(refuse(format!("larger than {MAX_KEY_FILE_BYTES} bytes")));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_BYTES as usize + 1));
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refuse(format!("cannot read: {error}")))?;
    if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(refuse(format!("larger than {MAX_KEY_FILE_BYTES} bytes")));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| refuse("not text".to_owned()))?
        .to_owned();
    Ok(Zeroizing::new(text))
}

fn is_encrypted(text: &str) -> bool {
    if text.contains("Proc-Type: 4,ENCRYPTED") {
        return true;
    }
    let Some(body) = text
        .split("-----BEGIN OPENSSH PRIVATE KEY-----")
        .nth(1)
        .and_then(|rest| rest.split("-----END OPENSSH PRIVATE KEY-----").next())
    else {
        return false;
    };
    let mut compact = Zeroizing::new(String::with_capacity(body.len()));
    compact.extend(body.chars().filter(|character| !character.is_whitespace()));
    let Ok(size) = BASE64.decode_len(compact.len()) else {
        return false;
    };
    let mut decoded = Zeroizing::new(vec![0; size]);
    let Ok(size) = BASE64.decode_mut(compact.as_bytes(), &mut decoded) else {
        return false;
    };
    decoded.truncate(size);
    let Some(rest) = decoded.strip_prefix(b"openssh-key-v1\0") else {
        return false;
    };
    let Some(length) = rest.get(..4) else {
        return false;
    };
    let length = u32::from_be_bytes([length[0], length[1], length[2], length[3]]) as usize;
    let Some(cipher) = rest.get(4..4 + length) else {
        return false;
    };
    cipher != b"none"
}

/// Where the signing key lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// An unencrypted Ed25519 OpenSSH private-key file read by this process.
    KeyFile(PathBuf),
    /// One Ed25519 identity, chosen by fingerprint, held by a local ssh-agent.
    Agent {
        /// The agent's Unix socket.
        socket: PathBuf,
        /// The fingerprint of the identity to sign with.
        fingerprint: Fingerprint,
    },
}

struct Credential {
    public_key: Vec<u8>,
    sign: Box<dyn FnMut(&[u8]) -> Result<Vec<u8>, Error>>,
}

fn credential(
    identity: &Identity,
    transport: &Transport,
    provider: &dyn CryptoProvider,
) -> Result<Credential, Error> {
    match identity {
        Identity::KeyFile(path) => {
            let key = load_key(path, provider)?;
            let algorithm = key.algorithm();
            let mut public_key = Vec::new();
            algorithm.encode(&mut public_key);
            key.public_key().encode(&mut public_key);
            Ok(Credential {
                public_key,
                sign: Box::new(move |data| {
                    let mut signature = Vec::new();
                    key.algorithm().encode(&mut signature);
                    key.sign(data).as_slice().encode(&mut signature);
                    Ok(signature)
                }),
            })
        }
        Identity::Agent {
            socket,
            fingerprint,
        } => {
            let mut agent = Agent::connect_bounded(
                socket,
                transport.idle_timeout(),
                transport.deadline(),
                transport.interrupt(),
            )?;
            let mut chosen = None;
            for blob in agent.identities()? {
                if crate::host_key::fingerprint(&blob, provider)? == fingerprint.as_str() {
                    chosen = Some(blob);
                    break;
                }
            }
            let public_key = chosen.ok_or_else(|| Error::Agent {
                detail: format!("agent holds no identity {}", fingerprint.as_str()),
            })?;
            if SshReader::new(&public_key).string()? != b"ssh-ed25519" {
                return Err(Error::Agent {
                    detail: "only Ed25519 identities are supported".to_owned(),
                });
            }
            let blob = public_key.clone();
            Ok(Credential {
                public_key,
                sign: Box::new(move |data| agent.sign(&blob, data)),
            })
        }
    }
}

/// Authenticate the user with the chosen identity.
pub(crate) fn authenticate(
    connection: &mut Connection,
    user: &str,
    identity: &Identity,
    session_id: &[u8],
    provider: &dyn CryptoProvider,
) -> Result<(), Error> {
    let mut credential = credential(identity, connection.transport(), provider)?;

    connection.transport().send_raw(&service_request(SERVICE_USERAUTH))?;
    loop {
        let packet = connection.next_message()?;
        match packet.message_type {
            MessageType::ServiceAccept => {
                let mut reader = SshReader::new(&packet.payload);
                let service = reader.string()?;
                reader.finish()?;
                if service != SERVICE_USERAUTH.as_bytes() {
                    return Err(Error::Protocol {
                        detail: "server accepted a different service than the one requested"
                            .to_owned(),
                    });
                }
                break;
            }
            MessageType::UserAuthBanner => continue,
            MessageType::Disconnect => {
                return Err(Error::Authentication {
                    detail: "server disconnected before authentication".to_owned(),
                });
            }
            other => {
                return Err(Error::Protocol {
                    detail: format!("expected service accept, got {other:?}"),
                });
            }
        }
    }

    let algorithm = PublicKeyAlgorithm::Ed25519;
    let public_key = credential.public_key.clone();
    let signature_input = SignatureData {
        session_id,
        user_name: user,
        service_name: ServiceName::Connection,
        algorithm: algorithm.clone(),
        public_key: &public_key,
    }
    .encode();
    let signature = (credential.sign)(signature_input.as_bytes())?;

    let mut request = Vec::new();
    MessageType::UserAuthRequest.encode(&mut request);
    put_string(&mut request, user.as_bytes());
    ServiceName::Connection.encode(&mut request);
    MethodName::PublicKey.encode(&mut request);
    request.push(1);
    algorithm.encode(&mut request);
    put_string(&mut request, &public_key);
    put_string(&mut request, &signature);
    connection.transport().send_raw(&request)?;

    loop {
        let packet = connection.next_message()?;
        match packet.message_type {
            MessageType::UserAuthSuccess => return Ok(()),
            MessageType::UserAuthBanner => continue,
            MessageType::UserAuthFailure => {
                let mut reader = SshReader::new(&packet.payload);
                let methods = plain_text(&reader.name_list()?.join(","));
                let partial = reader.u8()? != 0;
                return Err(Error::Authentication {
                    detail: format!("server rejected publickey; methods={methods} partial={partial}"),
                });
            }
            MessageType::UserAuthPkOk => continue,
            MessageType::Disconnect => {
                return Err(Error::Authentication {
                    detail: "server disconnected during authentication".to_owned(),
                });
            }
            other => {
                return Err(Error::Protocol {
                    detail: format!("unexpected authentication message {other:?}"),
                });
            }
        }
    }
}

fn service_request(service: &str) -> Vec<u8> {
    let mut request = Vec::new();
    MessageType::ServiceRequest.encode(&mut request);
    put_string(&mut request, service.as_bytes());
    request
}
