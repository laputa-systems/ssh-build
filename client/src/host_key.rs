use data_encoding::BASE64_NOPAD;
use oxish_proto::crypto::{CryptoProvider, Digest, Hash};
use oxish_proto::named::{KeyExchangeAlgorithm, Named, PublicKeyAlgorithm};

use crate::error::Error;
use crate::known_hosts::{KnownHosts, Verdict};
use crate::wire::SshReader;

/// A `SHA256:` fingerprint of an SSH public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    value: String,
}

impl Fingerprint {
    /// Parse and canonicalize a `SHA256:` fingerprint.
    pub fn parse(value: &str) -> Result<Self, Error> {
        let value = value.trim();
        let Some(encoded) = value.strip_prefix("SHA256:") else {
            return Err(Error::InvalidFingerprint {
                detail: "fingerprint must start with SHA256:".to_owned(),
            });
        };
        let decoded = BASE64_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| Error::InvalidFingerprint {
                detail: "fingerprint is not unpadded base64".to_owned(),
            })?;
        if decoded.len() != 32 {
            return Err(Error::InvalidFingerprint {
                detail: "fingerprint must be a SHA-256 digest".to_owned(),
            });
        }
        Ok(Self {
            value: format!("SHA256:{}", BASE64_NOPAD.encode(&decoded)),
        })
    }

    /// The canonical fingerprint text.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Compute the fingerprint of an encoded host key blob.
    pub fn fingerprint(
        &self,
        host_key_blob: &[u8],
        provider: &dyn CryptoProvider,
    ) -> Result<String, Error> {
        fingerprint(host_key_blob, provider)
    }

    /// Whether `host_key_blob` matches this pin.
    pub fn matches(
        &self,
        host_key_blob: &[u8],
        provider: &dyn CryptoProvider,
    ) -> Result<bool, Error> {
        Ok(fingerprint(host_key_blob, provider)? == self.value)
    }
}

/// How the client decides that a server host key is the intended one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostTrust {
    /// Accept exactly the key with this fingerprint.
    Pinned(Fingerprint),
    /// Accept keys that a `known_hosts` file lists for the endpoint.
    KnownHosts(KnownHosts),
}

impl HostTrust {
    /// Fail unless the presented key is trusted for the endpoint.
    pub fn verify(
        &self,
        host: &str,
        port: u16,
        host_key_blob: &[u8],
        fingerprint: &str,
    ) -> Result<(), Error> {
        match self {
            Self::Pinned(pin) if pin.as_str() == fingerprint => Ok(()),
            Self::Pinned(pin) => Err(Error::HostKeyMismatch {
                expected: pin.as_str().to_owned(),
                actual: fingerprint.to_owned(),
            }),
            Self::KnownHosts(known) => match known.judge(host, port, host_key_blob) {
                Verdict::Trusted => Ok(()),
                Verdict::Revoked => Err(Error::RevokedHostKey {
                    fingerprint: fingerprint.to_owned(),
                }),
                Verdict::Changed => Err(Error::HostKeyMismatch {
                    expected: format!("a key listed for {host}"),
                    actual: fingerprint.to_owned(),
                }),
                Verdict::Unknown => Err(Error::UnknownHostKey {
                    host: host.to_owned(),
                    fingerprint: fingerprint.to_owned(),
                }),
            },
        }
    }
}

/// The SHA-256 fingerprint of an SSH public key blob.
pub fn fingerprint(host_key_blob: &[u8], provider: &dyn CryptoProvider) -> Result<String, Error> {
    let hash: &'static dyn Hash = provider.hash(&KeyExchangeAlgorithm::Curve25519Sha256)?;
    let mut context = hash.start();
    context.update(host_key_blob);
    let digest: Digest = context.finish();
    Ok(format!("SHA256:{}", BASE64_NOPAD.encode(digest.as_ref())))
}

/// Verify the server's signature over the exchange hash.
pub fn verify(
    host_key_blob: &[u8],
    signature_blob: &[u8],
    exchange_hash: &[u8],
    provider: &dyn CryptoProvider,
    expected_algorithm: &PublicKeyAlgorithm<'static>,
) -> Result<(), Error> {
    let mut key_reader = SshReader::new(host_key_blob);
    let key_algorithm = key_reader.text()?;
    let algorithm = PublicKeyAlgorithm::typed(key_algorithm).to_owned();
    let key = key_reader.string()?;
    key_reader.finish()?;

    if algorithm != *expected_algorithm {
        return Err(Error::HostKey {
            detail: format!("server used host key algorithm {algorithm:?}"),
        });
    }

    let mut signature_reader = SshReader::new(signature_blob);
    let signature_algorithm = signature_reader.text()?;
    let signature = signature_reader.string()?;
    signature_reader.finish()?;
    if signature_algorithm != key_algorithm {
        return Err(Error::HostKey {
            detail: "signature algorithm differs from host key algorithm".to_owned(),
        });
    }

    let verifying_key = provider.verifying_key(key, &algorithm)?;
    verifying_key
        .verify(exchange_hash, signature)
        .map_err(|error| Error::HostKey {
            detail: format!("server signature is invalid: {error}"),
        })
}
