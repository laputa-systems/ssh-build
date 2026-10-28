use core::{fmt, str};
use std::{borrow::Cow, sync::Arc};

use tracing::{debug, warn};

use crate::{
    Decode, Decoded, Encode, IncomingPacket, MessageType, ProtoError,
    crypto::{CryptoProvider, VerifyingKey},
    named::{MethodName, Named, OutgoingNameList, PublicKeyAlgorithm, ServiceName},
};

/// An authorized public key for a user
#[derive(Clone)]
pub struct AuthorizedKey {
    algorithm: PublicKeyAlgorithm<'static>,
    blob: Vec<u8>,
    key: Arc<dyn VerifyingKey>,
    /// Options from the `authorized_keys` entry this key came from
    pub options: KeyOptions,
}

impl AuthorizedKey {
    /// Build an `AuthorizedKey` from a string in the format used in `authorized_keys`
    pub fn from_str(s: &str, provider: &dyn CryptoProvider) -> Option<Self> {
        // Empty lines and lines starting with `#` are ignored (sshd(8)).
        // A line with `#` after leading whitespace can't be a valid key
        // line either, so skip it here too.
        let s = s.trim();
        if s.is_empty() || s.starts_with('#') {
            return None;
        }

        let (options, algorithm, rest) = KeyOptions::parse(s);
        let Some(algorithm) = algorithm else {
            debug!("missing algorithm");
            return None;
        };

        let Some(key_data) = rest.split_whitespace().next() else {
            debug!("missing key data");
            return None;
        };

        let Ok(blob) = data_encoding::BASE64.decode(key_data.as_bytes()) else {
            debug!("invalid base64 key data");
            return None;
        };

        let Ok(Decoded {
            value: key_type,
            next,
        }) = <&[u8]>::decode(&blob)
        else {
            debug!("failed to decode key blob");
            return None;
        };

        if key_type != algorithm.name().as_bytes() {
            debug!(?key_type, ?algorithm, "key type does not match algorithm");
            return None;
        }

        let key = match algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                let Ok(Decoded { next, .. }) = <&[u8]>::decode(next) else {
                    debug!("invalid public key data");
                    return None;
                };

                let Ok(Decoded { value, next }) = <&[u8]>::decode(next) else {
                    debug!("invalid public key data");
                    return None;
                };

                if !next.is_empty() {
                    debug!("trailing data after ECDSA public key");
                    return None;
                }

                let Ok(key) = provider.verifying_key(value, &algorithm) else {
                    debug!("failed to build verifying key");
                    return None;
                };

                key
            }
            PublicKeyAlgorithm::Ed25519 => {
                let Ok(Decoded { value, next }) = <&[u8]>::decode(next) else {
                    debug!("invalid public key data");
                    return None;
                };

                if !next.is_empty() {
                    debug!("trailing data after ED25519 public key");
                    return None;
                }

                let Ok(key) = provider.verifying_key(value, &algorithm) else {
                    debug!("failed to build verifying key");
                    return None;
                };

                key
            }
            PublicKeyAlgorithm::Unknown(_) => {
                debug!(?algorithm, "unsupported public key algorithm");
                return None;
            }
        };

        Some(Self {
            algorithm: algorithm.to_owned(),
            key,
            blob,
            options,
        })
    }

    /// Verify a signature over the given message
    pub fn verify(
        &self,
        message: SignatureInput,
        signature: EncodedSignature,
    ) -> Result<(), ProtoError> {
        self.key
            .verify(&message.0, &signature.0)
            .map_err(|_| ProtoError::InvalidPacket("invalid signature"))
    }

    /// Check whether the given public key matches this authorized key
    pub fn matches(&self, public_key: &PublicKey<'_>) -> bool {
        self.algorithm == public_key.algorithm && self.blob.as_slice() == public_key.key_blob
    }

    /// Whether two authorized keys hold the same public key, whatever their options
    pub fn same_key(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.blob == other.blob
    }

    /// Get the public key algorithm for this authorized key
    pub fn algorithm(&self) -> &PublicKeyAlgorithm<'_> {
        &self.algorithm
    }
}

impl fmt::Debug for AuthorizedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedKey")
            .field("algorithm", &self.algorithm)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

/// Options attached to a single entry in an `authorized_keys` file
///
/// Options precede the key type on a line and are separated by commas, as described in
/// <https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT>.
#[derive(Clone, Debug, Default)]
pub struct KeyOptions {
    /// The Git access the key grants (`git-access="read"` or `git-access="write"`)
    pub git_access: Option<GitAccess>,
}

/// What a key may do with Git repositories; writing implies reading
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GitAccess {
    /// Fetch and clone only
    Read,
    /// Fetch, clone, and push
    Write,
}

impl GitAccess {
    /// Whether this grant covers an operation needing `needed`
    pub fn allows(self, needed: Self) -> bool {
        self >= needed
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            _ => None,
        }
    }
}

impl KeyOptions {
    /// Parse the options and key type at the start of an `authorized_keys` line
    ///
    /// Options are separated by commas and take the form `name` or `name="value"`, where `\"`
    /// in a value stands for a literal quote. Names are case-insensitive. Whitespace is only
    /// allowed inside quoted values, and ends the options. Unknown, duplicate or malformed
    /// options invalidate the line, in which case no key type is returned.
    ///
    /// Returns the options, the key type and the rest of the line after the key type.
    fn parse(s: &str) -> (Self, Option<PublicKeyAlgorithm<'_>>, &str) {
        let (first, next) = s.split_once([' ', '\t']).unwrap_or((s, ""));
        match PublicKeyAlgorithm::typed(first) {
            PublicKeyAlgorithm::Unknown(_) => {}
            alg => return (Self::default(), Some(alg), next),
        }

        let mut options = Self::default();
        let mut rest = s;
        loop {
            let end = rest.find(['=', ',', ' ', '\t']).unwrap_or(rest.len());
            let (name, next) = rest.split_at(end);
            let (value, next) = match next.strip_prefix('=') {
                Some(next) => {
                    let Some(mut rest) = next.strip_prefix('"') else {
                        debug!("missing start quote in key option value");
                        return (options, None, rest);
                    };

                    let mut value = String::new();
                    loop {
                        let Some((literal, next)) = rest.split_once('"') else {
                            debug!("missing end quote in key option value");
                            return (options, None, rest);
                        };

                        let Some(literal) = literal.strip_suffix('\\') else {
                            value.push_str(literal);
                            break (Some(value), next);
                        };

                        value.push_str(literal);
                        value.push('"');
                        rest = next;
                    }
                }
                None => (None, next),
            };

            match (name.to_ascii_lowercase().as_str(), value) {
                ("git-access", Some(value)) if options.git_access.is_none() => {
                    let Some(access) = GitAccess::parse(&value) else {
                        debug!(value, "invalid git-access value");
                        return (options, None, rest);
                    };
                    options.git_access = Some(access)
                }
                _ => {
                    debug!(option = name, "invalid key option");
                    return (options, None, rest);
                }
            }

            match next.chars().next() {
                Some(',') => rest = &next[1..],
                Some(' ' | '\t') | None => {
                    let rest = next.trim_start();
                    let (key_type, rest) = rest.split_once([' ', '\t']).unwrap_or((rest, ""));
                    return match key_type.is_empty() {
                        true => (options, None, rest),
                        false => (options, Some(PublicKeyAlgorithm::typed(key_type)), rest),
                    };
                }
                Some(_) => {
                    debug!("unexpected character after key option");
                    return (options, None, next);
                }
            }
        }
    }
}

impl Encode for KeyOptions {
    fn encode(&self, buf: &mut Vec<u8>) {
        let tag: u8 = match self.git_access {
            None => 0,
            Some(GitAccess::Read) => 1,
            Some(GitAccess::Write) => 2,
        };
        buf.push(tag);
    }
}

impl Decode<'_> for KeyOptions {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Some((&tag, next)) = bytes.split_first() else {
            return Err(ProtoError::InvalidPacket("truncated key options"));
        };

        let git_access = match tag {
            0 => None,
            1 => Some(GitAccess::Read),
            2 => Some(GitAccess::Write),
            _ => return Err(ProtoError::InvalidPacket("invalid git access in key options")),
        };

        Ok(Decoded {
            value: Self { git_access },
            next,
        })
    }
}

/// The `SSH_MSG_USERAUTH_REQUEST` message
///
/// Sent by the client to start or continue authentication.
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-5>.
#[derive(Debug)]
pub struct UserAuthRequest<'a> {
    /// The user name to authenticate as
    pub user_name: &'a str,
    /// The service to start after authentication succeeds
    pub service_name: ServiceName<'a>,
    /// The authentication method and its method-specific data
    pub method: Method<'a>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for UserAuthRequest<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        packet.expect(&[MessageType::UserAuthRequest])?;

        let Decoded {
            value: user_name,
            next,
        } = <&[u8]>::decode(packet.payload)?;
        let user_name = str::from_utf8(user_name)
            .map_err(|_| ProtoError::InvalidPacket("invalid UTF-8 in user name"))?;

        let Decoded {
            value: service_name,
            next,
        } = ServiceName::decode(next)?;

        let Decoded {
            value: method_name,
            next,
        } = MethodName::decode(next)?;

        let method = match method_name {
            MethodName::PublicKey => {
                let Decoded {
                    value: public_key,
                    next,
                } = PublicKey::decode(next)?;

                if !next.is_empty() {
                    return Err(ProtoError::InvalidPacket(
                        "trailing bytes in public key auth request",
                    ));
                }

                Method::PublicKey(public_key)
            }
            MethodName::None => {
                if !next.is_empty() {
                    return Err(ProtoError::InvalidPacket(
                        "unexpected data after none auth method",
                    ));
                }
                Method::None
            }
            _ => {
                warn!(method = ?method_name, "unsupported authentication method");
                return Err(ProtoError::InvalidPacket(
                    "unsupported authentication method",
                ));
            }
        };

        Ok(UserAuthRequest {
            user_name,
            service_name,
            method,
        })
    }
}

/// Authentication method data from a [`UserAuthRequest`]
#[derive(Debug)]
pub enum Method<'a> {
    /// The `publickey` method
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
    PublicKey(PublicKey<'a>),
    /// The `none` method
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4252#section-5.2>.
    None,
}

/// Method-specific data for `publickey` authentication
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
#[derive(Debug)]
pub struct PublicKey<'a> {
    /// The public key algorithm name
    pub algorithm: PublicKeyAlgorithm<'a>,
    /// The public key blob, encoded per its algorithm
    pub key_blob: &'a [u8],
    /// The signature proving possession of the private key, if present
    pub signature: Option<Signature<'a>>,
}

impl<'a> Decode<'a> for PublicKey<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded {
            value: has_signature,
            next,
        } = bool::decode(input)?;

        let Decoded {
            value: algorithm,
            next,
        } = PublicKeyAlgorithm::decode(next)?;

        let Decoded {
            value: key_blob,
            next,
        } = <&[u8]>::decode(next)?;

        let (signature, next) = match (has_signature, next.is_empty()) {
            (false, true) => (None, next),
            (false, false) => {
                return Err(ProtoError::InvalidPacket(
                    "trailing bytes in public key auth without signature",
                ));
            }
            (true, _) => {
                let Decoded {
                    value: signature,
                    next,
                } = Signature::decode(next)?;

                if !next.is_empty() {
                    return Err(ProtoError::InvalidPacket(
                        "trailing bytes in public key auth with signature",
                    ));
                }

                (Some(signature), next)
            }
        };

        Ok(Decoded {
            value: PublicKey {
                algorithm,
                key_blob,
                signature,
            },
            next,
        })
    }
}

/// A signature over the [`SignatureData`] in a `publickey` authentication request
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
#[derive(Debug)]
pub struct Signature<'a> {
    /// The public key algorithm used to produce the signature
    pub algorithm: PublicKeyAlgorithm<'a>,
    /// The raw signature bytes
    pub signature_blob: &'a [u8],
}

impl Signature<'_> {
    /// Encode the signature for verification
    pub fn encode(self) -> Result<EncodedSignature, ProtoError> {
        Ok(EncodedSignature(match &self.algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                let Decoded {
                    value: r,
                    next: rest,
                } = <&[u8]>::decode(self.signature_blob)?;

                let Decoded { value: s, next } = <&[u8]>::decode(rest)?;
                if !next.is_empty() {
                    return Err(ProtoError::InvalidPacket(
                        "extra data after ECDSA signature components",
                    ));
                }

                let mut fixed = [0u8; 64];
                if mpint_to_fixed(r, &mut fixed[..64 / 2]).is_none() {
                    return Err(ProtoError::InvalidPacket(
                        "failure to decode r in ECDSA signature",
                    ));
                }

                if mpint_to_fixed(s, &mut fixed[64 / 2..]).is_none() {
                    return Err(ProtoError::InvalidPacket(
                        "failure to decode s in ECDSA signature",
                    ));
                }

                fixed.to_vec()
            }
            PublicKeyAlgorithm::Ed25519 => self.signature_blob.to_vec(),
            algorithm => {
                warn!(
                    ?algorithm,
                    "unsupported public key algorithm for verification"
                );
                return Err(ProtoError::InvalidPacket(
                    "unsupported public key algorithm for verification",
                ));
            }
        }))
    }
}

/// Convert an SSH mpint to a fixed-width big-endian representation
fn mpint_to_fixed(mpint: &[u8], out: &mut [u8]) -> Option<()> {
    let data = match mpint.split_first() {
        Some((&0, rest)) if !rest.is_empty() => rest,
        _ => mpint,
    };

    if data.len() > out.len() {
        return None;
    }

    let offset = out.len() - data.len();
    out[offset..].copy_from_slice(data);
    Some(())
}

impl<'a> Decode<'a> for Signature<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: input, next } = <&[u8]>::decode(input)?;
        if !next.is_empty() {
            return Err(ProtoError::InvalidPacket("extra data in signature data"));
        }

        let Decoded {
            value: algorithm,
            next,
        } = PublicKeyAlgorithm::decode(input)?;

        let Decoded {
            value: signature_blob,
            next,
        } = <&[u8]>::decode(next)?;

        if !next.is_empty() {
            return Err(ProtoError::InvalidPacket("extra data in signature blob"));
        }

        Ok(Decoded {
            value: Signature {
                algorithm,
                signature_blob,
            },
            next,
        })
    }
}

/// Encoded signature for public key authentication
///
/// Constructed by [`Signature::encode()`].
pub struct EncodedSignature(Vec<u8>);

/// The `SSH_MSG_USERAUTH_FAILURE` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-5.1>.
#[derive(Debug)]
pub struct UserAuthFailure<'a> {
    /// Authentication methods that may productively continue the exchange
    pub can_continue: &'a [MethodName<'a>],
    /// Whether the rejected request was itself successful
    pub partial_success: bool,
}

impl Encode for UserAuthFailure<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self {
            can_continue,
            partial_success,
        } = self;

        MessageType::UserAuthFailure.encode(buf);
        OutgoingNameList(can_continue).encode(buf);
        partial_success.encode(buf);
    }
}

/// The `SSH_MSG_USERAUTH_PK_OK` message
///
/// Confirms that the given public key would be acceptable for authentication.
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
#[derive(Debug)]
pub struct UserAuthPkOk<'a> {
    /// The public key algorithm name from the request
    pub algorithm: PublicKeyAlgorithm<'a>,
    /// The public key blob from the request
    pub key_blob: Cow<'a, [u8]>,
}

impl Encode for UserAuthPkOk<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self {
            algorithm,
            key_blob,
        } = self;

        MessageType::UserAuthPkOk.encode(buf);
        algorithm.encode(buf);
        key_blob.encode(buf);
    }
}

/// The data signed by the client for `publickey` authentication
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
pub struct SignatureData<'a> {
    /// The session identifier from the initial key exchange
    pub session_id: &'a [u8],
    /// The user name from the authentication request
    pub user_name: &'a str,
    /// The service name from the authentication request
    pub service_name: ServiceName<'a>,
    /// The public key algorithm name
    pub algorithm: PublicKeyAlgorithm<'a>,
    /// The public key blob
    pub public_key: &'a [u8],
}

impl<'a> SignatureData<'a> {
    /// Build the data that the client signs for public key authentication (RFC 4252 Section 7)
    pub fn encode(&self) -> SignatureInput {
        let mut buf = Vec::new();
        self.session_id.encode(&mut buf);
        MessageType::UserAuthRequest.encode(&mut buf);
        self.user_name.as_bytes().encode(&mut buf);
        self.service_name.encode(&mut buf);
        MethodName::PublicKey.encode(&mut buf);
        true.encode(&mut buf);
        self.algorithm.encode(&mut buf);
        self.public_key.encode(&mut buf);
        SignatureInput(buf)
    }
}

/// Encoded signature input for public key authentication
///
/// Constructed by [`SignatureData::encode()`].
pub struct SignatureInput(Vec<u8>);

/// The `SSH_MSG_SERVICE_ACCEPT` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-10>.
#[derive(Debug)]
pub struct ServiceAccept<'a> {
    /// The service name from the accepted request
    pub service_name: ServiceName<'a>,
}

impl Encode for ServiceAccept<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self { service_name } = self;
        MessageType::ServiceAccept.encode(buf);
        service_name.encode(buf);
    }
}

/// The `SSH_MSG_SERVICE_REQUEST` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-10>.
#[derive(Debug)]
pub struct ServiceRequest<'a> {
    /// The name of the service to start
    pub service_name: ServiceName<'a>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ServiceRequest<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        packet.expect(&[MessageType::ServiceRequest])?;

        let Decoded {
            value: service_name,
            next,
        } = ServiceName::decode(packet.payload)?;
        if !next.is_empty() {
            return Err(ProtoError::InvalidPacket("extra data in service request"));
        }

        Ok(ServiceRequest { service_name })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_options() {
        use GitAccess::{Read, Write};
        let cases: &[(&str, Option<Option<GitAccess>>)] = &[
            ("", Some(None)),
            (r#"git-access="read""#, Some(Some(Read))),
            (r#"GIT-ACCESS="write""#, Some(Some(Write))),
            ("git-access=\"read\"\t", Some(Some(Read))),
            (r#"git-access="admin""#, None),
            (r#"git-access="""#, None),
            (r#"git-access="Read""#, None),
            (r#"git-access="read",git-access="write""#, None),
            (r#"git-access="read" ,git-access="write""#, None),
            ("git-access", None),
            ("git-access=read", None),
            (r#"git-access="read"#, None),
            (r#"git-access="read"junk"#, None),
            (r#",git-access="read""#, None),
            (r#"git-access="read","#, None),
            (r#"git-access="read",,"#, None),
            (r#"command="echo hi""#, None),
            (r#"git-access="read",command="echo hi""#, None),
            ("no-pty", None),
            (r#"restrict,git-access="read""#, None),
            (r#"from="10.0.0.1",git-access="read""#, None),
            (r#"environment="A=b",git-access="read""#, None),
            (r#"permitopen="x:1",git-access="read""#, None),
        ];

        for (options, expected) in cases {
            let line = match options.is_empty() {
                true => format!("ssh-ed25519 {KEY}"),
                false => format!("{options} ssh-ed25519 {KEY}"),
            };

            let (parsed, key_type, rest) = KeyOptions::parse(&line);
            let parsed = match (key_type, rest) {
                (Some(PublicKeyAlgorithm::Ed25519), KEY) => Some(parsed.git_access),
                _ => None,
            };

            assert_eq!(
                parsed, *expected,
                "unexpected result for options {options:?}",
            );
        }
    }

    #[test]
    fn key_options_round_trip() {
        for git_access in [None, Some(GitAccess::Read), Some(GitAccess::Write)] {
            let mut buf = Vec::new();
            KeyOptions { git_access }.encode(&mut buf);
            let decoded = KeyOptions::decode(&buf).unwrap();
            assert_eq!(decoded.value.git_access, git_access);
            assert!(decoded.next.is_empty());
        }
        assert!(KeyOptions::decode(&[3]).is_err());
        assert!(KeyOptions::decode(&[]).is_err());
    }

    const KEY: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIMPdEXeWrpzl1Lgk7akX7+7x4B1eoyV5tyD6674DIh3R user@host";
}
