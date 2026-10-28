use core::{fmt, ops::Deref, time::Duration};
use std::{borrow::Cow, io, path::Path, str};

use anyhow::Context as _;

use proto::{
    Disconnect, DisconnectReason, IncomingPacket, MessageType, ProtoError, WriteState,
    auth::{
        AuthorizedKey, KeyOptions, Method, ServiceAccept, ServiceRequest, SignatureData,
        UserAuthFailure, UserAuthPkOk, UserAuthRequest,
    },
    crypto::{CryptoError, CryptoProvider, Digest},
    named::{MethodName, PublicKeyAlgorithm, ServiceName},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::spawn_blocking,
    time::timeout,
};
use tracing::{debug, error, info, instrument, warn};

use crate::{Connection, Error, receive};

#[instrument(name = "authentication", skip(session_id, conn, account, provider), fields(addr = %conn.addr))]
pub(crate) async fn authenticate<T: AsyncRead + AsyncWrite + Unpin>(
    session_id: &Digest,
    conn: &mut Connection<T>,
    account: &Account,
    provider: &dyn CryptoProvider,
) -> anyhow::Result<Authenticated> {
    let mut state = AuthenticationState::default();
    let future = async {
        loop {
            let packet = receive(&mut conn.stream, &mut conn.read).await?;
            let handled = state
                .handle(
                    packet,
                    session_id,
                    &mut conn.write,
                    account,
                    provider,
                )
                .await;

            match (handled, conn.flush().await) {
                (Ok(AuthenticationState::Complete(auth)), Ok(())) => return Ok(auth),
                (Ok(next), Ok(())) => state = next,
                (Err(error), _) | (_, Err(error)) => return Err(error),
            }
        }
    };

    let (error, disconnect) = match timeout(AUTHENTICATION_TIMEOUT, future).await {
        Ok(Ok(auth)) => return Ok(auth),
        Ok(Err(error)) => {
            let disconnect = match &error {
                Error::Auth(AuthError::TooManyAttempts) => Disconnect {
                    reason_code: DisconnectReason::ByApplication,
                    description: "too many authentication attempts",
                },
                Error::InvalidState(description) => Disconnect {
                    reason_code: DisconnectReason::ByApplication,
                    description,
                },
                Error::InvalidUsername => Disconnect {
                    reason_code: DisconnectReason::IllegalUserName,
                    description: "invalid username",
                },
                Error::Proto(ProtoError::ServiceNotAvailable(description)) => Disconnect {
                    reason_code: DisconnectReason::ServiceNotAvailable,
                    description,
                },
                _ => Disconnect {
                    reason_code: DisconnectReason::ByApplication,
                    description: "authentication failed",
                },
            };

            (error, disconnect)
        }
        Err(_) => (
            Error::Io(io::Error::from(io::ErrorKind::TimedOut)),
            Disconnect {
                reason_code: DisconnectReason::ByApplication,
                description: "authentication timed out",
            },
        ),
    };

    conn.write.encode(&disconnect)?;
    let _ = timeout(Duration::from_secs(1), conn.flush()).await;
    Err(error.into())
}

#[derive(Default)]
enum AuthenticationState {
    #[default]
    AwaitServiceRequest,
    AwaitAuthRequest {
        attempts: u8,
    },
    Complete(Authenticated),
}

impl AuthenticationState {
    pub(crate) async fn handle(
        self,
        packet: IncomingPacket<'_>,
        session_id: &Digest,
        write: &mut WriteState,
        account: &Account,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, Error> {
        match (self, packet.message_type) {
            (state, MessageType::Ignore | MessageType::Debug) => Ok(state),
            (_, MessageType::Disconnect) => Err(AuthError::Canceled.into()),
            (Self::AwaitServiceRequest, MessageType::ServiceRequest) => {
                match ServiceRequest::try_from(packet)?.service_name {
                    ServiceName::UserAuth => {
                        write.encode(&ServiceAccept {
                            service_name: ServiceName::UserAuth,
                        })?;
                        Ok(Self::AwaitAuthRequest { attempts: MAX_ATTEMPTS })
                    }
                    service_name => {
                        error!(?service_name, "unsupported service requested");
                        Err(ProtoError::ServiceNotAvailable(
                            "only user authentication service is supported",
                        )
                        .into())
                    }
                }
            }
            (
                Self::AwaitAuthRequest { mut attempts },
                MessageType::UserAuthRequest,
            ) => {
                attempts -= 1;
                if attempts == 0 {
                    error!("too many authentication attempts");
                    return Err(AuthError::TooManyAttempts.into());
                }

                let user_auth_request = UserAuthRequest::try_from(packet)?;
                debug!(?user_auth_request, "received user auth request");
                if user_auth_request.service_name != ServiceName::Connection {
                    error!(
                        service_name = ?user_auth_request.service_name,
                        "unsupported service requested"
                    );

                    return Err(ProtoError::ServiceNotAvailable(
                        "only connection service is supported",
                    )
                    .into());
                }

                let Method::PublicKey(public_key) = user_auth_request.method else {
                    warn!(
                        method = ?user_auth_request.method,
                        "unsupported authentication method requested"
                    );
                    send_auth_failed(write)?;
                    return Ok(Self::AwaitAuthRequest { attempts });
                };

                let requested_user_matches = user_auth_request.user_name == &*account.name;
                if !requested_user_matches {
                    warn!(requested = user_auth_request.user_name, "requested user is not the Git account");
                }

                let authorized_key = match requested_user_matches {
                    true => account.keys.iter().find(|key| key.matches(&public_key)),
                    false => None,
                };
                let (sig, authorized_key, genuine) = match (public_key.signature, authorized_key) {
                    // Signature, authorized key => verify signature
                    (Some(sig), Some(key)) if &sig.algorithm == key.algorithm() => {
                        (sig, key.clone(), true)
                    }
                    // Signature, no authorized key => verify signature against fake key
                    (Some(sig), None) => (
                        sig,
                        match fake_key(&public_key.algorithm, provider) {
                            Ok(key) => key,
                            Err(_) => {
                                warn!(algorithm = ?public_key.algorithm, "unsupported public key algorithm");
                                send_auth_failed(write)?;
                                return Ok(Self::AwaitAuthRequest { attempts });
                            }
                        },
                        false,
                    ),
                    // Signature, authorized key but mismatched algorithms => fail authentication without verifying signature
                    (Some(_), Some(_)) => {
                        warn!(
                            algorithm = ?public_key.algorithm,
                            "mismatched signature algorithm in authentication request"
                        );
                        send_auth_failed(write)?;
                        return Ok(Self::AwaitAuthRequest { attempts });
                    }
                    // No signature, authorized key => send pk-ok and wait for signature
                    (None, Some(_)) => {
                        let pk_ok = UserAuthPkOk {
                            algorithm: public_key.algorithm.to_owned(),
                            key_blob: Cow::Owned(public_key.key_blob.to_vec()),
                        };
                        debug!(ok = ?pk_ok, "sending pk-ok for user");
                        write.encode(&pk_ok)?;
                        return Ok(Self::AwaitAuthRequest { attempts });
                    }
                    // No signature, no authorized key => fail authentication
                    (None, None) => {
                        send_auth_failed(write)?;
                        return Ok(Self::AwaitAuthRequest { attempts });
                    }
                };

                let message = SignatureData {
                    session_id: session_id.as_ref(),
                    user_name: user_auth_request.user_name,
                    service_name: user_auth_request.service_name,
                    algorithm: public_key.algorithm,
                    public_key: public_key.key_blob,
                }
                .encode();

                let signature = match sig.encode() {
                    Ok(signature) => signature,
                    Err(error) => {
                        debug!(%error, "failed to encode signature");
                        send_auth_failed(write)?;
                        return Ok(Self::AwaitAuthRequest { attempts });
                    }
                };

                let options = authorized_key.options.clone();
                match spawn_blocking(move || authorized_key.verify(message, signature)).await {
                    // The fake key only equalizes timing; a signature that verifies against it must
                    // never log anyone in.
                    Ok(Ok(())) if genuine => {
                        info!(user = %account.name, "authentication successful");

                        write.encode(&MessageType::UserAuthSuccess)?;
                        Ok(Self::Complete(Authenticated { options }))
                    }
                    _ => {
                        send_auth_failed(write)?;
                        Ok(Self::AwaitAuthRequest { attempts })
                    }
                }
            }
            (_, _) => {
                error!(
                    message_type = ?packet.message_type,
                    "unexpected packet received during authentication"
                );
                Err(Error::InvalidState(
                    "unexpected packet received during authentication",
                ))
            }
        }
    }
}

/// Build a fake key for the given `algorithm` to mitigate timing attacks
///
/// We want to execute a signature verification even when the user does not have a matching
/// authorized key, so we build a fake key for the requested algorithm and verify the
/// signature against it. This ensures that the response time is consistent regardless of
/// whether the user has a matching authorized key.
fn fake_key(
    algorithm: &PublicKeyAlgorithm<'_>,
    provider: &dyn CryptoProvider,
) -> Result<AuthorizedKey, CryptoError> {
    AuthorizedKey::from_str(
        match algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE4MlZd759Tv7GElTKPf1D0FCmDWB9LEkkWyaP3E8T0H/fKyFnA0e0yBm/XpkG9erfxrcgMkAu1CM3e19g9bZWg=",
            PublicKeyAlgorithm::Ed25519 => "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDX+GNCeikghR3A2bLB0KmlovqxdC+BUHAfYhYGcUJxA",
            _ => return Err(CryptoError::UnknownAlgorithm),
        },
        provider,
    )
    .ok_or(CryptoError::KeyRejected)
}

/// Encode a `SSH_MSG_USERAUTH_FAILURE` message
fn send_auth_failed(write: &mut WriteState) -> Result<(), ProtoError> {
    write.encode(&UserAuthFailure {
        can_continue: SUPPORTED_METHODS,
        partial_success: false,
    })
}

/// The one account that may authenticate, with the keys that may authenticate as it
pub struct Account {
    pub(crate) name: Username,
    pub(crate) keys: Vec<AuthorizedKey>,
}

impl Account {
    /// Build an account from already validated keys
    pub fn new(name: Username, keys: Vec<AuthorizedKey>) -> Self {
        Self { name, keys }
    }

    /// Load the account's keys from an `authorized_keys`-format file
    ///
    /// Fails closed: the file and its directory must belong to the server user and not be
    /// writable by anyone else, the file must not be a symlink, and every non-comment line
    /// must be a valid key carrying an explicit `git-access` option. Any other option, a
    /// duplicate option, or an unparsable line is an error rather than a skipped entry.
    pub fn from_file(
        name: Username,
        path: &Path,
        provider: &dyn CryptoProvider,
    ) -> anyhow::Result<Self> {
        use std::{
            fs::OpenOptions,
            io::Read as _,
            os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
        };

        let euid = rustix::process::geteuid().as_raw();
        let check = |meta: &std::fs::Metadata, what: &Path| -> anyhow::Result<()> {
            anyhow::ensure!(
                meta.uid() == euid && meta.mode() & 0o022 == 0,
                "{} must be owned by the server user and not writable by others",
                what.display()
            );
            Ok(())
        };

        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        check(&std::fs::metadata(parent).context("authorized keys directory")?, parent)?;

        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("failed to open authorized keys file `{}`", path.display()))?;
        let meta = file.metadata()?;
        anyhow::ensure!(meta.is_file(), "{} is not a regular file", path.display());
        check(&meta, path)?;
        anyhow::ensure!(meta.len() <= MAX_KEY_FILE_BYTES, "{} is too large", path.display());

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("failed to read `{}`", path.display()))?;

        let mut keys = Vec::new();
        for (index, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let number = index + 1;
            let key = AuthorizedKey::from_str(line, provider)
                .with_context(|| format!("{}:{number}: invalid key or unsupported option", path.display()))?;
            anyhow::ensure!(
                key.options.git_access.is_some(),
                "{}:{number}: missing git-access option",
                path.display()
            );
            anyhow::ensure!(
                !keys.iter().any(|existing: &AuthorizedKey| existing.same_key(&key)),
                "{}:{number}: duplicate key (a key may appear once, with one git-access)",
                path.display()
            );
            keys.push(key);
        }
        anyhow::ensure!(!keys.is_empty(), "{} contains no keys", path.display());
        anyhow::ensure!(keys.len() <= MAX_KEYS, "{} has too many keys", path.display());
        Ok(Self { name, keys })
    }
}

/// A successfully authenticated connection, with the options on the key it authenticated with
pub(crate) struct Authenticated {
    /// Options from the `authorized_keys` entry that matched
    pub(crate) options: KeyOptions,
}

/// A validated username
///
/// Must be valid UTF-8 without any ASCII control characters or slashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Username(String);

impl TryFrom<String> for Username {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.is_empty() || value.chars().any(|c| c.is_control() || c == '/') {
            true => Err(Error::InvalidUsername),
            false => Ok(Self(value)),
        }
    }
}

impl Deref for Username {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Errors that can occur during authentication
#[derive(Debug, Error)]
pub enum AuthError {
    /// The client canceled the authentication process
    #[error("canceled by the client")]
    Canceled,
    /// Too many authentication attempts for a single connection
    #[error("too many authentication attempts")]
    TooManyAttempts,
}

/// Authentication requests allowed per connection, including probes without a signature
const MAX_ATTEMPTS: u8 = 6;

/// Time from the end of key exchange to a successful public-key login
const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_KEY_FILE_BYTES: u64 = 1 << 20;
const MAX_KEYS: usize = 1024;

const SUPPORTED_METHODS: &[MethodName<'_>] = &[MethodName::PublicKey];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_PROVIDER;
    use proto::{Encode as _, auth::SignatureData};

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPdEXeWrpzl1Lgk7akX7+7x4B1eoyV5tyD6674DIh3R user@host";

    fn load(contents: &str, mode: u32) -> anyhow::Result<Account> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("authorized_keys");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let name = Username::try_from("git".to_owned()).unwrap();
        Account::from_file(name, &path, DEFAULT_PROVIDER)
    }

    #[test]
    fn authorized_keys_require_an_explicit_git_access() {
        assert_eq!(load(&format!("git-access=\"read\" {KEY}\n"), 0o600).unwrap().keys.len(), 1);
        const OTHER: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDX+GNCeikghR3A2bLB0KmlovqxdC+BUHAfYhYGcUJxA other@host";
        let two = format!("# comment\n\ngit-access=\"read\" {KEY}\ngit-access=\"write\" {OTHER}\n");
        assert_eq!(load(&two, 0o600).unwrap().keys.len(), 2);
        let duplicate = format!("git-access=\"read\" {KEY}\ngit-access=\"write\" {KEY}\n");
        assert!(load(&duplicate, 0o600).is_err());
        for bad in [
            format!("{KEY}\n"),
            format!("command=\"id\" {KEY}\n"),
            format!("git-access=\"read\",command=\"id\" {KEY}\n"),
            format!("git-access=\"read\",git-access=\"write\" {KEY}\n"),
            format!("git-access=\"admin\" {KEY}\n"),
            format!("restrict,git-access=\"read\" {KEY}\n"),
            format!("git-access=\"read\" {KEY}\ngarbage\n"),
            String::new(),
            "# only a comment\n".to_owned(),
        ] {
            assert!(load(&bad, 0o600).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn authorized_keys_file_must_be_private_and_not_a_symlink() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let line = format!("git-access=\"read\" {KEY}\n");
        assert!(load(&line, 0o660).is_err());
        assert!(load(&line, 0o666).is_err());
        assert!(load(&line, 0o644).is_ok());

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, &line).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let name = Username::try_from("git".to_owned()).unwrap();
        assert!(Account::from_file(name, &link, DEFAULT_PROVIDER).is_err());

        let open_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(open_dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let path = open_dir.path().join("authorized_keys");
        std::fs::write(&path, &line).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let name = Username::try_from("git".to_owned()).unwrap();
        assert!(Account::from_file(name, &path, DEFAULT_PROVIDER).is_err());
    }

    /// An Ed25519 key pair and the authorized-key entry that accepts it
    fn key_pair() -> (Box<dyn proto::crypto::SigningKey>, Vec<u8>, AuthorizedKey) {
        let (signing, _) = DEFAULT_PROVIDER
            .generate_signing_key(&PublicKeyAlgorithm::Ed25519)
            .unwrap();
        let mut blob = Vec::new();
        b"ssh-ed25519".as_slice().encode(&mut blob);
        signing.public_key().encode(&mut blob);
        let line = format!(
            "git-access=\"read\" ssh-ed25519 {}",
            data_encoding::BASE64.encode(&blob)
        );
        let key = AuthorizedKey::from_str(&line, DEFAULT_PROVIDER).unwrap();
        (signing, blob, key)
    }

    fn signed_by(signing: &dyn proto::crypto::SigningKey, session: &[u8], user: &str, blob: &[u8]) -> Result<Vec<u8>, ()> {
        let message = SignatureData {
            session_id: session,
            user_name: user,
            service_name: ServiceName::Connection,
            algorithm: PublicKeyAlgorithm::Ed25519,
            public_key: blob,
        }
        .encode();
        Ok(signing.sign(message.as_bytes()))
    }

    fn verifies(key: &AuthorizedKey, signature: &[u8], session: &[u8], user: &str, blob: &[u8]) -> bool {
        let message = SignatureData {
            session_id: session,
            user_name: user,
            service_name: ServiceName::Connection,
            algorithm: PublicKeyAlgorithm::Ed25519,
            public_key: blob,
        }
        .encode();
        let signature = proto::auth::Signature {
            algorithm: PublicKeyAlgorithm::Ed25519,
            signature_blob: signature,
        }
        .encode()
        .unwrap();
        key.verify(message, signature).is_ok()
    }

    #[test]
    fn forged_or_replayed_signatures_do_not_verify() {
        let (signing, blob, key) = key_pair();
        let genuine = signed_by(&*signing, b"session-1", "git", &blob).unwrap();
        assert!(verifies(&key, &genuine, b"session-1", "git", &blob));

        // Replayed on another session or for another user: the signed data differs.
        assert!(!verifies(&key, &genuine, b"session-2", "git", &blob));
        assert!(!verifies(&key, &genuine, b"session-1", "root", &blob));

        // A different key's signature over the same data.
        let (other, _, _) = key_pair();
        let forged = signed_by(&*other, b"session-1", "git", &blob).unwrap();
        assert!(!verifies(&key, &forged, b"session-1", "git", &blob));

        // Flipped bits and truncation.
        for index in 0..genuine.len() {
            let mut tampered = genuine.clone();
            tampered[index] ^= 0x01;
            assert!(!verifies(&key, &tampered, b"session-1", "git", &blob), "byte {index}");
        }
        assert!(!verifies(&key, &genuine[..genuine.len() - 1], b"session-1", "git", &blob));
        assert!(!verifies(&key, &[], b"session-1", "git", &blob));
    }

    #[test]
    fn usernames_are_plain() {
        for bad in ["", "a/b", "a\nb", "a\0b"] {
            assert!(Username::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
        assert!(Username::try_from("git".to_owned()).is_ok());
    }

    #[test]
    fn parse_fake_keys() {
        fake_key(&PublicKeyAlgorithm::EcdsaSha2Nistp256, DEFAULT_PROVIDER).unwrap();
        fake_key(&PublicKeyAlgorithm::Ed25519, DEFAULT_PROVIDER).unwrap();
    }
}
