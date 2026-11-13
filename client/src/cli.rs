use std::path::PathBuf;
use std::time::Duration;

use crate::wire::Interrupt;
use crate::{ClientConfig, Error, Fingerprint, HostTrust, Identity, KnownHosts};

/// How the server's host key is trusted. There is no trust on first use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// One `SHA256:` fingerprint.
    Pinned(String),
    /// An OpenSSH `known_hosts` file.
    KnownHosts(PathBuf),
}

/// How the client proves its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// An unencrypted Ed25519 private key file.
    Key(PathBuf),
    /// An ssh-agent socket and the fingerprint of the identity to use.
    Agent {
        /// The agent's socket.
        socket: PathBuf,
        /// The `SHA256:` fingerprint of the identity.
        identity: String,
    },
}

/// The port, credential and trust a command line named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    /// The SSH port.
    pub port: u16,
    /// The identity.
    pub credential: Credential,
    /// The host-key trust.
    pub trust: Trust,
}

/// Take the value of `option` from the argument stream.
pub fn value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{option} needs a value"))
}

/// Split `user@host`, both parts non-empty.
pub fn split_target(target: &str) -> Result<(String, String), String> {
    match target.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() && !host.is_empty() => {
            Ok((user.to_owned(), host.to_owned()))
        }
        _ => Err("the target must be user@host".to_owned()),
    }
}

/// Collects the connection flags every OxiSH client shares: the port flag the tool chooses,
/// `-i`, `--agent`, `--agent-identity`, `--host-key` and `--known-hosts`.
#[derive(Debug, Clone)]
pub struct ConnectArgs {
    port_flag: &'static str,
    port: u16,
    key: Option<PathBuf>,
    agent: Option<PathBuf>,
    agent_identity: Option<String>,
    host_key: Option<String>,
    known_hosts: Option<PathBuf>,
}

impl ConnectArgs {
    /// Start with port 22. `port_flag` is `-p` for `oxish` and `-P` for `oxish-sftp` and
    /// `oxish-scp`, as in OpenSSH.
    pub fn new(port_flag: &'static str) -> Self {
        Self {
            port_flag,
            port: 22,
            key: None,
            agent: None,
            agent_identity: None,
            host_key: None,
            known_hosts: None,
        }
    }

    /// Consume `flag` and its value when it is a connection flag. Returns whether it was.
    pub fn accept(
        &mut self,
        flag: &str,
        args: &mut impl Iterator<Item = String>,
    ) -> Result<bool, String> {
        if flag == self.port_flag {
            self.port = value(args, flag)?
                .parse()
                .map_err(|_| format!("{flag} needs a port number"))?;
            return Ok(true);
        }
        match flag {
            "-i" => self.key = Some(PathBuf::from(value(args, flag)?)),
            "--agent" => self.agent = Some(PathBuf::from(value(args, flag)?)),
            "--agent-identity" => self.agent_identity = Some(value(args, flag)?),
            "--host-key" => self.host_key = Some(value(args, flag)?),
            "--known-hosts" => self.known_hosts = Some(PathBuf::from(value(args, flag)?)),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Check the flags against each other and fill in the default key.
    pub fn finish(self) -> Result<Connect, String> {
        let credential = match (self.key, self.agent, self.agent_identity) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err("-i and --agent are exclusive".to_owned());
            }
            (None, Some(socket), Some(identity)) => Credential::Agent { socket, identity },
            (None, Some(_), None) => return Err("--agent needs --agent-identity".to_owned()),
            (None, None, Some(_)) => return Err("--agent-identity needs --agent".to_owned()),
            (Some(key), None, None) => Credential::Key(key),
            (None, None, None) => {
                let home =
                    std::env::var_os("HOME").ok_or_else(|| "no -i and HOME is unset".to_owned())?;
                Credential::Key(PathBuf::from(home).join(".ssh/id_ed25519"))
            }
        };
        let trust = match (self.host_key, self.known_hosts) {
            (Some(pin), None) => Trust::Pinned(pin),
            (None, Some(path)) => Trust::KnownHosts(path),
            (None, None) => return Err("one of --host-key and --known-hosts is required".to_owned()),
            (Some(_), Some(_)) => return Err("--host-key and --known-hosts are exclusive".to_owned()),
        };
        Ok(Connect {
            port: self.port,
            credential,
            trust,
        })
    }
}

impl Connect {
    /// The connection configuration for `user@host`, with trust and identity loaded.
    pub fn config(
        &self,
        host: &str,
        user: &str,
        timeout: Duration,
        interrupt: Option<Interrupt>,
    ) -> Result<ClientConfig, Error> {
        let identity = match &self.credential {
            Credential::Key(path) => Identity::KeyFile(path.clone()),
            Credential::Agent { socket, identity } => Identity::Agent {
                socket: socket.clone(),
                fingerprint: Fingerprint::parse(identity)?,
            },
        };
        let trust = match &self.trust {
            Trust::Pinned(pin) => HostTrust::Pinned(Fingerprint::parse(pin)?),
            Trust::KnownHosts(path) => HostTrust::KnownHosts(KnownHosts::from_file(path)?),
        };
        let mut config = ClientConfig::new(host, self.port, user, identity, trust, timeout);
        config.interrupt = interrupt;
        Ok(config)
    }
}

/// A `[user@]host[:path]` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSpec {
    /// The user, when the argument names one.
    pub user: Option<String>,
    /// The host name or address, without brackets.
    pub host: String,
    /// The path after the colon, empty when none.
    pub path: String,
}

/// Read an scp-style `[user@]host:path` argument, or return `None` when it names a local path.
///
/// An argument is local when it has no colon, when a slash comes before the first colon, or
/// when the host part is empty. IPv6 addresses go in brackets: `user@[::1]:path`.
pub fn parse_remote(argument: &str) -> Option<RemoteSpec> {
    if let Some(open) = argument.find('[') {
        let prefix = &argument[..open];
        let plain = prefix.is_empty() || (prefix.ends_with('@') && !prefix.contains(['/', ':']));
        if plain {
            let close = open + argument[open..].find(']')?;
            let path = argument[close + 1..].strip_prefix(':')?;
            let host = &argument[open + 1..close];
            if host.is_empty() {
                return None;
            }
            let user = prefix.strip_suffix('@').filter(|user| !user.is_empty());
            return Some(RemoteSpec {
                user: user.map(str::to_owned),
                host: host.to_owned(),
                path: path.to_owned(),
            });
        }
    }
    let colon = argument.find(':')?;
    let head = &argument[..colon];
    if head.contains('/') {
        return None;
    }
    let (user, host) = split_user(head);
    if host.is_empty() || host.contains('@') {
        return None;
    }
    Some(RemoteSpec {
        user,
        host: host.to_owned(),
        path: argument[colon + 1..].to_owned(),
    })
}

/// Read the `[user@]host[:path]` argument of `oxish-sftp`, where the colon and path are optional.
pub fn parse_host_argument(argument: &str) -> Result<RemoteSpec, String> {
    let spec = match parse_remote(argument) {
        Some(spec) => spec,
        None => {
            let (user, host) = split_user(argument);
            let host = host
                .strip_prefix('[')
                .and_then(|inner| inner.strip_suffix(']'))
                .unwrap_or(host);
            RemoteSpec {
                user,
                host: host.to_owned(),
                path: String::new(),
            }
        }
    };
    if spec.host.is_empty() || spec.host.contains('/') {
        return Err("the target must be [user@]host[:path]".to_owned());
    }
    Ok(spec)
}

fn split_user(head: &str) -> (Option<String>, &str) {
    match head.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() => (Some(user.to_owned()), host),
        _ => (None, head),
    }
}

/// The user name to log in as when the command line names none.
pub fn default_user() -> Option<String> {
    ["USER", "LOGNAME"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// How long connecting, authenticating and a silent server may take for the file-transfer tools.
pub const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect, verify the host key, authenticate and start the SFTP subsystem.
///
/// The host key is checked before authentication, so a mismatch ends the attempt before any
/// credential or data is sent.
pub fn open_sftp(connect: &Connect, host: &str, user: &str) -> Result<crate::sftp::Sftp, String> {
    let config = connect
        .config(host, user, TRANSFER_TIMEOUT, None)
        .map_err(|error| error.to_string())?;
    let mut connection = crate::Connection::connect(&config).map_err(|error| error.to_string())?;
    connection.authenticate().map_err(|error| error.to_string())?;
    crate::sftp::Sftp::connect(connection, None).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(user: Option<&str>, host: &str, path: &str) -> Option<RemoteSpec> {
        Some(RemoteSpec {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            path: path.to_owned(),
        })
    }

    #[test]
    fn remote_arguments_split_at_the_first_colon() {
        assert_eq!(parse_remote("user@host:path"), spec(Some("user"), "host", "path"));
        assert_eq!(parse_remote("host:path/with:colon"), spec(None, "host", "path/with:colon"));
        assert_eq!(parse_remote("host:"), spec(None, "host", ""));
        assert_eq!(parse_remote("user@host:/abs"), spec(Some("user"), "host", "/abs"));
        assert_eq!(parse_remote("a@b@host:p"), spec(Some("a@b"), "host", "p"));
        assert_eq!(parse_remote("host:p@q"), spec(None, "host", "p@q"));
    }

    #[test]
    fn bracketed_addresses_hold_colons() {
        assert_eq!(parse_remote("[::1]:p"), spec(None, "::1", "p"));
        assert_eq!(parse_remote("user@[fe80::1]:/x"), spec(Some("user"), "fe80::1", "/x"));
        assert_eq!(parse_remote("u@[::1]:"), spec(Some("u"), "::1", ""));
        assert_eq!(parse_remote("[::1]"), None);
        assert_eq!(parse_remote("[]:p"), None);
    }

    #[test]
    fn local_paths_are_not_remote() {
        for local in ["file", "dir/file", "./a:b", "/abs:path", "../x:y", "a/b:c", ":x", "@:x", "", "-"] {
            assert_eq!(parse_remote(local), None, "{local}");
        }
    }

    #[test]
    fn the_sftp_target_may_omit_the_path() {
        let parsed = |text: &str| parse_host_argument(text).expect("parses");
        assert_eq!(parsed("u@h"), spec(Some("u"), "h", "").expect("spec"));
        assert_eq!(parsed("h"), spec(None, "h", "").expect("spec"));
        assert_eq!(parsed("u@h:dir"), spec(Some("u"), "h", "dir").expect("spec"));
        assert_eq!(parsed("u@[::1]"), spec(Some("u"), "::1", "").expect("spec"));
        assert!(parse_host_argument("").is_err());
        assert!(parse_host_argument("a/b").is_err());
    }

    fn arguments(text: &str) -> std::vec::IntoIter<String> {
        text.split_whitespace().map(str::to_owned).collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn the_port_flag_is_the_callers_and_trust_is_required() {
        let mut args = arguments("2200");
        let mut upper = ConnectArgs::new("-P");
        assert!(upper.accept("-P", &mut args).expect("accepts"));
        assert!(!upper.accept("-p", &mut args).expect("not its flag"));
        upper.accept("--host-key", &mut arguments("SHA256:x")).expect("pin");
        upper.accept("-i", &mut arguments("key")).expect("key");
        let connect = upper.finish().expect("finishes");
        assert_eq!(connect.port, 2200);
        assert_eq!(connect.trust, Trust::Pinned("SHA256:x".to_owned()));
        assert!(ConnectArgs::new("-p").finish().is_err());
        assert!(ConnectArgs::new("-P").accept("-P", &mut arguments("x")).is_err());
        assert!(ConnectArgs::new("-P").accept("-i", &mut arguments("")).is_err());
    }

    #[test]
    fn identity_and_trust_flags_exclude_each_other() {
        let build = |flags: &[(&str, &str)]| {
            let mut connect = ConnectArgs::new("-p");
            for (flag, value) in flags {
                connect.accept(flag, &mut arguments(value)).expect("accepts");
            }
            connect.finish()
        };
        assert!(build(&[("-i", "k"), ("--agent", "s"), ("--host-key", "p")]).is_err());
        assert!(build(&[("--agent", "s"), ("--host-key", "p")]).is_err());
        assert!(build(&[("--agent-identity", "i"), ("--host-key", "p"), ("-i", "k")]).is_err());
        assert!(build(&[("-i", "k"), ("--host-key", "p"), ("--known-hosts", "f")]).is_err());
        assert!(build(&[("--agent", "s"), ("--agent-identity", "i"), ("--known-hosts", "f")]).is_ok());
    }
}
