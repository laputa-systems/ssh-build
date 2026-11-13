//! Login mode: accounts, the user database and the policy for one login session

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt as _, OsStringExt as _},
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use proto::{
    auth::AuthorizedKey,
    crypto::CryptoProvider,
    named::PublicKeyAlgorithm,
};

use crate::authentication::read_trusted_file;

const MAX_ACCOUNT_KEYS: usize = 1024;
const MAX_NAME_LEN: usize = 64;
const MAX_GROUPS: usize = 256;
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const DEFAULT_SHELL: &str = "/bin/sh";

/// The server-owned accounts file: one `name key` pair per line
///
/// Each non-comment line is an account name followed by one Ed25519 public key in
/// `authorized_keys` syntax (`ssh-ed25519 AAAA… comment`), without options. An account may have
/// several lines. The file has the same ownership and permission rules as an `authorized_keys`
/// file, and a user's `~/.ssh` is never read.
#[derive(Debug)]
pub struct LoginAccounts {
    accounts: BTreeMap<String, Vec<AuthorizedKey>>,
}

impl LoginAccounts {
    /// Load and validate the accounts file; every problem is an error rather than a skipped line
    pub fn from_file(path: &Path, provider: &dyn CryptoProvider) -> anyhow::Result<Self> {
        let contents = read_trusted_file(path, "accounts", false)?;
        let mut accounts = BTreeMap::<String, Vec<AuthorizedKey>>::new();
        let mut total = 0;
        for (index, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let number = index + 1;
            let Some((name, key)) = line.split_once(char::is_whitespace) else {
                anyhow::bail!("{}:{number}: expected an account name and a key", path.display());
            };
            anyhow::ensure!(valid_name(name), "{}:{number}: invalid account name", path.display());
            let key = AuthorizedKey::from_str(key.trim(), provider)
                .with_context(|| format!("{}:{number}: invalid key or unsupported option", path.display()))?;
            anyhow::ensure!(
                *key.algorithm() == PublicKeyAlgorithm::Ed25519,
                "{}:{number}: only ssh-ed25519 keys are accepted",
                path.display()
            );
            anyhow::ensure!(
                key.options.git_access.is_none(),
                "{}:{number}: options are not accepted in the accounts file",
                path.display()
            );
            let keys = accounts.entry(name.to_owned()).or_default();
            anyhow::ensure!(
                !keys.iter().any(|existing| existing.same_key(&key)),
                "{}:{number}: duplicate key for account {name}",
                path.display()
            );
            keys.push(key);
            total += 1;
            anyhow::ensure!(total <= MAX_ACCOUNT_KEYS, "{} has too many keys", path.display());
        }
        anyhow::ensure!(!accounts.is_empty(), "{} contains no accounts", path.display());
        Ok(Self { accounts })
    }

    pub(crate) fn keys_for(&self, name: &str) -> &[AuthorizedKey] {
        self.accounts.get(name).map_or(&[], Vec::as_slice)
    }

    /// The account names, in order
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.accounts.keys().map(String::as_str)
    }
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= MAX_NAME_LEN
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// An account as the user database describes it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserEntry {
    /// The login name
    pub name: String,
    /// The numeric user ID
    pub uid: u32,
    /// The primary group ID
    pub gid: u32,
    /// The supplementary group IDs, primary group first
    pub groups: Vec<u32>,
    /// The home directory
    pub home: PathBuf,
    /// The login shell
    pub shell: PathBuf,
}

impl UserEntry {
    /// Refuse accounts a login must never become: root, root's group, and non-login shells
    pub fn check(&self, allow_root: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            allow_root || (self.uid != 0 && !self.groups.contains(&0)),
            "account {} is root or in root's group; login to it is not allowed",
            self.name
        );
        let shell = self.shell.as_os_str().as_bytes();
        anyhow::ensure!(
            self.shell.is_absolute() && !shell.contains(&0),
            "account {} has no usable login shell",
            self.name
        );
        let program = self.shell.file_name().unwrap_or_default();
        anyhow::ensure!(
            program != "nologin" && program != "false",
            "account {} has a non-login shell",
            self.name
        );
        Ok(())
    }
}

/// The flat `passwd` and `group` files login accounts are resolved from
///
/// There is no NSS: a static server reads these two files, which must be owned by root or the
/// server user and not writable by others.
#[derive(Clone, Debug)]
pub struct UserDatabase {
    passwd: PathBuf,
    group: PathBuf,
}

impl UserDatabase {
    /// A database that reads these two files on every lookup
    pub fn new(passwd: PathBuf, group: PathBuf) -> Self {
        Self { passwd, group }
    }

    /// Resolve one account by name
    pub fn lookup(&self, name: &str) -> anyhow::Result<UserEntry> {
        let passwd = read_trusted_file(&self.passwd, "passwd", true)?;
        let group = read_trusted_file(&self.group, "group", true)?;
        let mut entry = parse_passwd(&passwd, name)
            .with_context(|| format!("account {name} is not in {}", self.passwd.display()))?;
        entry.groups = parse_groups(&group, name, entry.gid);
        Ok(entry)
    }
}

fn parse_passwd(contents: &str, name: &str) -> Option<UserEntry> {
    contents.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != name {
            return None;
        }
        let _password = fields.next()?;
        let uid = fields.next()?.parse().ok()?;
        let gid = fields.next()?.parse().ok()?;
        let _gecos = fields.next()?;
        let home = fields.next()?;
        let shell = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        Some(UserEntry {
            name: name.to_owned(),
            uid,
            gid,
            groups: vec![gid],
            home: if home.is_empty() { "/".into() } else { home.into() },
            shell: if shell.is_empty() { DEFAULT_SHELL.into() } else { shell.into() },
        })
    })
}

fn parse_groups(contents: &str, name: &str, primary: u32) -> Vec<u32> {
    let mut groups = vec![primary];
    for line in contents.lines() {
        let mut fields = line.split(':');
        let (Some(_), Some(_), Some(gid), Some(members), None) =
            (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(gid) = gid.parse::<u32>() else { continue };
        if members.split(',').any(|member| member == name) && !groups.contains(&gid) && groups.len() < MAX_GROUPS {
            groups.push(gid);
        }
    }
    groups
}

/// Settings of login mode that are not accounts
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct LoginPolicy {
    /// The `PATH` every session gets
    pub path: String,
    /// Whether `LANG` and `LC_*` requests from the client reach the session
    pub accept_locale: bool,
    /// Whether an account with user ID 0 (or in group 0) may log in
    pub allow_root: bool,
    /// The `passwd` file accounts are resolved from
    pub passwd: PathBuf,
    /// The `group` file supplementary groups are read from
    pub group: PathBuf,
}

impl Default for LoginPolicy {
    fn default() -> Self {
        Self {
            path: DEFAULT_PATH.to_owned(),
            accept_locale: false,
            allow_root: false,
            passwd: "/etc/passwd".into(),
            group: "/etc/group".into(),
        }
    }
}

impl LoginPolicy {
    /// Check the settings that cannot be checked on use
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.path.is_empty() && !self.path.contains(['\0', '\n']),
            "the session PATH must be a non-empty single line"
        );
        Ok(())
    }

    pub(crate) fn database(&self) -> UserDatabase {
        UserDatabase::new(self.passwd.clone(), self.group.clone())
    }
}

/// What the session process needs to serve one login: the account and the environment rules
#[derive(Clone, Debug)]
pub struct LoginSession {
    pub(crate) user: UserEntry,
    pub(crate) path: String,
    pub(crate) accept_locale: bool,
    pub(crate) allow_root: bool,
    pub(crate) launcher: PathBuf,
}

impl LoginSession {
    pub(crate) fn new(user: UserEntry, policy: &LoginPolicy, launcher: PathBuf) -> Self {
        Self {
            user,
            path: policy.path.clone(),
            accept_locale: policy.accept_locale,
            allow_root: policy.allow_root,
            launcher,
        }
    }

    /// The account's user and group IDs and the root-login switch, for privilege dropping
    pub(crate) fn user(&self) -> &UserEntry {
        &self.user
    }

    pub(crate) fn allow_root(&self) -> bool {
        self.allow_root
    }

    /// Arguments for `oxish-session` that carry this session from the listener
    pub(crate) fn to_args(&self) -> Vec<OsString> {
        let groups = self.user.groups.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        vec![
            "login".into(),
            "--name".into(), self.user.name.clone().into(),
            "--uid".into(), self.user.uid.to_string().into(),
            "--gid".into(), self.user.gid.to_string().into(),
            "--groups".into(), groups.into(),
            "--home".into(), self.user.home.clone().into(),
            "--shell".into(), self.user.shell.clone().into(),
            "--path".into(), self.path.clone().into(),
            "--locale".into(), bool_arg(self.accept_locale).into(),
            "--root".into(), bool_arg(self.allow_root).into(),
            "--launcher".into(), self.launcher.clone().into(),
        ]
    }

    /// Parse the arguments after `login`; fails closed on anything missing, repeated or unknown
    pub fn from_args(args: impl IntoIterator<Item = OsString>) -> anyhow::Result<Self> {
        let mut values = BTreeMap::<String, OsString>::new();
        let mut args = args.into_iter();
        while let Some(key) = args.next() {
            let key = key.into_string().map_err(|_| anyhow::anyhow!("invalid login argument"))?;
            let value = args.next().with_context(|| format!("{key} needs a value"))?;
            anyhow::ensure!(values.insert(key.clone(), value).is_none(), "{key} given twice");
        }
        let mut take = |key: &str| values.remove(key).with_context(|| format!("missing {key}"));
        let text = |value: OsString, key: &str| value.into_string().map_err(|_| anyhow::anyhow!("{key} is not UTF-8"));
        let number = |value: OsString, key: &str| -> anyhow::Result<u32> {
            text(value, key)?.parse().with_context(|| format!("{key} is not a number"))
        };

        let name = text(take("--name")?, "--name")?;
        let uid = number(take("--uid")?, "--uid")?;
        let gid = number(take("--gid")?, "--gid")?;
        let groups = text(take("--groups")?, "--groups")?
            .split(',')
            .filter(|group| !group.is_empty())
            .map(|group| group.parse::<u32>().context("invalid group"))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let user = UserEntry {
            name,
            uid,
            gid,
            groups,
            home: PathBuf::from(take("--home")?),
            shell: PathBuf::from(take("--shell")?),
        };
        let path = text(take("--path")?, "--path")?;
        let accept_locale = flag(&text(take("--locale")?, "--locale")?)?;
        let allow_root = flag(&text(take("--root")?, "--root")?)?;
        let launcher = PathBuf::from(take("--launcher")?);
        anyhow::ensure!(values.is_empty(), "unknown login argument");
        anyhow::ensure!(valid_name(&user.name), "invalid account name");
        anyhow::ensure!(user.groups.first() == Some(&user.gid), "the primary group must come first");
        anyhow::ensure!(!path.is_empty() && !path.contains(['\0', '\n']), "invalid PATH");
        anyhow::ensure!(launcher.is_absolute(), "the launcher path must be absolute");
        user.check(allow_root)?;
        Ok(Self { user, path, accept_locale, allow_root, launcher })
    }

    /// The fixed part of every session's environment
    pub(crate) fn environment(&self) -> Vec<(OsString, OsString)> {
        let name = OsString::from(&self.user.name);
        vec![
            ("HOME".into(), self.user.home.clone().into_os_string()),
            ("USER".into(), name.clone()),
            ("LOGNAME".into(), name),
            ("SHELL".into(), self.user.shell.clone().into_os_string()),
            ("PATH".into(), OsString::from(&self.path)),
        ]
    }

    /// Whether an `env` request names a variable the client may set
    pub(crate) fn accepts_env(&self, name: &str, value: &str) -> bool {
        self.accept_locale
            && (name == "LANG" || name.strip_prefix("LC_").is_some_and(|rest| !rest.is_empty()))
            && name.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            && value.len() <= 64
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'-' | b'+' | b'='))
    }

    /// The program and arguments to run for a `shell` (no command) or an `exec` request
    ///
    /// The command goes to the account's own shell with `-c`, as OpenSSH does; a login shell is
    /// started with a leading `-` in its `argv[0]`.
    pub(crate) fn command(&self, command: Option<&[u8]>) -> LoginCommand {
        let name = self.user.shell.file_name().unwrap_or_else(|| OsStr::new("sh"));
        let (argv0, args) = match command {
            Some(command) => (name.to_owned(), vec![OsString::from("-c"), OsString::from_vec(command.to_vec())]),
            None => {
                let mut login = OsString::from("-");
                login.push(name);
                (login, Vec::new())
            }
        };
        let cwd = match self.user.home.is_dir() {
            true => self.user.home.clone(),
            false => PathBuf::from("/"),
        };
        LoginCommand {
            program: self.user.shell.clone(),
            argv0,
            args,
            cwd,
            env: self.environment(),
        }
    }
}

/// A shell invocation ready to be spawned
#[derive(Clone, Debug)]
pub(crate) struct LoginCommand {
    pub(crate) program: PathBuf,
    pub(crate) argv0: OsString,
    pub(crate) args: Vec<OsString>,
    pub(crate) cwd: PathBuf,
    pub(crate) env: Vec<(OsString, OsString)>,
}

fn bool_arg(value: bool) -> &'static str {
    match value {
        true => "yes",
        false => "no",
    }
}

fn flag(value: &str) -> anyhow::Result<bool> {
    match value {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => anyhow::bail!("expected yes or no"),
    }
}

/// How long a `TERM` value may be, and which characters it may hold
pub(crate) fn valid_term(term: &str) -> bool {
    term.len() <= 64
        && term.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_PROVIDER;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPdEXeWrpzl1Lgk7akX7+7x4B1eoyV5tyD6674DIh3R user@host";
    const OTHER: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDX+GNCeikghR3A2bLB0KmlovqxdC+BUHAfYhYGcUJxA other@host";

    fn load(contents: &str, mode: u32) -> anyhow::Result<LoginAccounts> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("accounts");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        LoginAccounts::from_file(&path, DEFAULT_PROVIDER)
    }

    #[test]
    fn accounts_file_is_strict() {
        let good = format!("# comment\n\nalice {KEY}\nalice {OTHER}\nbob.b-1 {KEY}\n");
        let accounts = load(&good, 0o600).unwrap();
        assert_eq!(accounts.names().collect::<Vec<_>>(), ["alice", "bob.b-1"]);
        assert_eq!(accounts.keys_for("alice").len(), 2);
        assert!(accounts.keys_for("carol").is_empty());

        assert!(load(&good, 0o660).is_err());
        assert!(load(&good, 0o666).is_err());
        for bad in [
            String::new(),
            "# only a comment\n".to_owned(),
            format!("{KEY}\n"),
            "alice\n".to_owned(),
            format!("al/ice {KEY}\n"),
            format!("-alice {KEY}\n"),
            format!("alice git-access=\"read\" {KEY}\n"),
            format!("alice command=\"id\" {KEY}\n"),
            format!("alice {KEY}\nalice {KEY}\n"),
            format!("alice {KEY}\ngarbage here\n"),
            "alice ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE4MlZd759Tv7GElTKPf1D0FCmDWB9LEkkWyaP3E8T0H/fKyFnA0e0yBm/XpkG9erfxrcgMkAu1CM3e19g9bZWg=\n".to_owned(),
        ] {
            assert!(load(&bad, 0o600).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn accounts_file_must_not_be_a_symlink_or_in_an_open_directory() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, format!("alice {KEY}\n")).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(LoginAccounts::from_file(&link, DEFAULT_PROVIDER).is_err());
        assert!(LoginAccounts::from_file(&real, DEFAULT_PROVIDER).is_ok());

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(LoginAccounts::from_file(&real, DEFAULT_PROVIDER).is_err());
    }

    #[test]
    fn user_entries_come_from_the_flat_files() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nalice:x:1001:100:Alice:/home/alice:/bin/zsh\nbob:x:1002:1002::/home/bob:\n";
        let group = "users:x:100:\nwheel:x:10:alice,carol\naudio:x:18:bob,alice\nbad line\n";
        let alice = parse_passwd(passwd, "alice").unwrap();
        assert_eq!((alice.uid, alice.gid), (1001, 100));
        assert_eq!(alice.home, Path::new("/home/alice"));
        assert_eq!(alice.shell, Path::new("/bin/zsh"));
        assert_eq!(parse_groups(group, "alice", alice.gid), [100, 10, 18]);
        let bob = parse_passwd(passwd, "bob").unwrap();
        assert_eq!(bob.shell, Path::new("/bin/sh"));
        assert!(parse_passwd(passwd, "carol").is_none());
        assert!(parse_passwd(passwd, "ali").is_none());
        assert!(parse_passwd("alice:x:abc:100:::/bin/sh\n", "alice").is_none());
    }

    #[test]
    fn root_and_non_login_accounts_are_refused() {
        let entry = |uid: u32, gid: u32, groups: &[u32], shell: &str| UserEntry {
            name: "a".into(),
            uid,
            gid,
            groups: groups.to_vec(),
            home: "/".into(),
            shell: shell.into(),
        };
        assert!(entry(1000, 1000, &[1000], "/bin/sh").check(false).is_ok());
        assert!(entry(0, 0, &[0], "/bin/sh").check(false).is_err());
        assert!(entry(0, 0, &[0], "/bin/sh").check(true).is_ok());
        assert!(entry(1000, 0, &[0], "/bin/sh").check(false).is_err());
        assert!(entry(1000, 1000, &[1000, 0], "/bin/sh").check(false).is_err());
        assert!(entry(1000, 1000, &[1000], "/usr/sbin/nologin").check(false).is_err());
        assert!(entry(1000, 1000, &[1000], "/bin/false").check(false).is_err());
        assert!(entry(1000, 1000, &[1000], "sh").check(false).is_err());
    }

    #[test]
    fn session_arguments_round_trip_and_fail_closed() {
        let user = UserEntry {
            name: "alice".into(),
            uid: 1001,
            gid: 100,
            groups: vec![100, 10],
            home: "/home/alice".into(),
            shell: "/bin/sh".into(),
        };
        let session = LoginSession::new(user.clone(), &LoginPolicy::default(), "/usr/bin/oxish-session".into());
        let args = session.to_args();
        assert_eq!(args[0], "login");
        let parsed = LoginSession::from_args(args[1..].iter().cloned()).unwrap();
        assert_eq!(parsed.user, user);
        assert_eq!(parsed.path, DEFAULT_PATH);
        assert!(!parsed.accept_locale && !parsed.allow_root);

        let mut missing = args[1..].to_vec();
        missing.truncate(missing.len() - 2);
        assert!(LoginSession::from_args(missing).is_err());
        let mut extra = args[1..].to_vec();
        extra.extend(["--name".into(), "bob".into()]);
        assert!(LoginSession::from_args(extra).is_err());
        let mut unknown = args[1..].to_vec();
        unknown.extend(["--extra".into(), "x".into()]);
        assert!(LoginSession::from_args(unknown).is_err());

        let root = UserEntry { uid: 0, gid: 0, groups: vec![0], ..user };
        let args = LoginSession::new(root, &LoginPolicy::default(), "/x".into()).to_args();
        assert!(LoginSession::from_args(args[1..].iter().cloned()).is_err());
    }

    #[test]
    fn only_listed_environment_variables_are_ever_accepted() {
        let user = UserEntry {
            name: "alice".into(),
            uid: 1,
            gid: 1,
            groups: vec![1],
            home: "/".into(),
            shell: "/bin/sh".into(),
        };
        let mut policy = LoginPolicy::default();
        let off = LoginSession::new(user.clone(), &policy, "/x".into());
        assert!(!off.accepts_env("LANG", "C.UTF-8"));
        policy.accept_locale = true;
        let on = LoginSession::new(user, &policy, "/x".into());
        assert!(on.accepts_env("LANG", "C.UTF-8"));
        assert!(on.accepts_env("LC_ALL", "en_US.UTF-8"));
        for (name, value) in [
            ("LD_PRELOAD", "/tmp/x.so"),
            ("PATH", "/tmp"),
            ("LC_", "C"),
            ("LCX", "C"),
            ("LANG", "C;id"),
            ("LANG", "a b"),
            ("LC_ALL", "$(id)"),
            ("lang", "C"),
        ] {
            assert!(!on.accepts_env(name, value), "{name}={value}");
        }
    }

    #[test]
    fn term_values_are_plain_terminfo_names() {
        for good in ["xterm-256color", "screen.xterm-256color", "vt100", "xterm+256color", ""] {
            assert!(valid_term(good), "{good}");
        }
        for bad in ["../../etc", "a b", "x\n", "a/b", &"x".repeat(65)] {
            assert!(!valid_term(bad), "{bad}");
        }
    }
}
