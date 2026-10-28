//! Git-only command policy
//!
//! Turns the command string of an SSH `exec` request into a fixed argument vector for one of
//! the Git service programs found in a trusted directory chosen by the server operator. A
//! client never selects an executable, a filesystem path outside the repository root, or an
//! option.
//!
//! Trust boundary: the repository root and the Git binary directory must be owned by the
//! server's user and must not be writable by anyone else, and so must every repository
//! directory below the root. Repositories are trusted (their config and hooks run as the
//! server's user); a push cannot change them. Repository names are resolved component by
//! component without following symlinks, then the result is checked against the canonical
//! root. A writer who can replace a directory between that check and Git opening it is
//! outside the model.

use std::{
    ffi::OsString,
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub use proto::auth::GitAccess;
use thiserror::Error;

/// Longest accepted `exec` command, in bytes
const MAX_COMMAND_LEN: usize = 4096;
/// Longest accepted repository name, in bytes
const MAX_NAME_LEN: usize = 1024;
/// Deepest accepted repository name, in path components
const MAX_NAME_DEPTH: usize = 8;

/// The Git programs a client may reach over SSH
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitService {
    /// `git-upload-pack`: fetch, clone, `ls-remote`
    UploadPack,
    /// `git-receive-pack`: push
    ReceivePack,
}

impl GitService {
    fn parse(word: &str) -> Option<Self> {
        match word {
            "git-upload-pack" => Some(Self::UploadPack),
            "git-receive-pack" => Some(Self::ReceivePack),
            _ => None,
        }
    }

    fn program(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    fn required_access(self) -> GitAccess {
        match self {
            Self::UploadPack => GitAccess::Read,
            Self::ReceivePack => GitAccess::Write,
        }
    }
}

/// A validated Git invocation: absolute program, explicit arguments, fixed environment
#[derive(Debug, PartialEq, Eq)]
pub struct GitCommand {
    /// Which service was requested
    pub service: GitService,
    /// Absolute path of the service program inside the trusted Git directory
    pub program: PathBuf,
    /// Arguments, ending with the canonical repository path
    pub args: Vec<OsString>,
    /// Complete environment of the child; nothing is inherited
    pub env: Vec<(OsString, OsString)>,
}

/// Why a command or the policy configuration was rejected
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// The command is not exactly `<git-service> <repository>`
    #[error("command is not a supported Git command")]
    Command,
    /// The command names a service this server does not run
    #[error("unsupported Git service")]
    Service,
    /// The repository argument is malformed
    #[error("malformed repository argument")]
    Argument,
    /// The repository name is not an acceptable relative name
    #[error("invalid repository name")]
    Name,
    /// The repository does not exist under the root or is not a bare repository
    #[error("repository not found")]
    NotFound,
    /// The key does not carry the access the service needs
    #[error("access denied")]
    Denied,
    /// The server configuration is unsafe
    #[error("{0}")]
    Config(String),
}

/// Immutable Git policy: where repositories live and which Git binaries run
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitPolicy {
    repo_root: PathBuf,
    git_dir: PathBuf,
}

impl GitPolicy {
    /// Validate and canonicalize the repository root and the trusted Git binary directory
    pub fn new(repo_root: &Path, git_dir: &Path) -> Result<Self, PolicyError> {
        let repo_root = trusted_dir(repo_root, "repository root")?;
        let git_dir = trusted_dir(git_dir, "git directory")?;
        for program in ["git", "git-upload-pack", "git-receive-pack"] {
            let path = git_dir.join(program);
            let resolved = fs::canonicalize(&path)
                .map_err(|error| config(format!("{}: {error}", path.display())))?;
            if resolved.parent() != Some(&git_dir) {
                return Err(config(format!("{} resolves outside the git directory", path.display())));
            }
            let meta = fs::metadata(&resolved).map_err(|error| config(format!("{}: {error}", resolved.display())))?;
            if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
                return Err(config(format!("{} is not an executable file", resolved.display())));
            }
            check_owner_and_mode(&resolved, &meta)?;
        }
        Ok(Self { repo_root, git_dir })
    }

    /// The canonical repository root
    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    /// The canonical trusted Git binary directory
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    /// Validate an `exec` command for a key with the given access
    pub fn authorize(&self, command: &[u8], access: Option<GitAccess>) -> Result<GitCommand, PolicyError> {
        let command = parse_command(command)?;
        let service = GitService::parse(command.service).ok_or(PolicyError::Service)?;
        if !access.is_some_and(|granted| granted.allows(service.required_access())) {
            return Err(PolicyError::Denied);
        }

        let name = normalize_name(&command.argument)?;
        let repository = self.resolve(&name)?;

        let mut args = Vec::new();
        if service == GitService::UploadPack {
            args.push(OsString::from("--strict"));
        }
        args.push(repository.into_os_string());

        Ok(GitCommand {
            service,
            program: self.git_dir.join(service.program()),
            args,
            env: self.environment(),
        })
    }

    fn environment(&self) -> Vec<(OsString, OsString)> {
        let git_dir = self.git_dir.as_os_str();
        let settings = [("receive.fsckObjects", "true"), ("transfer.fsckObjects", "true")];
        let mut env: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), git_dir.into()),
            ("GIT_EXEC_PATH".into(), git_dir.into()),
            ("HOME".into(), self.repo_root.as_os_str().into()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
            ("LC_ALL".into(), "C".into()),
            ("GIT_CONFIG_COUNT".into(), settings.len().to_string().into()),
        ];
        for (index, (key, value)) in settings.iter().enumerate() {
            env.push((format!("GIT_CONFIG_KEY_{index}").into(), (*key).into()));
            env.push((format!("GIT_CONFIG_VALUE_{index}").into(), (*value).into()));
        }
        env
    }

    fn resolve(&self, name: &str) -> Result<PathBuf, PolicyError> {
        let mut path = self.repo_root.clone();
        for component in name.split('/') {
            path.push(component);
            let meta = fs::symlink_metadata(&path).map_err(not_found)?;
            if !meta.file_type().is_dir() {
                return Err(PolicyError::NotFound);
            }
        }

        for (entry, want_dir) in [("HEAD", false), ("objects", true), ("refs", true)] {
            let meta = fs::symlink_metadata(path.join(entry)).map_err(not_found)?;
            let kind = meta.file_type();
            if kind.is_symlink() || kind.is_dir() != want_dir {
                return Err(PolicyError::NotFound);
            }
        }

        let canonical = fs::canonicalize(&path).map_err(not_found)?;
        if canonical != path || !canonical.starts_with(&self.repo_root) {
            return Err(PolicyError::NotFound);
        }
        Ok(canonical)
    }
}

/// A validated `GIT_PROTOCOL` value to pass to the child, if the client's value is acceptable
pub fn validate_protocol(value: &str) -> Option<&'static str> {
    match value {
        "version=2" => Some("version=2"),
        _ => None,
    }
}

struct ParsedCommand<'a> {
    service: &'a str,
    argument: String,
}

fn parse_command(command: &[u8]) -> Result<ParsedCommand<'_>, PolicyError> {
    if command.len() > MAX_COMMAND_LEN {
        return Err(PolicyError::Command);
    }
    let command = core::str::from_utf8(command).map_err(|_| PolicyError::Command)?;
    if command.chars().any(char::is_control) {
        return Err(PolicyError::Command);
    }
    let (service, rest) = command.split_once(' ').ok_or(PolicyError::Command)?;
    if service.is_empty() || rest.is_empty() || rest.starts_with(' ') {
        return Err(PolicyError::Command);
    }
    Ok(ParsedCommand {
        service,
        argument: unquote(rest)?,
    })
}

/// Parse exactly what Git's `sq_quote` produces, or a bare word of safe characters
///
/// Quoted form: single-quoted runs, with `'\''` for a quote and `'\!'` for an exclamation
/// mark. Nothing may follow the argument.
fn unquote(argument: &str) -> Result<String, PolicyError> {
    if !argument.starts_with('\'') {
        let safe = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '~');
        return match argument.chars().all(safe) {
            true => Ok(argument.to_owned()),
            false => Err(PolicyError::Argument),
        };
    }

    let mut out = String::new();
    let mut rest = argument;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('\'') {
            let (literal, after) = after.split_once('\'').ok_or(PolicyError::Argument)?;
            out.push_str(literal);
            rest = after;
        } else if let Some(after) = rest.strip_prefix("\\'") {
            out.push('\'');
            rest = after;
        } else if let Some(after) = rest.strip_prefix("\\!") {
            out.push('!');
            rest = after;
        } else {
            return Err(PolicyError::Argument);
        }
    }
    Ok(out)
}

/// Turn the client's repository argument into a root-relative name
///
/// `ssh://host/repo.git` URLs always send a leading slash, so one is stripped; the name is
/// then relative to the repository root either way. A client can never name a path outside
/// the root: every component is a plain word.
fn normalize_name(argument: &str) -> Result<String, PolicyError> {
    let name = argument.strip_prefix('/').unwrap_or(argument);
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(PolicyError::Name);
    }
    let components: Vec<&str> = name.split('/').collect();
    if components.len() > MAX_NAME_DEPTH {
        return Err(PolicyError::Name);
    }
    let valid = |component: &&str| {
        !component.is_empty()
            && !component.starts_with(['.', '-'])
            && component
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    match components.iter().all(valid) {
        true => Ok(name.to_owned()),
        false => Err(PolicyError::Name),
    }
}

fn trusted_dir(path: &Path, what: &str) -> Result<PathBuf, PolicyError> {
    if !path.is_absolute() {
        return Err(config(format!("{what} must be an absolute path")));
    }
    let canonical = fs::canonicalize(path).map_err(|error| config(format!("{what} {}: {error}", path.display())))?;
    let meta = fs::metadata(&canonical).map_err(|error| config(format!("{what} {}: {error}", canonical.display())))?;
    if !meta.is_dir() {
        return Err(config(format!("{what} {} is not a directory", canonical.display())));
    }
    check_owner_and_mode(&canonical, &meta)?;
    Ok(canonical)
}

fn check_owner_and_mode(path: &Path, meta: &fs::Metadata) -> Result<(), PolicyError> {
    let euid = rustix::process::geteuid().as_raw();
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(config(format!("{} is not owned by the server user or root", path.display())));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(config(format!("{} is writable by group or others", path.display())));
    }
    Ok(())
}

fn config(message: String) -> PolicyError {
    PolicyError::Config(message)
}

fn not_found(_: io::Error) -> PolicyError {
    PolicyError::NotFound
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        _dir: TempDir,
        policy: GitPolicy,
        root: PathBuf,
    }

    fn mkdir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn bare_repo(path: &Path) {
        mkdir(&path.join("objects"));
        mkdir(&path.join("refs"));
        fs::write(path.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        let root = base.join("repos");
        let bin = base.join("bin");
        mkdir(&root);
        mkdir(&bin);
        fs::write(bin.join("git"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("git", bin.join("git-upload-pack")).unwrap();
        symlink("git", bin.join("git-receive-pack")).unwrap();
        bare_repo(&root.join("a.git"));
        bare_repo(&root.join("team").join("b.git"));
        let policy = GitPolicy::new(&root, &bin).unwrap();
        Fixture { _dir: dir, policy, root }
    }

    fn authorize(fixture: &Fixture, command: &str, access: GitAccess) -> Result<GitCommand, PolicyError> {
        fixture.policy.authorize(command.as_bytes(), Some(access))
    }

    #[test]
    fn accepts_git_client_syntax() {
        let f = fixture();
        for command in [
            "git-upload-pack 'a.git'",
            "git-upload-pack '/a.git'",
            "git-upload-pack a.git",
            "git-upload-pack '/team/b.git'",
        ] {
            let parsed = authorize(&f, command, GitAccess::Read).unwrap();
            assert_eq!(parsed.service, GitService::UploadPack);
            assert_eq!(parsed.program, f.policy.git_dir().join("git-upload-pack"));
            assert_eq!(parsed.args[0], "--strict");
            assert!(Path::new(parsed.args.last().unwrap()).starts_with(&f.root));
        }
        let push = authorize(&f, "git-receive-pack 'a.git'", GitAccess::Write).unwrap();
        assert_eq!(push.args, [f.root.join("a.git").into_os_string()]);
    }

    #[test]
    fn executable_is_never_client_supplied() {
        let f = fixture();
        for command in [
            "/usr/bin/git-upload-pack 'a.git'",
            "./git-upload-pack 'a.git'",
            "../bin/git-upload-pack 'a.git'",
            "git upload-pack 'a.git'",
            "git-upload-archive 'a.git'",
            "git-upload-pack-evil 'a.git'",
            "GIT-UPLOAD-PACK 'a.git'",
            "sh -c 'git-upload-pack a.git'",
            "git-shell -c 'a.git'",
            "",
            " ",
        ] {
            assert!(authorize(&f, command, GitAccess::Write).is_err(), "{command:?}");
        }
        let parsed = authorize(&f, "git-upload-pack 'a.git'", GitAccess::Read).unwrap();
        assert!(parsed.program.starts_with(f.policy.git_dir()));
    }

    #[test]
    fn rejects_injection_and_malformed_quoting() {
        let f = fixture();
        for command in [
            "git-upload-pack 'a.git'; id",
            "git-upload-pack 'a.git' extra",
            "git-upload-pack  'a.git'",
            "git-upload-pack\t'a.git'",
            "git-upload-pack 'a.git",
            "git-upload-pack a.git'",
            "git-upload-pack \"a.git\"",
            "git-upload-pack 'a.git'\\'",
            "git-upload-pack $(id)",
            "git-upload-pack `id`",
            "git-upload-pack a.git|id",
            "git-upload-pack a.git&&id",
            "git-upload-pack 'a.git'\nid",
            "git-upload-pack 'a\0.git'",
            "git-upload-pack 'a.git\u{7f}'",
            "git-upload-pack --help",
            "git-upload-pack -- 'a.git'",
            "git-upload-pack '--strict'",
            "git-upload-pack '-C'",
        ] {
            assert!(authorize(&f, command, GitAccess::Write).is_err(), "{command:?}");
        }
        assert!(f.policy.authorize(b"git-upload-pack '\xff.git'", Some(GitAccess::Read)).is_err());
        let long = format!("git-upload-pack '{}'", "a".repeat(5000));
        assert!(authorize(&f, &long, GitAccess::Read).is_err());
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        let f = fixture();
        let absolute = format!("git-upload-pack '{}'", f.root.join("a.git").display());
        for command in [
            "git-upload-pack '../a.git'",
            "git-upload-pack 'team/../a.git'",
            "git-upload-pack './a.git'",
            "git-upload-pack 'team/./b.git'",
            "git-upload-pack '//a.git'",
            "git-upload-pack 'team//b.git'",
            "git-upload-pack '/'",
            "git-upload-pack ''",
            "git-upload-pack '~/a.git'",
            "git-upload-pack '.git'",
            "git-upload-pack 'a.git/'",
            "git-upload-pack 'a.git/objects/..'",
            "git-upload-pack '/etc/passwd'",
            "git-upload-pack 'a.git/.git/hooks'",
            &absolute,
        ] {
            assert!(authorize(&f, command, GitAccess::Read).is_err(), "{command:?}");
        }
    }

    #[test]
    fn rejects_symlink_escapes_and_non_repositories() {
        let f = fixture();
        let outside = f.root.parent().unwrap().join("outside.git");
        bare_repo(&outside);
        symlink(&outside, f.root.join("link.git")).unwrap();
        symlink(&f.root.join("a.git"), f.root.join("alias.git")).unwrap();
        mkdir(&f.root.join("team2"));
        symlink(&outside, f.root.join("team2").join("c.git")).unwrap();
        symlink(f.root.parent().unwrap(), f.root.join("up")).unwrap();
        mkdir(&f.root.join("plain"));
        mkdir(&f.root.join("headlink.git").join("objects"));
        mkdir(&f.root.join("headlink.git").join("refs"));
        symlink("/etc/passwd", f.root.join("headlink.git").join("HEAD")).unwrap();
        for command in [
            "git-upload-pack 'link.git'",
            "git-upload-pack 'alias.git'",
            "git-upload-pack 'team2/c.git'",
            "git-upload-pack 'up/outside.git'",
            "git-upload-pack 'plain'",
            "git-upload-pack 'missing.git'",
            "git-upload-pack 'headlink.git'",
        ] {
            assert_eq!(authorize(&f, command, GitAccess::Read), Err(PolicyError::NotFound), "{command:?}");
        }
    }

    #[test]
    fn read_access_cannot_push() {
        let f = fixture();
        assert_eq!(authorize(&f, "git-receive-pack 'a.git'", GitAccess::Read), Err(PolicyError::Denied));
        assert!(authorize(&f, "git-upload-pack 'a.git'", GitAccess::Write).is_ok());
        assert_eq!(f.policy.authorize(b"git-upload-pack 'a.git'", None), Err(PolicyError::Denied));
    }

    #[test]
    fn environment_is_closed_and_pinned_to_the_git_directory() {
        let f = fixture();
        let parsed = authorize(&f, "git-upload-pack 'a.git'", GitAccess::Read).unwrap();
        let get = |key: &str| parsed.env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        assert_eq!(get("PATH").unwrap(), f.policy.git_dir().as_os_str());
        assert_eq!(get("GIT_EXEC_PATH").unwrap(), f.policy.git_dir().as_os_str());
        assert_eq!(get("GIT_CONFIG_GLOBAL").unwrap(), "/dev/null");
        assert_eq!(get("GIT_CONFIG_NOSYSTEM").unwrap(), "1");
        assert_eq!(get("GIT_CONFIG_COUNT").unwrap(), "2");
        assert!(get("GIT_PROTOCOL").is_none());
        assert!(get("GIT_DIR").is_none());
    }

    #[test]
    fn protocol_allows_only_version_two() {
        assert_eq!(validate_protocol("version=2"), Some("version=2"));
        for value in ["version=1", "version=0", "version=2:x=y", "version=2 ", "", "version=2\n", "x"] {
            assert_eq!(validate_protocol(value), None, "{value:?}");
        }
    }

    #[test]
    fn unsafe_configuration_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let writable = base.join("writable");
        mkdir(&writable);
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
        let f = fixture();
        assert!(GitPolicy::new(&writable, f.policy.git_dir()).is_err());
        assert!(GitPolicy::new(f.policy.repo_root(), &writable).is_err());
        assert!(GitPolicy::new(Path::new("relative"), f.policy.git_dir()).is_err());
        assert!(GitPolicy::new(&base.join("missing"), f.policy.git_dir()).is_err());
        let empty = base.join("empty");
        mkdir(&empty);
        assert!(GitPolicy::new(f.policy.repo_root(), &empty).is_err());
        let evil = base.join("evil");
        mkdir(&evil);
        for name in ["git", "git-upload-pack", "git-receive-pack"] {
            symlink(f.policy.git_dir().join("git"), evil.join(name)).unwrap();
        }
        assert!(GitPolicy::new(f.policy.repo_root(), &evil).is_err());
    }
}
