use std::ffi::OsStr;
use std::fmt;
use std::fs::{DirBuilder, File, FileTimes, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use crate::sftp::{Attrs, OpenFlags, Sftp, SftpError};
use crate::subsystem::Link;

const MAX_DEPTH: usize = 128;

/// What a copy does beyond a plain file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CopyOptions {
    /// Copy directories and what they hold.
    pub recursive: bool,
    /// Keep the permission bits and the access and modification times.
    pub preserve: bool,
}

/// Receives the progress of a copy.
pub trait Progress {
    /// A file of `size` bytes, when known, is about to transfer.
    fn file_start(&mut self, name: &str, size: Option<u64>);
    /// `done` bytes of the current file have transferred.
    fn file_advance(&mut self, done: u64);
    /// The current file finished.
    fn file_end(&mut self);
    /// Something was skipped.
    fn warn(&mut self, message: &str);
}

/// A [`Progress`] that reports nothing and prints warnings to standard error.
pub struct Quiet;

impl Progress for Quiet {
    fn file_start(&mut self, _name: &str, _size: Option<u64>) {}
    fn file_advance(&mut self, _done: u64) {}
    fn file_end(&mut self) {}
    fn warn(&mut self, message: &str) {
        eprintln!("{message}");
    }
}

/// A failed copy.
#[derive(Debug)]
pub enum CopyError {
    /// A remote operation failed.
    Remote {
        /// The remote path involved.
        path: String,
        /// What the session reported.
        source: SftpError,
    },
    /// A local operation failed.
    Local {
        /// The local path involved.
        path: PathBuf,
        /// The operating system's answer.
        source: std::io::Error,
    },
    /// The request itself was refused.
    Refused(String),
}

impl CopyError {
    /// Whether the session can carry no further request.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Remote { source, .. } if source.is_fatal())
    }
}

impl fmt::Display for CopyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remote { path, source } => write!(formatter, "{path}: {source}"),
            Self::Local { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Refused(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for CopyError {}

/// Show a remote path for messages.
pub fn display(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

fn remote_error(path: &[u8], source: SftpError) -> CopyError {
    CopyError::Remote {
        path: display(path),
        source,
    }
}

fn local_error(path: &Path, source: std::io::Error) -> CopyError {
    CopyError::Local {
        path: path.to_path_buf(),
        source,
    }
}

/// Join a remote directory and an entry name.
pub fn join_remote(base: &[u8], name: &[u8]) -> Vec<u8> {
    let mut joined = base.to_vec();
    if !joined.is_empty() && !joined.ends_with(b"/") {
        joined.push(b'/');
    }
    joined.extend_from_slice(name);
    joined
}

/// The last component of a remote path, ignoring trailing slashes.
pub fn remote_basename(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &path[..end];
    match trimmed.iter().rposition(|byte| *byte == b'/') {
        Some(slash) => &trimmed[slash + 1..],
        None => trimmed,
    }
}

/// Whether a directory entry name from the server is one plain path component.
pub fn safe_component(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}

fn seconds(time: i64) -> u32 {
    u32::try_from(time.max(0)).unwrap_or(u32::MAX)
}

fn file_times(accessed: u32, modified: u32) -> FileTimes {
    FileTimes::new()
        .set_accessed(UNIX_EPOCH + Duration::from_secs(u64::from(accessed)))
        .set_modified(UNIX_EPOCH + Duration::from_secs(u64::from(modified)))
}

fn usable_name<L: Link>(sftp: &mut Sftp<L>, remote: &[u8]) -> Result<Vec<u8>, CopyError> {
    let name = remote_basename(remote);
    if safe_component(name) {
        return Ok(name.to_vec());
    }
    let canonical = sftp.realpath(remote).map_err(|error| remote_error(remote, error))?;
    let name = remote_basename(&canonical);
    if safe_component(name) {
        Ok(name.to_vec())
    } else {
        Err(CopyError::Refused(format!(
            "{}: cannot name a local copy of it; give a destination",
            display(remote)
        )))
    }
}

/// Copy the remote file or, with `recursive`, directory tree `remote` to `local`.
///
/// When `local` is an existing directory the copy goes inside it under the remote name.
/// Symbolic links and special files inside a directory are skipped with a warning.
pub fn download<L: Link>(
    sftp: &mut Sftp<L>,
    remote: &[u8],
    local: &Path,
    options: CopyOptions,
    progress: &mut dyn Progress,
) -> Result<(), CopyError> {
    let attrs = sftp.stat(remote).map_err(|error| remote_error(remote, error))?;
    let target = if local.is_dir() {
        local.join(OsStr::from_bytes(&usable_name(sftp, remote)?))
    } else {
        local.to_path_buf()
    };
    if attrs.is_dir() {
        if !options.recursive {
            return Err(CopyError::Refused(format!(
                "{}: not a regular file",
                display(remote)
            )));
        }
        download_dir(sftp, remote, &attrs, &target, options, progress, 0)
    } else if attrs.is_regular() || attrs.permissions.is_none() {
        download_file(sftp, remote, &attrs, &target, options, progress)
    } else {
        Err(CopyError::Refused(format!(
            "{}: not a regular file",
            display(remote)
        )))
    }
}

fn download_file<L: Link>(
    sftp: &mut Sftp<L>,
    remote: &[u8],
    attrs: &Attrs,
    target: &Path,
    options: CopyOptions,
    progress: &mut dyn Progress,
) -> Result<(), CopyError> {
    let handle = sftp
        .open(remote, OpenFlags::READ, &Attrs::default())
        .map_err(|error| remote_error(remote, error))?;
    let mode = attrs.permissions.map_or(0o644, |mode| mode & 0o777);
    let opened = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode | 0o200)
        .open(target);
    let mut file = match opened {
        Ok(file) => file,
        Err(error) => {
            let _ = sftp.close_handle(&handle);
            return Err(local_error(target, error));
        }
    };
    let label = target
        .file_name()
        .map_or_else(|| display(remote), |name| name.to_string_lossy().into_owned());
    progress.file_start(&label, attrs.size);
    let outcome = sftp.download(&handle, 0, attrs.size, &mut file, &mut |done| {
        progress.file_advance(done);
    });
    let closed = sftp.close_handle(&handle);
    progress.file_end();
    match outcome {
        Ok(_) => {}
        Err(SftpError::Local(error)) => return Err(local_error(target, error)),
        Err(error) => return Err(remote_error(remote, error)),
    }
    closed.map_err(|error| remote_error(remote, error))?;
    if options.preserve {
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|error| local_error(target, error))?;
        if let Some((accessed, modified)) = attrs.times {
            file.set_times(file_times(accessed, modified))
                .map_err(|error| local_error(target, error))?;
        }
    }
    Ok(())
}

fn download_dir<L: Link>(
    sftp: &mut Sftp<L>,
    remote: &[u8],
    attrs: &Attrs,
    target: &Path,
    options: CopyOptions,
    progress: &mut dyn Progress,
    depth: usize,
) -> Result<(), CopyError> {
    if depth >= MAX_DEPTH {
        return Err(CopyError::Refused(format!(
            "{}: directories nest too deeply",
            display(remote)
        )));
    }
    let mode = attrs.permissions.map_or(0o755, |mode| mode & 0o777);
    match DirBuilder::new().mode(mode | 0o700).create(target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && target.is_dir() => {}
        Err(error) => return Err(local_error(target, error)),
    }
    let mut entries = sftp
        .read_dir(remote)
        .map_err(|error| remote_error(remote, error))?;
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    for entry in entries {
        if entry.name == b"." || entry.name == b".." {
            continue;
        }
        if !safe_component(&entry.name) {
            return Err(CopyError::Refused(format!(
                "{}: the server listed the unsafe name {:?}",
                display(remote),
                display(&entry.name)
            )));
        }
        let child_remote = join_remote(remote, &entry.name);
        let child_local = target.join(OsStr::from_bytes(&entry.name));
        if entry.attrs.is_dir() {
            download_dir(
                sftp,
                &child_remote,
                &entry.attrs,
                &child_local,
                options,
                progress,
                depth + 1,
            )?;
        } else if entry.attrs.is_regular() {
            download_file(sftp, &child_remote, &entry.attrs, &child_local, options, progress)?;
        } else {
            progress.warn(&format!(
                "{}: skipping, not a regular file or directory",
                display(&child_remote)
            ));
        }
    }
    if options.preserve {
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode))
            .map_err(|error| local_error(target, error))?;
        if let Some((accessed, modified)) = attrs.times {
            File::open(target)
                .and_then(|directory| directory.set_times(file_times(accessed, modified)))
                .map_err(|error| local_error(target, error))?;
        }
    }
    Ok(())
}

/// Copy the local file or, with `recursive`, directory tree `local` to `remote`.
///
/// When `remote` is an existing directory the copy goes inside it under the local name.
/// Symbolic links and special files inside a directory are skipped with a warning.
pub fn upload<L: Link>(
    sftp: &mut Sftp<L>,
    local: &Path,
    remote: &[u8],
    options: CopyOptions,
    progress: &mut dyn Progress,
) -> Result<(), CopyError> {
    let metadata = std::fs::metadata(local).map_err(|error| local_error(local, error))?;
    let target = match sftp.stat(remote) {
        Ok(attrs) if attrs.is_dir() => {
            let name = match local.file_name() {
                Some(name) => name.to_os_string(),
                None => local
                    .canonicalize()
                    .map_err(|error| local_error(local, error))?
                    .file_name()
                    .ok_or_else(|| {
                        CopyError::Refused(format!("{}: has no name to copy under", local.display()))
                    })?
                    .to_os_string(),
            };
            join_remote(remote, name.as_bytes())
        }
        Ok(_) => remote.to_vec(),
        Err(error) if error.is_fatal() => return Err(remote_error(remote, error)),
        Err(_) => remote.to_vec(),
    };
    if metadata.is_dir() {
        if !options.recursive {
            return Err(CopyError::Refused(format!(
                "{}: not a regular file",
                local.display()
            )));
        }
        upload_dir(sftp, local, &metadata, &target, options, progress, 0)
    } else if metadata.is_file() {
        upload_file(sftp, local, &target, options, progress)
    } else {
        Err(CopyError::Refused(format!(
            "{}: not a regular file",
            local.display()
        )))
    }
}

fn upload_file<L: Link>(
    sftp: &mut Sftp<L>,
    local: &Path,
    target: &[u8],
    options: CopyOptions,
    progress: &mut dyn Progress,
) -> Result<(), CopyError> {
    let mut file = File::open(local).map_err(|error| local_error(local, error))?;
    let metadata = file.metadata().map_err(|error| local_error(local, error))?;
    let mode = metadata.permissions().mode() & 0o777;
    let handle = sftp
        .open(
            target,
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            &Attrs::with_permissions(mode),
        )
        .map_err(|error| remote_error(target, error))?;
    let label = local
        .file_name()
        .map_or_else(|| display(target), |name| name.to_string_lossy().into_owned());
    progress.file_start(&label, Some(metadata.len()));
    let outcome = sftp.upload(&handle, 0, &mut file, &mut |done| progress.file_advance(done));
    progress.file_end();
    let preserved = match (&outcome, options.preserve) {
        (Ok(_), true) => sftp.fsetstat(
            &handle,
            &Attrs {
                permissions: Some(mode),
                times: Some((seconds(metadata.atime()), seconds(metadata.mtime()))),
                ..Attrs::default()
            },
        ),
        _ => Ok(()),
    };
    let closed = sftp.close_handle(&handle);
    match outcome {
        Ok(_) => {}
        Err(SftpError::Local(error)) => return Err(local_error(local, error)),
        Err(error) => return Err(remote_error(target, error)),
    }
    preserved.map_err(|error| remote_error(target, error))?;
    closed.map_err(|error| remote_error(target, error))
}

fn upload_dir<L: Link>(
    sftp: &mut Sftp<L>,
    local: &Path,
    metadata: &std::fs::Metadata,
    target: &[u8],
    options: CopyOptions,
    progress: &mut dyn Progress,
    depth: usize,
) -> Result<(), CopyError> {
    if depth >= MAX_DEPTH {
        return Err(CopyError::Refused(format!(
            "{}: directories nest too deeply",
            local.display()
        )));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if let Err(error) = sftp.mkdir(target, &Attrs::with_permissions(mode | 0o700)) {
        match sftp.stat(target) {
            Ok(attrs) if attrs.is_dir() => {}
            _ => return Err(remote_error(target, error)),
        }
    }
    let mut entries = std::fs::read_dir(local)
        .map_err(|error| local_error(local, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| local_error(local, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| local_error(&path, error))?;
        let child = join_remote(target, entry.file_name().as_bytes());
        if kind.is_dir() {
            let child_metadata = entry.metadata().map_err(|error| local_error(&path, error))?;
            upload_dir(sftp, &path, &child_metadata, &child, options, progress, depth + 1)?;
        } else if kind.is_file() {
            upload_file(sftp, &path, &child, options, progress)?;
        } else {
            progress.warn(&format!(
                "{}: skipping, not a regular file or directory",
                path.display()
            ));
        }
    }
    if options.preserve {
        sftp.setstat(
            target,
            &Attrs {
                permissions: Some(mode),
                times: Some((seconds(metadata.atime()), seconds(metadata.mtime()))),
                ..Attrs::default()
            },
        )
        .map_err(|error| remote_error(target, error))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_keep_one_slash() {
        assert_eq!(join_remote(b"/a", b"b"), b"/a/b");
        assert_eq!(join_remote(b"/a/", b"b"), b"/a/b");
        assert_eq!(join_remote(b"", b"b"), b"b");
        assert_eq!(join_remote(b"/", b"b"), b"/b");
    }

    #[test]
    fn basenames_ignore_trailing_slashes() {
        assert_eq!(remote_basename(b"/a/b"), b"b");
        assert_eq!(remote_basename(b"/a/b//"), b"b");
        assert_eq!(remote_basename(b"b"), b"b");
        assert_eq!(remote_basename(b"/"), b"");
        assert_eq!(remote_basename(b"a/.."), b"..");
    }

    #[test]
    fn server_names_must_be_one_plain_component() {
        for good in [&b"a"[..], b"a b", b"..a", b".hidden", "\u{e9}".as_bytes(), b"\xff"] {
            assert!(safe_component(good), "{good:?}");
        }
        for bad in [&b""[..], b".", b"..", b"a/b", b"/", b"../x", b"a\0b"] {
            assert!(!safe_component(bad), "{bad:?}");
        }
    }

    #[test]
    fn times_clamp_to_the_wire_range() {
        assert_eq!(seconds(-5), 0);
        assert_eq!(seconds(1_700_000_000), 1_700_000_000);
        assert_eq!(seconds(i64::MAX), u32::MAX);
    }
}
