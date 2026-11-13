
use core::fmt;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::File,
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::{ffi::OsStrExt as _, fs::FileExt as _},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rustix::{
    fs::{AtFlags, Dir, Gid, Mode, OFlags, RawMode, Stat, StatVfsMountFlags, Timespec, Timestamps, Uid},
    io::Errno,
};

pub(crate) const MAX_PACKET: usize = 256 * 1024;
pub(crate) const MAX_DATA: usize = MAX_PACKET - 1024;
pub(crate) const MAX_HANDLES: usize = 256;
pub(crate) const MAX_PENDING: usize = 1024;
pub(crate) const MAX_BUFFERED_INPUT: usize = 1 << 20;
const MAX_BATCH: usize = 64;
const OUTPUT_SOFT_LIMIT: usize = 512 * 1024;
const MAX_NAMES: usize = 100;
const MAX_PATH: usize = 4096;
const MAX_EXTENSIONS: usize = 32;
const MAX_LINKS: usize = 40;
const VERSION: u32 = 3;

const INIT: u8 = 1;
const VERSION_REPLY: u8 = 2;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const READ: u8 = 5;
const WRITE: u8 = 6;
const LSTAT: u8 = 7;
const FSTAT: u8 = 8;
const SETSTAT: u8 = 9;
const FSETSTAT: u8 = 10;
const OPENDIR: u8 = 11;
const READDIR: u8 = 12;
const REMOVE: u8 = 13;
const MKDIR: u8 = 14;
const RMDIR: u8 = 15;
const REALPATH: u8 = 16;
const STAT: u8 = 17;
const RENAME: u8 = 18;
const READLINK: u8 = 19;
const SYMLINK: u8 = 20;
const STATUS: u8 = 101;
const HANDLE: u8 = 102;
const DATA: u8 = 103;
const NAME: u8 = 104;
const ATTRS: u8 = 105;
const EXTENDED: u8 = 200;
const EXTENDED_REPLY: u8 = 201;

const OPEN_READ: u32 = 0x01;
const OPEN_WRITE: u32 = 0x02;
const OPEN_APPEND: u32 = 0x04;
const OPEN_CREATE: u32 = 0x08;
const OPEN_TRUNCATE: u32 = 0x10;
const OPEN_EXCLUSIVE: u32 = 0x20;

const ATTR_SIZE: u32 = 0x01;
const ATTR_OWNER: u32 = 0x02;
const ATTR_PERMISSIONS: u32 = 0x04;
const ATTR_TIMES: u32 = 0x08;
const ATTR_EXTENDED: u32 = 0x8000_0000;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFREG: u32 = 0o100_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFBLK: u32 = 0o060_000;
const S_IFIFO: u32 = 0o010_000;
const S_IFSOCK: u32 = 0o140_000;

const EXTENSIONS: [(&str, &str); 8] = [
    ("posix-rename@openssh.com", "1"),
    ("statvfs@openssh.com", "2"),
    ("fstatvfs@openssh.com", "2"),
    ("hardlink@openssh.com", "1"),
    ("fsync@openssh.com", "1"),
    ("lsetstat@openssh.com", "1"),
    ("limits@openssh.com", "1"),
    ("expand-path@openssh.com", "1"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fatal(pub(crate) &'static str);

impl fmt::Display for Fatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Status(pub(crate) u32);

impl Status {
    pub(crate) const OK: Self = Self(0);
    pub(crate) const EOF: Self = Self(1);
    pub(crate) const NO_SUCH_FILE: Self = Self(2);
    pub(crate) const PERMISSION_DENIED: Self = Self(3);
    pub(crate) const FAILURE: Self = Self(4);
    pub(crate) const BAD_MESSAGE: Self = Self(5);
    pub(crate) const OP_UNSUPPORTED: Self = Self(8);

    fn message(self) -> &'static str {
        match self.0 {
            0 => "Success",
            1 => "End of file",
            2 => "No such file",
            3 => "Permission denied",
            5 => "Bad message",
            6 => "No connection",
            7 => "Connection lost",
            8 => "Operation unsupported",
            _ => "Failure",
        }
    }
}

impl From<Errno> for Status {
    fn from(errno: Errno) -> Self {
        match errno {
            Errno::NOENT | Errno::NOTDIR | Errno::BADF | Errno::LOOP => Self::NO_SUCH_FILE,
            Errno::PERM | Errno::ACCESS | Errno::FAULT => Self::PERMISSION_DENIED,
            Errno::NAMETOOLONG | Errno::INVAL => Self::BAD_MESSAGE,
            Errno::NOSYS | Errno::OPNOTSUPP => Self::OP_UNSUPPORTED,
            _ => Self::FAILURE,
        }
    }
}

impl From<io::Error> for Status {
    fn from(error: io::Error) -> Self {
        Errno::from_io_error(&error).map_or(Self::FAILURE, Self::from)
    }
}

enum Fail {
    Status(Status),
    Fatal(Fatal),
}

impl From<Status> for Fail {
    fn from(status: Status) -> Self {
        Self::Status(status)
    }
}

impl From<Errno> for Fail {
    fn from(errno: Errno) -> Self {
        Self::Status(errno.into())
    }
}

impl From<io::Error> for Fail {
    fn from(error: io::Error) -> Self {
        Self::Status(error.into())
    }
}

impl From<Fatal> for Fail {
    fn from(fatal: Fatal) -> Self {
        Self::Fatal(fatal)
    }
}

type Outcome = Result<(), Fail>;

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Fatal> {
        match self.rest.split_at_checked(len) {
            Some((head, rest)) => {
                self.rest = rest;
                Ok(head)
            }
            None => Err(Fatal("truncated request")),
        }
    }

    fn u8(&mut self) -> Result<u8, Fatal> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Fatal> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, Fatal> {
        let bytes = self.take(8)?;
        let mut array = [0; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(array))
    }

    fn bytes(&mut self) -> Result<&'a [u8], Fatal> {
        let len = usize::try_from(self.u32()?).map_err(|_| Fatal("string too long"))?;
        self.take(len)
    }

    fn path(&mut self) -> Result<&'a [u8], Fail> {
        let bytes = self.bytes()?;
        match bytes.len() > MAX_PATH {
            true => Err(Errno::NAMETOOLONG.into()),
            false => Ok(bytes),
        }
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(bytes);
}

fn begin(out: &mut Vec<u8>, kind: u8) -> usize {
    let start = out.len();
    put_u32(out, 0);
    out.push(kind);
    start
}

fn end(out: &mut [u8], start: usize) {
    let len = u32::try_from(out.len() - start - 4).unwrap_or(u32::MAX);
    out[start..start + 4].copy_from_slice(&len.to_be_bytes());
}

fn status(out: &mut Vec<u8>, id: u32, status: Status) {
    let start = begin(out, STATUS);
    put_u32(out, id);
    put_u32(out, status.0);
    put_bytes(out, status.message().as_bytes());
    put_bytes(out, b"");
    end(out, start);
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Attrs {
    pub(crate) size: Option<u64>,
    pub(crate) owner: Option<(u32, u32)>,
    pub(crate) permissions: Option<u32>,
    pub(crate) times: Option<(u32, u32)>,
}

impl Attrs {
    fn parse(reader: &mut Reader<'_>) -> Result<Self, Fatal> {
        let flags = reader.u32()?;
        if flags & !(ATTR_SIZE | ATTR_OWNER | ATTR_PERMISSIONS | ATTR_TIMES | ATTR_EXTENDED) != 0 {
            return Err(Fatal("unknown attribute flags"));
        }
        let mut attrs = Self::default();
        if flags & ATTR_SIZE != 0 {
            attrs.size = Some(reader.u64()?);
        }
        if flags & ATTR_OWNER != 0 {
            attrs.owner = Some((reader.u32()?, reader.u32()?));
        }
        if flags & ATTR_PERMISSIONS != 0 {
            attrs.permissions = Some(reader.u32()?);
        }
        if flags & ATTR_TIMES != 0 {
            attrs.times = Some((reader.u32()?, reader.u32()?));
        }
        if flags & ATTR_EXTENDED != 0 {
            let count = reader.u32()?;
            if usize::try_from(count).map_or(true, |count| count > MAX_EXTENSIONS) {
                return Err(Fatal("too many attribute extensions"));
            }
            for _ in 0..count {
                reader.bytes()?;
                reader.bytes()?;
            }
        }
        Ok(attrs)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        let mut flags = 0;
        if self.size.is_some() {
            flags |= ATTR_SIZE;
        }
        if self.owner.is_some() {
            flags |= ATTR_OWNER;
        }
        if self.permissions.is_some() {
            flags |= ATTR_PERMISSIONS;
        }
        if self.times.is_some() {
            flags |= ATTR_TIMES;
        }
        put_u32(out, flags);
        if let Some(size) = self.size {
            put_u64(out, size);
        }
        if let Some((uid, gid)) = self.owner {
            put_u32(out, uid);
            put_u32(out, gid);
        }
        if let Some(permissions) = self.permissions {
            put_u32(out, permissions);
        }
        if let Some((atime, mtime)) = self.times {
            put_u32(out, atime);
            put_u32(out, mtime);
        }
    }

    fn from_stat(stat: &Stat) -> Self {
        let seconds = |value: i64| u32::try_from(value.max(0)).unwrap_or(u32::MAX);
        Self {
            size: Some(u64::try_from(stat.st_size).unwrap_or(0)),
            owner: Some((stat.st_uid, stat.st_gid)),
            permissions: Some(mode_bits(stat.st_mode)),
            times: Some((seconds(stat.st_atime), seconds(stat.st_mtime))),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Owner {
    pub(crate) uid: u32,
    pub(crate) name: String,
}

enum Handle {
    File(File),
    Dir(Dir),
}

pub(crate) struct Engine {
    root: OwnedFd,
    home: PathBuf,
    owner: Owner,
    handles: BTreeMap<u64, Handle>,
    next_handle: u64,
    started: bool,
}

#[allow(clippy::useless_conversion)]
fn mode_bits(mode: RawMode) -> u32 {
    u32::from(mode)
}

fn mode_of(bits: u32) -> Mode {
    Mode::from_raw_mode(RawMode::try_from(bits & 0o7777).unwrap_or(0))
}

fn follow(follow_links: bool) -> AtFlags {
    match follow_links {
        true => AtFlags::empty(),
        false => AtFlags::SYMLINK_NOFOLLOW,
    }
}

fn timestamps(times: (u32, u32)) -> Timestamps {
    let stamp = |seconds: u32| Timespec { tv_sec: i64::from(seconds), tv_nsec: 0 };
    Timestamps { last_access: stamp(times.0), last_modification: stamp(times.1) }
}

fn uid_gid(owner: (u32, u32)) -> Result<(Uid, Gid), Errno> {
    match owner.0 == u32::MAX || owner.1 == u32::MAX {
        true => Err(Errno::INVAL),
        false => Ok((Uid::from_raw(owner.0), Gid::from_raw(owner.1))),
    }
}

fn apply_fd(fd: impl AsFd, attrs: &Attrs, truncate: bool) -> Result<(), Errno> {
    if let Some(size) = attrs.size {
        if !truncate {
            return Err(Errno::ISDIR);
        }
        rustix::fs::ftruncate(&fd, size)?;
    }
    if let Some(permissions) = attrs.permissions {
        rustix::fs::fchmod(&fd, mode_of(permissions))?;
    }
    if let Some(owner) = attrs.owner {
        let (uid, gid) = uid_gid(owner)?;
        rustix::fs::fchown(&fd, Some(uid), Some(gid))?;
    }
    if let Some(times) = attrs.times {
        rustix::fs::futimens(&fd, &timestamps(times))?;
    }
    Ok(())
}

// The session process holds the host key and is non-dumpable so that the account cannot read its
// memory. This engine runs in that process, where `/proc/self/mem` and its siblings are readable, so
// no file on a procfs is ever opened, whatever path or link names it.
#[cfg(target_os = "linux")]
fn refuse_procfs(fd: &OwnedFd) -> Result<(), Errno> {
    match rustix::fs::fstatfs(fd)?.f_type == rustix::fs::PROC_SUPER_MAGIC {
        true => Err(Errno::ACCESS),
        false => Ok(()),
    }
}

#[cfg(not(target_os = "linux"))]
fn refuse_procfs(_fd: &OwnedFd) -> Result<(), Errno> {
    Ok(())
}

fn open_directory(path: &Path) -> Result<OwnedFd, Errno> {
    rustix::fs::open(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOCTTY, Mode::empty())
}

impl Engine {
    pub(crate) fn new(home: &Path, owner: Owner) -> io::Result<Self> {
        let (root, home) = match home.is_absolute().then(|| open_directory(home)) {
            Some(Ok(root)) => (root, std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf())),
            _ => (open_directory(Path::new("/"))?, PathBuf::from("/")),
        };
        Ok(Self { root, home, owner, handles: BTreeMap::new(), next_handle: 1, started: false })
    }

    pub(crate) fn handle(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), Fatal> {
        let mut reader = Reader { rest: packet };
        let kind = reader.u8()?;
        match (self.started, kind) {
            (false, INIT) => return self.init(&mut reader, out),
            (false, _) => return Err(Fatal("request before the version exchange")),
            (true, INIT) => return Err(Fatal("second version exchange")),
            (true, _) => {}
        }
        let id = reader.u32()?;
        let start = out.len();
        match self.request(kind, id, &mut reader, out) {
            Ok(()) => Ok(()),
            Err(Fail::Status(code)) => {
                out.truncate(start);
                status(out, id, code);
                Ok(())
            }
            Err(Fail::Fatal(fatal)) => {
                out.truncate(start);
                Err(fatal)
            }
        }
    }

    fn init(&mut self, reader: &mut Reader<'_>, out: &mut Vec<u8>) -> Result<(), Fatal> {
        reader.u32()?;
        let mut extensions = 0;
        while !reader.rest.is_empty() {
            reader.bytes()?;
            reader.bytes()?;
            extensions += 1;
            if extensions > MAX_EXTENSIONS {
                return Err(Fatal("too many extensions"));
            }
        }
        self.started = true;
        let start = begin(out, VERSION_REPLY);
        put_u32(out, VERSION);
        for (name, version) in EXTENSIONS {
            put_bytes(out, name.as_bytes());
            put_bytes(out, version.as_bytes());
        }
        end(out, start);
        Ok(())
    }

    fn request(&mut self, kind: u8, id: u32, reader: &mut Reader<'_>, out: &mut Vec<u8>) -> Outcome {
        match kind {
            OPEN => {
                let path = reader.path()?;
                let flags = reader.u32()?;
                let attrs = Attrs::parse(reader)?;
                let handle = self.open(path, flags, &attrs)?;
                self.reply_handle(out, id, handle);
            }
            CLOSE => {
                let key = self.key(reader.bytes()?)?;
                self.handles.remove(&key);
                done(out, id);
            }
            READ => {
                let handle = reader.bytes()?;
                let offset = reader.u64()?;
                let len = usize::try_from(reader.u32()?).unwrap_or(MAX_DATA).min(MAX_DATA);
                let key = self.key(handle)?;
                self.read(key, offset, len, id, out)?;
            }
            WRITE => {
                let handle = reader.bytes()?;
                let offset = reader.u64()?;
                let data = reader.bytes()?;
                let key = self.key(handle)?;
                match self.handles.get(&key) {
                    Some(Handle::File(file)) => file.write_all_at(data, offset)?,
                    _ => return Err(Status::FAILURE.into()),
                }
                done(out, id);
            }
            LSTAT | STAT => {
                let path = reader.path()?;
                let stat = rustix::fs::statat(&self.root, path, follow(kind == STAT))?;
                reply_attrs(out, id, &Attrs::from_stat(&stat));
            }
            FSTAT => {
                let key = self.key(reader.bytes()?)?;
                let stat = match self.handles.get(&key) {
                    Some(Handle::File(file)) => rustix::fs::fstat(file)?,
                    Some(Handle::Dir(dir)) => dir.stat()?,
                    None => return Err(Status::FAILURE.into()),
                };
                reply_attrs(out, id, &Attrs::from_stat(&stat));
            }
            SETSTAT => {
                let path = reader.path()?;
                let attrs = Attrs::parse(reader)?;
                self.set_path(path, &attrs, true)?;
                done(out, id);
            }
            FSETSTAT => {
                let handle = reader.bytes()?;
                let attrs = Attrs::parse(reader)?;
                let key = self.key(handle)?;
                match self.handles.get(&key) {
                    Some(Handle::File(file)) => apply_fd(file, &attrs, true)?,
                    Some(Handle::Dir(dir)) => apply_fd(dir.fd()?, &attrs, false)?,
                    None => return Err(Status::FAILURE.into()),
                }
                done(out, id);
            }
            OPENDIR => {
                let path = reader.path()?;
                self.room()?;
                let fd = rustix::fs::openat(
                    &self.root,
                    path,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOCTTY,
                    Mode::empty(),
                )?;
                let handle = self.insert(Handle::Dir(Dir::new(fd)?));
                self.reply_handle(out, id, handle);
            }
            READDIR => {
                let key = self.key(reader.bytes()?)?;
                self.read_dir(key, id, out)?;
            }
            REMOVE => {
                rustix::fs::unlinkat(&self.root, reader.path()?, AtFlags::empty())?;
                done(out, id);
            }
            MKDIR => {
                let path = reader.path()?;
                let attrs = Attrs::parse(reader)?;
                let mode = attrs.permissions.map_or(0o777, |permissions| permissions & 0o777);
                rustix::fs::mkdirat(&self.root, path, mode_of(mode))?;
                done(out, id);
            }
            RMDIR => {
                rustix::fs::unlinkat(&self.root, reader.path()?, AtFlags::REMOVEDIR)?;
                done(out, id);
            }
            REALPATH => {
                let resolved = self.realpath(reader.path()?)?;
                reply_name(out, id, &resolved, &Attrs::default());
            }
            RENAME => {
                let (old, new) = (reader.path()?, reader.path()?);
                self.rename(old, new)?;
                done(out, id);
            }
            READLINK => {
                let target = rustix::fs::readlinkat(&self.root, reader.path()?, Vec::new())?;
                reply_name(out, id, target.to_bytes(), &Attrs::default());
            }
            SYMLINK => {
                // OpenSSH sends the link's contents first and the new link's path second.
                let (target, link) = (reader.path()?, reader.path()?);
                rustix::fs::symlinkat(target, &self.root, link)?;
                done(out, id);
            }
            EXTENDED => {
                let name = reader.bytes()?;
                self.extended(name, id, reader, out)?;
            }
            _ => return Err(Status::OP_UNSUPPORTED.into()),
        }
        Ok(())
    }

    fn extended(&mut self, name: &[u8], id: u32, reader: &mut Reader<'_>, out: &mut Vec<u8>) -> Outcome {
        match name {
            b"posix-rename@openssh.com" => {
                let (old, new) = (reader.path()?, reader.path()?);
                rustix::fs::renameat(&self.root, old, &self.root, new)?;
                done(out, id);
            }
            b"hardlink@openssh.com" => {
                let (old, new) = (reader.path()?, reader.path()?);
                rustix::fs::linkat(&self.root, old, &self.root, new, AtFlags::empty())?;
                done(out, id);
            }
            b"fsync@openssh.com" => {
                let key = self.key(reader.bytes()?)?;
                match self.handles.get(&key) {
                    Some(Handle::File(file)) => rustix::fs::fsync(file)?,
                    _ => return Err(Status::FAILURE.into()),
                }
                done(out, id);
            }
            b"lsetstat@openssh.com" => {
                let path = reader.path()?;
                let attrs = Attrs::parse(reader)?;
                self.set_path(path, &attrs, false)?;
                done(out, id);
            }
            b"statvfs@openssh.com" => {
                let path = reader.path()?;
                let absolute = match path.first() {
                    Some(b'/') => PathBuf::from(OsStr::from_bytes(path)),
                    _ => self.home.join(OsStr::from_bytes(path)),
                };
                reply_statvfs(out, id, &rustix::fs::statvfs(&absolute)?);
            }
            b"fstatvfs@openssh.com" => {
                let key = self.key(reader.bytes()?)?;
                let vfs = match self.handles.get(&key) {
                    Some(Handle::File(file)) => rustix::fs::fstatvfs(file)?,
                    Some(Handle::Dir(dir)) => dir.statvfs()?,
                    None => return Err(Status::FAILURE.into()),
                };
                reply_statvfs(out, id, &vfs);
            }
            b"limits@openssh.com" => {
                let start = begin(out, EXTENDED_REPLY);
                put_u32(out, id);
                put_u64(out, MAX_PACKET as u64);
                put_u64(out, MAX_DATA as u64);
                put_u64(out, MAX_DATA as u64);
                put_u64(out, MAX_HANDLES as u64);
                end(out, start);
            }
            b"expand-path@openssh.com" => {
                let path = reader.path()?;
                let tilde = match path.strip_prefix(b"/") {
                    Some(rest) if rest.starts_with(b"~") => rest,
                    _ => path,
                };
                let home = self.home.as_os_str().as_bytes();
                let expanded = match tilde {
                    b"~" => home.to_vec(),
                    _ => match tilde.strip_prefix(b"~/") {
                        Some(rest) if home == b"/" => [home, rest].concat(),
                        Some(rest) => [home, b"/", rest].concat(),
                        None => path.to_vec(),
                    },
                };
                reply_name(out, id, &expanded, &Attrs::default());
            }
            _ => return Err(Status::OP_UNSUPPORTED.into()),
        }
        Ok(())
    }

    fn room(&self) -> Result<(), Status> {
        match self.handles.len() >= MAX_HANDLES {
            true => Err(Status::FAILURE),
            false => Ok(()),
        }
    }

    fn insert(&mut self, handle: Handle) -> u64 {
        let key = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(key, handle);
        key
    }

    fn key(&self, raw: &[u8]) -> Result<u64, Status> {
        let bytes: [u8; 8] = raw.try_into().map_err(|_| Status::FAILURE)?;
        let key = u64::from_be_bytes(bytes);
        match self.handles.contains_key(&key) {
            true => Ok(key),
            false => Err(Status::FAILURE),
        }
    }

    fn reply_handle(&self, out: &mut Vec<u8>, id: u32, key: u64) {
        let start = begin(out, HANDLE);
        put_u32(out, id);
        put_bytes(out, &key.to_be_bytes());
        end(out, start);
    }

    fn open(&mut self, path: &[u8], pflags: u32, attrs: &Attrs) -> Result<u64, Fail> {
        self.room()?;
        let mut flags = match (pflags & OPEN_READ != 0, pflags & OPEN_WRITE != 0) {
            (true, true) => OFlags::RDWR,
            (false, true) => OFlags::WRONLY,
            _ => OFlags::RDONLY,
        };
        // Non-blocking while opening, so a FIFO or device cannot hold the session; regular files
        // are switched back to blocking below.
        flags |= OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK;
        for (bit, flag) in [
            (OPEN_APPEND, OFlags::APPEND),
            (OPEN_CREATE, OFlags::CREATE),
            (OPEN_TRUNCATE, OFlags::TRUNC),
            (OPEN_EXCLUSIVE, OFlags::EXCL),
        ] {
            if pflags & bit != 0 {
                flags |= flag;
            }
        }
        let mode = attrs.permissions.map_or(0o666, |permissions| permissions & 0o777);
        let fd = rustix::fs::openat(&self.root, path, flags, mode_of(mode))?;
        refuse_procfs(&fd)?;
        match mode_bits(rustix::fs::fstat(&fd)?.st_mode) & S_IFMT {
            S_IFDIR => return Err(Errno::ISDIR.into()),
            S_IFREG => rustix::fs::fcntl_setfl(&fd, rustix::fs::fcntl_getfl(&fd)? - OFlags::NONBLOCK)?,
            _ => {}
        }
        Ok(self.insert(Handle::File(File::from(fd))))
    }

    fn read(&mut self, key: u64, offset: u64, len: usize, id: u32, out: &mut Vec<u8>) -> Outcome {
        let Some(Handle::File(file)) = self.handles.get(&key) else {
            return Err(Status::FAILURE.into());
        };
        let start = begin(out, DATA);
        put_u32(out, id);
        let length_at = out.len();
        put_u32(out, 0);
        let data_at = out.len();
        out.resize(data_at + len, 0);
        let read = loop {
            match file.read_at(&mut out[data_at..], offset) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                other => break other?,
            }
        };
        if read == 0 && len > 0 {
            return Err(Status::EOF.into());
        }
        out.truncate(data_at + read);
        out[length_at..data_at].copy_from_slice(&u32::try_from(read).unwrap_or(0).to_be_bytes());
        end(out, start);
        Ok(())
    }

    fn read_dir(&mut self, key: u64, id: u32, out: &mut Vec<u8>) -> Outcome {
        let Some(Handle::Dir(dir)) = self.handles.get_mut(&key) else {
            return Err(Status::FAILURE.into());
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
        let start = begin(out, NAME);
        put_u32(out, id);
        let count_at = out.len();
        put_u32(out, 0);
        let mut count = 0_u32;
        while (count as usize) < MAX_NAMES {
            let entry = match dir.read() {
                None => break,
                Some(Ok(entry)) => entry,
                Some(Err(error)) if count == 0 => return Err(error.into()),
                Some(Err(_)) => break,
            };
            let name = entry.file_name().to_bytes();
            let Ok(stat) = rustix::fs::statat(dir.fd()?, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW) else {
                continue;
            };
            let attrs = Attrs::from_stat(&stat);
            put_bytes(out, name);
            put_bytes(out, &long_name(&attrs, name, now, &self.owner));
            attrs.encode(out);
            count += 1;
        }
        if count == 0 {
            return Err(Status::EOF.into());
        }
        out[count_at..count_at + 4].copy_from_slice(&count.to_be_bytes());
        end(out, start);
        Ok(())
    }

    fn set_path(&self, path: &[u8], attrs: &Attrs, follow_links: bool) -> Result<(), Errno> {
        if let Some(size) = attrs.size {
            if !follow_links {
                return Err(Errno::OPNOTSUPP);
            }
            let fd = rustix::fs::openat(
                &self.root,
                path,
                OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            refuse_procfs(&fd)?;
            rustix::fs::ftruncate(&fd, size)?;
        }
        if let Some(permissions) = attrs.permissions {
            match follow_links {
                true => rustix::fs::chmodat(&self.root, path, mode_of(permissions), AtFlags::empty())?,
                false => self.chmod_link(path, permissions)?,
            }
        }
        if let Some(owner) = attrs.owner {
            let (uid, gid) = uid_gid(owner)?;
            rustix::fs::chownat(&self.root, path, Some(uid), Some(gid), follow(follow_links))?;
        }
        if let Some(times) = attrs.times {
            rustix::fs::utimensat(&self.root, path, &timestamps(times), follow(follow_links))?;
        }
        Ok(())
    }

    // Linux cannot change the mode of a link, and its `fchmodat` refuses AT_SYMLINK_NOFOLLOW even for
    // other files. Like glibc, pin the object without following a link, refuse a link, and change the
    // pinned object through its `/proc/self/fd` entry.
    #[cfg(target_os = "linux")]
    fn chmod_link(&self, path: &[u8], permissions: u32) -> Result<(), Errno> {
        use std::os::fd::AsRawFd as _;

        let pinned = rustix::fs::openat(
            &self.root,
            path,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if mode_bits(rustix::fs::fstat(&pinned)?.st_mode) & S_IFMT == S_IFLNK {
            return Err(Errno::OPNOTSUPP);
        }
        let proc = format!("/proc/self/fd/{}", pinned.as_raw_fd());
        match rustix::fs::chmodat(rustix::fs::CWD, proc, mode_of(permissions), AtFlags::empty()) {
            Err(Errno::NOENT) => Err(Errno::NOSYS),
            other => other,
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn chmod_link(&self, _path: &[u8], _permissions: u32) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    // A rename never replaces an existing target (draft-ietf-secsh-filexfer-02); OpenSSH answers
    // SSH_FX_FAILURE then. Where the file system lacks RENAME_NOREPLACE, a check precedes the rename.
    fn rename(&self, old: &[u8], new: &[u8]) -> Result<(), Fail> {
        #[cfg(target_os = "linux")]
        match rustix::fs::renameat_with(&self.root, old, &self.root, new, rustix::fs::RenameFlags::NOREPLACE) {
            Ok(()) => return Ok(()),
            Err(Errno::EXIST) => return Err(Status::FAILURE.into()),
            Err(Errno::INVAL | Errno::NOSYS | Errno::OPNOTSUPP) => {}
            Err(error) => return Err(error.into()),
        }
        match rustix::fs::statat(&self.root, new, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Err(Status::FAILURE.into()),
            Err(Errno::NOENT) => Ok(rustix::fs::renameat(&self.root, old, &self.root, new)?),
            Err(error) => Err(error.into()),
        }
    }

    fn realpath(&self, path: &[u8]) -> Result<Vec<u8>, Errno> {
        fn push(pending: &mut Vec<Vec<u8>>, path: &[u8]) {
            pending.extend(path.split(|byte| *byte == b'/').rev().map(<[u8]>::to_vec));
        }

        let mut pending: Vec<Vec<u8>> = Vec::new();
        let mut resolved = PathBuf::from("/");
        push(&mut pending, path);
        if path.first() != Some(&b'/') {
            push(&mut pending, self.home.as_os_str().as_bytes());
        }
        let mut links = 0;
        while let Some(component) = pending.pop() {
            match component.as_slice() {
                b"" | b"." => {}
                b".." => {
                    resolved.pop();
                }
                name => {
                    let candidate = resolved.join(OsStr::from_bytes(name));
                    match std::fs::symlink_metadata(&candidate) {
                        Ok(metadata) if metadata.file_type().is_symlink() => {
                            links += 1;
                            if links > MAX_LINKS {
                                return Err(Errno::LOOP);
                            }
                            let target = std::fs::read_link(&candidate).map_err(|error| Errno::from_io_error(&error).unwrap_or(Errno::IO))?;
                            if target.is_absolute() {
                                resolved = PathBuf::from("/");
                            }
                            push(&mut pending, target.as_os_str().as_bytes());
                        }
                        Ok(_) => resolved = candidate,
                        Err(error)
                            if error.kind() == io::ErrorKind::NotFound
                                && pending.iter().all(|rest| rest.is_empty() || rest == b".") =>
                        {
                            resolved = candidate;
                        }
                        Err(error) => return Err(Errno::from_io_error(&error).unwrap_or(Errno::IO)),
                    }
                }
            }
        }
        Ok(resolved.as_os_str().as_bytes().to_vec())
    }
}

fn done(out: &mut Vec<u8>, id: u32) {
    status(out, id, Status::OK);
}

fn reply_attrs(out: &mut Vec<u8>, id: u32, attrs: &Attrs) {
    let start = begin(out, ATTRS);
    put_u32(out, id);
    attrs.encode(out);
    end(out, start);
}

fn reply_name(out: &mut Vec<u8>, id: u32, name: &[u8], attrs: &Attrs) {
    let start = begin(out, NAME);
    put_u32(out, id);
    put_u32(out, 1);
    put_bytes(out, name);
    put_bytes(out, name);
    attrs.encode(out);
    end(out, start);
}

fn reply_statvfs(out: &mut Vec<u8>, id: u32, vfs: &rustix::fs::StatVfs) {
    let mut flags = 0;
    if vfs.f_flag.contains(StatVfsMountFlags::RDONLY) {
        flags |= 1;
    }
    if vfs.f_flag.contains(StatVfsMountFlags::NOSUID) {
        flags |= 2;
    }
    let start = begin(out, EXTENDED_REPLY);
    put_u32(out, id);
    for value in [
        vfs.f_bsize, vfs.f_frsize, vfs.f_blocks, vfs.f_bfree, vfs.f_bavail, vfs.f_files, vfs.f_ffree,
        vfs.f_favail, vfs.f_fsid, flags, vfs.f_namemax,
    ] {
        put_u64(out, value);
    }
    end(out, start);
}

pub(crate) fn long_name(attrs: &Attrs, name: &[u8], now: u64, owner: &Owner) -> Vec<u8> {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const SIX_MONTHS: u64 = 15_778_476;

    let permissions = attrs.permissions.unwrap_or(0);
    let mut mode = String::with_capacity(10);
    mode.push(match permissions & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        S_IFCHR => 'c',
        S_IFBLK => 'b',
        S_IFIFO => 'p',
        S_IFSOCK => 's',
        S_IFREG => '-',
        _ => '?',
    });
    for (shift, special, set, plain) in [(6, 0o4000, 's', 'S'), (3, 0o2000, 's', 'S'), (0, 0o1000, 't', 'T')] {
        let bits = (permissions >> shift) & 7;
        mode.push(if bits & 4 != 0 { 'r' } else { '-' });
        mode.push(if bits & 2 != 0 { 'w' } else { '-' });
        mode.push(match (bits & 1 != 0, permissions & special != 0) {
            (true, true) => set,
            (false, true) => plain,
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    let (uid, gid) = attrs.owner.unwrap_or((0, 0));
    let user = match uid == owner.uid {
        true => owner.name.clone(),
        false => uid.to_string(),
    };
    let mtime = u64::from(attrs.times.map_or(0, |(_, mtime)| mtime));
    let days = i64::try_from(mtime / 86_400).unwrap_or(0);
    let (year, month, day) = civil_from_days(days);
    let seconds = mtime % 86_400;
    let date = match now.abs_diff(mtime) < SIX_MONTHS {
        true => format!("{} {day:>2} {:02}:{:02}", MONTHS[month - 1], seconds / 3600, seconds % 3600 / 60),
        false => format!("{} {day:>2}  {year}", MONTHS[month - 1]),
    };
    let mut line = format!(
        "{mode} {:>3} {user:<8.8} {gid:<8} {:>8} {date} ",
        1,
        attrs.size.unwrap_or(0)
    )
    .into_bytes();
    line.extend_from_slice(name);
    line
}

fn civil_from_days(days: i64) -> (i64, usize, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, usize::try_from(month).unwrap_or(1), day)
}

pub(crate) struct Core {
    engine: Engine,
    input: Vec<u8>,
    output: Vec<u8>,
    sent: usize,
}

impl Core {
    pub(crate) fn new(engine: Engine) -> Self {
        Self { engine, input: Vec::new(), output: Vec::new(), sent: 0 }
    }

    pub(crate) fn push(&mut self, data: &[u8]) -> Result<(), Fatal> {
        if self.input.len() + data.len() > MAX_BUFFERED_INPUT {
            return Err(Fatal("too much unprocessed input"));
        }
        self.input.extend_from_slice(data);
        let (mut at, mut count) = (0, 0);
        while let Some(header) = self.input.get(at..at + 4) {
            let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
            if len == 0 || len > MAX_PACKET {
                return Err(Fatal("invalid packet length"));
            }
            if self.input.len() < at + 4 + len {
                break;
            }
            count += 1;
            if count > MAX_PENDING {
                return Err(Fatal("too many pending requests"));
            }
            at += 4 + len;
        }
        Ok(())
    }

    pub(crate) fn run(&mut self) -> Result<usize, Fatal> {
        let (mut at, mut requests) = (0, 0);
        let result = loop {
            if requests >= MAX_BATCH || self.output.len() - self.sent >= OUTPUT_SOFT_LIMIT {
                break Ok(());
            }
            let Some(header) = self.input.get(at..at + 4) else { break Ok(()) };
            let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
            if len == 0 || len > MAX_PACKET {
                break Err(Fatal("invalid packet length"));
            }
            let Some(packet) = self.input.get(at + 4..at + 4 + len) else { break Ok(()) };
            if let Err(fatal) = self.engine.handle(packet, &mut self.output) {
                break Err(fatal);
            }
            at += 4 + len;
            requests += 1;
        };
        self.input.drain(..at);
        result.map(|()| at)
    }

    pub(crate) fn has_request(&self) -> bool {
        self.input
            .get(..4)
            .map(|header| u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize)
            .is_some_and(|len| self.input.len() >= 4 + len)
    }

    pub(crate) fn output(&self, limit: usize) -> &[u8] {
        let waiting = &self.output[self.sent..];
        &waiting[..waiting.len().min(limit)]
    }

    pub(crate) fn sent(&mut self, count: usize) {
        self.sent = (self.sent + count).min(self.output.len());
        if self.sent == self.output.len() {
            self.output.clear();
            self.sent = 0;
        } else if self.sent >= OUTPUT_SOFT_LIMIT {
            self.output.drain(..self.sent);
            self.sent = 0;
        }
    }

    pub(crate) fn discard(&mut self) -> usize {
        let count = self.input.len();
        self.input.clear();
        count
    }

    pub(crate) fn has_output(&self) -> bool {
        self.sent < self.output.len()
    }
}
