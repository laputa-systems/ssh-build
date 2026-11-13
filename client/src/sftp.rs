use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::io::{Read, Write};
use std::ops::BitOr;

use crate::client::Connection;
use crate::error::Error;
use crate::subsystem::{Link, Subsystem};
use crate::wire::Interrupt;

/// The protocol version this client speaks.
pub const VERSION: u32 = 3;
/// The largest packet the client accepts from the server.
pub const MAX_PACKET: usize = 512 * 1024;
/// The read and write size used when the server offers no limits.
pub const DEFAULT_BLOCK: usize = 32 * 1024;
/// The largest read or write size the client asks for, whatever the server allows.
pub const MAX_BLOCK: usize = 64 * 1024;
/// The most requests a pipelined transfer keeps in flight.
pub const MAX_OUTSTANDING: usize = 64;
const MAX_HANDLE: usize = 256;
const MAX_DIR_ENTRIES: usize = 1 << 20;
const MAX_EXTENSIONS: usize = 256;
const READ_OVERHEAD: usize = 32;
const WRITE_OVERHEAD: usize = 1024;

const FXP_INIT: u8 = 1;
const FXP_VERSION: u8 = 2;
const FXP_OPEN: u8 = 3;
const FXP_CLOSE: u8 = 4;
const FXP_READ: u8 = 5;
const FXP_WRITE: u8 = 6;
const FXP_LSTAT: u8 = 7;
const FXP_FSTAT: u8 = 8;
const FXP_SETSTAT: u8 = 9;
const FXP_FSETSTAT: u8 = 10;
const FXP_OPENDIR: u8 = 11;
const FXP_READDIR: u8 = 12;
const FXP_REMOVE: u8 = 13;
const FXP_MKDIR: u8 = 14;
const FXP_RMDIR: u8 = 15;
const FXP_REALPATH: u8 = 16;
const FXP_STAT: u8 = 17;
const FXP_RENAME: u8 = 18;
const FXP_READLINK: u8 = 19;
const FXP_SYMLINK: u8 = 20;
const FXP_STATUS: u8 = 101;
const FXP_HANDLE: u8 = 102;
const FXP_DATA: u8 = 103;
const FXP_NAME: u8 = 104;
const FXP_ATTRS: u8 = 105;
const FXP_EXTENDED: u8 = 200;
const FXP_EXTENDED_REPLY: u8 = 201;

/// `SSH_FX_OK`.
pub const STATUS_OK: u32 = 0;
/// `SSH_FX_EOF`.
pub const STATUS_EOF: u32 = 1;
/// `SSH_FX_NO_SUCH_FILE`.
pub const STATUS_NO_SUCH_FILE: u32 = 2;
/// `SSH_FX_PERMISSION_DENIED`.
pub const STATUS_PERMISSION_DENIED: u32 = 3;
/// `SSH_FX_FAILURE`.
pub const STATUS_FAILURE: u32 = 4;
/// `SSH_FX_BAD_MESSAGE`.
pub const STATUS_BAD_MESSAGE: u32 = 5;
/// `SSH_FX_NO_CONNECTION`.
pub const STATUS_NO_CONNECTION: u32 = 6;
/// `SSH_FX_CONNECTION_LOST`.
pub const STATUS_CONNECTION_LOST: u32 = 7;
/// `SSH_FX_OP_UNSUPPORTED`.
pub const STATUS_OP_UNSUPPORTED: u32 = 8;

const ATTR_SIZE: u32 = 0x1;
const ATTR_UIDGID: u32 = 0x2;
const ATTR_PERMISSIONS: u32 = 0x4;
const ATTR_ACMODTIME: u32 = 0x8;
const ATTR_EXTENDED: u32 = 0x8000_0000;

const POSIX_RENAME: &str = "posix-rename@openssh.com";
const STATVFS: &str = "statvfs@openssh.com";
const FSTATVFS: &str = "fstatvfs@openssh.com";
const HARDLINK: &str = "hardlink@openssh.com";
const FSYNC: &str = "fsync@openssh.com";
const LIMITS: &str = "limits@openssh.com";

/// A failure of an SFTP operation.
#[derive(Debug)]
pub enum SftpError {
    /// The SSH connection failed; the session is unusable.
    Transport(Error),
    /// The server answered with a failure status.
    Status {
        /// The `SSH_FX_*` code.
        code: u32,
        /// The server's message, possibly empty.
        message: String,
    },
    /// The server sent something the protocol does not allow.
    Protocol(String),
    /// The server does not offer the extension the operation needs.
    Unsupported(&'static str),
    /// Reading or writing a local stream failed.
    Local(std::io::Error),
}

impl SftpError {
    /// Whether the server said the path does not exist.
    pub fn is_no_such_file(&self) -> bool {
        matches!(self, Self::Status { code, .. } if *code == STATUS_NO_SUCH_FILE)
    }

    /// Whether the session can carry no further request.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Protocol(_))
    }
}

fn status_text(code: u32) -> &'static str {
    match code {
        STATUS_OK => "Success",
        STATUS_EOF => "End of file",
        STATUS_NO_SUCH_FILE => "No such file or directory",
        STATUS_PERMISSION_DENIED => "Permission denied",
        STATUS_FAILURE => "Failure",
        STATUS_BAD_MESSAGE => "Bad message",
        STATUS_NO_CONNECTION => "No connection",
        STATUS_CONNECTION_LOST => "Connection lost",
        STATUS_OP_UNSUPPORTED => "Operation unsupported",
        _ => "Unknown status",
    }
}

impl fmt::Display for SftpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "{error}"),
            Self::Status { code, message } => {
                let text = status_text(*code);
                if message.is_empty() || text.to_lowercase().contains(&message.to_lowercase()) {
                    write!(formatter, "{text}")
                } else {
                    write!(formatter, "{text}: {message}")
                }
            }
            Self::Protocol(detail) => write!(formatter, "SFTP protocol error: {detail}"),
            Self::Unsupported(extension) => {
                write!(formatter, "the server does not offer {extension}")
            }
            Self::Local(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for SftpError {}

impl From<Error> for SftpError {
    fn from(error: Error) -> Self {
        Self::Transport(error)
    }
}

impl From<std::io::Error> for SftpError {
    fn from(error: std::io::Error) -> Self {
        Self::Local(error)
    }
}

fn protocol(detail: impl Into<String>) -> SftpError {
    SftpError::Protocol(detail.into())
}

/// Flags for [`Sftp::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// `SSH_FXF_READ`.
    pub const READ: Self = Self(0x01);
    /// `SSH_FXF_WRITE`.
    pub const WRITE: Self = Self(0x02);
    /// `SSH_FXF_APPEND`.
    pub const APPEND: Self = Self(0x04);
    /// `SSH_FXF_CREAT`.
    pub const CREATE: Self = Self(0x08);
    /// `SSH_FXF_TRUNC`.
    pub const TRUNCATE: Self = Self(0x10);
    /// `SSH_FXF_EXCL`.
    pub const EXCLUSIVE: Self = Self(0x20);
}

impl BitOr for OpenFlags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// An open remote file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle(Vec<u8>);

impl Handle {
    /// The opaque handle bytes the server chose.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// File attributes as SFTP version 3 carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attrs {
    /// Size in bytes.
    pub size: Option<u64>,
    /// Owner and group identifiers.
    pub uid_gid: Option<(u32, u32)>,
    /// The mode, including the file type bits.
    pub permissions: Option<u32>,
    /// Access and modification time in seconds since the epoch.
    pub times: Option<(u32, u32)>,
    /// Vendor extension pairs.
    pub extended: Vec<(Vec<u8>, Vec<u8>)>,
}

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

impl Attrs {
    /// Attributes that set only the mode.
    pub fn with_permissions(mode: u32) -> Self {
        Self {
            permissions: Some(mode),
            ..Self::default()
        }
    }

    /// Whether the mode says directory.
    pub fn is_dir(&self) -> bool {
        self.permissions.is_some_and(|mode| mode & S_IFMT == S_IFDIR)
    }

    /// Whether the mode says regular file.
    pub fn is_regular(&self) -> bool {
        self.permissions.is_some_and(|mode| mode & S_IFMT == S_IFREG)
    }

    /// Whether the mode says symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.permissions.is_some_and(|mode| mode & S_IFMT == S_IFLNK)
    }

    /// Append the wire form.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut flags = 0;
        if self.size.is_some() {
            flags |= ATTR_SIZE;
        }
        if self.uid_gid.is_some() {
            flags |= ATTR_UIDGID;
        }
        if self.permissions.is_some() {
            flags |= ATTR_PERMISSIONS;
        }
        if self.times.is_some() {
            flags |= ATTR_ACMODTIME;
        }
        if !self.extended.is_empty() {
            flags |= ATTR_EXTENDED;
        }
        put_u32(out, flags);
        if let Some(size) = self.size {
            put_u64(out, size);
        }
        if let Some((uid, gid)) = self.uid_gid {
            put_u32(out, uid);
            put_u32(out, gid);
        }
        if let Some(permissions) = self.permissions {
            put_u32(out, permissions);
        }
        if let Some((accessed, modified)) = self.times {
            put_u32(out, accessed);
            put_u32(out, modified);
        }
        if !self.extended.is_empty() {
            put_u32(out, self.extended.len() as u32);
            for (name, data) in &self.extended {
                put_string(out, name);
                put_string(out, data);
            }
        }
    }

    /// Read the wire form.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, SftpError> {
        let flags = reader.u32()?;
        let mut attrs = Self::default();
        if flags & ATTR_SIZE != 0 {
            attrs.size = Some(reader.u64()?);
        }
        if flags & ATTR_UIDGID != 0 {
            attrs.uid_gid = Some((reader.u32()?, reader.u32()?));
        }
        if flags & ATTR_PERMISSIONS != 0 {
            attrs.permissions = Some(reader.u32()?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            attrs.times = Some((reader.u32()?, reader.u32()?));
        }
        if flags & ATTR_EXTENDED != 0 {
            let count = reader.u32()? as usize;
            if count > reader.remaining() / 8 {
                return Err(protocol("extended attribute count exceeds the packet"));
            }
            for _ in 0..count {
                attrs
                    .extended
                    .push((reader.string()?.to_vec(), reader.string()?.to_vec()));
            }
        }
        Ok(attrs)
    }
}

/// One directory entry from `readdir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The file name.
    pub name: Vec<u8>,
    /// The server's `ls -l` style line.
    pub long_name: Vec<u8>,
    /// The attributes, without following a symbolic link.
    pub attrs: Attrs,
}

/// File system statistics from `statvfs@openssh.com`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatVfs {
    /// File system block size.
    pub block_size: u64,
    /// Fundamental block size.
    pub fragment_size: u64,
    /// Blocks in fragment-size units.
    pub blocks: u64,
    /// Free blocks.
    pub blocks_free: u64,
    /// Free blocks for unprivileged users.
    pub blocks_available: u64,
    /// File serial numbers.
    pub files: u64,
    /// Free file serial numbers.
    pub files_free: u64,
    /// Free file serial numbers for unprivileged users.
    pub files_available: u64,
    /// File system identifier.
    pub fsid: u64,
    /// Mount flags; bit 0 is read-only and bit 1 is no-setuid.
    pub flags: u64,
    /// The longest file name.
    pub name_max: u64,
}

/// The sizes the session uses, from the server's `limits@openssh.com` answer or the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The bytes asked for in one read request.
    pub read_len: usize,
    /// The bytes sent in one write request.
    pub write_len: usize,
    /// The requests a pipelined transfer keeps in flight.
    pub outstanding: usize,
    /// The most open handles the server allows, or zero when it did not say.
    pub open_handles: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            read_len: DEFAULT_BLOCK,
            write_len: DEFAULT_BLOCK,
            outstanding: MAX_OUTSTANDING,
            open_handles: 0,
        }
    }
}

impl Limits {
    fn from_server(max_packet: u64, max_read: u64, max_write: u64, open_handles: u64) -> Self {
        let clamp = |wanted: usize, server: u64, overhead: usize| {
            let mut size = wanted;
            if server != 0 {
                size = size.min(usize::try_from(server).unwrap_or(usize::MAX));
            }
            if max_packet != 0 {
                let room = usize::try_from(max_packet).unwrap_or(usize::MAX).saturating_sub(overhead);
                size = size.min(room);
            }
            size.max(1)
        };
        Self {
            read_len: clamp(MAX_BLOCK, max_read, READ_OVERHEAD),
            write_len: clamp(MAX_BLOCK, max_write, WRITE_OVERHEAD),
            outstanding: MAX_OUTSTANDING,
            open_handles,
        }
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

/// A bounds-checked reader over one packet body.
pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a packet body.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SftpError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| protocol("truncated packet"))?;
        let bytes = self
            .data
            .get(self.position..end)
            .ok_or_else(|| protocol("truncated packet"))?;
        self.position = end;
        Ok(bytes)
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8, SftpError> {
        Ok(self.take(1)?[0])
    }

    /// Read a big-endian 32-bit integer.
    pub fn u32(&mut self) -> Result<u32, SftpError> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(bytes))
    }

    /// Read a big-endian 64-bit integer.
    pub fn u64(&mut self) -> Result<u64, SftpError> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(bytes))
    }

    /// Read a length-prefixed string.
    pub fn string(&mut self) -> Result<&'a [u8], SftpError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    /// The bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    /// Require that nothing is left.
    pub fn finish(&self) -> Result<(), SftpError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(protocol("trailing bytes in a packet"))
        }
    }
}

/// A decoded server reply to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `SSH_FXP_STATUS`.
    Status {
        /// The `SSH_FX_*` code.
        code: u32,
        /// The server's message.
        message: String,
    },
    /// `SSH_FXP_HANDLE`.
    Handle(Vec<u8>),
    /// `SSH_FXP_DATA`.
    Data(Vec<u8>),
    /// `SSH_FXP_NAME`.
    Names(Vec<DirEntry>),
    /// `SSH_FXP_ATTRS`.
    Attrs(Attrs),
    /// `SSH_FXP_EXTENDED_REPLY`.
    Extended(Vec<u8>),
}

/// Frame a request or init packet: length, type, then `body`.
pub fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(5 + body.len());
    put_u32(&mut packet, (1 + body.len()) as u32);
    packet.push(kind);
    packet.extend_from_slice(body);
    packet
}

/// Decode a reply packet's type and body into its request identifier and content.
pub fn parse_reply(kind: u8, body: &[u8]) -> Result<(u32, Reply), SftpError> {
    let mut reader = Reader::new(body);
    let id = reader.u32()?;
    let reply = match kind {
        FXP_STATUS => {
            let code = reader.u32()?;
            let message = if reader.remaining() == 0 {
                String::new()
            } else {
                let message = String::from_utf8_lossy(reader.string()?).into_owned();
                if reader.remaining() != 0 {
                    reader.string()?;
                }
                message
            };
            reader.finish()?;
            Reply::Status { code, message }
        }
        FXP_HANDLE => {
            let handle = reader.string()?;
            reader.finish()?;
            if handle.len() > MAX_HANDLE {
                return Err(protocol("handle exceeds 256 bytes"));
            }
            Reply::Handle(handle.to_vec())
        }
        FXP_DATA => {
            let data = reader.string()?.to_vec();
            reader.finish()?;
            Reply::Data(data)
        }
        FXP_NAME => {
            let count = reader.u32()? as usize;
            if count > reader.remaining() / 12 {
                return Err(protocol("name count exceeds the packet"));
            }
            let mut names = Vec::with_capacity(count);
            for _ in 0..count {
                let name = reader.string()?.to_vec();
                let long_name = reader.string()?.to_vec();
                let attrs = Attrs::decode(&mut reader)?;
                names.push(DirEntry {
                    name,
                    long_name,
                    attrs,
                });
            }
            reader.finish()?;
            Reply::Names(names)
        }
        FXP_ATTRS => {
            let attrs = Attrs::decode(&mut reader)?;
            reader.finish()?;
            Reply::Attrs(attrs)
        }
        FXP_EXTENDED_REPLY => Reply::Extended(body[4..].to_vec()),
        other => return Err(protocol(format!("unexpected reply type {other}"))),
    };
    Ok((id, reply))
}

/// Decode the server's `SSH_FXP_VERSION` body.
pub fn parse_version(body: &[u8]) -> Result<(u32, Vec<(String, String)>), SftpError> {
    let mut reader = Reader::new(body);
    let version = reader.u32()?;
    let mut extensions = Vec::new();
    while reader.remaining() > 0 {
        if extensions.len() >= MAX_EXTENSIONS {
            return Err(protocol("too many extensions"));
        }
        let name = String::from_utf8_lossy(reader.string()?).into_owned();
        let data = String::from_utf8_lossy(reader.string()?).into_owned();
        extensions.push((name, data));
    }
    Ok((version, extensions))
}

struct Flight {
    offset: u64,
    length: usize,
}

/// An SFTP version 3 client session.
pub struct Sftp<L: Link = Subsystem> {
    link: L,
    next_id: u32,
    version: u32,
    extensions: Vec<(String, String)>,
    limits: Limits,
}

impl Sftp<Subsystem> {
    /// Start the `sftp` subsystem on an authenticated connection and negotiate the version.
    pub fn connect(connection: Connection, interrupt: Option<Interrupt>) -> Result<Self, SftpError> {
        let link = Subsystem::open(connection, "sftp", interrupt)?;
        Self::new(link)
    }

    /// The underlying SSH connection.
    pub fn connection(&self) -> &Connection {
        self.link.connection()
    }
}

impl<L: Link> Sftp<L> {
    /// Negotiate the protocol version over `link` and discover the server's extensions.
    pub fn new(link: L) -> Result<Self, SftpError> {
        let mut sftp = Self {
            link,
            next_id: 1,
            version: VERSION,
            extensions: Vec::new(),
            limits: Limits::default(),
        };
        sftp.link.send(&frame(FXP_INIT, &VERSION.to_be_bytes()))?;
        let (kind, body) = sftp.read_packet()?;
        if kind != FXP_VERSION {
            return Err(protocol(format!("expected a version reply, got type {kind}")));
        }
        let (version, extensions) = parse_version(&body)?;
        if version != VERSION {
            return Err(SftpError::Unsupported("SFTP version 3"));
        }
        sftp.version = version;
        sftp.extensions = extensions;
        if sftp.has_extension(LIMITS) {
            sftp.limits = sftp.discover_limits()?;
        }
        Ok(sftp)
    }

    fn discover_limits(&mut self) -> Result<Limits, SftpError> {
        match self.extended(LIMITS, &[])? {
            Reply::Extended(data) => {
                let mut reader = Reader::new(&data);
                let max_packet = reader.u64()?;
                let max_read = reader.u64()?;
                let max_write = reader.u64()?;
                let handles = reader.u64()?;
                reader.finish()?;
                Ok(Limits::from_server(max_packet, max_read, max_write, handles))
            }
            Reply::Status { .. } => Ok(Limits::default()),
            _ => Err(protocol("unexpected limits reply")),
        }
    }

    /// The negotiated protocol version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The extension names and data the server announced.
    pub fn extensions(&self) -> &[(String, String)] {
        &self.extensions
    }

    /// Whether the server announced `name`.
    pub fn has_extension(&self, name: &str) -> bool {
        self.extensions.iter().any(|(offered, _)| offered == name)
    }

    /// The sizes in force for this session.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// End the session.
    pub fn disconnect(mut self) {
        self.link.close();
    }

    fn read_packet(&mut self) -> Result<(u8, Vec<u8>), SftpError> {
        self.link.fill_at_least(4)?;
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&self.link.buffered()[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length == 0 || length > MAX_PACKET {
            return Err(protocol(format!("packet length {length} is out of bounds")));
        }
        self.link.fill_at_least(4 + length)?;
        let packet = &self.link.buffered()[4..4 + length];
        let kind = packet[0];
        let body = packet[1..].to_vec();
        self.link.consume(4 + length)?;
        Ok((kind, body))
    }

    fn read_reply(&mut self) -> Result<(u32, Reply), SftpError> {
        let (kind, body) = self.read_packet()?;
        parse_reply(kind, &body)
    }

    fn take_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn send_request(&mut self, kind: u8, build: impl FnOnce(&mut Vec<u8>)) -> Result<u32, SftpError> {
        let id = self.take_id();
        let mut body = Vec::new();
        put_u32(&mut body, id);
        build(&mut body);
        if body.len() + 1 > MAX_PACKET {
            return Err(protocol("request exceeds the packet bound"));
        }
        self.link.send(&frame(kind, &body))?;
        Ok(id)
    }

    fn call(&mut self, kind: u8, build: impl FnOnce(&mut Vec<u8>)) -> Result<Reply, SftpError> {
        let id = self.send_request(kind, build)?;
        let (reply_id, reply) = self.read_reply()?;
        if reply_id != id {
            return Err(protocol(format!("reply for request {reply_id}, expected {id}")));
        }
        Ok(reply)
    }

    fn extended(&mut self, name: &str, arguments: &[&[u8]]) -> Result<Reply, SftpError> {
        self.call(FXP_EXTENDED, |body| {
            put_string(body, name.as_bytes());
            for argument in arguments {
                put_string(body, argument);
            }
        })
    }

    fn require(&self, name: &'static str) -> Result<(), SftpError> {
        if self.has_extension(name) {
            Ok(())
        } else {
            Err(SftpError::Unsupported(name))
        }
    }

    fn expect_ok(reply: Reply) -> Result<(), SftpError> {
        match reply {
            Reply::Status { code: STATUS_OK, .. } => Ok(()),
            other => Err(Self::failure(other)),
        }
    }

    fn failure(reply: Reply) -> SftpError {
        match reply {
            Reply::Status { code, message } => SftpError::Status { code, message },
            other => protocol(format!("unexpected reply {}", reply_name(&other))),
        }
    }

    fn expect_handle(reply: Reply) -> Result<Handle, SftpError> {
        match reply {
            Reply::Handle(bytes) => Ok(Handle(bytes)),
            other => Err(Self::failure(other)),
        }
    }

    fn expect_attrs(reply: Reply) -> Result<Attrs, SftpError> {
        match reply {
            Reply::Attrs(attrs) => Ok(attrs),
            other => Err(Self::failure(other)),
        }
    }

    fn expect_one_name(reply: Reply) -> Result<Vec<u8>, SftpError> {
        match reply {
            Reply::Names(mut names) if names.len() == 1 => Ok(names.remove(0).name),
            Reply::Names(_) => Err(protocol("expected exactly one name")),
            other => Err(Self::failure(other)),
        }
    }

    /// Open a remote file.
    pub fn open(
        &mut self,
        path: impl AsRef<[u8]>,
        flags: OpenFlags,
        attrs: &Attrs,
    ) -> Result<Handle, SftpError> {
        let reply = self.call(FXP_OPEN, |body| {
            put_string(body, path.as_ref());
            put_u32(body, flags.0);
            attrs.encode(body);
        })?;
        Self::expect_handle(reply)
    }

    /// Close a handle.
    pub fn close_handle(&mut self, handle: &Handle) -> Result<(), SftpError> {
        let reply = self.call(FXP_CLOSE, |body| put_string(body, &handle.0))?;
        Self::expect_ok(reply)
    }

    /// Read up to `length` bytes at `offset` with one request. An empty answer is end of file.
    pub fn read(&mut self, handle: &Handle, offset: u64, length: usize) -> Result<Vec<u8>, SftpError> {
        let length = length.min(self.limits.read_len);
        let reply = self.call(FXP_READ, |body| {
            put_string(body, &handle.0);
            put_u64(body, offset);
            put_u32(body, length as u32);
        })?;
        match reply {
            Reply::Data(data) if data.len() <= length => Ok(data),
            Reply::Data(_) => Err(protocol("server returned more data than requested")),
            Reply::Status { code: STATUS_EOF, .. } => Ok(Vec::new()),
            other => Err(Self::failure(other)),
        }
    }

    /// Write `data` at `offset` with one request, which must not exceed the write size.
    pub fn write(&mut self, handle: &Handle, offset: u64, data: &[u8]) -> Result<(), SftpError> {
        if data.len() > self.limits.write_len {
            return Err(protocol("write exceeds the negotiated size"));
        }
        let reply = self.call(FXP_WRITE, |body| {
            put_string(body, &handle.0);
            put_u64(body, offset);
            put_string(body, data);
        })?;
        Self::expect_ok(reply)
    }

    /// Attributes of `path`, following symbolic links.
    pub fn stat(&mut self, path: impl AsRef<[u8]>) -> Result<Attrs, SftpError> {
        let reply = self.call(FXP_STAT, |body| put_string(body, path.as_ref()))?;
        Self::expect_attrs(reply)
    }

    /// Attributes of `path`, not following a final symbolic link.
    pub fn lstat(&mut self, path: impl AsRef<[u8]>) -> Result<Attrs, SftpError> {
        let reply = self.call(FXP_LSTAT, |body| put_string(body, path.as_ref()))?;
        Self::expect_attrs(reply)
    }

    /// Attributes of an open file.
    pub fn fstat(&mut self, handle: &Handle) -> Result<Attrs, SftpError> {
        let reply = self.call(FXP_FSTAT, |body| put_string(body, &handle.0))?;
        Self::expect_attrs(reply)
    }

    /// Set attributes of `path`.
    pub fn setstat(&mut self, path: impl AsRef<[u8]>, attrs: &Attrs) -> Result<(), SftpError> {
        let reply = self.call(FXP_SETSTAT, |body| {
            put_string(body, path.as_ref());
            attrs.encode(body);
        })?;
        Self::expect_ok(reply)
    }

    /// Set attributes of an open file.
    pub fn fsetstat(&mut self, handle: &Handle, attrs: &Attrs) -> Result<(), SftpError> {
        let reply = self.call(FXP_FSETSTAT, |body| {
            put_string(body, &handle.0);
            attrs.encode(body);
        })?;
        Self::expect_ok(reply)
    }

    /// Open a directory for listing.
    pub fn opendir(&mut self, path: impl AsRef<[u8]>) -> Result<Handle, SftpError> {
        let reply = self.call(FXP_OPENDIR, |body| put_string(body, path.as_ref()))?;
        Self::expect_handle(reply)
    }

    /// The next batch of entries, or `None` at the end of the directory.
    pub fn readdir(&mut self, handle: &Handle) -> Result<Option<Vec<DirEntry>>, SftpError> {
        let reply = self.call(FXP_READDIR, |body| put_string(body, &handle.0))?;
        match reply {
            Reply::Names(names) if names.is_empty() => Err(protocol("empty directory batch")),
            Reply::Names(names) => Ok(Some(names)),
            Reply::Status { code: STATUS_EOF, .. } => Ok(None),
            other => Err(Self::failure(other)),
        }
    }

    /// Every entry of a directory, including `.` and `..` when the server lists them.
    pub fn read_dir(&mut self, path: impl AsRef<[u8]>) -> Result<Vec<DirEntry>, SftpError> {
        let handle = self.opendir(path)?;
        let mut entries = Vec::new();
        let listed = loop {
            match self.readdir(&handle) {
                Ok(Some(batch)) => {
                    entries.extend(batch);
                    if entries.len() > MAX_DIR_ENTRIES {
                        break Err(protocol("directory listing exceeds a million entries"));
                    }
                }
                Ok(None) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        let closed = self.close_handle(&handle);
        listed?;
        closed?;
        Ok(entries)
    }

    /// Remove a file.
    pub fn remove(&mut self, path: impl AsRef<[u8]>) -> Result<(), SftpError> {
        let reply = self.call(FXP_REMOVE, |body| put_string(body, path.as_ref()))?;
        Self::expect_ok(reply)
    }

    /// Create a directory.
    pub fn mkdir(&mut self, path: impl AsRef<[u8]>, attrs: &Attrs) -> Result<(), SftpError> {
        let reply = self.call(FXP_MKDIR, |body| {
            put_string(body, path.as_ref());
            attrs.encode(body);
        })?;
        Self::expect_ok(reply)
    }

    /// Remove an empty directory.
    pub fn rmdir(&mut self, path: impl AsRef<[u8]>) -> Result<(), SftpError> {
        let reply = self.call(FXP_RMDIR, |body| put_string(body, path.as_ref()))?;
        Self::expect_ok(reply)
    }

    /// The canonical absolute form of `path`.
    pub fn realpath(&mut self, path: impl AsRef<[u8]>) -> Result<Vec<u8>, SftpError> {
        let reply = self.call(FXP_REALPATH, |body| put_string(body, path.as_ref()))?;
        Self::expect_one_name(reply)
    }

    /// Rename `from` to `to`, replacing an existing `to` when the server offers
    /// `posix-rename@openssh.com`.
    pub fn rename(&mut self, from: impl AsRef<[u8]>, to: impl AsRef<[u8]>) -> Result<(), SftpError> {
        let reply = if self.has_extension(POSIX_RENAME) {
            self.extended(POSIX_RENAME, &[from.as_ref(), to.as_ref()])?
        } else {
            self.call(FXP_RENAME, |body| {
                put_string(body, from.as_ref());
                put_string(body, to.as_ref());
            })?
        };
        Self::expect_ok(reply)
    }

    /// The target of the symbolic link `path`.
    pub fn readlink(&mut self, path: impl AsRef<[u8]>) -> Result<Vec<u8>, SftpError> {
        let reply = self.call(FXP_READLINK, |body| put_string(body, path.as_ref()))?;
        Self::expect_one_name(reply)
    }

    /// Create the symbolic link `link` pointing at `target`.
    pub fn symlink(&mut self, target: impl AsRef<[u8]>, link: impl AsRef<[u8]>) -> Result<(), SftpError> {
        // OpenSSH servers take the target first, the reverse of the draft's field order.
        let reply = self.call(FXP_SYMLINK, |body| {
            put_string(body, target.as_ref());
            put_string(body, link.as_ref());
        })?;
        Self::expect_ok(reply)
    }

    /// Create the hard link `link` to `existing`, with `hardlink@openssh.com`.
    pub fn hardlink(&mut self, existing: impl AsRef<[u8]>, link: impl AsRef<[u8]>) -> Result<(), SftpError> {
        self.require(HARDLINK)?;
        let reply = self.extended(HARDLINK, &[existing.as_ref(), link.as_ref()])?;
        Self::expect_ok(reply)
    }

    /// Flush an open file to stable storage, with `fsync@openssh.com`.
    pub fn fsync(&mut self, handle: &Handle) -> Result<(), SftpError> {
        self.require(FSYNC)?;
        let reply = self.extended(FSYNC, &[&handle.0])?;
        Self::expect_ok(reply)
    }

    /// Statistics of the file system holding `path`, with `statvfs@openssh.com`.
    pub fn statvfs(&mut self, path: impl AsRef<[u8]>) -> Result<StatVfs, SftpError> {
        self.require(STATVFS)?;
        let reply = self.extended(STATVFS, &[path.as_ref()])?;
        Self::expect_statvfs(reply)
    }

    /// Statistics of the file system holding an open file, with `fstatvfs@openssh.com`.
    pub fn fstatvfs(&mut self, handle: &Handle) -> Result<StatVfs, SftpError> {
        self.require(FSTATVFS)?;
        let reply = self.extended(FSTATVFS, &[&handle.0])?;
        Self::expect_statvfs(reply)
    }

    fn expect_statvfs(reply: Reply) -> Result<StatVfs, SftpError> {
        match reply {
            Reply::Extended(data) => {
                let mut reader = Reader::new(&data);
                let stats = StatVfs {
                    block_size: reader.u64()?,
                    fragment_size: reader.u64()?,
                    blocks: reader.u64()?,
                    blocks_free: reader.u64()?,
                    blocks_available: reader.u64()?,
                    files: reader.u64()?,
                    files_free: reader.u64()?,
                    files_available: reader.u64()?,
                    fsid: reader.u64()?,
                    flags: reader.u64()?,
                    name_max: reader.u64()?,
                };
                reader.finish()?;
                Ok(stats)
            }
            other => Err(Self::failure(other)),
        }
    }

    /// Read from `start` to the end of the file into `out`, with up to
    /// [`Limits::outstanding`] read requests in flight. A nonzero `size_hint` bounds the
    /// requests to the size the server reported; zero or `None` reads until end of file.
    /// `progress` receives the bytes written to `out` so far after each chunk.
    pub fn download(
        &mut self,
        handle: &Handle,
        start: u64,
        size_hint: Option<u64>,
        out: &mut dyn Write,
        progress: &mut dyn FnMut(u64),
    ) -> Result<u64, SftpError> {
        let mut flights = HashMap::new();
        let result = self.download_loop(handle, start, size_hint, out, progress, &mut flights);
        self.finish_flights(&result, flights.len());
        result
    }

    fn finish_flights(&mut self, result: &Result<u64, SftpError>, left: usize) {
        if matches!(result, Err(error) if !error.is_fatal()) {
            for _ in 0..left {
                if self.read_reply().is_err() {
                    break;
                }
            }
        }
    }

    fn download_loop(
        &mut self,
        handle: &Handle,
        start: u64,
        size_hint: Option<u64>,
        out: &mut dyn Write,
        progress: &mut dyn FnMut(u64),
        flights: &mut HashMap<u32, Flight>,
    ) -> Result<u64, SftpError> {
        let end = size_hint.filter(|size| *size > 0).map(|size| size.max(start));
        let block = self.limits.read_len;
        let outstanding = self.limits.outstanding;
        let mut next_offset = start;
        let mut write_at = start;
        let mut eof_at: Option<u64> = None;
        let mut retries: VecDeque<Flight> = VecDeque::new();
        let mut ready: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        loop {
            while flights.len() < outstanding {
                let flight = if let Some(retry) = retries.pop_front() {
                    if eof_at.is_some_and(|eof| retry.offset >= eof) {
                        continue;
                    }
                    retry
                } else if eof_at.is_none() && end.is_none_or(|end| next_offset < end) {
                    let mut length = block as u64;
                    if let Some(end) = end {
                        length = length.min(end - next_offset);
                    }
                    let flight = Flight {
                        offset: next_offset,
                        length: length as usize,
                    };
                    next_offset += length;
                    flight
                } else {
                    break;
                };
                let id = self.send_request(FXP_READ, |body| {
                    put_string(body, &handle.0);
                    put_u64(body, flight.offset);
                    put_u32(body, flight.length as u32);
                })?;
                flights.insert(id, flight);
            }
            if flights.is_empty() {
                break;
            }
            let (id, reply) = self.read_reply()?;
            let flight = flights
                .remove(&id)
                .ok_or_else(|| protocol(format!("reply for unknown request {id}")))?;
            match reply {
                Reply::Data(data) => {
                    if data.is_empty() || data.len() > flight.length {
                        return Err(protocol("read reply has a bad length"));
                    }
                    if data.len() < flight.length {
                        retries.push_back(Flight {
                            offset: flight.offset + data.len() as u64,
                            length: flight.length - data.len(),
                        });
                    }
                    if ready.insert(flight.offset, data).is_some() {
                        return Err(protocol("overlapping read replies"));
                    }
                    while let Some(chunk) = ready.remove(&write_at) {
                        out.write_all(&chunk)?;
                        write_at += chunk.len() as u64;
                        progress(write_at - start);
                    }
                }
                Reply::Status { code: STATUS_EOF, .. } => {
                    eof_at = Some(eof_at.map_or(flight.offset, |eof| eof.min(flight.offset)));
                }
                other => return Err(Self::failure(other)),
            }
        }
        if !ready.is_empty() || eof_at.is_some_and(|eof| write_at < eof) {
            return Err(protocol("the server left a gap in the file"));
        }
        if let Some(end) = end
            && eof_at.is_none()
            && write_at < end
        {
            return Err(protocol("the server left a gap in the file"));
        }
        Ok(write_at - start)
    }

    /// Write everything `input` yields to the file from `start`, with up to
    /// [`Limits::outstanding`] write requests in flight. `progress` receives the bytes
    /// acknowledged so far.
    pub fn upload(
        &mut self,
        handle: &Handle,
        start: u64,
        input: &mut dyn Read,
        progress: &mut dyn FnMut(u64),
    ) -> Result<u64, SftpError> {
        let mut flights = HashMap::new();
        let result = self.upload_loop(handle, start, input, progress, &mut flights);
        self.finish_flights(&result, flights.len());
        result
    }

    fn upload_loop(
        &mut self,
        handle: &Handle,
        start: u64,
        input: &mut dyn Read,
        progress: &mut dyn FnMut(u64),
        flights: &mut HashMap<u32, u64>,
    ) -> Result<u64, SftpError> {
        let block = self.limits.write_len;
        let outstanding = self.limits.outstanding;
        let mut buffer = vec![0u8; block];
        let mut offset = start;
        let mut acknowledged = 0u64;
        let mut exhausted = false;
        loop {
            while flights.len() < outstanding && !exhausted {
                let mut filled = 0;
                while filled < block {
                    match input.read(&mut buffer[filled..]) {
                        Ok(0) => {
                            exhausted = true;
                            break;
                        }
                        Ok(count) => filled += count,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if filled == 0 {
                    break;
                }
                let at = offset;
                let id = self.send_request(FXP_WRITE, |body| {
                    put_string(body, &handle.0);
                    put_u64(body, at);
                    put_string(body, &buffer[..filled]);
                })?;
                flights.insert(id, filled as u64);
                offset += filled as u64;
            }
            if flights.is_empty() {
                break;
            }
            let (id, reply) = self.read_reply()?;
            let length = flights
                .remove(&id)
                .ok_or_else(|| protocol(format!("reply for unknown request {id}")))?;
            Self::expect_ok(reply)?;
            acknowledged += length;
            progress(acknowledged);
        }
        Ok(acknowledged)
    }
}

fn reply_name(reply: &Reply) -> &'static str {
    match reply {
        Reply::Status { .. } => "status",
        Reply::Handle(_) => "handle",
        Reply::Data(_) => "data",
        Reply::Names(_) => "name",
        Reply::Attrs(_) => "attrs",
        Reply::Extended(_) => "extended reply",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, bytes);
        out
    }

    fn reply_frame(kind: u8, id: u32, rest: &[u8]) -> Vec<u8> {
        let mut body = id.to_be_bytes().to_vec();
        body.extend_from_slice(rest);
        frame(kind, &body)
    }

    fn status(id: u32, code: u32, message: &str) -> Vec<u8> {
        let mut rest = code.to_be_bytes().to_vec();
        rest.extend(string(message.as_bytes()));
        rest.extend(string(b""));
        reply_frame(FXP_STATUS, id, &rest)
    }

    fn data(id: u32, bytes: &[u8]) -> Vec<u8> {
        reply_frame(FXP_DATA, id, &string(bytes))
    }

    fn version_frame(extensions: &[(&str, &str)]) -> Vec<u8> {
        let mut body = VERSION.to_be_bytes().to_vec();
        for (name, value) in extensions {
            body.extend(string(name.as_bytes()));
            body.extend(string(value.as_bytes()));
        }
        frame(FXP_VERSION, &body)
    }

    type Responder = Box<dyn FnMut(u8, &[u8], &mut Vec<Vec<u8>>)>;
    type Hostile = Box<dyn Fn(u32, usize) -> Vec<u8>>;

    struct Scripted {
        inbound: Vec<u8>,
        outbound: Vec<u8>,
        reply: Responder,
        queued: Vec<Vec<u8>>,
        reverse: bool,
        requests: Vec<(u8, Vec<u8>)>,
        unanswered_peak: usize,
        closed: bool,
    }

    impl Scripted {
        fn new(
            initial: Vec<u8>,
            reply: impl FnMut(u8, &[u8], &mut Vec<Vec<u8>>) + 'static,
        ) -> Self {
            Self {
                inbound: initial,
                outbound: Vec::new(),
                reply: Box::new(reply),
                queued: Vec::new(),
                reverse: false,
                requests: Vec::new(),
                unanswered_peak: 0,
                closed: false,
            }
        }
    }

    impl Link for Scripted {
        fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
            self.outbound.extend_from_slice(bytes);
            while self.outbound.len() >= 4 {
                let length = u32::from_be_bytes(self.outbound[..4].try_into().expect("four")) as usize;
                if self.outbound.len() < 4 + length {
                    break;
                }
                let packet: Vec<u8> = self.outbound.drain(..4 + length).collect();
                let kind = packet[4];
                let body = packet[5..].to_vec();
                if kind == FXP_INIT {
                    continue;
                }
                self.requests.push((kind, body.clone()));
                (self.reply)(kind, &body, &mut self.queued);
                self.unanswered_peak = self.unanswered_peak.max(self.queued.len());
            }
            Ok(())
        }

        fn fill_at_least(&mut self, length: usize) -> Result<(), Error> {
            if self.inbound.len() < length {
                let mut queued = std::mem::take(&mut self.queued);
                if self.reverse {
                    queued.reverse();
                }
                for packet in queued {
                    self.inbound.extend(packet);
                }
            }
            if self.inbound.len() < length {
                return Err(Error::Channel {
                    detail: "the server closed the channel".to_owned(),
                });
            }
            Ok(())
        }

        fn buffered(&self) -> &[u8] {
            &self.inbound
        }

        fn consume(&mut self, length: usize) -> Result<(), Error> {
            self.inbound.drain(..length);
            Ok(())
        }

        fn close(&mut self) {
            self.closed = true;
        }
    }

    fn request_id(body: &[u8]) -> u32 {
        u32::from_be_bytes(body[..4].try_into().expect("id"))
    }

    fn read_request(body: &[u8]) -> (u64, usize) {
        let mut reader = Reader::new(&body[4..]);
        reader.string().expect("handle");
        (reader.u64().expect("offset"), reader.u32().expect("length") as usize)
    }

    fn file_server(content: Vec<u8>, slice: usize) -> Scripted {
        Scripted::new(version_frame(&[]), move |kind, body, out| {
            let id = request_id(body);
            match kind {
                FXP_OPEN => out.push(reply_frame(FXP_HANDLE, id, &string(b"h"))),
                FXP_READ => {
                    let (offset, length) = read_request(body);
                    let offset = offset as usize;
                    if offset >= content.len() {
                        out.push(status(id, STATUS_EOF, ""));
                    } else {
                        let end = (offset + length.min(slice)).min(content.len());
                        out.push(data(id, &content[offset..end]));
                    }
                }
                FXP_CLOSE => out.push(status(id, STATUS_OK, "")),
                _ => out.push(status(id, STATUS_OP_UNSUPPORTED, "")),
            }
        })
    }

    fn pattern(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index * 31 % 251) as u8).collect()
    }

    #[test]
    fn attributes_round_trip_in_every_combination() {
        let full = Attrs {
            size: Some(u64::MAX),
            uid_gid: Some((1000, 2000)),
            permissions: Some(0o100_644),
            times: Some((1, 2)),
            extended: vec![(b"a@b".to_vec(), b"v".to_vec())],
        };
        for mask in 0..32u32 {
            let attrs = Attrs {
                size: (mask & 1 != 0).then_some(full.size).flatten(),
                uid_gid: (mask & 2 != 0).then_some(full.uid_gid).flatten(),
                permissions: (mask & 4 != 0).then_some(full.permissions).flatten(),
                times: (mask & 8 != 0).then_some(full.times).flatten(),
                extended: if mask & 16 != 0 { full.extended.clone() } else { Vec::new() },
            };
            let mut wire = Vec::new();
            attrs.encode(&mut wire);
            let mut reader = Reader::new(&wire);
            assert_eq!(Attrs::decode(&mut reader).expect("decodes"), attrs, "{mask}");
            reader.finish().expect("fully consumed");
        }
        assert!(full.is_regular() && !full.is_dir() && !full.is_symlink());
        assert!(Attrs::with_permissions(0o040_755).is_dir());
        assert!(Attrs::with_permissions(0o120_777).is_symlink());
    }

    #[test]
    fn frames_carry_a_length_and_a_type() {
        assert_eq!(frame(FXP_INIT, &3u32.to_be_bytes()), [0, 0, 0, 5, 1, 0, 0, 0, 3]);
        assert_eq!(frame(FXP_CLOSE, &[]), [0, 0, 0, 1, 4]);
    }

    #[test]
    fn every_reply_type_decodes() {
        let (id, reply) = parse_reply(FXP_STATUS, &status(7, STATUS_NO_SUCH_FILE, "gone")[5..]).expect("status");
        assert_eq!((id, reply), (7, Reply::Status { code: STATUS_NO_SUCH_FILE, message: "gone".to_owned() }));
        let (_, reply) = parse_reply(FXP_HANDLE, &reply_frame(FXP_HANDLE, 1, &string(b"abc"))[5..]).expect("handle");
        assert_eq!(reply, Reply::Handle(b"abc".to_vec()));
        let (_, reply) = parse_reply(FXP_DATA, &data(1, b"xyz")[5..]).expect("data");
        assert_eq!(reply, Reply::Data(b"xyz".to_vec()));
        let mut names = 1u32.to_be_bytes().to_vec();
        names.extend(string(b"f"));
        names.extend(string(b"-rw f"));
        Attrs::with_permissions(0o100_600).encode(&mut names);
        let (_, reply) = parse_reply(FXP_NAME, &reply_frame(FXP_NAME, 1, &names)[5..]).expect("name");
        assert!(matches!(reply, Reply::Names(ref list) if list.len() == 1 && list[0].name == b"f" && list[0].attrs.is_regular()));
        let mut attrs = Vec::new();
        Attrs { size: Some(9), ..Attrs::default() }.encode(&mut attrs);
        let (_, reply) = parse_reply(FXP_ATTRS, &reply_frame(FXP_ATTRS, 1, &attrs)[5..]).expect("attrs");
        assert_eq!(reply, Reply::Attrs(Attrs { size: Some(9), ..Attrs::default() }));
        let (_, reply) = parse_reply(FXP_EXTENDED_REPLY, &reply_frame(FXP_EXTENDED_REPLY, 1, b"raw")[5..]).expect("extended");
        assert_eq!(reply, Reply::Extended(b"raw".to_vec()));
    }

    #[test]
    fn a_status_without_a_message_is_accepted() {
        let mut rest = 4u32.to_be_bytes().to_vec();
        let (_, reply) = parse_reply(FXP_STATUS, &[&1u32.to_be_bytes()[..], &rest].concat()).expect("short status");
        assert_eq!(reply, Reply::Status { code: STATUS_FAILURE, message: String::new() });
        rest.extend(string(b"m"));
        assert!(parse_reply(FXP_STATUS, &[&1u32.to_be_bytes()[..], &rest].concat()).is_ok());
    }

    #[test]
    fn malformed_replies_are_errors_and_never_panics() {
        let mut names = 1u32.to_be_bytes().to_vec();
        names.extend(string(b"f"));
        names.extend(string(b"l"));
        Attrs::with_permissions(1).encode(&mut names);
        let samples: Vec<(u8, Vec<u8>)> = vec![
            (FXP_STATUS, status(1, 4, "m")[5..].to_vec()),
            (FXP_HANDLE, reply_frame(FXP_HANDLE, 1, &string(b"abc"))[5..].to_vec()),
            (FXP_DATA, data(1, b"data")[5..].to_vec()),
            (FXP_NAME, reply_frame(FXP_NAME, 1, &names)[5..].to_vec()),
            (FXP_ATTRS, reply_frame(FXP_ATTRS, 1, &[0, 0, 0, 0xf])[5..].to_vec()),
        ];
        for (kind, body) in &samples {
            assert!(parse_reply(*kind, body).is_ok() || *kind == FXP_ATTRS);
            for cut in 0..body.len() {
                let _ = parse_reply(*kind, &body[..cut]);
            }
            let mut padded = body.clone();
            padded.push(0);
            assert!(parse_reply(*kind, &padded).is_err() || *kind == FXP_EXTENDED_REPLY, "trailing byte for {kind}");
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for round in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = (state % 48) as usize;
            let bytes: Vec<u8> = (0..length).map(|index| (state >> (index % 8 * 8)) as u8 ^ index as u8).collect();
            let kind = [FXP_STATUS, FXP_HANDLE, FXP_DATA, FXP_NAME, FXP_ATTRS, FXP_EXTENDED_REPLY, 0, 255][round % 8];
            let _ = parse_reply(kind, &bytes);
            let _ = parse_version(&bytes);
        }
        let huge_count = reply_frame(FXP_NAME, 1, &u32::MAX.to_be_bytes());
        assert!(parse_reply(FXP_NAME, &huge_count[5..]).is_err());
        let mut long_handle = Vec::new();
        long_handle.extend(string(&[0u8; 300]));
        assert!(parse_reply(FXP_HANDLE, &reply_frame(FXP_HANDLE, 1, &long_handle)[5..]).is_err());
        let mut many_extensions = Vec::new();
        for _ in 0..300 {
            many_extensions.extend(string(b"x"));
            many_extensions.extend(string(b"1"));
        }
        assert!(parse_version(&[&3u32.to_be_bytes()[..], &many_extensions].concat()).is_err());
    }

    #[test]
    fn the_version_reply_sets_extensions_and_limits() {
        let mut limits = Vec::new();
        for value in [262_144u64, 262_120, 262_000, 100] {
            limits.extend(value.to_be_bytes());
        }
        let link = Scripted::new(
            version_frame(&[("posix-rename@openssh.com", "1"), (LIMITS, "1")]),
            move |kind, body, out| {
                assert_eq!(kind, FXP_EXTENDED);
                out.push(reply_frame(FXP_EXTENDED_REPLY, request_id(body), &limits));
            },
        );
        let sftp = Sftp::new(link).expect("negotiates");
        assert_eq!(sftp.version(), 3);
        assert!(sftp.has_extension("posix-rename@openssh.com") && !sftp.has_extension("fsync@openssh.com"));
        assert_eq!(
            sftp.limits(),
            Limits { read_len: MAX_BLOCK, write_len: MAX_BLOCK, outstanding: MAX_OUTSTANDING, open_handles: 100 }
        );
        let small = Limits::from_server(2048, 700, 0, 0);
        assert_eq!((small.read_len, small.write_len), (700, 1024));
        assert_eq!(Limits::from_server(0, 0, 0, 0).read_len, MAX_BLOCK);
    }

    #[test]
    fn without_limits_the_default_block_applies() {
        let sftp = Sftp::new(Scripted::new(version_frame(&[]), |_, _, _| {})).expect("negotiates");
        assert_eq!(sftp.limits(), Limits::default());
        assert_eq!(sftp.limits().read_len, DEFAULT_BLOCK);
    }

    #[test]
    fn a_wrong_version_or_first_packet_is_refused() {
        let version_two = frame(FXP_VERSION, &2u32.to_be_bytes());
        assert!(matches!(Sftp::new(Scripted::new(version_two, |_, _, _| {})), Err(SftpError::Unsupported(_))));
        let status_first = status(0, 0, "");
        assert!(matches!(Sftp::new(Scripted::new(status_first, |_, _, _| {})), Err(SftpError::Protocol(_))));
        assert!(matches!(Sftp::new(Scripted::new(Vec::new(), |_, _, _| {})), Err(SftpError::Transport(_))));
    }

    #[test]
    fn oversized_and_empty_packets_are_protocol_errors() {
        for first in [vec![0, 0, 0, 0], ((MAX_PACKET + 1) as u32).to_be_bytes().to_vec(), u32::MAX.to_be_bytes().to_vec()] {
            match Sftp::new(Scripted::new(first, |_, _, _| {})) {
                Err(SftpError::Protocol(detail)) => assert!(detail.contains("out of bounds"), "{detail}"),
                other => panic!("expected a protocol error, got {:?}", other.map(|_| ())),
            }
        }
    }

    #[test]
    fn a_reply_for_another_request_is_a_protocol_error() {
        let link = Scripted::new(version_frame(&[]), |_, body, out| {
            out.push(status(request_id(body) + 5, STATUS_OK, ""));
        });
        let mut sftp = Sftp::new(link).expect("negotiates");
        assert!(matches!(sftp.remove("x"), Err(SftpError::Protocol(_))));
    }

    #[test]
    fn a_status_is_an_error_but_not_fatal() {
        let link = Scripted::new(version_frame(&[]), |_, body, out| {
            out.push(status(request_id(body), STATUS_PERMISSION_DENIED, "no"));
        });
        let mut sftp = Sftp::new(link).expect("negotiates");
        let error = sftp.remove("x").expect_err("denied");
        assert!(!error.is_fatal());
        assert_eq!(error.to_string(), "Permission denied: no");
        assert!(SftpError::Status { code: STATUS_NO_SUCH_FILE, message: "No such file".to_owned() }.to_string() == "No such file or directory");
    }

    #[test]
    fn extensions_the_server_lacks_are_refused_locally() {
        let mut sftp = Sftp::new(Scripted::new(version_frame(&[]), |_, _, _| panic!("no request expected"))).expect("negotiates");
        assert!(matches!(sftp.statvfs("/"), Err(SftpError::Unsupported(_))));
        assert!(matches!(sftp.hardlink("a", "b"), Err(SftpError::Unsupported(_))));
        assert!(matches!(sftp.fsync(&Handle(vec![1])), Err(SftpError::Unsupported(_))));
    }

    #[test]
    fn symlink_sends_the_target_first_and_rename_prefers_posix_rename() {
        let link = Scripted::new(version_frame(&[("posix-rename@openssh.com", "1")]), |_, body, out| {
            out.push(status(request_id(body), STATUS_OK, ""));
        });
        let mut sftp = Sftp::new(link).expect("negotiates");
        sftp.symlink("target", "linkname").expect("symlink");
        sftp.rename("a", "b").expect("rename");
        let requests = &sftp.link.requests;
        assert_eq!(requests[0].0, FXP_SYMLINK);
        let mut reader = Reader::new(&requests[0].1[4..]);
        assert_eq!((reader.string().expect("first"), reader.string().expect("second")), (&b"target"[..], &b"linkname"[..]));
        assert_eq!(requests[1].0, FXP_EXTENDED);
        let mut reader = Reader::new(&requests[1].1[4..]);
        assert_eq!(reader.string().expect("name"), b"posix-rename@openssh.com");
    }

    #[test]
    fn downloads_survive_reordered_and_short_replies() {
        let content = pattern(1_000_003);
        for (slice, reverse) in [(usize::MAX, false), (usize::MAX, true), (10_000, false), (777, true)] {
            let mut link = file_server(content.clone(), slice);
            link.reverse = reverse;
            let mut sftp = Sftp::new(link).expect("negotiates");
            let handle = sftp.open("f", OpenFlags::READ, &Attrs::default()).expect("open");
            let mut out = Vec::new();
            let mut last = 0;
            let total = sftp
                .download(&handle, 0, Some(content.len() as u64), &mut out, &mut |done| {
                    assert!(done > last);
                    last = done;
                })
                .expect("downloads");
            assert_eq!(total as usize, content.len(), "slice {slice} reverse {reverse}");
            assert!(out == content, "slice {slice} reverse {reverse}");
            assert!(sftp.link.unanswered_peak <= MAX_OUTSTANDING + 1);
            let longest = sftp
                .link
                .requests
                .iter()
                .filter(|(kind, _)| *kind == FXP_READ)
                .map(|(_, body)| read_request(body).1)
                .max()
                .expect("reads");
            assert!(longest <= DEFAULT_BLOCK, "{longest}");
        }
    }

    #[test]
    fn downloads_without_a_size_read_until_end_of_file() {
        for size in [0usize, 1, DEFAULT_BLOCK, DEFAULT_BLOCK * 3 + 5] {
            let content = pattern(size);
            let mut sftp = Sftp::new(file_server(content.clone(), usize::MAX)).expect("negotiates");
            let handle = sftp.open("f", OpenFlags::READ, &Attrs::default()).expect("open");
            for hint in [None, Some(0)] {
                let mut out = Vec::new();
                let total = sftp.download(&handle, 0, hint, &mut out, &mut |_| {}).expect("downloads");
                assert_eq!((total as usize, out), (size, content.clone()));
            }
        }
    }

    #[test]
    fn a_download_can_resume_at_an_offset() {
        let content = pattern(100_000);
        let mut sftp = Sftp::new(file_server(content.clone(), usize::MAX)).expect("negotiates");
        let handle = sftp.open("f", OpenFlags::READ, &Attrs::default()).expect("open");
        let mut out = Vec::new();
        let total = sftp.download(&handle, 40_000, Some(100_000), &mut out, &mut |_| {}).expect("downloads");
        assert_eq!(total, 60_000);
        assert!(out == content[40_000..]);
    }

    #[test]
    fn a_failing_read_ends_the_transfer_and_leaves_the_session_usable() {
        let content = pattern(DEFAULT_BLOCK * 10);
        let mut served = 0;
        let link = Scripted::new(version_frame(&[]), move |kind, body, out| {
            let id = request_id(body);
            match kind {
                FXP_READ => {
                    served += 1;
                    if served == 4 {
                        out.push(status(id, STATUS_FAILURE, "disk error"));
                    } else {
                        let (offset, length) = read_request(body);
                        out.push(data(id, &content[offset as usize..offset as usize + length]));
                    }
                }
                _ => out.push(status(id, STATUS_OK, "")),
            }
        });
        let mut sftp = Sftp::new(link).expect("negotiates");
        let mut out = Vec::new();
        let error = sftp
            .download(&Handle(vec![1]), 0, Some((DEFAULT_BLOCK * 10) as u64), &mut out, &mut |_| {})
            .expect_err("the fourth read fails");
        assert!(matches!(error, SftpError::Status { code: STATUS_FAILURE, .. }), "{error}");
        sftp.remove("still-works").expect("the stray replies were drained");
    }

    #[test]
    fn hostile_read_replies_are_protocol_errors() {
        let hostile: Vec<Hostile> = vec![
            Box::new(|id, length| data(id, &vec![0; length + 1])),
            Box::new(|id, _| data(id, b"")),
            Box::new(|id, _| reply_frame(FXP_HANDLE, id, &string(b"h"))),
            Box::new(|id, _| reply_frame(FXP_ATTRS, id, &[0, 0, 0, 0])),
        ];
        for respond in hostile {
            let link = Scripted::new(version_frame(&[]), move |_, body, out| {
                let (_, length) = read_request(body);
                out.push(respond(request_id(body), length));
            });
            let mut sftp = Sftp::new(link).expect("negotiates");
            let mut out = Vec::new();
            let error = sftp.download(&Handle(vec![1]), 0, Some(100_000), &mut out, &mut |_| {}).expect_err("rejected");
            assert!(error.is_fatal() || matches!(error, SftpError::Status { .. }), "{error}");
        }
    }

    #[test]
    fn a_reply_that_leaves_a_gap_is_detected() {
        let link = Scripted::new(version_frame(&[]), |_, body, out| {
            let (offset, length) = read_request(body);
            if offset == 0 {
                out.push(status(request_id(body), STATUS_EOF, ""));
            } else {
                out.push(data(request_id(body), &vec![1; length]));
            }
        });
        let mut sftp = Sftp::new(link).expect("negotiates");
        let mut out = Vec::new();
        assert!(sftp.download(&Handle(vec![1]), 0, None, &mut out, &mut |_| {}).is_err());
    }

    #[test]
    fn uploads_chunk_to_the_write_size_and_bound_the_outstanding_requests() {
        let content = pattern(DEFAULT_BLOCK * 200 + 17);
        let written = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
        let sink = std::rc::Rc::clone(&written);
        let link = Scripted::new(version_frame(&[]), move |kind, body, out| {
            let id = request_id(body);
            if kind == FXP_WRITE {
                let mut reader = Reader::new(&body[4..]);
                reader.string().expect("handle");
                let offset = reader.u64().expect("offset") as usize;
                let bytes = reader.string().expect("data");
                let mut file = sink.borrow_mut();
                if file.len() < offset + bytes.len() {
                    file.resize(offset + bytes.len(), 0);
                }
                file[offset..offset + bytes.len()].copy_from_slice(bytes);
            }
            out.push(status(id, STATUS_OK, ""));
        });
        let mut sftp = Sftp::new(link).expect("negotiates");
        let mut reader = content.as_slice();
        let mut last = 0;
        let total = sftp
            .upload(&Handle(vec![1]), 0, &mut reader, &mut |done| {
                assert!(done > last);
                last = done;
            })
            .expect("uploads");
        assert_eq!(total as usize, content.len());
        assert!(*written.borrow() == content);
        assert!(sftp.link.unanswered_peak <= MAX_OUTSTANDING, "{}", sftp.link.unanswered_peak);
        assert!(sftp.link.unanswered_peak > 8, "requests are pipelined: {}", sftp.link.unanswered_peak);
        assert!(sftp.link.requests.iter().all(|(kind, body)| *kind != FXP_WRITE || body.len() <= DEFAULT_BLOCK + 64));
    }

    #[test]
    fn a_failed_write_is_reported_and_the_rest_is_drained() {
        let mut seen = 0;
        let link = Scripted::new(version_frame(&[]), move |kind, body, out| {
            let id = request_id(body);
            if kind == FXP_WRITE {
                seen += 1;
                out.push(status(id, if seen == 3 { STATUS_FAILURE } else { STATUS_OK }, "quota"));
            } else {
                out.push(status(id, STATUS_OK, ""));
            }
        });
        let mut sftp = Sftp::new(link).expect("negotiates");
        let content = pattern(DEFAULT_BLOCK * 20);
        let mut reader = content.as_slice();
        let error = sftp.upload(&Handle(vec![1]), 0, &mut reader, &mut |_| {}).expect_err("write 3 fails");
        assert!(matches!(error, SftpError::Status { code: STATUS_FAILURE, .. }));
        sftp.remove("x").expect("usable afterwards");
    }

    #[test]
    fn a_local_read_error_is_reported_as_local() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        let mut sftp = Sftp::new(Scripted::new(version_frame(&[]), |_, body, out| {
            out.push(status(request_id(body), STATUS_OK, ""));
        }))
        .expect("negotiates");
        assert!(matches!(sftp.upload(&Handle(vec![1]), 0, &mut Broken, &mut |_| {}), Err(SftpError::Local(_))));
    }

    #[test]
    fn oversized_writes_and_directory_batches_are_checked() {
        let mut sftp = Sftp::new(Scripted::new(version_frame(&[]), |_, body, out| {
            out.push(reply_frame(FXP_NAME, request_id(body), &0u32.to_be_bytes()));
        }))
        .expect("negotiates");
        assert!(sftp.write(&Handle(vec![1]), 0, &vec![0; DEFAULT_BLOCK + 1]).is_err());
        assert!(matches!(sftp.readdir(&Handle(vec![1])), Err(SftpError::Protocol(_))));
        assert!(matches!(sftp.realpath("/"), Err(SftpError::Protocol(_))));
    }
}
